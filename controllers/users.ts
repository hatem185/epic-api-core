import {
  BaseController,
  Controller,
  Delete,
  Env,
  Get,
  type IRequestContext,
  type IRoute,
  parseQueryParams,
  Patch,
  Post,
  Put,
  Response,
  Versioned,
} from "@Core/common/mod.ts";
import { Store } from "@Core/common/store.ts";
import {
  normalizeFilters,
  queryValidator,
  responseValidator,
} from "@Core/common/validators.ts";
import { type RouterContext, Status } from "oak";
import e from "validator";
import { hash as bcryptHash, verify as bcryptVerify } from "bcrypt";
import { MongoTransaction, ObjectId } from "mongo";

import verifyHuman from "@Middlewares/verifyHuman.ts";
import {
  CreateUserSchema,
  DeviceReportPayloadSchema,
  EmailValidator,
  PasswordValidator,
  PhoneValidator,
  TUserInput,
  UpdateUserSchema,
  UserModel,
  UserReferenceValidator,
} from "@Models/user.ts";
import { GeoPointSchema } from "@Models/location.ts";
import { CollaboratorModel } from "@Models/collaborator.ts";
import { AccountModel } from "@Models/account.ts";
import { OauthAppModel } from "@Models/oauthApp.ts";
import { OauthSessionModel } from "@Models/oauthSession.ts";

import { PermanentlyDeleteUser } from "@Jobs/deleteUsers.ts";
import UsersIdentificationController, {
  IdentificationMethod,
  IdentificationPurpose,
} from "@Controllers/usersIdentification.ts";
import UploadsController from "@Controllers/uploads.ts";
import { Database } from "@Database";
import { allowPopulate } from "@Helpers/utils.ts";
import {
  updatePasswordQueue,
  updateVerifiedStatusQueue,
  verifyUserQueue,
} from "@Jobs/activityEvents.ts";

@Controller("/users/", { group: "User", name: "users" })
export default class UsersController extends BaseController {
  static async create(
    user: Omit<TUserInput, "role" | "passwordHistory" | "collaborates">,
    opts?: {
      databaseSession?: MongoTransaction;
    },
  ) {
    if (
      user.reference &&
      (await UserModel.exists({
        reference: user.reference,
      }))
    ) throw e.error(`Reference already registered!`);

    if (
      user.username &&
      (await UserModel.exists({
        username: new RegExp(`^${user.username}$`, "i"),
      }))
    ) throw e.error(`Username is already taken!`);

    if (
      user.phone &&
      (await UserModel.exists({ phone: user.phone }))
    ) throw e.error(`Phone number already registered!`);

    if (
      user.email &&
      (await UserModel.exists({
        email: new RegExp(`^${user.email}$`, "i"),
      }))
    ) throw e.error(`Email already registered!`);

    const UserId = new ObjectId();
    const AccountId = new ObjectId();
    const CollaboratorId = new ObjectId();

    const Password = bcryptHash(
      user.password ?? Math.random().toString(36) + Date.now().toString(36),
    );

    return Database.transaction(async (session) => ({
      user: await UserModel.create(
        {
          ...user,
          _id: UserId,
          password: Password,
          passwordHistory: [Password],
          role: ["", undefined].includes(
              await Env.get("VERIFIED_ROLE_POLICY", true),
            )
            ? "user"
            : "unverified",
          collaborates: [CollaboratorId],
        },
        { session },
      ),
      account: await AccountModel.create(
        {
          _id: AccountId,
          createdBy: UserId,
          createdFor: UserId,
          email: user.email,
          phone: user.phone,
        },
        { session },
      ),
      collaborator: await CollaboratorModel.create(
        {
          _id: CollaboratorId,
          createdBy: UserId,
          createdFor: UserId,
          account: AccountId,
          isOwned: true,
          isPrimary: true,
        },
        { session },
      ),
    }), opts?.databaseSession);
  }

  static async verify(method: IdentificationMethod, userId: string) {
    switch (method) {
      case IdentificationMethod.EMAIL:
        await UserModel.updateOne(userId, { isEmailVerified: true });
        break;

      case IdentificationMethod.PHONE:
        await UserModel.updateOne(userId, { isPhoneVerified: true });
        break;

      default:
        throw new Error(`Invalid identification method for verification!`);
    }
  }

  static async scheduleDeletion(
    userId: string,
    options?: { timeoutMs?: number },
  ) {
    await UserModel.updateOne(userId, {
      deletionAt: new Date(
        Date.now() +
          (options?.timeoutMs ??
            parseFloat(
              (await Env.get("USER_DELETION_TIMEOUT_MS", true)) ?? "1.296e+9", // Deletion in 15 days default
            )),
      ),
    });
  }

  @Post("/:oauthAppId/", {
    middlewares: () => [verifyHuman()],
  })
  public create(route: IRoute) {
    // Define Query Schema
    const QuerySchema = e.object(
      {
        reference: e.any().custom(async (ctx) => {
          if (typeof ctx.output === "string") {
            const { error } = await UserReferenceValidator().try(ctx.output);
            if (error) ctx.output = undefined;
          }
        }),
      },
      { allowUnexpectedProps: true },
    );

    // Define Params Schema
    const ParamsSchema = e.object({
      oauthAppId: e.string().checkpoint(),
      oauthApp: e
        .any()
        .custom(async (ctx) => {
          const App = await OauthAppModel.findOne(
            ctx.parent!.output.oauthAppId,
          ).project({
            _id: 1,
            "consent.availableSignups": 1,
          });

          if (!App) throw new Error("Invalid oauth app id!");

          if (!App.consent.availableSignups) {
            throw new Error("Signup is not available!");
          }

          return App;
        }),
    });

    // Define Body Schema
    const BodySchema = e.omit(CreateUserSchema, ["oauthApp"]);

    return {
      shape: () => ({
        query: QuerySchema.toSample(),
        params: ParamsSchema.toSample(),
        body: BodySchema.toSample(),
        return: responseValidator(e.object({
          user: UserModel.getSchema(),
          account: AccountModel.getSchema(),
          collaborator: CollaboratorModel.getSchema(),
        })).toSample(),
      }),
      handler: async (ctx: IRequestContext<RouterContext<string>>) => {
        // Query Validation
        const Query = await QuerySchema.validate(
          parseQueryParams(ctx.router.request.url.search),
          { name: `${route.scope}.query` },
        );

        // Params Validation
        const Params = await ParamsSchema.validate(ctx.router.params, {
          name: `${route.scope}.params`,
        });

        // Body Validation
        const Body = await BodySchema.validate(
          await ctx.router.request.body.json(),
          { name: `${route.scope}.body` },
        );

        const User = await Database.transaction(async (session) => {
          const {
            password: _,
            passwordHistory: __,
            oauthApp: ___,
            collaborates: ____,
            ...user
          } = (
            await UsersController.create({
              oauthApp: new ObjectId(Params.oauthAppId),
              reference: Query.reference,
              ...Body,
            }, { databaseSession: session })
          ).user;

          await OauthAppModel.updateOneOrFail(Params.oauthAppId, {
            $inc: {
              "consent.availableSignups": -1,
            },
          }, { session });

          return user;
        });

        return Response.statusCode(Status.Created).data(User);
      },
    };
  }

  @Patch("/me/")
  public update(route: IRoute) {
    // Extend the profile schema with transport-only fields the app may send
    const BodySchema = e.partial(
      UpdateUserSchema.extends(
        e.object({
          geoPoint: e.optional(GeoPointSchema),
          deviceLog: e.optional(DeviceReportPayloadSchema),
        }),
      ),
      { nullish: true },
    );

    return Versioned.add("1.0.0", {
      shape: () => ({
        body: BodySchema.toSample(),
        return: responseValidator(e.partial(UpdateUserSchema)).toSample(),
      }),
      handler: async (ctx: IRequestContext<RouterContext<string>>) => {
        if (!ctx.router.state.auth) ctx.router.throw(Status.Unauthorized);

        // Body Validation
        const Body = await BodySchema.validate(
          await ctx.router.request.body.json(),
          { name: `${route.scope}.body` },
        );

        const { deviceLog, geoPoint, ...profileFields } = Body;

        // deno-lint-ignore no-explicit-any
        const updatePush: Record<string, any> = {};

        // Legacy geoPoint support for older app versions
        if (geoPoint) {
          updatePush.locationHistory = { $each: [geoPoint], $slice: -10 };
        }

        // Store device log entry (best-effort, rate-limited to 1/min per user)
        if (deviceLog) {
          const userId = ctx.router.state.auth.userId;
          const count = await Store.incr(`deviceLogPatch:${userId}`, {
            expiresInMs: 60_000,
          });

          if (count <= 1) {
            const ip = (
              ctx.router.request.headers.get("x-forwarded-for")
                ?.split(",")[0]
                .trim() ?? ctx.router.request.ip
            ).slice(0, 45);

            updatePush.deviceLoginHistory = {
              $each: [{ receivedAt: new Date(), ip, payload: deviceLog }],
              $slice: -100,
            };
          }
        }

        // deno-lint-ignore no-explicit-any
        const update: Record<string, any> = {};
        if (Object.keys(profileFields).length) update.$set = profileFields;
        if (Object.keys(updatePush).length) update.$push = updatePush;

        if (Object.keys(update).length) {
          await UserModel.updateOne(ctx.router.state.auth.userId, update);
        }

        return Response.data(profileFields);
      },
    });
  }

  @Put("/password/")
  public updatePassword(route: IRoute) {
    // Define Body Schema
    const BodySchema = e.object({
      method: e.in(Object.values(IdentificationMethod)),
      token: e.string(),
      code: e.number({ cast: true }).length(6),
      password: PasswordValidator(),
      hashedPassword: e
        .any()
        .custom((ctx) => bcryptHash(ctx.parent?.output.password)),
    });

    return new Versioned().add("1.0.0", {
      shape: () => ({
        body: BodySchema.toSample(),
      }),
      handler: async (ctx: IRequestContext<RouterContext<string>>) => {
        // Body Validation
        const Body = await BodySchema.validate(
          await ctx.router.request.body.json(),
          { name: `${route.scope}.body` },
        );

        const Payload =
          (ctx.router.state.verifyTokenPayload =
            await UsersIdentificationController.verify<{
              userId: string;
            }>(
              Body.token,
              Body.code,
              IdentificationPurpose.RECOVERY,
              Body.method,
            ).catch(e.error));

        const User = await UserModel.findOne(Payload.userId).project({
          passwordHistory: 1,
        });

        if (!User) e.error(`User not found!`);

        if (
          User!.passwordHistory?.some((hashedPassword) =>
            bcryptVerify(Body.password, hashedPassword)
          )
        ) e.error(`Cannot use an old password!`);

        await UserModel.updateOne(
          { _id: new ObjectId(Payload.userId) },
          {
            password: Body.hashedPassword,
            $push: {
              passwordHistory: {
                $each: [Body.hashedPassword],
                $slice: -10,
              },
            },
            failedLoginAttempts: 0,
            deletionAt: null,
          },
        );

        await updatePasswordQueue.enqueue({
          data: {
            verifyTokenPayload: ctx.router.state.verifyTokenPayload,
          },
        });

        return Response.true();
      },
    });
  }

  @Put("/email/")
  public updateEmail(route: IRoute) {
    // Define Body Schema
    const BodySchema = e.object({
      email: EmailValidator().custom(async (ctx) => {
        if (await UserModel.countDocuments({ email: ctx.output })) {
          throw "Please provide a different email!";
        }
      }),
    });

    return Versioned.add("1.0.0", {
      shape: () => ({
        body: BodySchema.toSample(),
        return: responseValidator(e.object({
          type: e.in(Object.values(IdentificationMethod)),
          value: e.string(),
          verified: e.boolean(),
        })).toSample(),
      }),
      handler: async (ctx: IRequestContext<RouterContext<string>>) => {
        if (!ctx.router.state.auth) ctx.router.throw(Status.Unauthorized);

        // Body Validation
        const Body = await BodySchema.validate(
          await ctx.router.request.body.json(),
          { name: `${route.scope}.body` },
        );

        const Verified = false;

        await UserModel.updateOne(ctx.router.state.auth.userId, {
          email: Body.email,
          isEmailVerified: Verified,
        });

        await updateVerifiedStatusQueue.enqueue({
          data: { userId: ctx.router.state.auth.userId },
        });

        return Response.data({
          type: IdentificationMethod.EMAIL,
          value: Body.email,
          verified: Verified,
        });
      },
    });
  }

  @Put("/phone/")
  public updatePhone(route: IRoute) {
    // Define Body Schema
    const BodySchema = e.object({
      phone: PhoneValidator().custom(async (ctx) => {
        if (await UserModel.countDocuments({ phone: ctx.output })) {
          throw "Please provide a different phone!";
        }
      }),
    });

    return Versioned.add("1.0.0", {
      shape: () => ({
        body: BodySchema.toSample(),
        return: responseValidator(e.object({
          type: e.in(Object.values(IdentificationMethod)),
          value: e.string(),
          verified: e.boolean(),
        })).toSample(),
      }),
      handler: async (ctx: IRequestContext<RouterContext<string>>) => {
        if (!ctx.router.state.auth) ctx.router.throw(Status.Unauthorized);

        // Body Validation
        const Body = await BodySchema.validate(
          await ctx.router.request.body.json(),
          { name: `${route.scope}.body` },
        );

        const Verified = false;

        await UserModel.updateOne(ctx.router.state.auth.userId, {
          phone: Body.phone,
          isPhoneVerified: Verified,
        });

        await updateVerifiedStatusQueue.enqueue({
          data: { userId: ctx.router.state.auth.userId },
        });

        return Response.data({
          type: IdentificationMethod.PHONE,
          value: Body.phone,
          verified: Verified,
        });
      },
    });
  }

  @Put("/fcm/token/")
  public setFcmToken() {
    // Define Body Schema
    const BodySchema = e.object({
      token: e.string(),
    });

    return Versioned.add("1.0.0", {
      shape: () => ({
        body: BodySchema.toSample(),
      }),
      handler: async (ctx: IRequestContext<RouterContext<string>>) => {
        if (!ctx.router.state.auth) ctx.router.throw(Status.Unauthorized);

        // Body Validation
        const Body = await BodySchema.validate(
          await ctx.router.request.body.json(),
          { name: "oauth.body" },
        );

        await UserModel.updateOne(ctx.router.state.auth.userId, {
          $addToSet: {
            fcmDeviceTokens: Body.token,
          },
        });

        // Background event may fetch the data based on this userId
        ctx.router.state.updateFcmDeviceTokens = ctx.router.state.auth.userId;

        return Response.true();
      },
    });
  }

  @Delete("/fcm/token/")
  public deleteFcmToken(route: IRoute) {
    // Define Query Schema
    const QuerySchema = e.object(
      {
        token: e.string(),
      },
      { allowUnexpectedProps: true },
    );

    return Versioned.add("1.0.0", {
      shape: () => ({
        query: QuerySchema.toSample(),
      }),
      handler: async (ctx: IRequestContext<RouterContext<string>>) => {
        if (!ctx.router.state.auth) ctx.router.throw(Status.Unauthorized);

        // Query Validation
        const Query = await QuerySchema.validate(
          parseQueryParams(ctx.router.request.url.search),
          { name: `${route.scope}.query` },
        );

        await UserModel.updateOne(ctx.router.state.auth.userId, {
          $pull: {
            fcmDeviceTokens: Query.token,
          },
        });

        // Background event may fetch the data based on this userId
        ctx.router.state.updateFcmDeviceTokens = ctx.router.state.auth.userId;

        return Response.true();
      },
    });
  }

  @Post("/verify/")
  public verify(route: IRoute) {
    // Define Body Schema
    const BodySchema = e.object({
      method: e.in(Object.values(IdentificationMethod)),
      token: e.string(),
      code: e.number({ cast: true }).length(6),
    });

    return new Versioned().add("1.0.0", {
      shape: () => ({
        body: BodySchema.toSample(),
      }),
      handler: async (ctx: IRequestContext<RouterContext<string>>) => {
        // Body Validation
        const Body = await BodySchema.validate(
          await ctx.router.request.body.json(),
          { name: `${route.scope}.body` },
        );

        const Payload =
          (ctx.router.state.verifyTokenPayload =
            await UsersIdentificationController.verify<{
              userId: string;
            }>(
              Body.token,
              Body.code,
              IdentificationPurpose.VERIFICATION,
              Body.method,
            ).catch(e.error));

        await UsersController.verify(Body.method, Payload.userId);

        await verifyUserQueue.enqueue({
          data: {
            sessionId: ctx.router.state.sessionInfo?.claims.sessionId,
            secretId: ctx.router.state.sessionInfo?.claims.secretId,
            accountId: ctx.router.state.auth?.accountId,
            verifyTokenPayload: ctx.router.state.verifyTokenPayload,
          },
        });

        return Response.true();
      },
    });
  }

  @Get("/:id?/")
  public get(route: IRoute) {
    // Define Query Schema
    const QuerySchema = e.deepCast(
      e.object(
        {
          includeTags: e.optional(e.array(e.string()).min(1)),
          excludeTags: e.optional(e.array(e.string()).min(1)),
        },
        { allowUnexpectedProps: true },
      ).extends(queryValidator()),
    );

    // Define Params Schema
    const ParamsSchema = e.object({
      id: e.optional(e.string()),
    });

    const PopulatedUser = e.object({
      collaborates: e.array(
        e.object({
          account: AccountModel.getSchema(),
        }).extends(e.omit(CollaboratorModel.getSchema(), ["account"])),
      ),
    }).extends(
      e.omit(UserModel.getSchema(), ["collaborates", "deviceLoginHistory"]),
    );

    return Versioned.add("1.0.0", {
      shape: () => ({
        query: QuerySchema.toSample(),
        params: ParamsSchema.toSample(),
        return: responseValidator(e.object({
          totalCount: e.optional(e.number()),
          users: e.array(PopulatedUser),
        })).toSample(),
      }),
      handler: async (ctx: IRequestContext<RouterContext<string>>) => {
        // Query Validation
        const Query = await QuerySchema.validate(
          parseQueryParams(ctx.router.request.url.search),
          { name: `${route.scope}.query` },
        );

        // Params Validation
        const Params = await ParamsSchema.validate(ctx.router.params, {
          name: `${route.scope}.params`,
        });

        let tags: string[] | undefined;

        if (Query.includeTags instanceof Array) {
          tags = Query.includeTags;

          if (Query.excludeTags instanceof Array) {
            tags = tags.filter((tag) => !Query.excludeTags?.includes(tag));
          }
        } else tags = Query.excludeTags;

        // Fetch users
        const UsersListQuery = UserModel.search(Query.search)
          .filter({
            ...normalizeFilters(Query.filters),
            ...(Params.id ? { _id: new ObjectId(Params.id) } : {}),
            ...(ctx.router.state.auth?.user.username === "root" ? {} : {
              username: { $ne: "root" },
            }),
            ...(tags
              ? { tags: { [!Query.includeTags ? "$nin" : "$in"]: tags } }
              : {}),
            ...(Query.range instanceof Array
              ? {
                createdAt: {
                  $gt: new Date(Query.range[0]),
                  $lt: new Date(Query.range[1]),
                },
              }
              : {}),
          })
          .project({
            password: 0,
            passwordHistory: 0,
            passkeys: 0,
            deviceLoginHistory: 0,
          })
          .sort(Query.sort)
          .skip(Query.offset)
          .limit(Query.limit)
          .populate(
            "collaborates",
            CollaboratorModel.populateOne("account", AccountModel, {
              disabled: !allowPopulate(
                /^collaborates\.account.*/,
                Query.project,
              ),
            }),
            { disabled: !allowPopulate(/^collaborates.*/, Query.project) },
          );

        if (Query.project) UsersListQuery.project(Query.project);

        return Response.data({
          totalCount: Query.includeTotalCount
            ? await Store.cache(
              ["totalCount", "User"],
              () => UserModel.countDocuments(),
              (await Env.number("GLOBAL_PAGINATION_COUNT_TTL")) * 1000,
            )
            : undefined,
          users: await UsersListQuery,
        });
      },
    });
  }

  @Get("/me/")
  public me(route: IRoute) {
    // Define Query Schema
    const QuerySchema = e.object(
      {
        project: e.optional(
          e.record(e.number({ cast: true }).min(0).max(1), { cast: true }),
        ),
      },
      { allowUnexpectedProps: true },
    );

    return Versioned.add("1.0.0", {
      shape: () => ({
        return: responseValidator(e.object({
          user: e.object({
            collaborates: e.array(
              e.object({
                account: AccountModel.getSchema(),
              }).extends(e.omit(CollaboratorModel.getSchema(), ["account"])),
            ),
          }).extends(e.omit(UserModel.getSchema(), [
            "password",
            "passwordHistory",
            "passkeys",
            "fcmDeviceTokens",
            "collaborates",
            "deviceLoginHistory",
          ])),
        })).toSample(),
      }),
      handler: async (ctx: IRequestContext<RouterContext<string>>) => {
        if (!ctx.router.state.auth) ctx.router.throw(Status.Unauthorized);

        // Query Validation
        const Query = await QuerySchema.validate(
          parseQueryParams(ctx.router.request.url.search),
          { name: `${route.scope}.query` },
        );

        // Fetch user
        const UserQuery = UserModel.findOne(ctx.router.state.auth.userId)
          .project({
            password: 0,
            passwordHistory: 0,
            "passkeys.publicKey": 0,
            "passkeys.counter": 0,
            "passkeys.deviceType": 0,
            "passkeys.backedUp": 0,
            fcmDeviceTokens: 0,
            deviceLoginHistory: 0,
          })
          .populate(
            "collaborates",
            CollaboratorModel.populateOne("account", AccountModel, {
              disabled: !allowPopulate(
                /^collaborates\.account.*/,
                Query.project,
              ),
            }),
            { disabled: !allowPopulate(/^collaborates.*/, Query.project) },
          );

        if (Query.project) UserQuery.project(Query.project);

        return Response.data({
          user: await UserQuery,
        });
      },
    });
  }

  @Delete("/")
  public delete(route: IRoute) {
    // Define Query Schema
    const QuerySchema = e.object(
      { deletionTimeoutMs: e.optional(e.number({ cast: true })) },
      { allowUnexpectedProps: true },
    );

    return Versioned.add("1.0.0", {
      shape: () => ({
        query: QuerySchema.toSample(),
      }),
      handler: async (ctx: IRequestContext<RouterContext<string>>) => {
        if (!ctx.router.state.auth) ctx.router.throw(Status.Unauthorized);

        // Query Validation
        const Query = await QuerySchema.validate(
          parseQueryParams(ctx.router.request.url.search),
          { name: `${route.scope}.query` },
        );

        const UserId = new ObjectId(ctx.router.state.auth.userId);

        // Logout all sessions
        await OauthSessionModel.deleteMany({
          createdBy: UserId,
        });

        if (Query.deletionTimeoutMs === 0) {
          // Instant user deletion
          await PermanentlyDeleteUser.exec({ userId: UserId });
        } else {
          await UsersController.scheduleDeletion(ctx.router.state.auth.userId, {
            timeoutMs: Query.deletionTimeoutMs,
          });
        }

        return Response.true();
      },
    });
  }

  @Patch("/role/:id/")
  public updateRole(route: IRoute) {
    // Define Params Schema
    const ParamsSchema = e.object({
      id: e.optional(e.string()),
    });

    // Define Body Schema
    const BodySchema = e.object({
      role: e.string(),
    });

    return new Versioned().add("1.0.0", {
      shape: () => ({
        params: ParamsSchema.toSample(),
        body: BodySchema.toSample(),
      }),
      handler: async (ctx: IRequestContext<RouterContext<string>>) => {
        // Params Validation
        const Params = await ParamsSchema.validate(ctx.router.params, {
          name: `${route.scope}.params`,
        });

        // Body Validation
        const Body = await BodySchema.validate(
          await ctx.router.request.body.json(),
          { name: `${route.scope}.body` },
        );

        await UserModel.updateOneOrFail(Params.id, { role: Body.role });

        return Response.true();
      },
    });
  }

  @Get("/avatar/sign/")
  @Put("/avatar/")
  @Delete("/avatar/")
  public updateAvatar(route: IRoute) {
    return UploadsController.upload(
      route,
      {
        allowedContentTypes: [
          "image/png",
          "image/jpg",
          "image/jpeg",
          "image/svg+xml",
          "image/webp",
        ],
        maxContentLength: 2e6,
        location: "users/{{userId}}/avatar/",
      },
      async (ctx, avatar) => {
        if (!ctx.router.state.auth) ctx.router.throw(Status.Unauthorized);

        await UserModel.updateOneOrFail(ctx.router.state.auth!.userId, {
          avatar,
        });
      },
      async (ctx, deleteObject) => {
        if (!ctx.router.state.auth) ctx.router.throw(Status.Unauthorized);

        const ObjectUrl = ctx.router.state.auth?.user.avatar?.url;

        if (ObjectUrl) {
          await UserModel.updateOneOrFail(ctx.router.state.auth!.userId, {
            $unset: {
              avatar: 1,
            },
          });

          await deleteObject(ObjectUrl);
        }
      },
    );
  }

  @Patch("/toggle/blocked/:id/:isBlocked/")
  public toggleBlocked(route: IRoute) {
    // Define Params Schema
    const ParamsSchema = e.object({
      id: e.string(),
      isBlocked: e.boolean({ cast: true }),
    });

    return new Versioned().add("1.0.0", {
      shape: () => ({
        params: ParamsSchema.toSample(),
      }),
      handler: async (ctx: IRequestContext<RouterContext<string>>) => {
        // Params Validation
        const Params = await ParamsSchema.validate(ctx.router.params, {
          name: `${route.scope}.params`,
        });

        // Update user's blocking status
        await UserModel.updateOneOrFail(Params.id, {
          isBlocked: Params.isBlocked,
        });

        return Response.true();
      },
    });
  }
}
