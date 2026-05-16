import {
  BaseController,
  Controller,
  Get,
  type IRequestContext,
  type IRoute,
  parseQueryParams,
  Put,
  Response,
  Versioned,
} from "@Core/common/mod.ts";
import { responseValidator } from "@Core/common/validators.ts";
import { type RouterContext } from "oak";
import e from "validator";
import { ObjectId } from "mongo";
import {
  DeviceLoginEntrySchema,
  PasswordValidator,
  UserModel,
} from "@Models/user.ts";
import { hash as bcryptHash } from "bcrypt";

@Controller("/manage/users/", { group: "User", name: "manageUsers" })
export default class ManageUsersController extends BaseController {
  @Put("/password/:id/")
  public updatePassword(route: IRoute) {
    // Define Params Schema
    const ParamsSchema = e.object({
      id: e.instanceOf(ObjectId, { instantiate: true }),
    });

    // Define Body Schema
    const BodySchema = e.object({
      password: PasswordValidator(),
      hashedPassword: e
        .any()
        .custom((ctx) => bcryptHash(ctx.parent?.output.password)),
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

        await UserModel.updateOneOrFail(Params.id, {
          password: Body.hashedPassword,
          $push: {
            passwordHistory: {
              $each: [Body.hashedPassword],
              $slice: -10,
            },
          },
          failedLoginAttempts: 0,
          deletionAt: null,
        });

        return Response.true();
      },
    });
  }

  @Get("/device-log/:id/")
  public getDeviceLog(route: IRoute) {
    // Define Params Schema
    const ParamsSchema = e.object({
      id: e.instanceOf(ObjectId, { instantiate: true }),
    });

    // Define Query Schema
    const QuerySchema = e.object(
      {
        limit: e.optional(e.number({ cast: true }).min(1).max(100)).default(50),
        before: e.optional(e.date()),
      },
      { allowUnexpectedProps: true },
    );

    return new Versioned().add("1.0.0", {
      shape: () => ({
        params: ParamsSchema.toSample(),
        query: QuerySchema.toSample(),
        return: responseValidator(
          e.object({
            entries: e.array(DeviceLoginEntrySchema),
          }),
        ).toSample(),
      }),
      handler: async (ctx: IRequestContext<RouterContext<string>>) => {
        // Params Validation
        const Params = await ParamsSchema.validate(ctx.router.params, {
          name: `${route.scope}.params`,
        });

        // Query Validation
        const Query = await QuerySchema.validate(
          parseQueryParams(ctx.router.request.url.search),
          { name: `${route.scope}.query` },
        );

        const User = await UserModel.findOne(Params.id).project({
          deviceLoginHistory: 1,
        });

        const entries = (User?.deviceLoginHistory ?? [])
          .slice()
          .reverse()
          .filter((entry) =>
            Query.before ? entry.receivedAt < Query.before! : true,
          )
          .slice(0, Query.limit);

        return Response.data({ entries });
      },
    });
  }
}
