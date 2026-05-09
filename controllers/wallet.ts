import {
  BaseController,
  Controller,
  Delete,
  Env,
  EnvType,
  Get,
  type IRequestContext,
  type IRoute,
  parseQueryParams,
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
import { ObjectId } from "mongo";
import { hash } from "ohash";

import { TWalletFeeStructure, Wallet } from "@Lib/wallet.ts";
import UsersIdentificationController, {
  IdentificationMethod,
  IdentificationPurpose,
} from "@Controllers/usersIdentification.ts";

import { UserModel } from "@Models/user.ts";
import { TransactionModel } from "@Models/transaction.ts";
import { AccountModel } from "@Models/account.ts";
import { FileSchema, TFileOutput } from "@Models/file.ts";
import { WalletModel } from "@Models/wallet.ts";
import { CollaboratorModel } from "@Models/collaborator.ts";
import UploadsController from "./uploads.ts";
import { allowPopulate } from "@Helpers/utils.ts";
import { Database } from "@Database";

@Controller("/wallet/", { group: "Wallet", name: "wallet" })
export default class WalletController extends BaseController {
  @Get("/metadata/", {
    group: "public",
  })
  public metadata() {
    return new Versioned().add("1.0.0", {
      shape: () => ({
        return: responseValidator(e.object({
          defaultType: e.string(),
          availableTypes: e.array(e.string()),
          defaultCurrency: e.string(),
          availableCurrencies: e.array(e.string()),
        })).toSample(),
      }),
      handler: async () => {
        const [
          defaultType,
          availableTypes,
          defaultCurrency,
          availableCurrencies,
        ] = await Promise.all([
          Wallet.getDefaultType(),
          Wallet.getTypes(),
          Wallet.getDefaultCurrency(),
          Wallet.getCurrencies(),
        ]);

        return Response.data({
          defaultType,
          availableTypes,
          defaultCurrency,
          availableCurrencies,
        });
      },
    });
  }

  @Get("/transfer/sign/:type?/:currency?/", {
    group: "public",
  })
  public signTransfer(route: IRoute) {
    // Define Query Schema
    const QuerySchema = e.object(
      {
        method: e
          .optional(e.in(Object.values(IdentificationMethod)))
          .describe("Provide a 3D security method to verify the transfer."),
        receiver: e.string(),
        amount: e.number({ cast: true }),
        description: e.optional(e.string().max(300)),
        metadata: e.optional(
          e.record(e.or([e.number(), e.boolean(), e.string()]), { cast: true }),
        ),
      },
      { allowUnexpectedProps: true },
    );

    // Define Params Schema
    const ParamsSchema = e.object({
      type: e.optional(e.string()),
      currency: e.optional(e.string()),
    });

    return new Versioned().add("1.0.0", {
      shape: () => ({
        query: QuerySchema.toSample(),
        params: ParamsSchema.toSample(),
        return: responseValidator(e.object({
          sender: e.object({
            accountId: e.string(),
            userId: e.string(),
            fname: e.string(),
            mname: e.string(),
            lname: e.string(),
            avatar: e.string(),
          }),
          receiver: e.object({
            accountId: e.string(),
            accountName: e.string(),
            accountLogo: FileSchema,
            userId: e.string(),
            fname: e.string(),
            mname: e.string(),
            lname: e.string(),
            avatar: e.string(),
          }),
          transactionDetails: e.object({
            type: e.string(),
            currency: e.string(),
            amount: e.number(),
            fee: e.number(),
            description: e.string(),
            metadata: e.record(e.or([e.string(), e.number(), e.boolean()])),
          }),
          challenge: e.object({
            token: e.string(),
            otp: e.optional(e.number()),
          }),
        })).toSample(),
      }),
      handler: async (ctx: IRequestContext<RouterContext<string>>) => {
        if (!ctx.router.state.auth) ctx.router.throw(Status.Unauthorized);

        // Query Validation
        const Query = await QuerySchema.validate(
          parseQueryParams(ctx.router.request.url.search),
          { name: `${route.scope}.query` },
        );

        // Params Validation
        const Params = await ParamsSchema.validate(ctx.router.params, {
          name: `${route.scope}.params`,
        });

        const [receiverId, accountId] = Query.receiver.split(":");

        const ReceivingUser = await UserModel.findOne({
          $or: [
            ...(ObjectId.isValid(receiverId)
              ? [{ _id: new ObjectId(receiverId) }]
              : []),
            { username: receiverId },
            { email: receiverId },
            { phone: receiverId },
            { reference: receiverId },
          ],
        }).project({
          _id: 1,
          fname: 1,
          mname: 1,
          lname: 1,
          avatar: 1,
        });

        if (!ReceivingUser?._id) {
          throw e.error(
            `Receiving user not found!`,
            `${route.scope}.query.receiver`,
          );
        }

        const Collaborations = await CollaboratorModel.find({
          createdFor: ReceivingUser._id,
          ...(ObjectId.isValid(accountId)
            ? { account: new ObjectId(accountId) }
            : {
              $or: [
                { isOwned: true, isPrimary: true },
                { isOwned: true },
              ],
            }),
          isBlocked: { $ne: true },
        }).project({ account: 1 });

        if (!Collaborations.length) {
          throw new Error("No relevant account found!");
        }

        const ReceiverAccount = await AccountModel.findOne({
          _id: { $in: Collaborations.map(($) => $.account) },
          isBlocked: { $ne: true },
        }).project({ name: 1, logo: 1 });

        if (!ReceiverAccount) throw new Error("Receiver account not found!");

        const feeStructure = await Wallet.calculateFee({
          category:
            ctx.router.state.guard.isPermitted("wallet", "signInternalTransfer")
              ? "internal"
              : "external",
          from: ctx.router.state.auth.accountId,
          sender: ctx.router.state.auth.user._id,
          to: ReceiverAccount._id,
          receiver: ReceivingUser._id,
          type: Params.type,
          currency: Params.currency,
          amount: Query.amount,
        });

        const TransferDetails = {
          sender: {
            accountId: ctx.router.state.auth.accountId,
            userId: ctx.router.state.auth.user._id.toString(),
            fname: ctx.router.state.auth.user.fname,
            mname: ctx.router.state.auth.user.mname,
            lname: ctx.router.state.auth.user.lname,
            avatar: ctx.router.state.auth.user.avatar,
          },
          receiver: {
            accountId: ReceiverAccount._id.toString(),
            accountName: ReceiverAccount.name,
            accountLogo: ReceiverAccount.logo,
            userId: ReceivingUser._id.toString(),
            fname: ReceivingUser.fname,
            mname: ReceivingUser.mname,
            lname: ReceivingUser.lname,
            avatar: ReceivingUser.avatar,
          },
          transactionDetails: {
            type: Params.type,
            currency: Params.currency,
            amount: Query.amount,
            fee: feeStructure.total,
            feeStructure,
            description: Query.description,
            metadata: Query.metadata,
          },
        };

        if (Query.method) {
          const Challenge = await UsersIdentificationController.request(
            IdentificationPurpose.VERIFICATION,
            Query.method,
            { userId: ctx.router.state.auth.userId },
            TransferDetails,
            ctx.router.lang,
          );

          return Response.statusCode(Status.Created).data({
            ...TransferDetails,
            challenge: {
              token: Challenge.token,

              // Return OTP if its a test.
              otp: Env.is(EnvType.TEST) ? Challenge.otp : undefined,
            },
          });
        }

        const Challenge = await UsersIdentificationController.sign(
          IdentificationPurpose.VERIFICATION,
          null,
          TransferDetails,
        );

        return Response.statusCode(Status.Created).data({
          ...TransferDetails,
          challenge: Challenge,
        });
      },
    });
  }

  @Post("/transfer/", {
    group: "public",
  })
  public transfer(route: IRoute) {
    // Define Body Schema
    const BodySchema = e.object({
      method: e.optional(e.in(Object.values(IdentificationMethod))),
      token: e.string(),
      code: e.number({ cast: true }).length(6),
      tags: e.optional(e.array(e.string())),
    });

    return new Versioned().add("1.0.0", {
      shape: () => ({
        body: BodySchema.toSample(),
        return: responseValidator(e.object({
          transaction: TransactionModel.getSchema(),
        })).toSample(),
      }),
      handler: async (ctx: IRequestContext<RouterContext<string>>) => {
        if (!ctx.router.state.auth) ctx.router.throw(Status.Unauthorized);

        // Body Validation
        const Body = await BodySchema.validate(
          await ctx.router.request.body.json(),
          { name: `${route.scope}.body` },
        );

        type TransferEntity = {
          accountId: string;
          userId: string;
          fname: string;
          mname: string;
          lname: string;
          avatar: TFileOutput;
        };

        const Payload = await UsersIdentificationController.verify<{
          sender: TransferEntity;
          receiver: TransferEntity;
          transactionDetails: {
            type?: string;
            currency?: string;
            amount: number;
            fee: number;
            feeStructure?: TWalletFeeStructure;
            description: string;
            metadata?: Record<string, string | number | boolean>;
          };
        }>(Body.token, Body.code, IdentificationPurpose.VERIFICATION).catch(
          e.error,
        );

        const { transaction } = await Database.transaction(async (session) => {
          const MainTransfer = await Wallet.transfer({
            sessionId: Payload.challengeId,
            fromName: [
              Payload.sender.fname,
              Payload.sender.mname,
              Payload.sender.lname,
            ],
            from: Payload.sender.accountId,
            sender: Payload.sender.userId,
            toName: [
              Payload.receiver.fname,
              Payload.receiver.mname,
              Payload.receiver.lname,
            ],
            to: Payload.receiver.accountId,
            receiver: Payload.receiver.userId,
            user: ctx.router.state.auth!.userId,
            type: Payload.transactionDetails.type,
            currency: Payload.transactionDetails.currency,
            amount: Payload.transactionDetails.amount,
            description: Payload.transactionDetails.description,
            methodOf3DSecurity: Body.method,
            tags: Body.tags,
            backgroundEvent: true,
            metadata: Payload.transactionDetails.metadata,
            databaseSession: session,
          });

          const FeeBreakdown: TWalletFeeStructure | undefined =
            Payload.transactionDetails.feeStructure;

          if (FeeBreakdown?.breakdown instanceof Array) {
            for (
              const { account, user, name, amount } of FeeBreakdown.breakdown
            ) {
              await Wallet.transfer({
                fromName: [
                  Payload.sender.fname,
                  Payload.sender.mname,
                  Payload.sender.lname,
                ],
                from: Payload.sender.accountId,
                sender: Payload.sender.userId,
                toName: name,
                to: account,
                receiver: user,
                user: ctx.router.state.auth!.userId,
                type: Payload.transactionDetails.type,
                currency: Payload.transactionDetails.currency,
                amount,
                description: ctx.router.t("Fund transfer fee charges"),
                databaseSession: session,
              });
            }
          }

          return {
            transaction: MainTransfer.transaction,
          };
        });

        return Response.statusCode(Status.Created).data({
          transaction,
        });
      },
    });
  }

  @Get("/balance/:type?/:currency?/", {
    group: "public",
  })
  public balance(route: IRoute) {
    // Define Params Schema
    const ParamsSchema = e.object({
      type: e.optional(e.string()),
      currency: e.optional(e.string()),
    });

    return Versioned.add("1.0.0", {
      shape: () => ({
        params: ParamsSchema.toSample(),
        return: responseValidator(e.omit(WalletModel.getSchema(), ["digest"]))
          .toSample(),
      }),
      handler: async (ctx: IRequestContext<RouterContext<string>>) => {
        if (!ctx.router.state.auth) ctx.router.throw(Status.Unauthorized);

        // Params Validation
        const Params = await ParamsSchema.validate(ctx.router.params, {
          name: `${route.scope}.params`,
        });

        const wallet = await Wallet.get(
          ctx.router.state.auth.accountId,
          Params,
        );

        // deno-lint-ignore ban-ts-comment
        // @ts-ignore
        delete wallet.digest;

        return Response.data(wallet);
      },
    });
  }

  @Post("/balance/list/", {
    group: "public",
  })
  public balanceList(route: IRoute) {
    // Define Body Schema
    const BodySchema = e.object({
      types: e.optional(e.array(e.string())),
      currencies: e.optional(e.array(e.string())),
    });

    return Versioned.add("1.0.0", {
      shape: () => ({
        body: BodySchema.toSample(),
        return: responseValidator(
          e.array(e.omit(WalletModel.getSchema(), ["digest"])),
        ).toSample(),
      }),
      handler: async (ctx: IRequestContext<RouterContext<string>>) => {
        if (!ctx.router.state.auth) ctx.router.throw(Status.Unauthorized);

        // Body Validation
        const Body = await BodySchema.validate(
          await ctx.router.request.body.json(),
          { name: `${route.scope}.body` },
        );

        const walletList = await Wallet.list(
          ctx.router.state.auth.accountId,
          Body,
        );

        return Response.data(walletList.map((wallet) => {
          // deno-lint-ignore ban-ts-comment
          // @ts-ignore
          delete wallet.digest;

          return wallet;
        }));
      },
    });
  }

  @Get("/transactions/:type?/:currency?/", {
    group: "public",
  })
  public transactions(route: IRoute) {
    // Define Query Schema

    const excludeFromProjection = (
      project: Record<string, number> | undefined,
      excludeKeys: string[],
    ): Record<string, number> => {
      return project
        ? Object.fromEntries(
          Object.entries(project).filter(([key]) => !excludeKeys.includes(key)),
        )
        : Object.fromEntries(excludeKeys.map((key) => [key, 0]));
    };

    const QuerySchema = e.deepCast(
      e.object(
        {
          sent: e.optional(e.boolean()),
          received: e.optional(e.boolean()),
        },
        { allowUnexpectedProps: true },
      ).extends(queryValidator()),
    );

    // Define Params Schema
    const ParamsSchema = e.object({
      type: e.optional(e.string()).default(() => Wallet.getDefaultType()),
      currency: e
        .optional(e.string())
        .default(() => Wallet.getDefaultCurrency()),
    });

    const LimitedAccount = e.pick(AccountModel.getSchema(), [
      "_id",
      "name",
      "logo",
    ]);
    const LimitedUser = e.pick(UserModel.getSchema(), [
      "_id",
      "fname",
      "mname",
      "lname",
      "avatar",
    ]);

    return Versioned.add("1.0.0", {
      shape: () => ({
        query: QuerySchema.toSample(),
        params: ParamsSchema.toSample(),
        return: responseValidator(e.object({
          totalCount: e.optional(e.number()),
          results: e.array(
            e.object({
              from: LimitedAccount,
              to: LimitedAccount,
              sender: LimitedUser,
              receiver: LimitedUser,
            }).extends(
              e.omit(TransactionModel.getSchema(), [
                "sender",
                "receiver",
                "from",
                "to",
              ]),
            ),
          ),
        })).toSample(),
      }),
      handler: async (ctx: IRequestContext<RouterContext<string>>) => {
        if (!ctx.router.state.auth) ctx.router.throw(Status.Unauthorized);

        // Query Validation
        const Query = await QuerySchema.validate(
          parseQueryParams(ctx.router.request.url.search),
          { name: `${route.scope}.query` },
        );

        // Params Validation
        const Params = await ParamsSchema.validate(ctx.router.params, {
          name: `${route.scope}.params`,
        });

        const TargetAccountId = new ObjectId(ctx.router.state.auth.accountId);

        const targets = [
          ...(Query.sent ? [{ from: TargetAccountId }] : []),
          ...(Query.received ? [{ to: TargetAccountId }] : []),
        ];

        const TransactionListBaseConditions = {
          ...normalizeFilters(Query.filters),
          ...(targets.length === 1 ? targets[0] : {
            $or: targets.length ? targets : [
              { from: TargetAccountId },
              { to: TargetAccountId },
            ],
          }),
          ...Params,
          ...(Query.range instanceof Array
            ? {
              createdAt: {
                $gt: new Date(Query.range[0]),
                $lt: new Date(Query.range[1]),
              },
            }
            : {}),
        };

        const TransactionListQuery = TransactionModel.search(Query.search)
          .filter(TransactionListBaseConditions)
          .sort(Query.sort)
          .skip(Query.offset)
          .limit(Query.limit)
          .populateOne("from", AccountModel, {
            project: { name: 1, logo: 1 },
            disabled: !allowPopulate(/^from.*/, Query.project),
          })
          .populateOne("sender", UserModel, {
            project: { fname: 1, mname: 1, lname: 1, avatar: 1 },
            disabled: !allowPopulate(/^sender.*/, Query.project),
          })
          .populateOne("to", AccountModel, {
            project: { name: 1, logo: 1 },
            disabled: !allowPopulate(/^to.*/, Query.project),
          })
          .populateOne("receiver", UserModel, {
            project: { fname: 1, mname: 1, lname: 1, avatar: 1 },
            disabled: !allowPopulate(/^receiver.*/, Query.project),
          });

        const fromApi = ctx.router.request.headers.get("Authorization")
          ?.startsWith("apiKey");

        TransactionListQuery.project(
          excludeFromProjection(
            Query.project,
            fromApi
              ? ["digest", "senderPreviousBalance", "receiverPreviousBalance"]
              : ["digest"],
          ),
        );

        return Response.data({
          totalCount: Query.includeTotalCount
            ? await Store.cache(
              [
                "totalCount",
                "Transaction",
                hash(TransactionListBaseConditions),
              ],
              () =>
                TransactionModel.countDocuments(TransactionListBaseConditions),
              (await Env.number("GLOBAL_PAGINATION_COUNT_TTL")) * 1000,
            )
            : undefined,
          results: await TransactionListQuery,
        });
      },
    });
  }

  @Get("/transactions/attach/:id/sign/", {
    group: "public",
  })
  @Put("/transactions/attach/:id/", {
    group: "public",
  })
  @Delete("/transactions/attach/:id/", {
    group: "public",
  })
  public attach(route: IRoute) {
    // Define Query Schema
    const QuerySchema = e.deepCast(e.object(
      { objectUrl: e.url() },
      { allowUnexpectedProps: true },
    ));

    // Define Params Schema
    const ParamsSchema = e.object({
      id: e.instanceOf(ObjectId, { instantiate: true }),
    });

    return UploadsController.upload(
      route,
      {
        allowedContentTypes: [
          "image/png",
          "image/jpg",
          "image/jpeg",
          "image/webp",
          "application/pdf",
          "application/vnd.ms-excel",
          "application/msword",
          "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ],
        maxContentLength: 6e+6, // 6mb max size
        location: (ctx) => `/transactions/${ctx.router.params.id}/attachments/`,
      },
      async (ctx, file) => {
        if (!ctx.router.state.auth) ctx.router.throw(Status.Unauthorized);

        // Params Validation
        const Params = await ParamsSchema.validate(ctx.router.params, {
          name: `${route.scope}.params`,
        });

        const TargetAccount = new ObjectId(ctx.router.state.auth!.accountId);

        await TransactionModel.updateOneOrFail(
          {
            _id: Params.id,
            from: TargetAccount,
          },
          {
            $push: {
              attachments: file,
            },
          },
        );
      },
      async (ctx, deleteObject) => {
        if (!ctx.router.state.auth) ctx.router.throw(Status.Unauthorized);

        // Query Validation
        const Query = await QuerySchema.validate(
          parseQueryParams(ctx.router.request.url.search),
          { name: `${route.scope}.query` },
        );

        // Params Validation
        const Params = await ParamsSchema.validate(ctx.router.params, {
          name: `${route.scope}.params`,
        });

        const TargetAccount = new ObjectId(ctx.router.state.auth!.accountId);
        const TargetUser = new ObjectId(ctx.router.state.auth!.userId);

        await TransactionModel.updateOneOrFail({
          _id: Params.id,
          from: TargetAccount,
        }, {
          $pull: {
            attachments: {
              createdBy: TargetUser,
              url: Query.objectUrl,
            },
          },
        });

        await deleteObject(Query.objectUrl);
      },
    );
  }
}
