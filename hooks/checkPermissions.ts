import {
  Env,
  EnvType,
  type IRequestContext,
  Response,
  Store,
} from "@Core/common/mod.ts";
import { type RouterContext, Status } from "oak";
import e from "validator";
import { ObjectId } from "mongo";
import { SecurityGuard } from "@Lib/securityGuard.ts";

import { OauthPolicyModel } from "@Models/oauthPolicy.ts";
import { UserModel } from "@Models/user.ts";
import { CollaboratorModel } from "@Models/collaborator.ts";
import { AccountModel } from "@Models/account.ts";
import { MapStore } from "@Core/common/store/map.ts";

export const ResolveScopeRole = async (role: string) => {
  if (!role) throw new Error("Role not provided!");

  const OauthScopes = await Store.cache(
    ["roleCache", role],
    async () => {
      const Policy = await OauthPolicyModel.findOne({
        role,
      }).project({ scopes: 1, ttl: 1 });

      return {
        result: Policy?.scopes,
        expiresInMs: ((Policy?.ttl ?? 0) * 1000) || 600000, // Default TTL 10 minutes
      };
    },
    { store: MapStore },
  );

  if (!(OauthScopes instanceof Array)) {
    throw e.error(
      `Unable to fetch the available scopes for the role '${role}'!`,
    );
  }

  return OauthScopes;
};

export const SessionValidator = e.optional(
  e.object({
    claims: e.object(
      {
        secretId: e.optional(e.string()),
        sessionId: e.optional(e.string()),
        version: e.optional(e.number()),
        refreshable: e.optional(e.boolean()),
        scopes: e.optional(e.array(e.string())),
      },
      { allowUnexpectedProps: true },
    ),
    session: e.optional(e.object(
      {
        scopes: e.record(e.array(e.string())),
        createdBy: e.string({ cast: true }),
      },
      { allowUnexpectedProps: true },
    )),
    secret: e.optional(e.object(
      {
        scopes: e.optional(e.record(e.array(e.string()))),
        createdBy: e.string({ cast: true }),
      },
      { allowUnexpectedProps: true },
    )),
  }),
);

export default {
  pre: async (
    scope: string,
    name: string,
    ctx: IRequestContext<RouterContext<string>>,
  ) => {
    if (!ctx.router.state.authBypass) {
      const SessionInfo = await SessionValidator.validate(
        ctx.router.state.sessionInfo,
        {
          name: `${scope}.state.sessionInfo`,
        },
      );

      if (SessionInfo) {
        const Session = SessionInfo.session ?? SessionInfo.secret;

        if (!Session) {
          throw new Error("No session details! Something is not correct!");
        }

        const Scopes = Session.scopes ?? {};

        const AccountId = await e
          .instanceOf(ObjectId, { instantiate: true })
          .validate(
            ctx.router.request.headers.get("X-Account-ID") ??
              Object.keys(Scopes)[0],
            { name: `${scope}.headers.x-account-id` },
          ).catch((cause) => {
            throw new Error("Missing x-account-id header!", { cause });
          });

        const { auth, scopePipeline } = await Store.cache(
          `checkPermissions:${
            SessionInfo.claims.sessionId ?? SessionInfo.claims.secretId
          }:${AccountId}`,
          async () => {
            const UserId = new ObjectId(Session.createdBy);

            const User = await UserModel.findOne(
              UserId,
            ).project({
              password: 0,
              passwordHistory: 0,
              "passkeys.publicKey": 0,
              "passkeys.counter": 0,
              "passkeys.deviceType": 0,
              "passkeys.backedUp": 0,
              collaborates: 0,
              deviceLoginHistory: 0,
            });

            if (!User || User.isBlocked) {
              throw Response.statusCode(Status.Unauthorized)
                .message(
                  "Authorized user not found or is blocked!",
                );
            }

            const Collaborator = await CollaboratorModel.findOne({
              account: AccountId,
              createdFor: UserId,
            })
              .project({
                createdBy: 1,
                role: 1,
                isOwned: 1,
                isPrimary: 1,
                isBlocked: 1,
              });

            if (!Collaborator || Collaborator.isBlocked) {
              throw Response.statusCode(Status.Unauthorized)
                .message(
                  "You don't have access to this account or it is blocked!",
                );
            }

            const Account = await AccountModel.findOne(AccountId);

            if (!Account || Account.isBlocked) {
              throw Response.statusCode(Status.Unauthorized)
                .message(
                  "Account not found or is blocked!",
                );
            }

            if (Collaborator.isOwned) {
              // deno-lint-ignore no-explicit-any
              let Updates: Record<string, any> | undefined;

              if (!Account.phone && User.phone) {
                (Updates ??= {}).phone = User.phone;
              }

              if (!Account.email && User.email) {
                (Updates ??= {}).email = User.email;
              }

              if (Updates) {
                await AccountModel.updateOne(AccountId, Updates);
              }
            }

            let GlobalRole = User.role;

            if (!GlobalRole) {
              throw Response.statusCode(Status.Unauthorized)
                .message(
                  "You don't have a role assigned!",
                );
            }

            rbacCascade: if (!Collaborator.createdBy.equals(User._id)) {
              const noCascade = await Env.enabled("RBAC_NO_CASCADE");

              if (noCascade) {
                GlobalRole = "root";

                break rbacCascade;
              }

              const ParentCollaborator = (await CollaboratorModel.findOne({
                account: AccountId,
                createdFor: Collaborator.createdBy,
              }).project({
                role: 1,
              })) ?? User;

              GlobalRole = ParentCollaborator.role;

              if (GlobalRole === "root") {
                const ParentUser =
                  (await UserModel.findOne(Collaborator.createdBy).project({
                    role: 1,
                  })) ?? User;

                GlobalRole = ParentUser.role;
              }
            }

            return {
              auth: {
                secretId: SessionInfo.claims.secretId,
                sessionId: SessionInfo.claims.sessionId,
                userId: UserId.toString(),
                accountId: AccountId.toString(),
                isAccountOwned: Collaborator.isOwned,
                isAccountPrimary: Collaborator.isPrimary,
                role: GlobalRole,
                accountRole: Collaborator.role,
                resolvedRole: Collaborator.role === "root"
                  ? GlobalRole
                  : Collaborator.role,
                user: User,
                account: Account,
                collaborator: Collaborator,
              },
              scopePipeline: {
                all: [`role:${GlobalRole}`],
                available: [`role:${Collaborator.role}`],
                requested: Scopes[AccountId.toString()] ?? ["*"],
                permitted: SessionInfo.claims.scopes ?? ["*"],
              },
            };
          },
          60 * 1000, // 1m cache
        );

        ctx.router.state.auth = auth;
        ctx.router.state.scopePipeline = scopePipeline;
      }

      const DefaultScopePipeline = {
        all: ["role:unauthenticated"],
        available: ["*"],
        requested: ["*"],
        permitted: ["*"],
      };

      ctx.router.state.scopePipeline ??= DefaultScopePipeline;
    } else {
      ctx.router.state.scopePipeline = {
        all: ["*"],
        available: ["*"],
        requested: ["*"],
        permitted: ["*"],
      };
    }

    const Guard = (ctx.router.state.guard = new SecurityGuard())
      .addStage(ctx.router.state.scopePipeline.all)
      .addStage(ctx.router.state.scopePipeline.available)
      .addStage(ctx.router.state.scopePipeline.requested)
      .addStage(ctx.router.state.scopePipeline.permitted);

    (await Env.get("MAINTENANCE_ROLES", true))?.split(
      /\s*,\s*/,
    ).filter(Boolean).map((_) => {
      const [role, depth] = _.split(":");

      Guard.addStage({
        scopes: [`role:${role}`],
        resolveDepth: depth ? parseInt(depth) : 10, // Default depth 5
      }, { denial: true });
    });

    await Guard.compile({ resolveScopeRole: ResolveScopeRole });

    if (!Guard.isAllowed(scope, name)) {
      const ErrorResponse = Response.statusCode(Status.PaymentRequired)
        .message(
          `You are not permitted! Missing permission '${`${scope}.${name}`}'.`,
        );

      if (!Env.is(EnvType.PRODUCTION)) ErrorResponse.data(Guard);

      throw ErrorResponse;
    }

    if (Guard.isDenied(scope, name)) {
      const ErrorResponse = Response.statusCode(Status.Forbidden)
        .message(
          `You are limited! Permission '${`${scope}.${name}`}' is denied. Try again later.`,
        );

      if (!Env.is(EnvType.PRODUCTION)) ErrorResponse.data(Guard);

      throw ErrorResponse;
    }
  },
};
