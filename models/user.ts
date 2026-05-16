import e, { inferInput, inferOutput } from "validator";
import { Store } from "@Core/common/store.ts";
import { Env } from "@Core/common/env.ts";
import { InputDocument, Mongo, ObjectId, OutputDocument } from "mongo";
import { FileSchema } from "@Models/file.ts";
import { GeoPointSchema } from "@Models/location.ts";

const AllowedUserReferencePrefix =
  Env.getSync("ALLOWED_USER_REFERENCE_PREFIX", true) ?? "UID";
const DefaultUserReferencePrefix =
  Env.getSync("DEFAULT_USER_REFERENCE_PREFIX", true) ?? "UID";
const UserReferenceMinLength = parseInt(
  Env.getSync("USER_REFERENCE_MIN_LENGTH", true) ?? "5",
);
const UserReferenceStart = Env.getSync("USER_REFERENCE_START", true) ?? "10000";

export const UserReferenceValidator = () =>
  e.string().matches({
    regex: new RegExp(
      `^(${
        AllowedUserReferencePrefix.split(/\s*,\s*/).join(
          "|",
        )
      })[0-9]{${UserReferenceMinLength},}$`,
    ),
  }).max(50);

export const UsernameValidator = () =>
  e.string()
    .matches({
      regex: /^[A-Za-z0-9_]{3,29}$/,
    })
    .custom((ctx) => ctx.output.toLowerCase());

export const PasswordValidator = () => e.string().min(6).max(300);

export const EmailValidator = () =>
  e.string().matches({
    regex: /^([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/,
  }).max(300);

export const PhoneValidator = () =>
  e.string().matches({
    regex: /^\+[1-9]\d{6,14}$/,
  });

export enum Gender {
  MALE = "male",
  FEMALE = "female",
  OTHER = "other",
}

export const UpdateUserSchema = e.object({
  fname: e.string().max(50),
  mname: e.optional(e.string().max(50)),
  lname: e.optional(e.string().max(50)),
  gender: e.optional(e.in(Object.values(Gender))),
  dob: e.optional(e.date()),
  locale: e.optional(e.string().max(50)),
  country: e.optional(e.string().max(50)),
  state: e.optional(e.string().max(50)),
  city: e.optional(e.string().max(50)),
  address_1: e.optional(e.string().max(300)),
  address_2: e.optional(e.string().max(300)),
  postalCode: e.optional(e.string().max(50)),
});

export const CreateUserSchema = e
  .object({
    username: UsernameValidator(),
    password: PasswordValidator(),
    avatar: e.optional(FileSchema),
    tags: e.optional(e.array(e.string().max(50), { cast: true }).max(100))
      .default([]),
    email: e.optional(EmailValidator()),
    phone: e.optional(PhoneValidator()),
  })
  .extends(UpdateUserSchema);

export const DeviceReportPayloadSchema = e.object({
  capturedAt: e.date(),
  device: e.object({
    platform: e.string().max(50),
    operatingSystem: e.optional(e.string().max(128)),
    osVersion: e.optional(e.string().max(64)),
    model: e.optional(e.string().max(128)),
    manufacturer: e.optional(e.string().max(128)),
    webViewVersion: e.optional(e.string().max(64)),
    isVirtual: e.optional(e.boolean({ cast: true })),
    deviceId: e.string().max(256),
    appVersion: e.string().max(64),
    userAgent: e.string().max(1024),
    language: e.string().max(35),
    languages: e.array(e.string().max(35)).max(50),
    timezone: e.string().max(64),
    screen: e.object({
      width: e.number(),
      height: e.number(),
      dpr: e.number(),
    }),
    network: e.optional(e.string().max(32)),
  }),
  location: e.or([
    e.null(),
    e.object({
      lat: e.number(),
      lng: e.number(),
      accuracy: e.or([e.number(), e.null()]),
      altitude: e.or([e.number(), e.null()]),
      altitudeAccuracy: e.or([e.number(), e.null()]),
      heading: e.or([e.number(), e.null()]),
      speed: e.or([e.number(), e.null()]),
      capturedAt: e.date(),
    }),
  ]),
});

export const DeviceLoginEntrySchema = e.object({
  receivedAt: e.date(),
  ip: e.string().max(45),
  payload: DeviceReportPayloadSchema,
});

export const UserSchema = CreateUserSchema.extends(
  e.object({
    _id: e.optional(e.instanceOf(ObjectId, { instantiate: true })),
    createdAt: e.optional(e.date()).default(() => new Date()),
    updatedAt: e.optional(e.date()).default(() => new Date()),
    oauthApp: e.instanceOf(ObjectId, { instantiate: true }),
    reference: e
      .optional(UserReferenceValidator())
      .default(
        async () =>
          `${DefaultUserReferencePrefix}${
            parseInt(UserReferenceStart) +
            (await Store.incr(`user-reference-${DefaultUserReferencePrefix}`))
          }`,
      ),
    passwordHistory: e.array(e.string()),
    locationHistory: e.optional(e.array(GeoPointSchema)),
    deviceLoginHistory: e.optional(e.array(DeviceLoginEntrySchema)),
    role: e.string().max(50),
    isEmailVerified: e.optional(e.boolean({ cast: true })).default(false),
    isPhoneVerified: e.optional(e.boolean({ cast: true })).default(false),
    lastLogin: e.optional(e.date()),
    loginCount: e.optional(e.number({ cast: true })).default(0),
    failedLoginAttempts: e.optional(e.number({ cast: true })).default(0),
    fcmDeviceTokens: e.optional(e.array(e.string())),
    passkeys: e.optional(
      e.array(
        e.object({
          id: e.string(),
          publicKey: e.string(),
          counter: e.number(),
          deviceType: e.string(),
          backedUp: e.boolean(),
          transports: e.array(e.string()),
          timestamp: e.optional(e.date()).default(() => new Date()),
        }),
      ),
    ),
    passkeyEnabled: e.optional(e.boolean()),
    isBlocked: e.optional(e.boolean({ cast: true })).default(false),
    collaborates: e.array(e.instanceOf(ObjectId, { instantiate: true })),
    deletionAt: e.optional(e.or([e.date(), e.null()])),
    metadata: e.optional(e.record(e.any())),
  }),
);

export type TUserInput = InputDocument<inferInput<typeof UserSchema>>;
export type TUserOutput = OutputDocument<inferOutput<typeof UserSchema>>;

export const UserModel = Mongo.model("user", UserSchema);

UserModel.pre("update", (details) => {
  details.updates.$set = {
    ...details.updates.$set,
    updatedAt: new Date(),
  };
});

UserModel.createIndex(
  {
    name: "searchUser",
    key: {
      reference: "text",
      username: "text",
      fname: "text",
      mname: "text",
      lname: "text",
      tags: "text",
      email: "text",
      phone: "text",
      role: "text",
    },
    default_language: "none",
    background: true,
  },
  {
    key: { username: 1 },
    unique: true,
    background: true,
  },
  {
    key: { reference: 1 },
    unique: true,
    background: true,
  },
  {
    key: { email: 1 },
    unique: true,
    partialFilterExpression: { email: { $exists: true } },
  },
  {
    key: { phone: 1 },
    unique: true,
    partialFilterExpression: { phone: { $exists: true } },
  },
);
