import e from "@oridune/validator";
import { TFunction } from "i18next";

export const UsernameValidator = (t: TFunction) =>
  e.string({
      messages: {
        matchFailed: t("Please provide a valid username format!"),
      },
    })
    .matches({ regex: /^\s*([A-Za-z0-9_]{3,29})\s*$/ })
    .length(50)
    .custom(ctx => {
      if(typeof ctx.output !== "string")
        throw new Error("Something is not right with the username!");

      return ctx.output.trim();
    });

export const PasswordFormatValidator = (
  t: TFunction,
  strength: 0 | 1 | 2 = 2,
  minLength = 8,
  maxLength = 260,
) => {
  const PasswordLevels = [
    [
      "A password should be {{length}} characters long, must contain a character and a number!",
      [/[A-Za-z]/, /\d/],
    ],
    [
      "A password should be {{length}} characters long, must contain an uppercase, a lowercase and a number!",
      [/[A-Z]/, /[a-z]/, /[0-9]/],
    ],
    [
      "A password should be {{length}} characters long, must contain an uppercase, a lowercase, a number and a special character!",
      [/[A-Z]/, /[a-z]/, /[0-9]/, /[^a-zA-Z0-9]/],
    ],
  ] as const;

  const PasswordRule = PasswordLevels[strength];
  const ErrorMessage = t(
    PasswordRule[0],
    { length: minLength },
  );

  return e.string({
    messages: {
      greaterLength: ErrorMessage,
      smallerLength: ErrorMessage,
    },
  }).length({ min: minLength, max: maxLength }).custom((ctx) => {
    if (
      !PasswordRule[1].reduce<boolean>(
        (matches, regex) => matches && regex.test(ctx.output),
        true,
      )
    ) throw new Error(ErrorMessage);
  });
};

export const PasswordValidator = (t: TFunction) =>
  e
    .string({
      messages: {
        typeError: t("Please provide a valid password!"),
        smallerLength: t("Password is required!"),
      },
    })
    .length({ min: 1, max: 300 });

export const PhoneValidator = (t: TFunction) =>
  e
    .string({
      messages: { matchFailed: t("Please provide a valid phone!") },
    })
    .matches({
      regex: /^0[0-9]{8,12}$/,
    });

export const EmailValidator = (t: TFunction) =>
  e
    .string({
      messages: { matchFailed: t("Please provide a valid email!") },
    })
    .matches({
      regex: /^([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/,
    });
