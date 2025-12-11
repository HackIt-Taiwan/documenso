import { IdentityProvider, UserSecurityAuditLogType } from '@prisma/client';
import { generateState } from 'arctic';
import type { Context } from 'hono';
import { deleteCookie, setCookie } from 'hono/cookie';

import { APP_I18N_OPTIONS, type SupportedLanguageCodes } from '@documenso/lib/constants/i18n';
import { AppError, AppErrorCode } from '@documenso/lib/errors/app-error';
import { setAvatarImage } from '@documenso/lib/server-only/profile/set-avatar-image';
import { onCreateUserHook } from '@documenso/lib/server-only/user/create-user';
import { env } from '@documenso/lib/utils/env';
import { isValidReturnTo, normalizeReturnTo } from '@documenso/lib/utils/is-valid-return-to';
import type { ApiRequestMetadata, RequestMetadata } from '@documenso/lib/universal/extract-request-metadata';
import { prisma } from '@documenso/prisma';

import { PassportAuthOptions } from '../../config';
import { AuthenticationErrorCode } from '../errors/error-codes';
import { sessionCookieOptions } from '../session/session-cookies';
import { onAuthorize } from './authorizer';

type PassportConsentConfig = typeof PassportAuthOptions;

type PassportProfile = {
  id?: string;
  logto_id?: string;
  email: string;
  nickname?: string | null;
  role?: string | null;
  avatar_url?: string | null;
  preferred_language?: string | null;
};

const ALLOWED_PASSPORT_ROLES = new Set(['partner', 'core']);
const PASSPORT_STATE_COOKIE = 'passport_oauth_state';
const PASSPORT_REDIRECT_COOKIE = 'passport_oauth_redirect_path';
const PASSPORT_ALLOWED_FIELDS = ['email', 'nickname', 'avatar_url', 'preferred_language', 'role'];
const PASSPORT_COOKIE_MAX_AGE_SECONDS = 60 * 10; // 10 minutes

const passportCookieOptions = {
  ...sessionCookieOptions,
  sameSite: 'lax' as const,
  maxAge: PASSPORT_COOKIE_MAX_AGE_SECONDS,
  expires: undefined,
};

const languageCookieOptions = {
  httpOnly: true,
  path: '/',
  sameSite: 'lax' as const,
  secure: env('NODE_ENV') === 'production',
  // Keep under browser limit of 400 days (34560000s)
  maxAge: 60 * 60 * 24 * 365,
};

const ensurePassportConfig = (config: PassportConsentConfig) => {
  if (!config.apiBaseUrl || !config.apiToken || !config.clientId) {
    throw new AppError(AppErrorCode.NOT_SETUP, {
      message: 'Passport SSO is not configured',
      statusCode: 400,
    });
  }
};

const requestPassportConsent = async (
  config: PassportConsentConfig,
  state: string,
  restartUri?: string,
) => {
  ensurePassportConfig(config);

  const consentUrl = `${config.apiBaseUrl}/services/consent/request`;

  const response = await fetch(consentUrl, {
    method: 'POST',
    headers: {
      'X-API-Token': config.apiToken,
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      client_id: config.clientId,
      redirect_uri: config.redirectUrl,
      fields: config.requestedFields.filter((field) => PASSPORT_ALLOWED_FIELDS.includes(field)),
      state,
      restart_uri: restartUri,
    }),
  });

  if (!response.ok) {
    let errorBody: unknown;

    try {
      errorBody = await response.json();
    } catch {
      try {
        errorBody = await response.text();
      } catch {
        errorBody = undefined;
      }
    }

    throw new AppError(AppErrorCode.INVALID_REQUEST, {
      message: `Passport consent request failed (${response.status})${errorBody ? `: ${JSON.stringify(errorBody)}` : ''}`,
      statusCode: response.status,
    });
  }

  const data = (await response.json().catch(() => ({}))) as {
    request_id?: string;
    consent_url?: string;
    consentUrl?: string;
  };

  const redirectUrl = data.consent_url || data.consentUrl;

  if (!data.request_id || !redirectUrl) {
    throw new AppError(AppErrorCode.INVALID_REQUEST, {
      message: 'Passport consent response missing request_id/consent_url',
    });
  }

  return {
    requestId: data.request_id,
    consentUrl: redirectUrl,
  };
};

const exchangePassportConsent = async (config: PassportConsentConfig, code: string) => {
  ensurePassportConfig(config);

  const tokenUrl = `${config.apiBaseUrl}/services/consent/token`;

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: {
      'X-API-Token': config.apiToken,
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      code,
      client_id: config.clientId,
    }),
  });

  if (!response.ok) {
    throw new AppError(AppErrorCode.INVALID_REQUEST, {
      message: `Passport consent token exchange failed (${response.status})`,
      statusCode: response.status,
    });
  }

  const data = (await response.json().catch(() => ({}))) as { user?: PassportProfile };

  if (!data.user) {
    throw new AppError(AppErrorCode.INVALID_REQUEST, {
      message: 'Passport consent token did not include a user payload',
    });
  }

  return data.user;
};

const normalizePreferredLanguage = (
  language?: string | null,
): SupportedLanguageCodes | undefined => {
  if (!language) {
    return undefined;
  }

  const candidate = language.toLowerCase().replace('_', '-');
  const [base] = candidate.split(/[-_]/);

  const supported = APP_I18N_OPTIONS.supportedLangs.find((lang) => lang === base);

  return supported ?? undefined;
};

const setLanguageCookie = (c: Context, language: SupportedLanguageCodes) => {
  setCookie(c, 'lang', language, languageCookieOptions);
};

const buildRestartUri = (redirectUrl: string) => {
  try {
    const url = new URL(redirectUrl);
    return `${url.origin}/signin`;
  } catch {
    return undefined;
  }
};

const buildAvatarAuditMetadata = (
  userId: number,
  email: string,
  name: string | null | undefined,
  metadata?: RequestMetadata,
): ApiRequestMetadata => ({
  requestMetadata: metadata ?? {},
  source: 'app',
  auth: 'session',
  auditUser: {
    id: userId,
    email,
    name,
  },
});

const setUserAvatarFromUrl = async (
  userId: number,
  avatarUrl?: string | null,
  email?: string,
  name?: string | null,
  metadata?: RequestMetadata,
) => {
  if (!avatarUrl) {
    return;
  }

  let parsed: URL;

  try {
    parsed = new URL(avatarUrl);
  } catch {
    return;
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return;
  }

  try {
    const response = await fetch(avatarUrl);

    if (!response.ok) {
      return;
    }

    const buffer = Buffer.from(await response.arrayBuffer());

    await setAvatarImage({
      userId,
      target: { type: 'user' },
      bytes: buffer.toString('base64'),
      requestMetadata: buildAvatarAuditMetadata(userId, email ?? '', name, metadata),
    });
  } catch (err) {
    console.error('Failed to set avatar from Passport profile', err);
  }
};

const updateUserProfileFromPassport = async (
  userId: number,
  profile: PassportProfile,
  metadata?: RequestMetadata,
) => {
  const updates: { name?: string; lastSignedIn?: Date; passportRole?: string | null } = {};

  if (profile.nickname) {
    updates.name = profile.nickname;
  }

  if (profile.role) {
    updates.passportRole = profile.role.toLowerCase();
  }

  updates.lastSignedIn = new Date();

  await prisma.user.update({
    where: { id: userId },
    data: updates,
  });

  await setUserAvatarFromUrl(userId, profile.avatar_url, profile.email, profile.nickname, metadata);
};

const validateRedirect = (storedRedirect: string, storedState: string) => {
  let [redirectState, redirectPath] = storedRedirect.split(' ');

  if (redirectState !== storedState || !redirectPath) {
    return '/';
  }

  if (!isValidReturnTo(redirectPath)) {
    return '/';
  }

  return normalizeReturnTo(redirectPath) || '/';
};

const preparePassportAuthorize = async (c: Context, redirectPath?: string) => {
  const state = generateState();

  const restartUri = buildRestartUri(PassportAuthOptions.redirectUrl);

  const { consentUrl } = await requestPassportConsent(PassportAuthOptions, state, restartUri);

  setCookie(c, PASSPORT_STATE_COOKIE, state, passportCookieOptions);

  if (redirectPath) {
    setCookie(c, PASSPORT_REDIRECT_COOKIE, `${state} ${redirectPath}`, passportCookieOptions);
  }

  return consentUrl;
};

export const handlePassportAuthorize = async ({
  c,
  redirectPath,
}: {
  c: Context;
  redirectPath?: string;
}) => {
  const consentUrl = await preparePassportAuthorize(c, redirectPath);

  return c.json({ redirectUrl: consentUrl });
};

export const handlePassportAuthorizeRedirect = async ({
  c,
  redirectPath,
}: {
  c: Context;
  redirectPath?: string;
}) => {
  const consentUrl = await preparePassportAuthorize(c, redirectPath);

  return c.redirect(consentUrl, 302);
};

export const handlePassportCallback = async (c: Context) => {
  try {
    const code = c.req.query('code');
    const state = c.req.query('state');

    const storedState = deleteCookie(c, PASSPORT_STATE_COOKIE);
    const storedRedirect = deleteCookie(c, PASSPORT_REDIRECT_COOKIE) ?? '';

    if (!code || !storedState || state !== storedState) {
      throw new AppError(AppErrorCode.INVALID_REQUEST, {
        message: 'Invalid or missing consent state',
      });
    }

    const redirectPath = validateRedirect(storedRedirect, storedState);

    const profile = await exchangePassportConsent(PassportAuthOptions, code);

    const email = profile.email?.toLowerCase();
    const normalizedRole = profile.role?.toLowerCase();

    if (!email) {
      throw new AppError(AuthenticationErrorCode.InvalidRequest, {
        message: 'Passport profile missing email',
      });
    }

    if (!normalizedRole || !ALLOWED_PASSPORT_ROLES.has(normalizedRole)) {
      throw new AppError(AppErrorCode.UNAUTHORIZED, {
        message: `Passport role not permitted: ${profile.role ?? 'unknown'}`,
        userMessage: 'Only Passport partner or core users can sign in.',
        statusCode: 403,
      });
    }

    const providerAccountId = profile.id ?? profile.logto_id ?? email;
    const preferredLanguage = normalizePreferredLanguage(profile.preferred_language);
    const requestMetadata = c.get('requestMetadata');
    const profileWithNormalizedRole: PassportProfile = {
      ...profile,
      role: normalizedRole,
    };

    const existingAccount = await prisma.account.findFirst({
      where: {
        provider: PassportAuthOptions.id,
        providerAccountId,
      },
      select: {
        userId: true,
      },
    });

    let userId: number;

    if (existingAccount?.userId) {
      userId = existingAccount.userId;
    } else {
      const userWithSameEmail = await prisma.user.findFirst({
        where: {
          email,
        },
        select: {
          id: true,
          emailVerified: true,
        },
      });

      if (userWithSameEmail) {
        await prisma.$transaction(async (tx) => {
          await tx.account.create({
            data: {
              type: 'oauth',
              provider: PassportAuthOptions.id,
              providerAccountId,
              access_token: code,
              token_type: 'Bearer',
              userId: userWithSameEmail.id,
            },
          });

          await tx.userSecurityAuditLog.create({
            data: {
              userId: userWithSameEmail.id,
              ipAddress: requestMetadata?.ipAddress,
              userAgent: requestMetadata?.userAgent,
              type: UserSecurityAuditLogType.ACCOUNT_SSO_LINK,
            },
          });

          if (!userWithSameEmail.emailVerified) {
            await tx.user.update({
              where: {
                id: userWithSameEmail.id,
              },
              data: {
                emailVerified: new Date(),
                password: null,
              },
            });
          }
        });

        userId = userWithSameEmail.id;
      } else {
        const createdUser = await prisma.$transaction(async (tx) => {
          const user = await tx.user.create({
            data: {
              email,
              name: profile.nickname ?? email,
              emailVerified: new Date(),
              password: null,
              source: PassportAuthOptions.id,
              identityProvider: IdentityProvider.OIDC,
            },
          });

          await tx.account.create({
            data: {
              type: 'oauth',
              provider: PassportAuthOptions.id,
              providerAccountId,
              access_token: code,
              token_type: 'Bearer',
              userId: user.id,
            },
          });

          return user;
        });

        await onCreateUserHook(createdUser).catch((err) => console.error(err));

        userId = createdUser.id;
      }
    }

    await updateUserProfileFromPassport(userId, profileWithNormalizedRole, requestMetadata);

    if (preferredLanguage) {
      setLanguageCookie(c, preferredLanguage);
    }

    await onAuthorize({ userId }, c);

    return c.redirect(redirectPath, 302);
  } catch (err) {
    console.error('Passport callback failed', err);

    if (err instanceof AppError) {
      throw err;
    }

    throw new AppError(AppErrorCode.UNKNOWN_ERROR, {
      message: err instanceof Error ? err.message : 'Passport callback failed',
      statusCode: 500,
    });
  }
};
