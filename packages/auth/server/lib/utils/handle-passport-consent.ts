import { IdentityProvider, UserSecurityAuditLogType } from '@prisma/client';
import type { Context } from 'hono';
import { setCookie } from 'hono/cookie';

import { APP_I18N_OPTIONS, type SupportedLanguageCodes } from '@documenso/lib/constants/i18n';
import { AppError, AppErrorCode } from '@documenso/lib/errors/app-error';
import { setAvatarImage } from '@documenso/lib/server-only/profile/set-avatar-image';
import { onCreateUserHook } from '@documenso/lib/server-only/user/create-user';
import { env } from '@documenso/lib/utils/env';
import type { ApiRequestMetadata, RequestMetadata } from '@documenso/lib/universal/extract-request-metadata';
import { prisma } from '@documenso/prisma';

import { PassportAuthOptions } from '../../config';
import { onAuthorize } from './authorizer';
import { createOAuthAuthorizeUrl } from './handle-oauth-authorize-url';
import { validateOauth } from './handle-oauth-callback-url';

type PassportProfile = {
  email: string;
  nickname?: string | null;
  role?: string | null;
  avatar_url?: string | null;
  preferred_language?: string | null;
};

const ALLOWED_PASSPORT_ROLES = new Set(['partner', 'core']);

const languageCookieOptions = {
  httpOnly: true,
  path: '/',
  sameSite: 'lax' as const,
  secure: env('NODE_ENV') === 'production',
  // Keep under browser limit of 400 days (34560000s)
  maxAge: 60 * 60 * 24 * 365,
};

const normalizeRole = (role?: string | null) => (role ? role.toLowerCase().trim() : null);

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
  const updates: { name?: string; lastSignedIn?: Date; passportRole?: string | null } = {
    lastSignedIn: new Date(),
  };

  if (profile.nickname) {
    updates.name = profile.nickname;
  }

  if (profile.role) {
    updates.passportRole = profile.role.toLowerCase();
  }

  await prisma.user.update({
    where: { id: userId },
    data: updates,
  });

  await setUserAvatarFromUrl(userId, profile.avatar_url, profile.email, profile.nickname, metadata);
};

const getStringClaim = (claims: Record<string, unknown>, key: string) => {
  const value = claims[key];
  return typeof value === 'string' ? value : undefined;
};

const buildPassportProfileFromClaims = ({
  email,
  name,
  role,
  claims,
}: {
  email: string;
  name: string;
  role: string;
  claims: Record<string, unknown>;
}): PassportProfile => ({
  email,
  nickname:
    getStringClaim(claims, 'nickname') ??
    getStringClaim(claims, 'preferred_username') ??
    name,
  role,
  avatar_url: getStringClaim(claims, 'picture'),
  preferred_language: getStringClaim(claims, 'locale'),
});

const assertAllowedPassportRole = (role: string | null): role is string => {
  if (!role || !ALLOWED_PASSPORT_ROLES.has(role)) {
    throw new AppError(AppErrorCode.UNAUTHORIZED, {
      message: `Passport role not permitted: ${role ?? 'unknown'}`,
      userMessage: 'Only Passport partner or core users can sign in.',
      statusCode: 403,
    });
  }
};

export const handlePassportAuthorize = async ({
  c,
  redirectPath,
}: {
  c: Context;
  redirectPath?: string;
}) => {
  const redirectUrl = await createOAuthAuthorizeUrl({
    c,
    clientOptions: PassportAuthOptions,
    redirectPath,
  });

  return c.json({ redirectUrl });
};

export const handlePassportAuthorizeRedirect = async ({
  c,
  redirectPath,
}: {
  c: Context;
  redirectPath?: string;
}) => {
  const redirectUrl = await createOAuthAuthorizeUrl({
    c,
    clientOptions: PassportAuthOptions,
    redirectPath,
  });

  return c.redirect(redirectUrl, 302);
};

export const handlePassportCallback = async (c: Context) => {
  try {
    const {
      email,
      name,
      sub,
      accessToken,
      accessTokenExpiresAt,
      idToken,
      redirectPath,
      claims,
    } = await validateOauth({ c, clientOptions: PassportAuthOptions });

    const normalizedRole = normalizeRole(getStringClaim(claims, 'role'));
    assertAllowedPassportRole(normalizedRole);

    const profile = buildPassportProfileFromClaims({
      email,
      name,
      role: normalizedRole,
      claims,
    });

    const preferredLanguage = normalizePreferredLanguage(profile.preferred_language);
    const requestMetadata = c.get('requestMetadata');
    const providerAccountId = sub;

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
              access_token: accessToken,
              expires_at: Math.floor(accessTokenExpiresAt.getTime() / 1000),
              token_type: 'Bearer',
              id_token: idToken,
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
              name: profile.nickname ?? name ?? email,
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
              access_token: accessToken,
              expires_at: Math.floor(accessTokenExpiresAt.getTime() / 1000),
              token_type: 'Bearer',
              id_token: idToken,
              userId: user.id,
            },
          });

          return user;
        });

        await onCreateUserHook(createdUser).catch((err) => console.error(err));

        userId = createdUser.id;
      }
    }

    await updateUserProfileFromPassport(userId, profile, requestMetadata);

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
