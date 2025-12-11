import { NEXT_PUBLIC_WEBAPP_URL } from '@documenso/lib/constants/app';
import { env } from '@documenso/lib/utils/env';

/**
 * How long a session should live for in milliseconds.
 */
export const AUTH_SESSION_LIFETIME = 1000 * 60 * 60 * 24 * 30; // 30 days.

export type OAuthClientOptions = {
  id: string;
  scope: string[];
  clientId: string;
  clientSecret: string;
  wellKnownUrl: string;
  redirectUrl: string;
  bypassEmailVerification?: boolean;
};

type PassportConsentOptions = {
  id: string;
  clientId: string;
  apiBaseUrl: string;
  apiToken: string;
  redirectUrl: string;
  requestedFields: string[];
};

const normalizePassportApiBaseUrl = () => {
  const baseUrl = env('PASSPORT_API_BASE_URL')?.replace(/\/+$/, '') ?? '';

  if (!baseUrl) {
    return '';
  }

  return /\/api$/i.test(baseUrl) ? baseUrl : `${baseUrl}/api`;
};

export const GoogleAuthOptions: OAuthClientOptions = {
  id: 'google',
  scope: ['openid', 'email', 'profile'],
  clientId: env('NEXT_PRIVATE_GOOGLE_CLIENT_ID') ?? '',
  clientSecret: env('NEXT_PRIVATE_GOOGLE_CLIENT_SECRET') ?? '',
  redirectUrl: `${NEXT_PUBLIC_WEBAPP_URL()}/api/auth/callback/google`,
  wellKnownUrl: 'https://accounts.google.com/.well-known/openid-configuration',
  bypassEmailVerification: false,
};

export const MicrosoftAuthOptions: OAuthClientOptions = {
  id: 'microsoft',
  scope: ['openid', 'email', 'profile'],
  clientId: env('NEXT_PRIVATE_MICROSOFT_CLIENT_ID') ?? '',
  clientSecret: env('NEXT_PRIVATE_MICROSOFT_CLIENT_SECRET') ?? '',
  redirectUrl: `${NEXT_PUBLIC_WEBAPP_URL()}/api/auth/callback/microsoft`,
  wellKnownUrl: 'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
  bypassEmailVerification: false,
};

export const OidcAuthOptions: OAuthClientOptions = {
  id: 'oidc',
  scope: ['openid', 'email', 'profile'],
  clientId: env('NEXT_PRIVATE_OIDC_CLIENT_ID') ?? '',
  clientSecret: env('NEXT_PRIVATE_OIDC_CLIENT_SECRET') ?? '',
  redirectUrl: `${NEXT_PUBLIC_WEBAPP_URL()}/api/auth/callback/oidc`,
  wellKnownUrl: env('NEXT_PRIVATE_OIDC_WELL_KNOWN') ?? '',
  bypassEmailVerification: env('NEXT_PRIVATE_OIDC_SKIP_VERIFY') === 'true',
};

export const PassportAuthOptions: PassportConsentOptions = {
  id: 'passport',
  clientId: env('PASSPORT_CLIENT_ID') ?? env('NEXT_PRIVATE_OIDC_CLIENT_ID') ?? '',
  apiBaseUrl: normalizePassportApiBaseUrl(),
  apiToken: env('PASSPORT_API_TOKEN') ?? '',
  redirectUrl: `${NEXT_PUBLIC_WEBAPP_URL()}/api/auth/callback/passport`,
  requestedFields: ['email', 'nickname', 'avatar_url', 'preferred_language', 'role'],
};
