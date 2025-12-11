import { env } from '../../utils/env';

export type PassportUser = {
  id?: string;
  logto_id?: string;
  email?: string;
  role?: string | null;
};

const CACHE_TTL_MS = 5 * 60 * 1000;
const cache = new Map<string, { user: PassportUser | null; expiresAt: number }>();

const normalizeBaseUrl = () => {
  const baseUrl = env('PASSPORT_API_BASE_URL')?.replace(/\/+$/, '') ?? '';

  if (!baseUrl) {
    return '';
  }

  return /\/api$/i.test(baseUrl) ? baseUrl : `${baseUrl}/api`;
};

type GetPassportUserOptions = {
  forceRefresh?: boolean;
};

export const getPassportUserByEmail = async (
  email: string,
  options: GetPassportUserOptions = {},
): Promise<PassportUser | null> => {
  const apiToken = env('PASSPORT_API_TOKEN');
  const baseUrl = normalizeBaseUrl();

  if (!apiToken || !baseUrl) {
    throw new Error('Passport API configuration is missing');
  }

  const cacheKey = email.toLowerCase();
  const cached = cache.get(cacheKey);

  if (cached && cached.expiresAt > Date.now() && !options.forceRefresh) {
    return cached.user;
  }

  const url = `${baseUrl}/v2/passport_users/by-email/${encodeURIComponent(cacheKey)}`;

  const response = await fetch(url, {
    headers: {
      'X-API-Token': apiToken,
      Accept: 'application/json',
    },
  });

  if (response.status === 404) {
    cache.delete(cacheKey);
    return null;
  }

  if (!response.ok) {
    throw new Error(`Passport user lookup failed (${response.status})`);
  }

  const user = (await response.json()) as PassportUser;

  cache.set(cacheKey, {
    user,
    expiresAt: Date.now() + CACHE_TTL_MS,
  });

  return user;
};
