import { createCookie } from 'react-router';

import { env } from '@documenso/lib/utils/env';

export const langCookie = createCookie('lang', {
  path: '/',
  // Keep under browser limit of 400 days (34560000s)
  maxAge: 60 * 60 * 24 * 365,
  httpOnly: true,
  secure: env('NODE_ENV') === 'production',
});
