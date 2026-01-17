import { TRPCError } from '@trpc/server';

import { authenticatedProcedure } from '../trpc';

const ALLOWED_PASSPORT_ROLES = new Set(['partner', 'core']);

const normalizeRole = (role?: string | null) => {
  if (!role) {
    return null;
  }

  return role.toLowerCase().trim();
};

export const documentProcedure = authenticatedProcedure.use(async ({ ctx, next }) => {
  const role = normalizeRole(ctx.user.passportRole);

  if (!role || !ALLOWED_PASSPORT_ROLES.has(role)) {
    throw new TRPCError({
      code: 'FORBIDDEN',
      message: 'Access limited to Passport partner or core users',
    });
  }

  return next({
    ctx: {
      ...ctx,
      user: {
        ...ctx.user,
        passportRole: role,
      },
    },
  });
});
