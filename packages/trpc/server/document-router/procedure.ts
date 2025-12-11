import { TRPCError } from '@trpc/server';

import { getPassportUserByEmail } from '@documenso/lib/server-only/passport/get-passport-user';
import { prisma } from '@documenso/prisma';

import { authenticatedProcedure } from '../trpc';

const ALLOWED_PASSPORT_ROLES = new Set(['partner', 'core']);

const normalizeRole = (role?: string | null) =>
  role ? role.toLowerCase().trim() : null;

const syncPassportRole = async (userId: number, email: string, currentRole: string | null) => {
  const passportUser = await getPassportUserByEmail(email);
  const role = normalizeRole(passportUser?.role);

  // Persist when the latest role differs from what we have stored.
  if (role !== currentRole) {
    await prisma.user.update({
      where: { id: userId },
      data: {
        passportRole: role,
      },
    });
  }

  return role;
};

export const documentProcedure = authenticatedProcedure.use(async ({ ctx, next }) => {
  const email = ctx.user.email;

  if (!email) {
    throw new TRPCError({
      code: 'FORBIDDEN',
      message: 'Email required for passport verification',
    });
  }

  let role = normalizeRole(ctx.user.passportRole);

  try {
    role = await syncPassportRole(ctx.user.id, email, role);
  } catch (err) {
    ctx.logger.error(
      {
        err,
        userId: ctx.user.id,
      },
      'Failed to refresh passport role for document access',
    );

    throw new TRPCError({
      code: 'INTERNAL_SERVER_ERROR',
      message: 'Unable to verify passport access',
    });
  }

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
