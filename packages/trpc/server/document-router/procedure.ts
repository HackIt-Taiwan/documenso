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

  // Prefer the newly fetched role, otherwise fall back to what we already had.
  return role ?? currentRole;
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

  // Fast-path if the session already has an allowed role.
  const hasAllowedRole = role && ALLOWED_PASSPORT_ROLES.has(role);

  // Only reach out to Passport when we don't already have a valid role.
  if (!hasAllowedRole) {
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

      // If we previously had an allowed role, continue; otherwise block.
      if (!hasAllowedRole) {
        throw new TRPCError({
          code: 'INTERNAL_SERVER_ERROR',
          message: 'Unable to verify passport access',
        });
      }
    }
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
