import { EnvelopeType } from '@prisma/client';

import { AppError, AppErrorCode } from '@documenso/lib/errors/app-error';
import { prisma } from '@documenso/prisma';

import { documentProcedure } from './procedure';
import {
  ZGetDocumentByTokenRequestSchema,
  ZGetDocumentByTokenResponseSchema,
} from './get-document-by-token.types';

export const getDocumentByTokenRoute = documentProcedure
  .input(ZGetDocumentByTokenRequestSchema)
  .output(ZGetDocumentByTokenResponseSchema)
  .query(async ({ input, ctx }) => {
    const { token } = input;

    const envelope = await prisma.envelope.findFirst({
      where: {
        type: EnvelopeType.DOCUMENT,
        recipients: {
          some: {
            token,
            email: ctx.user.email,
          },
        },
      },
      include: {
        envelopeItems: {
          include: {
            documentData: true,
          },
        },
      },
    });

    const firstDocumentData = envelope?.envelopeItems[0].documentData;

    if (!envelope || !firstDocumentData) {
      throw new AppError(AppErrorCode.NOT_FOUND, {
        message: 'Document not found',
      });
    }

    if (envelope.envelopeItems.length !== 1) {
      throw new AppError(AppErrorCode.INVALID_REQUEST, {
        message: 'This endpoint does not support multiple items',
      });
    }

    ctx.logger.info({
      documentId: envelope.id,
    });

    return {
      documentData: firstDocumentData,
    };
  });
