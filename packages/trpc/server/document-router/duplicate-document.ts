import { duplicateEnvelope } from '@documenso/lib/server-only/envelope/duplicate-envelope';

import { documentProcedure } from './procedure';
import {
  ZDuplicateDocumentRequestSchema,
  ZDuplicateDocumentResponseSchema,
  duplicateDocumentMeta,
} from './duplicate-document.types';

export const duplicateDocumentRoute = documentProcedure
  .meta(duplicateDocumentMeta)
  .input(ZDuplicateDocumentRequestSchema)
  .output(ZDuplicateDocumentResponseSchema)
  .mutation(async ({ input, ctx }) => {
    const { teamId, user } = ctx;
    const { documentId } = input;

    ctx.logger.info({
      input: {
        documentId,
      },
    });

    const duplicatedEnvelope = await duplicateEnvelope({
      id: {
        type: 'documentId',
        id: documentId,
      },
      userId: user.id,
      teamId,
    });

    return {
      id: duplicatedEnvelope.id,
      documentId: duplicatedEnvelope.legacyId.id,
    };
  });
