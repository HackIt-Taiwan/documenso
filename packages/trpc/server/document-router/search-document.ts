import { searchDocumentsWithKeyword } from '@documenso/lib/server-only/document/search-documents-with-keyword';

import { documentProcedure } from './procedure';
import {
  ZSearchDocumentRequestSchema,
  ZSearchDocumentResponseSchema,
} from './search-document.types';

export const searchDocumentRoute = documentProcedure
  .input(ZSearchDocumentRequestSchema)
  .output(ZSearchDocumentResponseSchema)
  .query(async ({ input, ctx }) => {
    const { query } = input;

    const documents = await searchDocumentsWithKeyword({
      query,
      userId: ctx.user.id,
    });

    return documents;
  });
