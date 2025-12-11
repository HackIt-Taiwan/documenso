#!/bin/sh
set -euo pipefail

# 🚀 Starting Documenso...
printf "🚀 Starting Documenso...\n\n"

# 🔌 Validate database configuration
printf "🧪 Validating database configuration...\n"

if [ -z "${NEXT_PRIVATE_DATABASE_URL:-}" ]; then
    printf "❌ NEXT_PRIVATE_DATABASE_URL is not set. Please provide a Postgres connection string.\n"
    exit 1
fi

if [ -z "${NEXT_PRIVATE_DIRECT_DATABASE_URL:-}" ]; then
    NEXT_PRIVATE_DIRECT_DATABASE_URL="$NEXT_PRIVATE_DATABASE_URL"
fi

db_target=$(node -e "const url=new URL(process.env.NEXT_PRIVATE_DATABASE_URL);console.log(\`\${url.hostname}\${url.port?':'+url.port:''}/\${url.pathname.slice(1)}\`);" 2>/dev/null || true)
direct_target=$(node -e "const url=new URL(process.env.NEXT_PRIVATE_DIRECT_DATABASE_URL);console.log(\`\${url.hostname}\${url.port?':'+url.port:''}/\${url.pathname.slice(1)}\`);" 2>/dev/null || true)

if [ -z "$db_target" ] || [ -z "$direct_target" ]; then
    printf "❌ Invalid database URL provided. Please double-check NEXT_PRIVATE_DATABASE_URL and NEXT_PRIVATE_DIRECT_DATABASE_URL.\n"
    exit 1
fi

if [ "$db_target" != "$direct_target" ]; then
    printf "❌ Database URLs do not point to the same database.\n"
    printf "    NEXT_PRIVATE_DATABASE_URL        -> %s\n" "$db_target"
    printf "    NEXT_PRIVATE_DIRECT_DATABASE_URL -> %s\n" "$direct_target"
    printf "    Migrations would run against the direct URL, but the app would query the other one, leading to missing tables (e.g. Account).\n"
    printf "    Please align these URLs so they target the same host/database.\n"
    exit 1
fi

# Friendly hint showing the target without secrets
printf "✅ Target database: %s\n\n" "$db_target"

# 🔐 Check certificate configuration
printf "🔐 Checking certificate configuration...\n"

CERT_PATH="${NEXT_PRIVATE_SIGNING_LOCAL_FILE_PATH:-/opt/documenso/cert.p12}"

if [ -f "$CERT_PATH" ] && [ -r "$CERT_PATH" ]; then
    printf "✅ Certificate file found and readable - document signing is ready!\n"
else
    printf "⚠️  Certificate not found or not readable\n"
    printf "💡 Tip: Documenso will still start, but document signing will be unavailable\n"
    printf "🔧 Check: http://localhost:3000/api/certificate-status for detailed status\n"
fi

printf "\n📚 Useful Links:\n"
printf "📖 Documentation: https://docs.documenso.com\n"
printf "🐳 Self-hosting guide: https://docs.documenso.com/developers/self-hosting\n"
printf "🔐 Certificate setup: https://docs.documenso.com/developers/self-hosting/signing-certificate\n"
printf "🏥 Health check: http://localhost:3000/api/health\n"
printf "📊 Certificate status: http://localhost:3000/api/certificate-status\n"
printf "👥 Community: https://github.com/documenso/documenso\n\n"

printf "🗄️  Running database migrations...\n"
if ! npx prisma migrate deploy --schema ../../packages/prisma/schema.prisma; then
    printf "❌ Database migrations failed. Documenso will not start until this is resolved.\n"
    exit 1
fi

printf "🌟 Starting Documenso server...\n"
HOSTNAME=0.0.0.0 node build/server/main.js
