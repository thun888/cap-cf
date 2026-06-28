#!/bin/bash
# Local development setup script

echo "🚀 Setting up local development environment..."

# Check if .dev.vars exists
if [ ! -f .dev.vars ]; then
  echo "❌ .dev.vars not found. Please create it first."
  exit 1
fi

# Create local D1 database
echo "📦 Creating local D1 database..."
npx wrangler d1 execute cap-db --local --file=./schema.sql

echo ""
echo "✅ Local development setup complete!"
echo ""
echo "To start the dev server, run:"
echo "  npm run dev"
echo ""
echo "Default admin key: dev-admin-key-12345"
echo ""
