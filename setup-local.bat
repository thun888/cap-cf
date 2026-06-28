@echo off
REM Local development setup script for Windows

echo 🚀 Setting up local development environment...

REM Check if .dev.vars exists
if not exist .dev.vars (
    echo ❌ .dev.vars not found. Please create it first.
    exit /b 1
)

REM Create local D1 database
echo 📦 Creating local D1 database...
call npx wrangler d1 execute cap-db --local --file=./schema.sql

echo.
echo ✅ Local development setup complete!
echo.
echo To start the dev server, run:
echo   npm run dev
echo.
echo Default admin key: dev-admin-key-12345
echo.
