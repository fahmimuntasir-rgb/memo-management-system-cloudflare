# MemoFlow Secure Inter-Office Memo Management

Cloudflare Workers and D1 version with application-owned email/password authentication.

## Security features

- PBKDF2-SHA256 password hashing with 210,000 iterations and per-user salts.
- Opaque sessions; only token hashes are stored.
- HttpOnly, Secure and SameSite=Strict session cookies.
- Server-side authentication and administrator checks.
- Every protected query takes the organization ID from the authenticated session.
- Prepared D1 statements and validated input.
- Single-use, hashed, 30-minute password-reset tokens.
- Existing sessions are revoked after a password reset.
- Generic reset responses prevent account discovery.
- Origin checks and immutable audit events.

## Demonstration accounts

| Organization | Role | Email | Password |
|---|---|---|---|
| Northstar Group | Administrator | admin@northstar.demo | DemoAdmin!2026 |
| Northstar Group | Regular user | user@northstar.demo | DemoUser!2026 |
| Riverside Institute | Administrator | admin@riverside.demo | RiversideAdmin!2026 |

Replace demonstration credentials before real organizational use.

## Upload to GitHub

1. Extract memo-management-system.zip.
2. Open the empty GitHub repository.
3. Select uploading an existing file.
4. Drag all extracted files and folders into the upload area.
5. Use the commit message: Initial secure MemoFlow application.
6. Select Commit changes.

## Cloudflare setup

1. Open Storage and databases, then D1 SQL database.
2. Create a database named memo-management-db.
3. Copy the database ID.
4. In GitHub, edit wrangler.jsonc and replace REPLACE_WITH_D1_DATABASE_ID.
5. Return to Workers and Pages and import the repository.
6. Select branch main.
7. Leave Build command blank.
8. Set Deploy command to: npx wrangler deploy
9. Deploy the project.

## Initialize the database

On a computer with Node.js:

    npm install
    npx wrangler login
    npm run db:remote
    npm run seed:remote

Run migrations and the seed only once.

## Optional reset emails

Without email settings, reset displays a temporary demonstration token. For real email delivery, add Worker secrets RESEND_API_KEY and RESET_FROM_EMAIL. Never commit secrets to GitHub.

## Local development

    npm install
    npm run db:local
    npm run seed:local
    npm run dev

## Architecture

Browser to Cloudflare Worker API to D1 database.

The Worker serves the frontend and handles authentication, authorization, resets, memos and administrator actions. D1 stores organizations, users, hashes, sessions, tokens, memos and audit records.

## Limitation

Real password-reset email delivery requires a transactional-email account. Until configured, the application displays the reset token for course demonstration.
