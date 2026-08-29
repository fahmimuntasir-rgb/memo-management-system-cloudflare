# MemoFlow — Secure Inter-Office Memo Management

MemoFlow is a multi-organization memo and approval system built with Cloudflare Workers, D1 SQLite, and a browser interface.

Live demo: `https://memo-management-system-cloudflare.fahmimuntasir.workers.dev`

## Features

- Tenant-isolated administrator and user accounts.
- Secure authentication, password reset, profiles, and user administration.
- Draft editing, submission, revision, resubmission, versions, and audit history.
- Ordered approval workflows with approve, reject, request changes, and comments.
- Time-bounded workflow delegation and delegated action tracking.
- D1 attachments for PDF, PNG, JPG, TXT, DOC, and DOCX files up to 750 KB.
- Departments, categories, and reusable workflow templates.
- Advanced memo search, filters, sorting, and date ranges.
- Workflow notifications with individual and bulk read controls.
- Organization reports, statistics, CSV export, and print/PDF output.
- Organization name, HTTPS logo, contact information, and safe rich-text formatting.

## Demo accounts

| Organization | Role | Email | Password |
|---|---|---|---|
| Northstar Group | Administrator | `admin@northstar.demo` | `DemoAdmin!2026` |
| Northstar Group | User | `user@northstar.demo` | `DemoUser!2026` |
| Riverside Institute | Administrator | `admin@riverside.demo` | `RiversideAdmin!2026` |

Replace all demo credentials before real use.

## Architecture

The browser loads assets from Cloudflare Workers Assets. `/api/*` requests run through `src/index.ts`, which authenticates the session, applies role and organization authorization, and uses prepared statements with D1.

- `src/` — Worker API and security logic.
- `public/` — browser interface.
- `migrations/` — D1 schema migrations.
- `tests/` — automated security checks.
- `seed.sql` — demo data for a new empty database only.

## Security

- PBKDF2-SHA256 with 210,000 iterations and per-user salts.
- Opaque sessions; only SHA-256 token hashes are stored.
- `HttpOnly`, `Secure`, `SameSite=Strict` cookies.
- Same-origin validation for state-changing requests.
- Server-side roles and organization IDs taken from authenticated sessions.
- Prepared D1 statements and validated input.
- Hashed, single-use, 30-minute reset tokens and session revocation.
- Attachment type/size validation and HTTPS-only logo URLs.
- Escaped rich-text rendering to prevent script injection.
- Tenant-scoped memos, notifications, reports, delegation, and audit logs.

## Fresh Cloudflare installation

1. Create a D1 database named `memo-management-db`.
2. Put its database ID in `wrangler.jsonc` in place of `REPLACE_WITH_D1_DATABASE_ID`.
3. Run `npm install` and `npx wrangler login`.
4. Apply all migrations once with `npm run db:remote`.
5. On a new empty demo database only, run `npm run seed:remote` once.
6. Deploy with `npm run deploy`, or connect GitHub with deploy command `npx wrangler deploy`.

Do not run `seed:remote` on the existing live database. Do not manually rerun migrations already recorded by Wrangler.

## Local development and testing

```bash
npm install
npm run db:local
npm run seed:local
npm run dev
```

```bash
npm test
npx tsc --noEmit
```

## Optional reset email

For real password-reset email, configure `RESEND_API_KEY` and `RESET_FROM_EMAIL` as Worker secrets. Without them, the course demo displays a temporary reset token. Never commit secrets.

## Basic operation

1. Administrators configure users, departments, categories, templates, and branding.
2. An author creates a memo and ordered workflow, then submits it.
3. Current participants act from Inbox; later steps activate sequentially.
4. Authors revise and resubmit when changes are requested.
5. Administrators use Reports for statistics, CSV, and PDF output.

## Limitations

- Attachments are limited to 750 KB because they are stored in D1.
- Logo display depends on the supplied HTTPS image URL.
- Production reset email needs a transactional email provider.
- Demo accounts and records are not suitable for confidential production data.

See `FINAL_VERIFICATION.md` for the final checklist.
