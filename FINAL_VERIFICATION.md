# MemoFlow Final Verification Checklist

## Automated checks

- [ ] `npm test` passes every test.
- [ ] `npx tsc --noEmit` reports no errors.
- [ ] The latest Cloudflare deployment reports a 0% error rate.

## Authentication and isolation

- [ ] Administrator and regular-user logins work.
- [ ] Invalid passwords are rejected and logout removes access.
- [ ] Password reset revokes existing sessions.
- [ ] Northstar users cannot access Riverside records.
- [ ] Regular users cannot access administrator pages or endpoints.

## Workflow

- [ ] Draft save, edit, delete, submit, and resubmit work.
- [ ] Ordered steps activate one participant at a time.
- [ ] Approve, reject, request changes, and comments work.
- [ ] Versions and activity history appear.
- [ ] Delegation works only during its active period.
- [ ] Delegated actions identify the delegate.

## Supporting features

- [ ] Allowed attachments upload/download; invalid files are rejected.
- [ ] Search, filters, sorting, and date ranges work.
- [ ] Notifications open and can be marked read.
- [ ] Reports, CSV download, and Print/Save PDF work.
- [ ] Organization branding and safe rich-text preview work.

## Submission evidence

- [ ] GitHub `main` contains every merged pull request.
- [ ] Capture login, dashboard, workflow, delegation, reports, and branding screenshots.
- [ ] Record the live Worker URL and GitHub repository URL.
- [ ] Replace demo credentials before real use.
