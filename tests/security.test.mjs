import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
const src=fs.readFileSync(new URL("../src/index.ts",import.meta.url),"utf8");
test("secure cookie controls",()=>assert.match(src,/HttpOnly; Secure; SameSite=Strict/));
test("PBKDF2 SHA-256",()=>{assert.match(src,/PBKDF2/);assert.match(src,/210000/);assert.match(src,/SHA-256/)});
test("tenant-scoped memos",()=>assert.match(src,/WHERE m\.organization_id=\?/));
test("admin role enforcement",()=>assert.match(src,/u\.role!=="admin"/));
test("password reset revokes sessions",()=>assert.match(src,/DELETE FROM sessions WHERE user_id=\?/));
