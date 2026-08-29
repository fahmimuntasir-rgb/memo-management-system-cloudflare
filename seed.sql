INSERT INTO organizations VALUES('org_northstar','Northstar Group','NSG-001',1,'2026-08-28T00:00:00Z');
INSERT INTO organizations VALUES('org_riverside','Riverside Institute','RSI-002',1,'2026-08-28T00:00:00Z');
INSERT INTO departments VALUES('dept_finance','org_northstar','Finance',1);
INSERT INTO departments VALUES('dept_operations','org_northstar','Operations',1);
INSERT INTO departments VALUES('dept_academic','org_riverside','Academic Affairs',1);
-- Demo password hashes are PBKDF2-SHA256. Passwords are listed in README.md.
INSERT INTO users VALUES('user_admin','org_northstar','dept_finance','Muntasir Fahmi','admin@northstar.demo','pbkdf2_sha256$100000$YWRtaW4tc2FsdC0yMDI2$p+X06yq/aYPpWVZPYGJBHy2Z4BBwWagPb4qI2d3z5KE=','admin','active','2026-08-28T00:00:00Z','2026-08-28T00:00:00Z');
INSERT INTO users VALUES('user_regular','org_northstar','dept_operations','Ayesha Rahman','user@northstar.demo','pbkdf2_sha256$100000$dXNlci1zYWx0LTIwMjY=$iAMjOmlKek/aLqMwqQxqtsEli9ejtkHOje/YyKM26Jc=','user','active','2026-08-28T00:00:00Z','2026-08-28T00:00:00Z');
INSERT INTO users VALUES('user_other','org_riverside','dept_academic','Nafis Ahmed','admin@riverside.demo','pbkdf2_sha256$100000$cml2ZXJzaWRlLXNhbHQtMjAyNg==$X+07N7R8n+vzF3M7zG16mTHWxPXyMQMfesdknAEz4Q8=','admin','active','2026-08-28T00:00:00Z','2026-08-28T00:00:00Z');
INSERT INTO memos VALUES('memo_1','org_northstar','user_regular','dept_operations','MEM-2026-0084','Laboratory equipment purchase','Approval is requested for twelve laboratory kits.','Pending Approval','Urgent','2026-08-27T12:12:00Z','2026-08-27T12:12:00Z');
INSERT INTO memos VALUES('memo_2','org_riverside','user_other','dept_academic','MEM-2026-0001','Faculty meeting schedule','Internal Riverside memo that Northstar users must never receive.','Draft','Normal','2026-08-27T12:12:00Z','2026-08-27T12:12:00Z');
