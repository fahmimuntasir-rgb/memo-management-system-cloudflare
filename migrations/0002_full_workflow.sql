PRAGMA foreign_keys = ON;

ALTER TABLE organizations ADD COLUMN logo_url TEXT;
ALTER TABLE organizations ADD COLUMN contact_info TEXT;
ALTER TABLE users ADD COLUMN designation TEXT;
ALTER TABLE memos ADD COLUMN category_id TEXT;
ALTER TABLE memos ADD COLUMN submitted_at TEXT;
ALTER TABLE memos ADD COLUMN completed_at TEXT;
ALTER TABLE memos ADD COLUMN current_step INTEGER;
ALTER TABLE memos ADD COLUMN version_no INTEGER NOT NULL DEFAULT 1;
ALTER TABLE memos ADD COLUMN cancelled_at TEXT;

CREATE TABLE categories(
 id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, name TEXT NOT NULL,
 description TEXT, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL,
 UNIQUE(organization_id,name), FOREIGN KEY(organization_id) REFERENCES organizations(id)
);

CREATE TABLE workflow_templates(
 id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, name TEXT NOT NULL,
 description TEXT, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL,
 UNIQUE(organization_id,name), FOREIGN KEY(organization_id) REFERENCES organizations(id)
);
CREATE TABLE workflow_template_steps(
 id TEXT PRIMARY KEY, template_id TEXT NOT NULL, position INTEGER NOT NULL,
 label TEXT NOT NULL, action_type TEXT NOT NULL DEFAULT 'Approve',
 UNIQUE(template_id,position), FOREIGN KEY(template_id) REFERENCES workflow_templates(id) ON DELETE CASCADE
);

CREATE TABLE workflow_steps(
 id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, memo_id TEXT NOT NULL,
 position INTEGER NOT NULL, participant_id TEXT NOT NULL, label TEXT,
 required_action TEXT NOT NULL DEFAULT 'Approve', status TEXT NOT NULL DEFAULT 'Future',
 acted_by TEXT, acted_on_behalf_of TEXT, action TEXT, comment TEXT,
 started_at TEXT, completed_at TEXT,
 UNIQUE(memo_id,position),
 FOREIGN KEY(organization_id) REFERENCES organizations(id),
 FOREIGN KEY(memo_id) REFERENCES memos(id) ON DELETE CASCADE,
 FOREIGN KEY(participant_id) REFERENCES users(id), FOREIGN KEY(acted_by) REFERENCES users(id)
);

CREATE TABLE memo_versions(
 id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, memo_id TEXT NOT NULL,
 version_no INTEGER NOT NULL, editor_id TEXT NOT NULL, subject TEXT NOT NULL,
 body TEXT NOT NULL, created_at TEXT NOT NULL, submission_note TEXT,
 UNIQUE(memo_id,version_no), FOREIGN KEY(memo_id) REFERENCES memos(id) ON DELETE CASCADE
);
CREATE TABLE comments(
 id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, memo_id TEXT NOT NULL,
 user_id TEXT NOT NULL, comment_type TEXT NOT NULL DEFAULT 'General', text TEXT NOT NULL,
 created_at TEXT NOT NULL, FOREIGN KEY(memo_id) REFERENCES memos(id) ON DELETE CASCADE
);
CREATE TABLE memo_events(
 id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, memo_id TEXT NOT NULL,
 user_id TEXT, event_type TEXT NOT NULL, description TEXT NOT NULL, comment TEXT,
 created_at TEXT NOT NULL, FOREIGN KEY(memo_id) REFERENCES memos(id) ON DELETE CASCADE
);
CREATE TABLE notifications(
 id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, user_id TEXT NOT NULL,
 memo_id TEXT, type TEXT NOT NULL, message TEXT NOT NULL, read_at TEXT, created_at TEXT NOT NULL
);
CREATE TABLE delegations(
 id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, delegator_id TEXT NOT NULL,
 delegate_id TEXT NOT NULL, start_at TEXT NOT NULL, end_at TEXT NOT NULL,
 reason TEXT, status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL
);
CREATE TABLE attachments(
 id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, memo_id TEXT NOT NULL,
 uploaded_by TEXT NOT NULL, file_name TEXT NOT NULL, content_type TEXT NOT NULL,
 size INTEGER NOT NULL CHECK(size <= 750000), content BLOB NOT NULL, created_at TEXT NOT NULL,
 FOREIGN KEY(memo_id) REFERENCES memos(id) ON DELETE CASCADE,
 FOREIGN KEY(uploaded_by) REFERENCES users(id)
);

CREATE INDEX idx_steps_memo ON workflow_steps(organization_id,memo_id,position);
CREATE INDEX idx_steps_participant ON workflow_steps(organization_id,participant_id,status);
CREATE INDEX idx_events_memo ON memo_events(organization_id,memo_id,created_at);
CREATE INDEX idx_comments_memo ON comments(organization_id,memo_id,created_at);
CREATE INDEX idx_notifications_user ON notifications(organization_id,user_id,read_at);
CREATE INDEX idx_versions_memo ON memo_versions(organization_id,memo_id,version_no);

INSERT INTO categories VALUES
 ('cat_ns_general','org_northstar','General','General office communication',1,'2026-08-29T00:00:00Z'),
 ('cat_ns_finance','org_northstar','Financial','Finance and approval memos',1,'2026-08-29T00:00:00Z'),
 ('cat_ns_hr','org_northstar','HR','Human resources memos',1,'2026-08-29T00:00:00Z'),
 ('cat_rv_general','org_riverside','General','General institutional communication',1,'2026-08-29T00:00:00Z');
