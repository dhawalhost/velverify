-- 000045_add_user_mfa_enforced.up.sql
ALTER TABLE identities ADD COLUMN IF NOT EXISTS mfa_enforced BOOLEAN DEFAULT FALSE;
