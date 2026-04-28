-- 000045_add_user_mfa_enforced.down.sql
ALTER TABLE identities DROP COLUMN IF EXISTS mfa_enforced;
