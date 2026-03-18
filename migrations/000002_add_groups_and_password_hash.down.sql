-- 000002_add_groups_and_password_hash.down.sql
ALTER TABLE accounts DROP COLUMN IF EXISTS password_hash;

DROP TABLE IF EXISTS identity_groups;
DROP TABLE IF EXISTS groups;
