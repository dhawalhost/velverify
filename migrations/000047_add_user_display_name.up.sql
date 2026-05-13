-- 000047_add_user_display_name.up.sql
ALTER TABLE identities ADD COLUMN IF NOT EXISTS display_name VARCHAR(255);
