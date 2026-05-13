ALTER TABLE identities ADD COLUMN external_id TEXT;
ALTER TABLE identities ADD COLUMN phone_numbers JSONB;
ALTER TABLE identities ADD COLUMN department TEXT;
ALTER TABLE identities ADD COLUMN title TEXT;
ALTER TABLE identities ADD COLUMN timezone TEXT;
