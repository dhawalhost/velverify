ALTER TABLE access_requests ADD COLUMN requester_type TEXT DEFAULT 'user';
ALTER TABLE access_requests ADD COLUMN metadata JSONB;
