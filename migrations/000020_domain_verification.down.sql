ALTER TABLE organizations DROP COLUMN IF EXISTS domain_verification_token;
ALTER TABLE organizations DROP COLUMN IF EXISTS domain_verification_expires_at;
