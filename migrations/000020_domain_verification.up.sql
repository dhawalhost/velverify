-- Add domain verification token to organizations
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS domain_verification_token VARCHAR(64);
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS domain_verification_expires_at TIMESTAMP WITH TIME ZONE;
