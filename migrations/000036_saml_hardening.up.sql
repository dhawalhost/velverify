-- Migration to add encryption and signing options to SAML providers
ALTER TABLE saml_providers ADD COLUMN IF NOT EXISTS encrypt_assertions BOOLEAN DEFAULT FALSE;
ALTER TABLE saml_providers ADD COLUMN IF NOT EXISTS sign_assertions BOOLEAN DEFAULT TRUE;

-- Update existing records to match defaults if they were null (though DEFAULT handles new ones)
UPDATE saml_providers SET encrypt_assertions = FALSE WHERE encrypt_assertions IS NULL;
UPDATE saml_providers SET sign_assertions = TRUE WHERE sign_assertions IS NULL;
