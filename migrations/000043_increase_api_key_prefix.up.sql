-- Migration: Increase API Key prefix length to prevent 500 errors
-- Path: migrations/000043_increase_api_key_prefix.up.sql

ALTER TABLE api_keys ALTER COLUMN key_prefix TYPE VARCHAR(50);
