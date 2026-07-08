-- +goose Up
-- Tenant provisioning (K8): record an optional human display name alongside the
-- tenant id, set by the managed onboarding API.
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS display_name text;

-- +goose Down
ALTER TABLE tenants DROP COLUMN IF EXISTS display_name;
