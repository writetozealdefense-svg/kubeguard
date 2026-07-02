-- +goose Up
-- Findings lifecycle (K6): triage state, ownership, and waivers per stable
-- finding identity (cluster + check id + resource, hashed into `key`).
-- Tenant-partitioned like every other table (no cross-tenant FKs, NFR-3).

CREATE TABLE IF NOT EXISTS finding_lifecycle (
    tenant             text NOT NULL,
    key                text NOT NULL,
    cluster_id         text NOT NULL,
    finding_id         text NOT NULL,
    resource_kind      text,
    resource_namespace text,
    resource_name      text,
    state              text NOT NULL DEFAULT 'open',
    assignee           text,
    waiver             jsonb,
    first_seen         text,
    last_updated       text,
    resolved_at        text,
    PRIMARY KEY (tenant, key)
);
CREATE INDEX IF NOT EXISTS finding_lifecycle_cluster_idx
    ON finding_lifecycle (tenant, cluster_id);

-- +goose Down
DROP TABLE IF EXISTS finding_lifecycle;
