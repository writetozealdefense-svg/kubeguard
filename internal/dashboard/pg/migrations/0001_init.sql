-- +goose Up
-- Tenant-partitioned schema for the dashboard. Every row carries its tenant;
-- there are no cross-tenant foreign keys. The full scan report is stored as
-- jsonb so the API reconstructs findings/paths/compliance without a wide schema.

CREATE TABLE IF NOT EXISTS tenants (
    id          text PRIMARY KEY,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    id          text NOT NULL,
    tenant      text NOT NULL,
    email       text,
    role        text NOT NULL DEFAULT 'viewer',
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, id)
);

CREATE TABLE IF NOT EXISTS clusters (
    tenant            text NOT NULL,
    id                text NOT NULL,
    name              text NOT NULL,
    environment       text,
    last_scan_at      text,
    total_findings    int  NOT NULL DEFAULT 0,
    overall_pass_rate double precision NOT NULL DEFAULT 0,
    registered_seq    bigint GENERATED ALWAYS AS IDENTITY,
    PRIMARY KEY (tenant, id)
);

CREATE TABLE IF NOT EXISTS scans (
    tenant         text NOT NULL,
    id             text NOT NULL,
    cluster_id     text NOT NULL,
    status         text NOT NULL,
    started_at     text,
    finished_at    text,
    total_findings int  NOT NULL DEFAULT 0,
    is_latest      boolean NOT NULL DEFAULT false,
    report         jsonb NOT NULL,
    PRIMARY KEY (tenant, id)
);
CREATE INDEX IF NOT EXISTS scans_cluster_idx ON scans (tenant, cluster_id, started_at DESC);
CREATE INDEX IF NOT EXISTS scans_latest_idx  ON scans (tenant, cluster_id) WHERE is_latest;

CREATE TABLE IF NOT EXISTS history (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant            text NOT NULL,
    cluster_id        text NOT NULL,
    scan_id           text NOT NULL,
    at                text NOT NULL,
    total_findings    int  NOT NULL,
    controls_assessed int  NOT NULL,
    controls_breached int  NOT NULL,
    overall_pass_rate double precision NOT NULL,
    by_severity       jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS history_cluster_idx ON history (tenant, cluster_id, at);

CREATE TABLE IF NOT EXISTS audit (
    id        bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant    text NOT NULL,
    at        text NOT NULL,
    subject   text NOT NULL,
    action    text NOT NULL,
    resource  text,
    result    text NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_tenant_idx ON audit (tenant, id);

-- +goose Down
DROP TABLE IF EXISTS audit;
DROP TABLE IF EXISTS history;
DROP TABLE IF EXISTS scans;
DROP TABLE IF EXISTS clusters;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS tenants;
