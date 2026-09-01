-- LightRAG Row-Level Security: schema
--
-- Adds the ACL column and its indexes to the tables that hold retrievable
-- content. Run AFTER LightRAG has started once and created its tables, since
-- it creates them lazily on first connect.
--
-- Idempotent: safe to re-run.
--
-- NOTE ON TABLE NAMES. The vector tables carry the embedding model and
-- dimension in their name (lightrag_vdb_chunks_<model>_<dim>d), so changing
-- EMBEDDING_MODEL creates a NEW table without this column and silently without
-- RLS. Re-run this script after any embedding-model change. Verify the current
-- name with:
--     SELECT tablename FROM pg_tables
--      WHERE schemaname='public' AND tablename LIKE 'lightrag_vdb%';

\set ON_ERROR_STOP on

-- ---------------------------------------------------------------------------
-- 1. The ACL column
-- ---------------------------------------------------------------------------
-- Default is the public tier: a row inserted by a pipeline that does not yet
-- set an ACL is readable by everyone rather than by no one. That is the right
-- default for INGESTION (a document nobody can read is invisible and looks like
-- data loss), and the wrong one for a classified corpus -- so Phase 6, which
-- gives ingestion a real ACL source, must land before this is trusted with
-- restricted material.

ALTER TABLE lightrag_doc_chunks
    ADD COLUMN IF NOT EXISTS authorized_groups TEXT[] NOT NULL
    DEFAULT '{Sec-Public-Access}';

ALTER TABLE lightrag_doc_full
    ADD COLUMN IF NOT EXISTS authorized_groups TEXT[] NOT NULL
    DEFAULT '{Sec-Public-Access}';

ALTER TABLE lightrag_doc_status
    ADD COLUMN IF NOT EXISTS authorized_groups TEXT[] NOT NULL
    DEFAULT '{Sec-Public-Access}';

ALTER TABLE lightrag_vdb_chunks_bge_m3_latest_1024d
    ADD COLUMN IF NOT EXISTS authorized_groups TEXT[] NOT NULL
    DEFAULT '{Sec-Public-Access}';

-- ---------------------------------------------------------------------------
-- 2. Indexes
-- ---------------------------------------------------------------------------
-- GIN on the array so the && (overlap) operator in the policy is index-assisted
-- rather than evaluated per tuple. Without this the RLS predicate is a
-- sequential filter applied to every candidate row the vector scan produces.

CREATE INDEX IF NOT EXISTS idx_doc_chunks_acl_gin
    ON lightrag_doc_chunks USING GIN (authorized_groups);

CREATE INDEX IF NOT EXISTS idx_doc_full_acl_gin
    ON lightrag_doc_full USING GIN (authorized_groups);

CREATE INDEX IF NOT EXISTS idx_doc_status_acl_gin
    ON lightrag_doc_status USING GIN (authorized_groups);

CREATE INDEX IF NOT EXISTS idx_vdb_chunks_acl_gin
    ON lightrag_vdb_chunks_bge_m3_latest_1024d USING GIN (authorized_groups);

-- ---------------------------------------------------------------------------
-- 3. Application role
-- ---------------------------------------------------------------------------
-- RLS does not apply to superusers, nor to the table owner unless FORCE ROW
-- LEVEL SECURITY is set. Connecting LightRAG as the superuser that created the
-- tables would therefore leave every policy inert while appearing configured --
-- the failure mode this whole design exists to avoid.
--
-- NOLOGIN by default: set a password and grant LOGIN deliberately, and point
-- POSTGRES_USER at this role rather than at your own account.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'lightrag_app') THEN
        CREATE ROLE lightrag_app NOLOGIN;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO lightrag_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO lightrag_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO lightrag_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO lightrag_app;
