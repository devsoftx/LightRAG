-- LightRAG Row-Level Security: policies
--
-- Run after 01_schema.sql. Idempotent.
--
-- Mode B (session-variable context) from the design document. Mode A --
-- resolving a delegated token to a per-user database role -- is not usable
-- here: LightRAG shares one asyncpg pool across all requests, so a per-identity
-- connection would mean a pool per identity.
--
-- The session variable is set by lightrag.kg.postgres_impl inside a
-- transaction, via set_config('app.current_user_groups', $1, true). The
-- transaction is what makes it safe on a shared pool: SET LOCAL unwinds at
-- commit, so a recycled connection cannot carry one caller's entitlements into
-- another's request.

\set ON_ERROR_STOP on

-- ---------------------------------------------------------------------------
-- Read policy
-- ---------------------------------------------------------------------------
-- A row is visible when the caller's group set OVERLAPS its authorized_groups,
-- or when the row is in the public tier.
--
-- current_setting(..., true) returns NULL when unset; NULLIF maps the empty
-- string to NULL as well. && against NULL is NULL, i.e. not true, so a session
-- with no identity sees only public rows. That is the correct floor: the
-- application refuses such queries before they reach here (see
-- _run_with_rls_context), so this is defence in depth, not the primary gate.

CREATE OR REPLACE FUNCTION lightrag_current_groups() RETURNS TEXT[] AS $$
    SELECT NULLIF(current_setting('app.current_user_groups', true), '')::TEXT[];
$$ LANGUAGE sql STABLE;

DO $$
DECLARE
    t TEXT;
    tables TEXT[] := ARRAY[
        'lightrag_doc_chunks',
        'lightrag_doc_full',
        'lightrag_doc_status',
        'lightrag_vdb_chunks_bge_m3_latest_1024d'
    ];
BEGIN
    FOREACH t IN ARRAY tables LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        -- FORCE so the policies also apply to the table OWNER. Without it the
        -- role that created the tables is exempt, and on a single-role
        -- development install that is every query -- policies present, nothing
        -- filtered.
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);

        EXECUTE format('DROP POLICY IF EXISTS rls_%s_select ON %I', t, t);
        EXECUTE format($f$
            CREATE POLICY rls_%s_select ON %I
            FOR SELECT TO public
            USING (
                authorized_groups && lightrag_current_groups()
                OR 'Sec-Public-Access' = ANY(authorized_groups)
            )
        $f$, t, t);

        -- Write policies are permissive, and are declared per-command.
        --
        -- CRITICAL: they must NOT use FOR ALL. FOR ALL includes SELECT, and
        -- PostgreSQL OR-s permissive policies together -- so a
        -- "FOR ALL ... USING (true)" policy alongside the read policy above
        -- would make every row visible to everyone while the configuration
        -- still looked correct. Each write command is therefore named
        -- explicitly, leaving SELECT governed solely by the ACL policy.
        --
        -- Permitting all writes is a deliberate limitation of this phase.
        -- LightRAG performs ingestion and retrieval through the SAME pool and
        -- the SAME database role, so there is no connection-level distinction
        -- between a writer and a reader to attach different policies to. With
        -- RLS enabled and no write policy, every INSERT would be denied and
        -- ingestion would stop.
        --
        -- Writes are gated by the application's own authentication. The
        -- production split -- a BYPASSRLS ingestion role separate from a
        -- restricted query role, per section 6 of the design document --
        -- requires LightRAG to hold two pools, which it does not today.
        EXECUTE format('DROP POLICY IF EXISTS rls_%s_insert ON %I', t, t);
        EXECUTE format(
            'CREATE POLICY rls_%s_insert ON %I FOR INSERT TO public WITH CHECK (true)',
            t, t);

        EXECUTE format('DROP POLICY IF EXISTS rls_%s_update ON %I', t, t);
        EXECUTE format(
            'CREATE POLICY rls_%s_update ON %I FOR UPDATE TO public '
            'USING (true) WITH CHECK (true)', t, t);

        EXECUTE format('DROP POLICY IF EXISTS rls_%s_delete ON %I', t, t);
        EXECUTE format(
            'CREATE POLICY rls_%s_delete ON %I FOR DELETE TO public USING (true)',
            t, t);
    END LOOP;
END
$$;
