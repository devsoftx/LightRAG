# TODO — Entity/Relation and Graph Access Control under RLS

**Status: a live, reproduced disclosure. Deferred to the next iteration.**

Row-Level Security currently protects documents, chunks and chunk embeddings.
It does **not** protect entity/relation embeddings or the knowledge graph, and
those are read by every graph-backed retrieval mode. A user can therefore
retrieve content from documents they cannot read.

> **Correction to the previous version of this note.** This was written up as a
> *graph* problem. That was wrong, and the mis-scoping matters: the same defect
> exists in the entity/relation **vector tables**, which `local` / `global` /
> `hybrid` / `mix` read regardless of which graph backend is configured. There
> are three enforcement surfaces, not one.

---

## 1. Current state

| Surface | Tables / store | RLS |
|---|---|---|
| Documents | `lightrag_doc_full`, `lightrag_doc_status` | ✅ enforced |
| Chunks | `lightrag_doc_chunks` | ✅ enforced |
| Chunk embeddings | `lightrag_vdb_chunks_<model>_<dim>d` | ✅ enforced |
| **Entity embeddings** | `lightrag_vdb_entity_<model>_<dim>d` | ❌ **no ACL column, no policy** |
| **Relation embeddings** | `lightrag_vdb_relation_<model>_<dim>d` | ❌ **no ACL column, no policy** |
| **Knowledge graph** | NetworkX `.graphml` file | ❌ **outside PostgreSQL entirely** |

Only `naive` mode reads exclusively from protected tables. Every other mode
traverses at least one unprotected surface.

## 2. Reproduction

Three documents, ACLs assigned: finance → `Sec-Fin-Admins`, HR →
`Sec-HR-General`, public statement → `Sec-Public-Access`.

```
# As a Sec-Fin-Admins user, in local mode:
"What is workforce investigation WI-2024-07 and which control was ineffective?"

-> "Workforce investigation WI-2024-07 concerns the alleged misuse of
    privileged access by an employee in the payroll function ...
    the segregation of duties control (CTRL-455) was ineffective."
```

The same question in `naive` mode returns "I do not have enough information",
which is the correct behaviour and confirms the chunk path is filtered.

Both unprotected surfaces hold the material independently:

```sql
SELECT id, content FROM lightrag_vdb_entity_<model>_<dim>d
 WHERE content ILIKE '%payroll%' OR content ILIKE '%CTRL-455%';
-- 5 rows: WI-2024-07, CTRL-455, "Employee in Payroll Function", ...
```

```python
G = nx.read_graphml('rag_storage/graph_chunk_entity_relation.graphml')
# 6 HR-derived nodes present in the file
```

## 3. The blocker: entities merge across documents

Surface 1 looks like a mechanical fix — add `authorized_groups`, add a policy,
done. It is not, and this is the whole reason the work is deferred rather than
scheduled.

`merge_nodes_and_edges` merges an entity across every chunk that mentions it,
summarising one description from all of them. Measured on the current
three-document corpus:

| Entity | Chunks merged |
|---|---|
| `NuTech Corp` | **70** |
| `ISO/IEC 27001` | 5 |
| `Chief Information Security Officer` | 2 |

Where those chunks span different classifications, the merged description
contains restricted content. A single `authorized_groups` value on that row
cannot be correct:

- **Union of contributors** → a public user reads a description synthesised
  partly from HR and finance documents. The leak, relocated.
- **Intersection** → the entity is visible only to a caller cleared for all 70
  sources. The best-connected entities disappear for nearly everyone, degrading
  retrieval silently rather than failing loudly.

This is a data-modelling decision, not an implementation task, and it
determines the schema — so it must be settled before any column is added.

## 4. Options

### Option A — Partition by classification *(recommended)*

One workspace/graph per security tier; ingestion routes a document to the tier
matching its classification.

- **Pro:** no mixed entities by construction. ACL becomes a tier selection, not
  a per-tuple predicate. No query-time cost. Requires **no change** to
  LightRAG's merge semantics.
- **Con:** no cross-tier entity resolution — `NuTech Corp` in a public filing
  and in a restricted report become unrelated. Storage and extraction cost
  multiply by the number of tiers a corpus spans.

### Option B — ACL as the intersection of contributors

- **Pro:** single graph, cross-document resolution preserved, provably safe.
- **Con:** collapses toward invisible, and does so quietly. **Avoid** — it is
  the smallest change and the worst failure mode.

### Option C — Re-summarise per tier

Each entity carries N descriptions, each synthesised only from sources visible
to that tier.

- **Pro:** correct and lossless; cross-document resolution preserved.
- **Con:** extraction cost multiplies by tier; `merge_nodes_and_edges` and the
  recovery-anchor contract both need rework, since a document's contribution is
  no longer a single description.

## 5. Infrastructure constraint (discovered while evaluating AGE)

Moving the graph into PostgreSQL via Apache AGE would put it somewhere policies
*could* apply. It is currently not installable here, and would not fix the leak
anyway (§3 applies to AGE vertices unchanged).

| | PostgreSQL 16 | PostgreSQL 17 *(in use)* |
|---|---|---|
| pgvector (Homebrew) | ❌ no build | ✅ 0.8.6 |
| Apache AGE | ✅ upstream supports 11–16 | ❌ unsupported |

No Homebrew-installable server provides both. There is no `apache-age` formula
at all. Having both means compiling at least one from source against
PostgreSQL 16 — the `@16` data directory is still intact, so the server switch
itself is trivial.

Note also that filtering *after* a Cypher traversal is post-filtering, which
§2 of `RLS-CD-Detect` explicitly argues against: the traversal still walks
restricted vertices, and multi-hop paths can disclose structure even when
endpoints are filtered.

## 6. Plan for the next iteration

1. **Decide §4.** Recommend Option A. Everything downstream depends on it.
2. **Interim containment** — refuse `local` / `global` / `hybrid` / `mix` when
   `POSTGRES_RLS_ENABLED=true`, with an error naming the unprotected surface.
   Leaves `naive` fully functional and closes the disclosure honestly rather
   than appearing protected while traversing unfiltered data.
3. **Close surface 1** — `authorized_groups` + GIN + policies on
   `vdb_entity` / `vdb_relation`, with values derived per the §4 decision.
4. **Surface 2** — only after (1). If Option A is chosen, per-tier graphs may
   remove the need for graph-level ACLs entirely.
5. **Re-enable** the graph-backed modes and re-run §2 as a regression test.

## 7. Also outstanding

- **Ingestion ACL source (Phase 6).** ACLs are currently assigned by hand via
  `UPDATE`. New documents default to `Sec-Public-Access`, so the default is
  open, not closed. This must land before restricted material is ingested.
- **Model-suffixed vector tables.** Changing `EMBEDDING_MODEL` creates
  `lightrag_vdb_chunks_<newmodel>_<dim>d` with no ACL column and no policies —
  silently unprotected. Flagged in `docs/rls/01_schema.sql`; deserves a startup
  check.
- **Write policies are permissive.** Ingestion and retrieval share one pool and
  one role, so there is no connection-level distinction to attach different
  rules to. The `BYPASSRLS` ingestion role in `RLS-CD-Detect` §6 presumes two
  pools, which LightRAG does not have.

## 8. Related

- `docs/rls/01_schema.sql`, `02_policies.sql` — what is enforced today
- `docs/RLS-CD-Detect` §2.1 — the response-cache bypass (fixed)
- `docs/RLS-CD-Detect` §7 — the AGE design this note supersedes
- `docs/RLS-CD-Detect` §8 — connection/session integration point
- `AGENTS.md`, "Purge recovery contract" — the anchor invariant Options A and C
  both disturb
