-- VulnIntel AI canonical schema.
--
-- Written once, rendered for DuckDB or PostgreSQL by data/db.py. Dialect
-- differences are confined to the {{TOKENS}} below:
--   {{JSON}}    JSON / JSONB
--   {{VECTOR}}  FLOAT[] / REAL[]
--   {{SERIAL}}  BIGINT DEFAULT nextval(...) — declared per-table via sequences
--
-- Design rules enforced here:
--   * Every silver table carries provenance (source_run_id, retrieved_at).
--   * CVSS is stored as rows, never flattened — providers disagree.
--   * CPE ranges and OSV ranges keep their native shapes.
--   * Score components are persisted, never recomputed inside a view.
--   * Lexical search is done in Python, so no tsvector/FTS dialect split.

-- ============================================================================
-- Provenance
-- ============================================================================

CREATE SEQUENCE IF NOT EXISTS seq_ingest_run START 1;

CREATE TABLE IF NOT EXISTS ingest_run (
    run_id          BIGINT PRIMARY KEY DEFAULT nextval('seq_ingest_run'),
    source          VARCHAR NOT NULL,          -- nvd | kev | epss | osv | attack | knowledge | synthetic
    status          VARCHAR NOT NULL,          -- running | succeeded | failed
    started_at      TIMESTAMP NOT NULL,
    completed_at    TIMESTAMP,
    window_start    TIMESTAMP,
    window_end      TIMESTAMP,
    rows_in         BIGINT,
    rows_out        BIGINT,
    bronze_path     VARCHAR,
    checksum        VARCHAR,
    error           VARCHAR,
    notes           {{JSON}}
);

-- ============================================================================
-- Vulnerability intelligence (silver)
-- ============================================================================

CREATE TABLE IF NOT EXISTS cve (
    cve_id              VARCHAR PRIMARY KEY,
    published_at        TIMESTAMP,
    last_modified_at    TIMESTAMP,
    vuln_status         VARCHAR,
    description         VARCHAR,
    source_identifier   VARCHAR,
    configurations_raw  {{JSON}},
    source_run_id       BIGINT,
    retrieved_at        TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS cve_cvss (
    cve_id          VARCHAR NOT NULL,
    cvss_version    VARCHAR NOT NULL,   -- 2.0 | 3.0 | 3.1 | 4.0
    provider        VARCHAR NOT NULL,   -- nvd@nist.gov or the CNA
    metric_type     VARCHAR NOT NULL,   -- Primary | Secondary
    vector_string   VARCHAR,
    base_score      DOUBLE,
    base_severity   VARCHAR,
    exploitability  DOUBLE,
    impact          DOUBLE,
    PRIMARY KEY (cve_id, cvss_version, provider, metric_type)
);

CREATE TABLE IF NOT EXISTS cve_cwe (
    cve_id      VARCHAR NOT NULL,
    cwe_id      VARCHAR NOT NULL,
    provider    VARCHAR NOT NULL,
    PRIMARY KEY (cve_id, cwe_id, provider)
);

CREATE TABLE IF NOT EXISTS cve_reference (
    cve_id  VARCHAR NOT NULL,
    url     VARCHAR NOT NULL,
    source  VARCHAR,
    tags    VARCHAR,
    PRIMARY KEY (cve_id, url)
);

-- Flattened NVD configuration tree. The unflattened original stays on
-- cve.configurations_raw so a bad flattening can be re-derived.
CREATE TABLE IF NOT EXISTS cve_cpe_match (
    cve_id                      VARCHAR NOT NULL,
    node_ordinal                INTEGER NOT NULL,
    match_ordinal               INTEGER NOT NULL,
    operator                    VARCHAR,
    negate                      BOOLEAN,
    vulnerable                  BOOLEAN,
    criteria                    VARCHAR NOT NULL,
    cpe_part                    VARCHAR,
    cpe_vendor                  VARCHAR,
    cpe_product                 VARCHAR,
    cpe_version                 VARCHAR,
    cpe_update                  VARCHAR,
    version_start_including     VARCHAR,
    version_start_excluding     VARCHAR,
    version_end_including       VARCHAR,
    version_end_excluding       VARCHAR,
    PRIMARY KEY (cve_id, node_ordinal, match_ordinal)
);

-- Package advisories (OSV / GHSA) live in their own identity space.
CREATE TABLE IF NOT EXISTS advisory (
    advisory_id     VARCHAR PRIMARY KEY,
    source          VARCHAR NOT NULL,       -- osv | ghsa
    summary         VARCHAR,
    details         VARCHAR,
    severity_vector VARCHAR,
    severity_score  DOUBLE,
    published_at    TIMESTAMP,
    modified_at     TIMESTAMP,
    withdrawn_at    TIMESTAMP,
    raw             {{JSON}},
    source_run_id   BIGINT,
    retrieved_at    TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS advisory_alias (
    advisory_id VARCHAR NOT NULL,
    alias       VARCHAR NOT NULL,
    PRIMARY KEY (advisory_id, alias)
);

CREATE TABLE IF NOT EXISTS advisory_affected (
    advisory_id         VARCHAR NOT NULL,
    range_ordinal       INTEGER NOT NULL,
    ecosystem           VARCHAR NOT NULL,
    package_name        VARCHAR NOT NULL,
    purl                VARCHAR,
    range_type          VARCHAR,            -- SEMVER | ECOSYSTEM | GIT
    introduced          VARCHAR,
    fixed               VARCHAR,
    last_affected       VARCHAR,
    explicit_versions   VARCHAR,            -- comma-joined; parsed in Python
    PRIMARY KEY (advisory_id, range_ordinal)
);

-- ============================================================================
-- Exploitation signals
-- ============================================================================

-- Slowly-changing dimension: valid_to IS NULL means "currently in the catalog".
CREATE TABLE IF NOT EXISTS kev (
    cve_id                  VARCHAR NOT NULL,
    valid_from              DATE NOT NULL,
    valid_to                DATE,
    date_added              DATE,
    due_date                DATE,
    vendor_project          VARCHAR,
    product                 VARCHAR,
    vulnerability_name      VARCHAR,
    short_description       VARCHAR,
    required_action         VARCHAR,
    known_ransomware_use    BOOLEAN,
    notes                   VARCHAR,
    source_run_id           BIGINT,
    PRIMARY KEY (cve_id, valid_from)
);

CREATE TABLE IF NOT EXISTS epss_current (
    cve_id      VARCHAR PRIMARY KEY,
    probability DOUBLE NOT NULL,
    percentile  DOUBLE NOT NULL,
    score_date  DATE NOT NULL,
    source_run_id BIGINT
);

-- Rolling window only. The full daily series stays in bronze Parquet —
-- ~300k rows/day would be ~110M rows/year in the warehouse.
CREATE TABLE IF NOT EXISTS epss_history (
    cve_id      VARCHAR NOT NULL,
    score_date  DATE NOT NULL,
    probability DOUBLE NOT NULL,
    percentile  DOUBLE NOT NULL,
    PRIMARY KEY (cve_id, score_date)
);

-- ============================================================================
-- ATT&CK
-- ============================================================================

CREATE TABLE IF NOT EXISTS attack_object (
    stix_id         VARCHAR PRIMARY KEY,
    attack_id       VARCHAR,
    object_type     VARCHAR NOT NULL,   -- attack-pattern | course-of-action | intrusion-set | ...
    name            VARCHAR,
    description     VARCHAR,
    domain          VARCHAR,
    tactics         VARCHAR,            -- comma-joined kill-chain phases
    platforms       VARCHAR,
    is_subtechnique BOOLEAN,
    revoked         BOOLEAN,
    deprecated      BOOLEAN,
    attack_release  VARCHAR,
    source_run_id   BIGINT,
    retrieved_at    TIMESTAMP
);

CREATE TABLE IF NOT EXISTS attack_relationship (
    source_ref          VARCHAR NOT NULL,
    relationship_type   VARCHAR NOT NULL,
    target_ref          VARCHAR NOT NULL,
    description         VARCHAR,
    attack_release      VARCHAR,
    PRIMARY KEY (source_ref, relationship_type, target_ref)
);

-- Derived CVE -> technique mappings. Always carries evidence and confidence so
-- the critic can downgrade or drop speculative links (design doc §7.4).
CREATE TABLE IF NOT EXISTS attack_mapping (
    cve_id      VARCHAR NOT NULL,
    attack_id   VARCHAR NOT NULL,
    confidence  DOUBLE NOT NULL,
    basis       VARCHAR NOT NULL,   -- cwe-bridge | kev-action | manual
    evidence    VARCHAR,
    PRIMARY KEY (cve_id, attack_id, basis)
);

-- ============================================================================
-- Synthetic enterprise inventory
-- ============================================================================

CREATE TABLE IF NOT EXISTS applications (
    application_id          VARCHAR PRIMARY KEY,
    name                    VARCHAR NOT NULL,
    business_service        VARCHAR,
    tier                    INTEGER,            -- 1 = most critical
    owner_team              VARCHAR,
    owner_email             VARCHAR,
    revenue_impact_band     VARCHAR,
    external_customer_facing BOOLEAN,
    data_classification     VARCHAR
);

CREATE TABLE IF NOT EXISTS assets (
    asset_id            VARCHAR PRIMARY KEY,
    hostname            VARCHAR NOT NULL,
    application_id      VARCHAR,
    environment         VARCHAR,        -- production | staging | development
    region              VARCHAR,
    internet_facing     BOOLEAN,
    business_criticality VARCHAR,       -- critical | high | medium | low
    data_classification VARCHAR,        -- restricted | confidential | internal | public
    os_platform         VARCHAR,
    owner               VARCHAR,
    last_patch_date     DATE,
    compensating_controls VARCHAR
);

CREATE TABLE IF NOT EXISTS software_inventory (
    sw_id               BIGINT PRIMARY KEY,
    asset_id            VARCHAR,
    application_id      VARCHAR,
    ecosystem           VARCHAR,        -- PyPI | npm | Maven | Go | OS | platform
    vendor              VARCHAR,
    product             VARCHAR NOT NULL,
    version             VARCHAR NOT NULL,
    purl                VARCHAR,        -- canonical key for OSV matching
    cpe23               VARCHAR,        -- canonical key for NVD matching
    purl_confidence     DOUBLE,
    cpe23_confidence    DOUBLE,
    discovered_at       TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dependencies (
    application_id      VARCHAR NOT NULL,
    ecosystem           VARCHAR NOT NULL,
    package             VARCHAR NOT NULL,
    version             VARCHAR NOT NULL,
    purl                VARCHAR,
    direct_or_transitive VARCHAR,
    PRIMARY KEY (application_id, ecosystem, package, version)
);

CREATE TABLE IF NOT EXISTS vulnerability_finding (
    finding_id          BIGINT PRIMARY KEY,
    asset_id            VARCHAR,
    application_id      VARCHAR,
    sw_id               BIGINT,
    cve_id              VARCHAR,
    advisory_id         VARCHAR,
    match_path          VARCHAR NOT NULL,   -- cpe | purl | alias
    match_confidence    DOUBLE NOT NULL,
    version_verdict     VARCHAR NOT NULL,   -- affected | not_affected | unknown
    fixed_version       VARCHAR,
    detected_at         TIMESTAMP,
    first_seen          TIMESTAMP,
    last_seen           TIMESTAMP,
    status              VARCHAR,            -- open | remediated | risk_accepted
    scanner_confidence  DOUBLE,
    -- How many raw advisory/range matches collapsed into this finding, and
    -- which sources agreed. One asset plus one vulnerability is one row;
    -- without that, the same issue is counted several times and the two
    -- rows can disagree on the upgrade target.
    evidence_count      INTEGER,
    match_paths         VARCHAR
);

CREATE TABLE IF NOT EXISTS risk_acceptances (
    acceptance_id       VARCHAR PRIMARY KEY,
    finding_id          BIGINT,
    cve_id              VARCHAR,
    application_id      VARCHAR,
    approver            VARCHAR,
    reason              VARCHAR,
    approved_date       DATE,
    expiration_date     DATE,
    compensating_control VARCHAR
);

-- ============================================================================
-- Deterministic scoring output (gold)
-- ============================================================================

CREATE TABLE IF NOT EXISTS finding_score (
    finding_id          BIGINT PRIMARY KEY,
    model_version       VARCHAR NOT NULL,
    score               DOUBLE NOT NULL,
    cvss_base           DOUBLE,
    cvss_norm           DOUBLE,
    epss                DOUBLE,
    epss_percentile     DOUBLE,
    kev_flag            INTEGER,
    criticality         DOUBLE,
    exposure            INTEGER,
    sensitivity         DOUBLE,
    weights             {{JSON}},
    contributions       {{JSON}},
    sla_days            INTEGER,
    sla_due_date        DATE,
    sla_breached        BOOLEAN,
    age_days            INTEGER,
    scored_at           TIMESTAMP NOT NULL
);

-- ============================================================================
-- Knowledge base (RAG)
-- ============================================================================

CREATE TABLE IF NOT EXISTS kb_document (
    doc_id          VARCHAR PRIMARY KEY,
    title           VARCHAR NOT NULL,
    source_url      VARCHAR,
    publisher       VARCHAR,
    doc_type        VARCHAR,        -- policy | standard | runbook | guidance | advisory
    authority       VARCHAR,        -- internal | nist | owasp | vendor
    trust_tag       VARCHAR,
    policy_version  VARCHAR,
    effective_date  DATE,
    superseded_by   VARCHAR,
    visibility      VARCHAR,
    control_family  VARCHAR,
    product         VARCHAR,
    sha256          VARCHAR,
    source_path     VARCHAR,
    ingested_at     TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS kb_chunk (
    chunk_id        VARCHAR PRIMARY KEY,
    doc_id          VARCHAR NOT NULL,
    ordinal         INTEGER NOT NULL,
    section_path    VARCHAR,
    heading         VARCHAR,
    text            VARCHAR NOT NULL,
    token_count     INTEGER
);

-- Kept separate so the vector store can be swapped for pgvector/Qdrant
-- without touching chunk text or metadata.
CREATE TABLE IF NOT EXISTS kb_chunk_embedding (
    chunk_id    VARCHAR PRIMARY KEY,
    dim         INTEGER NOT NULL,
    provider    VARCHAR NOT NULL,
    embedding   {{VECTOR}} NOT NULL
);

-- ============================================================================
-- Observability
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_run (
    run_id          VARCHAR PRIMARY KEY,
    question        VARCHAR NOT NULL,
    user_role       VARCHAR,
    response_mode   VARCHAR,
    started_at      TIMESTAMP NOT NULL,
    completed_at    TIMESTAMP,
    status          VARCHAR NOT NULL,
    replan_count    INTEGER DEFAULT 0,
    total_input_tokens  BIGINT DEFAULT 0,
    total_output_tokens BIGINT DEFAULT 0,
    latency_ms      BIGINT,
    model           VARCHAR,
    final_answer    {{JSON}},
    error           VARCHAR
);

CREATE TABLE IF NOT EXISTS agent_span (
    span_id         VARCHAR PRIMARY KEY,
    run_id          VARCHAR NOT NULL,
    node            VARCHAR NOT NULL,
    seq             INTEGER NOT NULL,
    started_at      TIMESTAMP NOT NULL,
    completed_at    TIMESTAMP,
    latency_ms      BIGINT,
    status          VARCHAR,
    input_tokens    BIGINT,
    output_tokens   BIGINT,
    detail          {{JSON}},
    error           VARCHAR
);

CREATE TABLE IF NOT EXISTS tool_call (
    call_id     VARCHAR PRIMARY KEY,
    run_id      VARCHAR NOT NULL,
    span_id     VARCHAR,
    tool_name   VARCHAR NOT NULL,
    server      VARCHAR,
    arguments   {{JSON}},
    row_count   INTEGER,
    latency_ms  BIGINT,
    status      VARCHAR,
    error       VARCHAR,
    called_at   TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS eval_result (
    eval_id     VARCHAR PRIMARY KEY,
    suite       VARCHAR NOT NULL,
    case_id     VARCHAR NOT NULL,
    metric      VARCHAR NOT NULL,
    value       DOUBLE,
    passed      BOOLEAN,
    detail      {{JSON}},
    run_at      TIMESTAMP NOT NULL
);
