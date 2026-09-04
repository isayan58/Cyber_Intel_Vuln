-- Gold serving views.
--
-- Deliberately thin: they join and filter, they never compute the risk score.
-- The score and its components come from finding_score, written by
-- risk/scoring.py, so the number an analyst sees is the number that was
-- actually computed and stored — not one a view re-derived with inline
-- weights that could drift from the scorer.
--
-- Written in the intersection of DuckDB and PostgreSQL SQL: window functions
-- and CASE only, no DISTINCT ON, no array_position, no date arithmetic
-- (age/SLA days are precomputed by the scorer).

-- Provider precedence for CVSS: prefer the newest spec version, then a
-- Primary metric, then NVD itself. Every underlying row is still queryable
-- so a vendor/NVD disagreement can be surfaced rather than hidden.
CREATE OR REPLACE VIEW v_cve_cvss_effective AS
SELECT cve_id, cvss_version, provider, metric_type, vector_string, base_score, base_severity
FROM (
    SELECT
        c.*,
        row_number() OVER (
            PARTITION BY c.cve_id
            ORDER BY
                CASE c.cvss_version
                    WHEN '4.0' THEN 0 WHEN '3.1' THEN 1
                    WHEN '3.0' THEN 2 WHEN '2.0' THEN 3 ELSE 4 END,
                CASE WHEN c.metric_type = 'Primary' THEN 0 ELSE 1 END,
                CASE WHEN c.provider = 'nvd@nist.gov' THEN 0 ELSE 1 END,
                c.provider
        ) AS rn
    FROM cve_cvss c
) ranked
WHERE rn = 1;

-- Where NVD and another provider disagree by more than 2.0 CVSS points.
-- The critic agent reads this to flag contradictions (design doc §7.7).
CREATE OR REPLACE VIEW v_cvss_disagreement AS
SELECT
    a.cve_id,
    a.provider          AS provider_a,
    a.base_score        AS score_a,
    b.provider          AS provider_b,
    b.base_score        AS score_b,
    abs(a.base_score - b.base_score) AS delta
FROM cve_cvss a
JOIN cve_cvss b
  ON a.cve_id = b.cve_id
 AND a.provider < b.provider
WHERE a.base_score IS NOT NULL
  AND b.base_score IS NOT NULL
  AND abs(a.base_score - b.base_score) > 2.0;

-- The workhorse join: finding + asset + application + vulnerability + score.
CREATE OR REPLACE VIEW v_finding_enriched AS
SELECT
    f.finding_id,
    f.cve_id,
    f.advisory_id,
    f.match_path,
    f.match_confidence,
    f.version_verdict,
    f.fixed_version,
    f.status,
    f.detected_at,
    f.first_seen,
    f.last_seen,

    a.asset_id,
    a.hostname,
    a.environment,
    a.internet_facing,
    a.business_criticality,
    a.data_classification,
    a.os_platform,
    a.owner,
    a.last_patch_date,
    a.compensating_controls,

    app.application_id,
    app.name                     AS application_name,
    app.business_service,
    app.tier,
    app.owner_team,
    app.revenue_impact_band,
    app.external_customer_facing,

    sw.ecosystem,
    sw.vendor,
    sw.product,
    sw.version                   AS installed_version,
    sw.purl,
    sw.cpe23,

    c.description                AS cve_description,
    c.published_at               AS cve_published_at,
    c.last_modified_at           AS cve_last_modified_at,
    eff.base_score               AS cvss_base,
    eff.base_severity            AS cvss_severity,
    eff.cvss_version,
    eff.vector_string            AS cvss_vector,
    eff.provider                 AS cvss_provider,

    e.probability                AS epss,
    e.percentile                 AS epss_percentile,
    e.score_date                 AS epss_score_date,

    CASE WHEN k.cve_id IS NULL THEN FALSE ELSE TRUE END AS kev_listed,
    k.date_added                 AS kev_date_added,
    k.due_date                   AS kev_due_date,
    k.known_ransomware_use,
    k.required_action            AS kev_required_action,

    s.score,
    s.model_version,
    s.cvss_norm,
    s.kev_flag,
    s.criticality,
    s.exposure,
    s.sensitivity,
    s.contributions,
    s.weights,
    s.sla_days,
    s.sla_due_date,
    s.sla_breached,
    s.age_days,

    CASE WHEN ra.acceptance_id IS NULL THEN FALSE ELSE TRUE END AS risk_accepted,
    ra.expiration_date           AS risk_acceptance_expires
FROM vulnerability_finding f
LEFT JOIN assets a                 ON a.asset_id = f.asset_id
LEFT JOIN applications app         ON app.application_id = COALESCE(f.application_id, a.application_id)
LEFT JOIN software_inventory sw    ON sw.sw_id = f.sw_id
LEFT JOIN cve c                    ON c.cve_id = f.cve_id
LEFT JOIN v_cve_cvss_effective eff ON eff.cve_id = f.cve_id
LEFT JOIN epss_current e           ON e.cve_id = f.cve_id
LEFT JOIN kev k                    ON k.cve_id = f.cve_id AND k.valid_to IS NULL
LEFT JOIN finding_score s          ON s.finding_id = f.finding_id
LEFT JOIN risk_acceptances ra      ON ra.finding_id = f.finding_id;

-- One row per CVE with its enterprise blast radius. This is the executive view:
-- it answers "how much of our estate does this touch", not "how bad is the CVE".
CREATE OR REPLACE VIEW v_executive_top_risks AS
SELECT
    cve_id,
    max(score)                    AS top_score,
    count(*)                      AS finding_count,
    count(DISTINCT asset_id)      AS asset_count,
    count(DISTINCT application_id) AS application_count,
    max(cvss_base)                AS cvss_base,
    max(epss)                     AS epss,
    max(CASE WHEN kev_listed THEN 1 ELSE 0 END)            AS kev_flag,
    max(CASE WHEN internet_facing THEN 1 ELSE 0 END)       AS any_internet_facing,
    min(CASE WHEN tier IS NULL THEN 99 ELSE tier END)      AS best_tier,
    sum(CASE WHEN sla_breached THEN 1 ELSE 0 END)          AS breached_count,
    min(sla_due_date)             AS earliest_due_date,
    max(cve_description)          AS cve_description
FROM v_finding_enriched
WHERE version_verdict = 'affected'
  AND status <> 'remediated'
  AND cve_id IS NOT NULL
GROUP BY cve_id;

CREATE OR REPLACE VIEW v_sla_breach AS
SELECT *
FROM v_finding_enriched
WHERE sla_breached = TRUE
  AND status <> 'remediated'
  AND risk_accepted = FALSE;

CREATE OR REPLACE VIEW v_app_risk_summary AS
SELECT
    application_id,
    application_name,
    business_service,
    tier,
    owner_team,
    external_customer_facing,
    count(*)                                          AS open_findings,
    count(DISTINCT cve_id)                            AS distinct_cves,
    max(score)                                        AS max_score,
    avg(score)                                        AS avg_score,
    sum(CASE WHEN kev_listed THEN 1 ELSE 0 END)       AS kev_findings,
    sum(CASE WHEN sla_breached THEN 1 ELSE 0 END)     AS breached_findings,
    sum(CASE WHEN internet_facing THEN 1 ELSE 0 END)  AS internet_facing_findings
FROM v_finding_enriched
WHERE version_verdict = 'affected'
  AND status <> 'remediated'
  AND application_id IS NOT NULL
GROUP BY application_id, application_name, business_service, tier, owner_team,
         external_customer_facing;

-- Findings the matcher could not resolve. Surfacing these is what keeps the
-- platform honest: "we do not know" is an answer, not a gap to paper over.
CREATE OR REPLACE VIEW v_unknown_verdicts AS
SELECT
    f.finding_id, f.cve_id, f.advisory_id, f.match_path, f.match_confidence,
    sw.ecosystem, sw.product, sw.version AS installed_version,
    a.hostname, a.environment, a.business_criticality
FROM vulnerability_finding f
LEFT JOIN software_inventory sw ON sw.sw_id = f.sw_id
LEFT JOIN assets a              ON a.asset_id = f.asset_id
WHERE f.version_verdict = 'unknown';

-- Feed freshness, for the stale-intelligence check in §7.3.
CREATE OR REPLACE VIEW v_feed_freshness AS
SELECT
    source,
    max(completed_at)                                        AS last_success,
    sum(CASE WHEN status = 'failed' THEN 1 ELSE 0 END)       AS failure_count,
    count(*)                                                 AS run_count
FROM ingest_run
GROUP BY source;
