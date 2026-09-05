"""Synthetic enterprise inventory generator.

Design doc §10.2: *generate the inventory with controlled distributions rather
than pure randomness*. Everything here is driven by one seed, so the same
command always produces the same estate — which is what makes the golden
evaluation scenarios meaningful and the demos repeatable.

Controlled properties, not left to chance:
  * a small, fixed number of Tier-1 applications
  * ~12% of assets internet-facing, concentrated in production
  * a deliberate tail of assets with old ``last_patch_date`` values
  * a known subset pinned to *older* package versions, so real advisories
    actually match once feeds are loaded (see ``plant_scenarios``)
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

from faker import Faker

from vulnintel.config import get_settings
from vulnintel.data.db import Database, get_db
from vulnintel.generator.catalog import (
    BUSINESS_SERVICES,
    COMPENSATING_CONTROLS,
    OS_PLATFORMS,
    OWNER_TEAMS,
    PACKAGE_CATALOG,
    PLATFORM_CATALOG,
    REGIONS,
)
from vulnintel.logging_setup import get_logger
from vulnintel.risk.matching import build_cpe23, build_purl
from vulnintel.risk.versions import compare

log = get_logger(__name__)

ENVIRONMENTS = [("production", 0.55), ("staging", 0.20), ("development", 0.25)]
DATA_CLASSES = [
    ("restricted", 0.12),
    ("confidential", 0.28),
    ("internal", 0.45),
    ("public", 0.15),
]


@dataclass
class GenerationSummary:
    applications: int = 0
    assets: int = 0
    software: int = 0
    dependencies: int = 0
    risk_acceptances: int = 0
    seed: int = 0

    def __str__(self) -> str:
        return (
            f"seed={self.seed} applications={self.applications} assets={self.assets} "
            f"software={self.software} dependencies={self.dependencies} "
            f"risk_acceptances={self.risk_acceptances}"
        )


class SyntheticGenerator:
    def __init__(
        self,
        db: Database | None = None,
        seed: int | None = None,
        asset_count: int | None = None,
        application_count: int | None = None,
    ) -> None:
        settings = get_settings()
        self.db = db or get_db()
        self.seed = seed if seed is not None else settings.synthetic_seed
        self.asset_count = asset_count or settings.synthetic_assets
        self.application_count = application_count or settings.synthetic_applications
        self.rng = random.Random(self.seed)
        self.faker = Faker()
        Faker.seed(self.seed)
        self.today = datetime.now(UTC).date()

    # -- entry point ----------------------------------------------------------

    def generate(self) -> GenerationSummary:
        log.info(
            "generating synthetic estate (seed=%d, assets=%d, apps=%d)",
            self.seed,
            self.asset_count,
            self.application_count,
        )
        self._clear()

        applications = self._applications()
        assets = self._assets(applications)
        software, dependencies = self._software(applications, assets)
        acceptances = self._risk_acceptances(applications)

        self.db.insert_many("applications", applications)
        self.db.insert_many("assets", assets)
        self.db.insert_many("software_inventory", software)
        self.db.insert_many("dependencies", dependencies)
        self.db.insert_many("risk_acceptances", acceptances)

        summary = GenerationSummary(
            applications=len(applications),
            assets=len(assets),
            software=len(software),
            dependencies=len(dependencies),
            risk_acceptances=len(acceptances),
            seed=self.seed,
        )
        log.info("generated %s", summary)
        return summary

    def _clear(self) -> None:
        for table in (
            "risk_acceptances",
            "dependencies",
            "software_inventory",
            "assets",
            "applications",
        ):
            self.db.execute(f"DELETE FROM {table}")

    # -- applications ---------------------------------------------------------

    def _applications(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for index in range(self.application_count):
            service, tier, _criticality, customer_facing = BUSINESS_SERVICES[
                index % len(BUSINESS_SERVICES)
            ]
            suffix = index // len(BUSINESS_SERVICES)
            slug = service.lower().replace(" ", "-").replace("&", "and")
            name = slug if suffix == 0 else f"{slug}-{suffix + 1}"

            # Tier drifts down for the duplicated instances so Tier-1 stays rare.
            effective_tier = tier if suffix == 0 else min(4, tier + 1)
            rows.append(
                {
                    "application_id": f"APP-{index + 1:04d}",
                    "name": name,
                    "business_service": service,
                    "tier": effective_tier,
                    "owner_team": OWNER_TEAMS[index % len(OWNER_TEAMS)],
                    "owner_email": f"{OWNER_TEAMS[index % len(OWNER_TEAMS)]}@example.internal",
                    "revenue_impact_band": self._revenue_band(effective_tier),
                    "external_customer_facing": customer_facing and suffix == 0,
                    "data_classification": self._data_class_for_tier(effective_tier),
                }
            )
        return rows

    @staticmethod
    def _revenue_band(tier: int) -> str:
        return {1: ">10M", 2: "1M-10M", 3: "100k-1M", 4: "<100k"}.get(tier, "<100k")

    def _data_class_for_tier(self, tier: int) -> str:
        if tier == 1:
            return self.rng.choice(["restricted", "restricted", "confidential"])
        if tier == 2:
            return self.rng.choice(["confidential", "confidential", "internal"])
        return self.rng.choice(["internal", "internal", "public"])

    # -- assets ---------------------------------------------------------------

    def _assets(self, applications: list[dict[str, Any]]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for index in range(self.asset_count):
            app = applications[index % len(applications)]
            environment = self._weighted(ENVIRONMENTS)

            # Exposure is concentrated in production on customer-facing apps.
            if environment == "production" and app["external_customer_facing"]:
                internet_facing = self.rng.random() < 0.45
            elif environment == "production":
                internet_facing = self.rng.random() < 0.08
            else:
                internet_facing = self.rng.random() < 0.02

            criticality = self._criticality(app["tier"], environment)
            rows.append(
                {
                    "asset_id": f"AST-{index + 1:06d}",
                    "hostname": f"{app['name']}-{environment[:4]}-{index % 97:02d}",
                    "application_id": app["application_id"],
                    "environment": environment,
                    "region": self.rng.choice(REGIONS),
                    "internet_facing": internet_facing,
                    "business_criticality": criticality,
                    "data_classification": (
                        app["data_classification"]
                        if environment == "production"
                        else self._weighted(DATA_CLASSES)
                    ),
                    "os_platform": self.rng.choice(OS_PLATFORMS),
                    "owner": app["owner_team"],
                    "last_patch_date": self._patch_date(environment),
                    "compensating_controls": (
                        self.rng.choice(COMPENSATING_CONTROLS)
                        if internet_facing and self.rng.random() < 0.35
                        else None
                    ),
                }
            )
        return rows

    def _criticality(self, tier: int, environment: str) -> str:
        if environment != "production":
            return "low" if tier >= 3 else "medium"
        return {1: "critical", 2: "high", 3: "medium"}.get(tier, "low")

    def _patch_date(self, environment: str) -> date:
        """A deliberate long tail — some assets are badly out of date."""
        roll = self.rng.random()
        if roll < 0.55:
            days = self.rng.randint(1, 30)
        elif roll < 0.80:
            days = self.rng.randint(31, 90)
        elif roll < 0.94:
            days = self.rng.randint(91, 200)
        else:
            days = self.rng.randint(201, 640)
        if environment != "production":
            days = int(days * 1.4)
        return self.today - timedelta(days=days)

    # -- software -------------------------------------------------------------

    def _software(
        self, applications: list[dict[str, Any]], assets: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        software: list[dict[str, Any]] = []
        dependencies: list[dict[str, Any]] = []
        sw_id = 1
        now = datetime.now(UTC).replace(tzinfo=None)

        # Each application picks a stable language stack.
        app_stacks: dict[str, list[tuple[str, str, str, list[str]]]] = {}
        for app in applications:
            ecosystem = self.rng.choice(["PyPI", "npm", "Maven", "Go"])
            pool = [p for p in PACKAGE_CATALOG if p[0] == ecosystem]
            picked = self.rng.sample(pool, k=min(len(pool), self.rng.randint(4, 8)))
            app_stacks[app["application_id"]] = picked

        # Application-level dependency manifest.
        for app in applications:
            for ecosystem, _vendor, package, versions in app_stacks[app["application_id"]]:
                version = self._skewed_version(versions)
                dependencies.append(
                    {
                        "application_id": app["application_id"],
                        "ecosystem": ecosystem,
                        "package": package,
                        "version": version,
                        "purl": build_purl(ecosystem, package, version),
                        "direct_or_transitive": (
                            "direct" if self.rng.random() < 0.6 else "transitive"
                        ),
                    }
                )

        dep_index: dict[str, list[dict[str, Any]]] = {}
        for dep in dependencies:
            dep_index.setdefault(dep["application_id"], []).append(dep)

        for asset in assets:
            app_id = asset["application_id"]

            # Language packages, inherited from the application manifest.
            for dep in dep_index.get(app_id, []):
                software.append(
                    {
                        "sw_id": sw_id,
                        "asset_id": asset["asset_id"],
                        "application_id": app_id,
                        "ecosystem": dep["ecosystem"],
                        "vendor": None,
                        "product": dep["package"],
                        "version": dep["version"],
                        "purl": dep["purl"],
                        "cpe23": None,
                        "purl_confidence": 1.0,  # from a lockfile
                        "cpe23_confidence": None,
                        "discovered_at": now,
                    }
                )
                sw_id += 1

            # Platform software, matched by CPE with lower confidence.
            for vendor, product, versions in self.rng.sample(
                PLATFORM_CATALOG, k=self.rng.randint(2, 5)
            ):
                version = self._skewed_version(versions)
                software.append(
                    {
                        "sw_id": sw_id,
                        "asset_id": asset["asset_id"],
                        "application_id": app_id,
                        "ecosystem": "platform",
                        "vendor": vendor,
                        "product": product,
                        "version": version,
                        "purl": None,
                        "cpe23": build_cpe23(vendor, product, version),
                        "purl_confidence": None,
                        # Vendor/product mapping is a heuristic, so never 1.0.
                        "cpe23_confidence": 0.8,
                        "discovered_at": now,
                    }
                )
                sw_id += 1

        return software, dependencies

    def _skewed_version(self, versions: list[str]) -> str:
        """Skew towards older releases so the estate has genuine exposure.

        ~35% of installs sit on the two oldest versions in the ladder. That is
        what makes real advisories match; a fully patched synthetic estate
        would produce an empty and rather boring demo.
        """
        roll = self.rng.random()
        if roll < 0.20:
            return versions[0]
        if roll < 0.35:
            return versions[min(1, len(versions) - 1)]
        if roll < 0.70:
            return versions[len(versions) // 2]
        return versions[-1]

    # -- risk acceptances -----------------------------------------------------

    def _risk_acceptances(self, applications: list[dict[str, Any]]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for index, app in enumerate(applications):
            if self.rng.random() > 0.08:
                continue
            approved = self.today - timedelta(days=self.rng.randint(10, 200))
            rows.append(
                {
                    "acceptance_id": f"RA-{index + 1:04d}",
                    "finding_id": None,
                    "cve_id": None,
                    "application_id": app["application_id"],
                    "approver": self.faker.name(),
                    "reason": self.rng.choice(
                        [
                            "Vendor fix pending; compensating control in place",
                            "Legacy component scheduled for decommission",
                            "Not reachable from untrusted networks",
                            "Business change freeze until quarter end",
                        ]
                    ),
                    "approved_date": approved,
                    "expiration_date": approved + timedelta(days=self.rng.choice([90, 180, 365])),
                    "compensating_control": self.rng.choice(COMPENSATING_CONTROLS),
                }
            )
        return rows

    # -- helpers --------------------------------------------------------------

    def _weighted(self, options: list[tuple[str, float]]) -> str:
        roll = self.rng.random()
        cumulative = 0.0
        for value, weight in options:
            cumulative += weight
            if roll <= cumulative:
                return value
        return options[-1][0]


def plant_scenarios(db: Database | None = None, seed: int | None = None) -> dict[str, int]:
    """Guarantee that loaded advisories actually hit the synthetic estate.

    Run *after* feeds are ingested. For a sample of advisories that have a
    concrete ``fixed`` version, this pins some inventory rows to a version
    below the fix, so the demo scenarios have known-affected assets instead of
    depending on luck. Returns a count of adjusted rows per ecosystem.
    """
    db = db or get_db()
    rng = random.Random(seed if seed is not None else get_settings().synthetic_seed)

    candidates = db.query(
        "SELECT DISTINCT aa.ecosystem, aa.package_name, aa.fixed "
        "FROM advisory_affected aa "
        "WHERE aa.fixed IS NOT NULL AND aa.fixed <> '' "
        "  AND lower(aa.package_name) IN ("
        "     SELECT DISTINCT lower(product) FROM software_inventory WHERE purl IS NOT NULL)"
    )
    if not candidates:
        log.warning("no overlapping advisories found; nothing to plant")
        return {}

    by_package: dict[tuple[str, str], list[str]] = {}
    for row in candidates:
        key = (row["ecosystem"], (row["package_name"] or "").lower())
        by_package.setdefault(key, []).append(row["fixed"])

    adjusted: dict[str, int] = {}
    for (ecosystem, package), fixes in by_package.items():
        # Target the highest fixed version so anything below it is affected.
        target = fixes[0]
        for candidate in fixes[1:]:
            try:
                if compare(candidate, target, ecosystem) > 0:
                    target = candidate
            except Exception:  # noqa: BLE001 - unparseable fix versions are skipped
                continue

        rows = db.query(
            "SELECT sw_id, version FROM software_inventory "
            "WHERE lower(product) = ? AND purl IS NOT NULL",
            [package],
        )
        if not rows:
            continue

        # Pin a deterministic ~40% sample below the fix.
        sample = [r for r in rows if rng.random() < 0.4]
        below = _version_below(target)
        if below is None:
            continue

        db.executemany(
            "UPDATE software_inventory SET version = ?, purl = ? WHERE sw_id = ?",
            [[below, build_purl(ecosystem, package, below), r["sw_id"]] for r in sample],
        )
        adjusted[f"{ecosystem}/{package}"] = len(sample)

    log.info("planted %d affected package/version scenarios", len(adjusted))
    return adjusted


def _version_below(version: str) -> str | None:
    """Nearest lower version — decrement the last numeric component."""
    parts = version.split(".")
    for index in range(len(parts) - 1, -1, -1):
        digits = "".join(ch for ch in parts[index] if ch.isdigit())
        if digits and int(digits) > 0:
            parts[index] = str(int(digits) - 1)
            return ".".join(parts[: index + 1])
    return None
