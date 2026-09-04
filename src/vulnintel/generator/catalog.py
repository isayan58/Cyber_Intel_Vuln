"""Software catalogue used to build the synthetic estate.

Real product and package names with plausible version ladders. Using real
names matters: it means the generated inventory actually joins to real OSV and
NVD data, so "which of our Python services use a vulnerable Django?" resolves
against genuine advisories rather than a closed synthetic loop.

The inventory itself — hostnames, owners, criticality, exposure — is entirely
fabricated. Only the software names are real.
"""

from __future__ import annotations

# (ecosystem, vendor, package, [versions oldest -> newest])
PACKAGE_CATALOG: list[tuple[str, str, str, list[str]]] = [
    # --- Python ---------------------------------------------------------------
    ("PyPI", "djangoproject", "django", ["3.2.18", "4.1.7", "4.2.3", "4.2.11", "5.0.2", "5.1.1"]),
    ("PyPI", "palletsprojects", "flask", ["2.0.3", "2.2.2", "2.3.2", "3.0.0", "3.0.3"]),
    ("PyPI", "encode", "starlette", ["0.25.0", "0.27.0", "0.35.1", "0.37.2"]),
    ("PyPI", "python-pillow", "pillow", ["9.0.1", "9.5.0", "10.0.1", "10.2.0", "10.3.0"]),
    ("PyPI", "psf", "requests", ["2.25.1", "2.28.2", "2.31.0", "2.32.3"]),
    ("PyPI", "yaml", "pyyaml", ["5.4.1", "6.0", "6.0.1", "6.0.2"]),
    ("PyPI", "pyca", "cryptography", ["3.4.8", "39.0.1", "41.0.7", "42.0.5", "43.0.1"]),
    ("PyPI", "aio-libs", "aiohttp", ["3.8.1", "3.8.6", "3.9.2", "3.9.5", "3.10.5"]),
    ("PyPI", "numpy", "numpy", ["1.22.4", "1.24.3", "1.26.4", "2.0.1"]),
    ("PyPI", "sqlalchemy", "sqlalchemy", ["1.4.46", "2.0.19", "2.0.30"]),
    ("PyPI", "urllib3", "urllib3", ["1.26.12", "1.26.18", "2.0.7", "2.2.2"]),
    ("PyPI", "jinja", "jinja2", ["3.0.3", "3.1.2", "3.1.3", "3.1.4"]),
    # --- JavaScript -----------------------------------------------------------
    ("npm", "expressjs", "express", ["4.17.1", "4.18.2", "4.19.2", "4.21.0"]),
    ("npm", "axios", "axios", ["0.21.1", "0.27.2", "1.6.0", "1.6.8", "1.7.7"]),
    ("npm", "lodash", "lodash", ["4.17.19", "4.17.21"]),
    ("npm", "webpack", "webpack", ["5.72.0", "5.88.2", "5.94.0"]),
    ("npm", "vercel", "next", ["12.3.4", "13.4.12", "14.1.1", "14.2.10"]),
    ("npm", "facebook", "react", ["17.0.2", "18.2.0", "18.3.1"]),
    ("npm", "auth0", "jsonwebtoken", ["8.5.1", "9.0.0", "9.0.2"]),
    ("npm", "socketio", "socket.io", ["4.4.1", "4.6.1", "4.7.5"]),
    # --- Java -----------------------------------------------------------------
    ("Maven", "apache", "log4j-core", ["2.14.1", "2.17.1", "2.20.0", "2.23.1"]),
    ("Maven", "springframework", "spring-core", ["5.3.20", "5.3.31", "6.0.13", "6.1.6"]),
    ("Maven", "springframework", "spring-boot", ["2.6.6", "2.7.14", "3.1.5", "3.2.5"]),
    ("Maven", "fasterxml", "jackson-databind", ["2.12.6", "2.13.4", "2.15.3", "2.17.1"]),
    ("Maven", "apache", "tomcat-embed-core", ["9.0.60", "9.0.83", "10.1.16", "10.1.25"]),
    ("Maven", "apache", "commons-text", ["1.9", "1.10.0", "1.11.0", "1.12.0"]),
    # --- Go -------------------------------------------------------------------
    ("Go", "golang", "golang.org/x/net", ["0.7.0", "0.17.0", "0.23.0", "0.28.0"]),
    ("Go", "gin-gonic", "github.com/gin-gonic/gin", ["1.7.7", "1.9.1", "1.10.0"]),
    ("Go", "prometheus", "github.com/prometheus/client_golang", ["1.12.2", "1.16.0", "1.19.1"]),
]

# (vendor, product, [versions]) — platform software matched via CPE, not purl.
PLATFORM_CATALOG: list[tuple[str, str, list[str]]] = [
    ("openbsd", "openssh", ["8.2p1", "8.9p1", "9.3p1", "9.6p1", "9.8p1"]),
    ("openssl", "openssl", ["1.1.1n", "3.0.8", "3.0.13", "3.2.1", "3.3.1"]),
    ("nginx", "nginx", ["1.18.0", "1.22.1", "1.24.0", "1.26.1"]),
    ("apache", "http_server", ["2.4.52", "2.4.57", "2.4.59", "2.4.62"]),
    ("postgresql", "postgresql", ["13.10", "14.9", "15.5", "16.3"]),
    ("redis", "redis", ["6.2.7", "7.0.12", "7.2.4", "7.4.0"]),
    ("mongodb", "mongodb", ["5.0.14", "6.0.8", "7.0.5"]),
    ("elastic", "elasticsearch", ["7.17.9", "8.9.1", "8.13.4"]),
    ("docker", "docker", ["20.10.21", "24.0.7", "25.0.5", "26.1.4"]),
    ("hashicorp", "consul", ["1.12.4", "1.15.4", "1.18.1"]),
    ("kubernetes", "kubernetes", ["1.24.9", "1.27.8", "1.29.4"]),
    ("canonical", "ubuntu_linux", ["20.04", "22.04", "24.04"]),
]

BUSINESS_SERVICES = [
    ("Payments", 1, "critical", True),
    ("Customer Identity", 1, "critical", True),
    ("Core Banking Ledger", 1, "critical", False),
    ("Fraud Detection", 1, "critical", False),
    ("Customer Portal", 2, "high", True),
    ("Mobile Banking API", 1, "critical", True),
    ("Partner Integrations", 2, "high", True),
    ("Data Platform", 2, "high", False),
    ("Marketing Site", 3, "medium", True),
    ("Internal HR Tools", 3, "medium", False),
    ("Reporting & BI", 3, "medium", False),
    ("Developer Tooling", 4, "low", False),
    ("Document Archive", 3, "medium", False),
    ("Notification Service", 2, "high", False),
]

OWNER_TEAMS = [
    "payments-platform",
    "identity-engineering",
    "core-banking",
    "risk-and-fraud",
    "digital-channels",
    "data-engineering",
    "platform-infrastructure",
    "corporate-it",
    "developer-experience",
]

REGIONS = ["eu-west-1", "eu-central-1", "us-east-1", "us-west-2", "ap-southeast-1"]

OS_PLATFORMS = [
    "Ubuntu 22.04 LTS",
    "Ubuntu 24.04 LTS",
    "Red Hat Enterprise Linux 9",
    "Amazon Linux 2023",
    "Windows Server 2022",
    "Container (distroless)",
]

COMPENSATING_CONTROLS = [
    "WAF rule deployed",
    "network segmentation enforced",
    "service behind mTLS gateway",
    "runtime EDR blocking policy",
    "read-only filesystem",
]
