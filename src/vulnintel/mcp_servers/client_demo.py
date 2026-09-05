"""MCP client demonstration.

Spawns each server as a real subprocess, speaks the protocol over stdio,
lists the advertised tools and calls a few. This is what proves the boundary
is a genuine MCP boundary rather than a Python import wearing a costume —
which is the difference between "uses MCP" and "mentions MCP" on a CV.

    python -m vulnintel.mcp_servers.client_demo
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

REPO_ROOT = Path(__file__).resolve().parents[3]

SERVERS = {
    "security-intel-mcp": "vulnintel.mcp_servers.security_intel.server",
    "enterprise-assets-mcp": "vulnintel.mcp_servers.enterprise_assets.server",
}


def _env() -> dict[str, str]:
    env = dict(os.environ)
    src = str(REPO_ROOT / "src")
    env["PYTHONPATH"] = f"{src}:{env['PYTHONPATH']}" if env.get("PYTHONPATH") else src
    return env


async def probe(server_label: str, module: str, calls: list[tuple[str, dict[str, Any]]]):
    params = StdioServerParameters(command=sys.executable, args=["-m", module], env=_env())

    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        init = await session.initialize()
        info = getattr(init, "server_info", None) or getattr(init, "serverInfo", None)
        print(f"\n=== {server_label} ===")
        print(f"connected to: {info.name} v{info.version}")

        listing = await session.list_tools()
        print(f"advertises {len(listing.tools)} tools:")
        for tool in listing.tools:
            schema = getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", None)
            required = (schema or {}).get("required", [])
            first_line = (tool.description or "").strip().splitlines()[0]
            print(f"  - {tool.name}({', '.join(required)}) — {first_line}")

        for tool_name, arguments in calls:
            result = await session.call_tool(tool_name, arguments)
            payload = _payload(result)
            print(f"\n  call {tool_name}({json.dumps(arguments)}) ->")
            print("   ", _summarise(payload))


def _payload(result: Any) -> Any:
    structured = getattr(result, "structured_content", None) or getattr(
        result, "structuredContent", None
    )
    if structured:
        return structured
    for block in getattr(result, "content", []) or []:
        text = getattr(block, "text", None)
        if text:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return text
    return None


def _summarise(payload: Any, limit: int = 320) -> str:
    text = json.dumps(payload, default=str)
    return text if len(text) <= limit else text[:limit] + f" ... [{len(text)} chars total]"


async def main() -> None:
    await probe(
        "security-intel-mcp",
        SERVERS["security-intel-mcp"],
        [
            ("get_feed_freshness", {}),
            ("get_kev_status", {"cve_ids": ["CVE-2021-44228", "CVE-2014-0160"]}),
            (
                "get_package_advisories",
                {"ecosystem": "PyPI", "package": "django", "version": "3.2.18"},
            ),
        ],
    )
    await probe(
        "enterprise-assets-mcp",
        SERVERS["enterprise-assets-mcp"],
        [
            ("get_inventory_summary", {}),
            ("find_assets_by_software", {"product": "django", "limit": 3}),
            ("search_assets", {"tier": 1, "internet_facing": True, "limit": 3}),
        ],
    )
    print("\nBoth servers responded over stdio MCP.")


if __name__ == "__main__":
    asyncio.run(main())
