"""
SAINT recon pipeline.

basically what happens here that it get request from app.py like -> 

javascript fetch send the domain -> apps.py -> pipline
AND THEN pipline -> domain and returns a single clean JSON blob ready to hand to the LLM layer.

pipeline work is to run this this tools and giev to output to llm in the JSON
recon tools used (subfinder, httpx, naabu) against a target SO PLS FCKING INSTALL IT 


"""

import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field


DEFAULT_TIMEOUT = 90  # seconds give to each tools to run


@dataclass
class ScanResult:
    domain: str
    subdomains: list = field(default_factory=list)
    alive_hosts: list = field(default_factory=list)
    open_ports: dict = field(default_factory=dict)  # host -> [ports]
    warnings: list = field(default_factory=list)
    elapsed_seconds: float = 0.0

    def to_dict(self):
        return {
            "domain": self.domain,
            "subdomains": self.subdomains,
            "alive_hosts": self.alive_hosts,
            "open_ports": self.open_ports,
            "warnings": self.warnings,
            "elapsed_seconds": round(self.elapsed_seconds, 1),
        }


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def run_subfinder(domain: str, timeout: int = DEFAULT_TIMEOUT) -> list:
    """Passive subdomain enumeration. Returns a list of subdomain strings."""
    if not _tool_available("subfinder"):
        return []
    try:
        proc = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-json"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        subs = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                host = obj.get("host")
                if host:
                    subs.append(host)
            except json.JSONDecodeError:
                # so subfinder can be run without -json as a fallback format
                subs.append(line)
        return sorted(set(subs))
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []


def run_httpx(hosts: list, timeout: int = DEFAULT_TIMEOUT) -> list:
    """Probe which hosts are alive over HTTP(S). Returns enriched host dicts."""
    if not hosts or not _tool_available("httpx"):
        return []
    try:
        proc = subprocess.run(
            ["httpx", "-silent", "-json", "-title", "-status-code", "-tech-detect"],
            input="\n".join(hosts),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        alive = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                alive.append({
                    "host": obj.get("input") or obj.get("url"),
                    "url": obj.get("url"),
                    "status_code": obj.get("status_code"),
                    "title": obj.get("title", ""),
                    "tech": obj.get("tech", []),
                })
            except json.JSONDecodeError:
                continue
        return alive
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []


def run_naabu(hosts: list, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Fast port scan on given hosts. Returns {host: [ports]}."""
    if not hosts or not _tool_available("naabu"):
        return {}
    try:
        proc = subprocess.run(
            ["naabu", "-silent", "-json", "-top-ports", "100"],
            input="\n".join(hosts),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        ports_by_host = {}
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                host = obj.get("host")
                port = obj.get("port")
                if host and port:
                    ports_by_host.setdefault(host, []).append(port)
            except json.JSONDecodeError:
                continue
        return ports_by_host
    except subprocess.TimeoutExpired:
        return {}
    except Exception:
        return {}


def run_full_scan(domain: str) -> ScanResult:
    """Runs the full recon chain: subfinder -> httpx -> naabu."""
    start = time.time()
    result = ScanResult(domain=domain)

    if not _tool_available("subfinder"):
        result.warnings.append("subfinder not found on PATH - subdomain enum skipped")
    subs = run_subfinder(domain)
    result.subdomains = subs if subs else [domain]  # always at least scan root domain

    if not _tool_available("httpx"):
        result.warnings.append("httpx not found on PATH - liveness probing skipped")
    result.alive_hosts = run_httpx(result.subdomains)

    alive_host_names = [h["host"] for h in result.alive_hosts if h.get("host")]
    scan_targets = alive_host_names if alive_host_names else result.subdomains

    if not _tool_available("naabu"):
        result.warnings.append("naabu not found on PATH - port scan skipped")
    result.open_ports = run_naabu(scan_targets)

    result.elapsed_seconds = time.time() - start
    return result


def load_demo_data(path: str = "templates/demo_scan.json") -> dict:
    """Fallback for live demos: cached, realistic-looking scan output so the
    demo works even with no wifi / tools not installed on the venue laptop."""
    with open(path) as f:
        return json.load(f)
