"""
SAINT recon pipeline.

basically what happens here that it get request from app.py like -> 

javascript fetch send the domain -> apps.py -> pipline
AND THEN pipline -> domain and returns a single clean JSON blob ready to hand to the LLM layer.

pipeline work is to run this this tools and giev to output to llm in the JSON
recon tools used (subfinder, httpx, naabu) against a target SO PLS FCKING INSTALL IT 


"""

import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field


DEFAULT_TIMEOUT = 90  # seconds per tool stage

# Cache resolved binary paths so we don't re-scan the filesystem on every call
_TOOL_PATH_CACHE = {}


def normalize_domain(raw: str) -> str:
    """Strips scheme, path, port and trailing slashes from user input so
    'https://example.com/foo' or 'example.com/' becomes 'example.com'."""
    d = raw.strip()
    d = re.sub(r"^https?://", "", d, flags=re.IGNORECASE)
    d = d.split("/")[0]      # drop any path
    d = d.split(":")[0]      # drop any port
    return d.strip().lower()


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


def _find_tool(name: str) -> str | None:
    """Locate a recon tool's real binary.

    Deliberately checks the standard Go install location FIRST, before
    falling back to whatever `PATH` resolves. This matters specifically for
    `httpx`: ProjectDiscovery's recon tool and Python's `httpx` HTTP client
    library (a dependency of the `anthropic` SDK) both install a command
    called `httpx`. When a venv is active, the venv's `bin/` is prepended to
    `PATH`, so the *Python* httpx CLI shadows the real recon tool and every
    scan silently returns zero results. Checking the Go path directly avoids
    that collision regardless of PATH ordering or venv state.
    """
    if name in _TOOL_PATH_CACHE:
        return _TOOL_PATH_CACHE[name]

    candidates = []
    gopath = os.environ.get("GOPATH")
    gobin = os.environ.get("GOBIN")
    if gobin:
        candidates.append(os.path.join(gobin, name))
    if gopath:
        candidates.append(os.path.join(gopath, "bin", name))
    candidates.append(os.path.expanduser(f"~/go/bin/{name}"))

    for path in candidates:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            _TOOL_PATH_CACHE[name] = path
            return path

    # Fall back to PATH lookup for tools with no Go-specific collision risk
    found = shutil.which(name)
    _TOOL_PATH_CACHE[name] = found
    return found


def _tool_available(name: str) -> bool:
    return _find_tool(name) is not None


def _clean_host(s: str) -> str:
    """Some terminals auto-hyperlink URLs and mangle copy/pasted or piped
    output into markdown-link form, e.g. '[host](https://host)'. Strip that
    defensively so a stray artifact never gets treated as a real hostname."""
    s = s.strip()
    m = re.match(r"^\[([^\]]+)\]\(.*\)$", s)
    return m.group(1) if m else s


def run_subfinder(domain: str, timeout: int = DEFAULT_TIMEOUT) -> list:
    """Passive subdomain enumeration. Returns a list of subdomain strings."""
    if not _tool_available("subfinder"):
        return []
    try:
        proc = subprocess.run(
            [_find_tool("subfinder"), "-d", domain, "-silent", "-json"],
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
                    subs.append(_clean_host(host))
            except json.JSONDecodeError:
                # subfinder can be run without -json as a fallback format
                subs.append(_clean_host(line))
        return sorted(set(s for s in subs if s))
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
            [_find_tool("httpx"), "-silent", "-json", "-title", "-status-code", "-tech-detect"],
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

        if not alive:
            # Don't fail silently - this is the #1 thing to check when the
            # httpx box shows nothing but the tool is clearly installed.
            print("=" * 60)
            print(f"SAINT DEBUG: httpx ran on {len(hosts)} hosts but parsed 0 alive results.")
            print(f"httpx exit code: {proc.returncode}")
            print(f"httpx stdout (raw, first 2000 chars): {proc.stdout[:2000]!r}")
            print(f"httpx stderr (first 2000 chars): {proc.stderr[:2000]!r}")
            print("=" * 60)

        return alive
    except subprocess.TimeoutExpired:
        print(f"SAINT DEBUG: httpx timed out after {timeout}s on {len(hosts)} hosts")
        return []
    except Exception as e:
        print(f"SAINT DEBUG: httpx raised an exception: {e!r}")
        return []


def run_naabu(hosts: list, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Fast port scan on given hosts. Returns {host: [ports]}."""
    if not hosts or not _tool_available("naabu"):
        return {}
    try:
        proc = subprocess.run(
            [_find_tool("naabu"), "-silent", "-json", "-top-ports", "100"],
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
    domain = normalize_domain(domain)
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


def load_demo_data(path: str = "sample_data/demo_scan.json") -> dict:
    """Fallback for live demos: cached, realistic-looking scan output so the
    demo works even with no wifi / tools not installed on the venue laptop."""
    with open(path) as f:
        return json.load(f)