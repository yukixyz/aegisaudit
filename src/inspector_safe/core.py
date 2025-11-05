import json
import asyncio
from pathlib import Path
from typing import List, Dict, Any, Optional
import socket
import time
import dns.resolver
import httpx
from .logger import get_logger

logger = get_logger()

class AuthorizationError(Exception):
    pass

class InspectorConfig:
    def __init__(self, token_file: Path = Path("authorized_tokens.json"), rate_limit: float = 10.0, concurrency: int = 5, timeout: float = 5.0):
        self.token_file = token_file
        self.rate_limit = rate_limit
        self.concurrency = concurrency
        self.timeout = timeout

def load_tokens(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)

def validate_token(token: str, config: InspectorConfig) -> bool:
    tokens = load_tokens(config.token_file)
    for entry in tokens:
        if entry.get("token") == token:
            return True
    raise AuthorizationError("invalid or missing authorization token")

def dns_enumeration(domain: str, timeout: float = 5.0) -> Dict[str, Any]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    result = {"domain": domain, "records": {}}
    record_types = ["A", "AAAA", "MX", "NS", "TXT"]
    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            result["records"][rtype] = [str(r.to_text()) for r in answers]
        except Exception as e:
            result["records"][rtype] = []
            logger.debug("dns %s lookup failed for %s %s", rtype, domain, str(e))
    return result

async def safe_head(url: str, timeout: float = 5.0) -> Dict[str, Any]:
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        try:
            r = await client.head(url)
            return {"url": url, "status_code": r.status_code, "headers": dict(r.headers)}
        except httpx.HTTPError as e:
            logger.debug("http head failed %s %s", url, str(e))
            return {"url": url, "error": str(e)}

async def banner_grab(host: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
    loop = asyncio.get_event_loop()
    try:
        fut = loop.run_in_executor(None, _sync_banner, host, port, timeout)
        banner = await asyncio.wait_for(fut, timeout + 1)
        return {"host": host, "port": port, "banner": banner}
    except Exception as e:
        logger.debug("banner grab failed %s:%s %s", host, port, str(e))
        return {"host": host, "port": port, "banner": ""}

def _sync_banner(host: str, port: int, timeout: float = 3.0) -> str:
    try:
        sock = socket.create_connection((host, port), timeout)
        sock.settimeout(timeout)
        try:
            data = sock.recv(1024)
            sock.close()
            return data.decode("utf-8", errors="ignore").strip()
        except Exception:
            sock.close()
            return ""
    except Exception:
        return ""

async def perform_scan(target: str, config: InspectorConfig, ports: Optional[List[int]] = None) -> Dict[str, Any]:
    ts = time.time()
    sem = asyncio.Semaphore(config.concurrency)
    rate_interval = 1.0 / max(1.0, config.rate_limit)
    results = {"target": target, "timestamp": int(ts), "dns": {}, "http": [], "banners": []}
    loop = asyncio.get_event_loop()
    dns_res = await loop.run_in_executor(None, dns_enumeration, target, config.timeout)
    results["dns"] = dns_res
    urls = []
    if "A" in dns_res.get("records", {}) and dns_res["records"]["A"]:
        urls.append(f"http://{target}")
        urls.append(f"https://{target}")
    async def http_task(u: str):
        async with sem:
            await asyncio.sleep(rate_interval)
            res = await safe_head(u, timeout=config.timeout)
            results["http"].append(res)
    http_tasks = [http_task(u) for u in urls]
    if ports is None:
        ports = [22, 80, 443, 3306, 143, 110]
    async def banner_task(p: int):
        async with sem:
            await asyncio.sleep(rate_interval)
            res = await banner_grab(target, p, timeout=config.timeout)
            results["banners"].append(res)
    banner_tasks = [banner_task(p) for p in ports]
    await asyncio.gather(*(http_tasks + banner_tasks))
    return results
