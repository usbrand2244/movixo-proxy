import ipaddress
import re
import urllib.parse
from fastapi import FastAPI, Request, Response, HTTPException
import httpx

app = FastAPI()
client = httpx.AsyncClient(follow_redirects=True, timeout=20.0, verify=False)

STRIP_HEADERS = {
    "x-frame-options", "content-security-policy",
    "content-security-policy-report-only", "clear-site-data",
}
HOP_BY_HOP = {
    "content-length", "transfer-encoding", "connection", "keep-alive",
    "proxy-authenticate", "proxy-authorization", "te", "trailers", "upgrade",
}

def _is_private_host(host: str) -> bool:
    host = host.strip().lower()
    if host in ("localhost", "0.0.0.0", "::1"): return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return False

def _safe_url(raw: str) -> str:
    if not raw: raise HTTPException(400, "missing url")
    try: p = urllib.parse.urlparse(raw)
    except Exception: raise HTTPException(400, "bad url")
    if p.scheme not in ("http", "https"): raise HTTPException(400, "only http/https")
    if _is_private_host(p.hostname or ""): raise HTTPException(403, "blocked target")
    return raw

def _rewrite_html(html: str, base_url: str, proxy_root: str) -> str:
    base_parsed = urllib.parse.urlparse(base_url)
    proxy_origin = proxy_root.rstrip("/")

    def to_proxy(u):
        if not u or u.startswith(("#", "data:", "javascript:", "mailto:", "tel:")): return u
        if u.startswith("//"): absu = f"{base_parsed.scheme}:{u}"
        elif u.startswith("/"): absu = f"{base_parsed.scheme}://{base_parsed.netloc}{u}"
        elif u.startswith(("http://", "https://")): absu = u
        else: absu = urllib.parse.urljoin(base_url.rsplit('/', 1)[0] + '/', u)
        return f"{proxy_origin}/?url={urllib.parse.quote(absu, safe='')}"

    html = re.sub(r'(src\s*=\s*")([^"]*)(")', lambda m: m.group(1) + to_proxy(m.group(2)) + m.group(3), html, flags=re.I)
    html = re.sub(r"(src\s*=\s*')([^']*)(')", lambda m: m.group(1) + to_proxy(m.group(2)) + m.group(3), html, flags=re.I)
    html = re.sub(r'(href\s*=\s*")([^"]*)(")', lambda m: m.group(1) + to_proxy(m.group(2)) + m.group(3), html, flags=re.I)
    html = re.sub(r"(href\s*=\s*')([^']*)(')", lambda m: m.group(1) + to_proxy(m.group(2)) + m.group(3), html, flags=re.I)
    return html

@app.get("/")
async def proxy(request: Request, url: str = ""):
    if not url:
        return {"status": "ok", "message": "Proxy is running. Use /?url=<target>"}

    target = _safe_url(url)
    fwd = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "connection", "accept-encoding")}
    
    try:
        r = await client.get(target, headers=fwd)
    except httpx.HTTPError as e:
        raise HTTPException(502, f"upstream error: {e}")

    ctype = (r.headers.get("content-type") or "text/plain").lower()
    body = r.content

    if "text/html" in ctype:
        proxy_root = str(request.base_url).rstrip("/")
        body = _rewrite_html(body.decode("utf-8", "replace"), target, proxy_root).encode("utf-8")
        ctype = "text/html; charset=utf-8"

    out = Response(content=body, status_code=r.status_code)
    for k, v in r.headers.items():
        lk = k.lower()
        if lk not in STRIP_HEADERS and lk not in HOP_BY_HOP:
            out.headers[k] = v

    out.headers["X-Frame-Options"] = "ALLOWALL"
    out.headers["Content-Security-Policy"] = "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; frame-ancestors *;"
    out.headers["Access-Control-Allow-Origin"] = "*"
    out.headers["Content-Type"] = ctype
    return out
