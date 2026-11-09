import ipaddress
import re
import urllib.parse
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import Response as Resp
import httpx

app = FastAPI()
client = httpx.AsyncClient(follow_redirects=True, timeout=20.0, verify=False)

# These headers stop Vidly from detecting the iframe or blocking the embed
STRIP_HEADERS = {
    "x-frame-options",
    "content-security-policy",
    "content-security-policy-report-only",
    "clear-site-data",
}

HOP_BY_HOP = {
    "content-length", "transfer-encoding", "connection", "keep-alive",
    "proxy-authenticate", "proxy-authorization", "te", "trailers", "upgrade",
}

def _is_private_host(host: str) -> bool:
    host = host.strip().lower()
    if host in ("localhost", "0.0.0.0", "::1"):
        return True
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
    except ValueError:
        return False

def _safe_url(raw: str) -> str:
    if not raw:
        raise HTTPException(400, "missing url")
    if len(raw) > 4096:
        raise HTTPException(414, "url too long")
    try:
        p = urllib.parse.urlparse(raw)
    except Exception:
        raise HTTPException(400, "bad url")
    if p.scheme not in ("http", "https"):
        raise HTTPException(400, "only http/https allowed")
    if _is_private_host(p.hostname or ""):
        raise HTTPException(403, "blocked: private/loopback target")
    return raw

def _rewrite_html(html: str, base_url: str, proxy_root: str) -> str:
    """Rewrite links so assets load through the proxy."""
    base_parsed = urllib.parse.urlparse(base_url)
    proxy_origin = proxy_root.rstrip("/")

    def to_proxy(u):
        if not u or u.startswith(("#", "data:", "javascript:", "mailto:", "tel:")):
            return u
        if u.startswith("//"):
            absu = f"{base_parsed.scheme}:{u}"
        elif u.startswith("/"):
            absu = f"{base_parsed.scheme}://{base_parsed.netloc}{u}"
        elif u.startswith("http://") or u.startswith("https://"):
            absu = u
        else:
            # Relative path
            base_path = base_url.rsplit('/', 1)[0] + '/'
            absu = urllib.parse.urljoin(base_path, u)
        
        return f"{proxy_origin}/?url={urllib.parse.quote(absu, safe='')}"

    # Rewrite src and href attributes
    html = re.sub(r'(src\s*=\s*")([^"]*)(")', lambda m: m.group(1) + to_proxy(m.group(2)) + m.group(3), html, flags=re.IGNORECASE)
    html = re.sub(r"(src\s*=\s*')([^']*)(')", lambda m: m.group(1) + to_proxy(m.group(2)) + m.group(3), html, flags=re.IGNORECASE)
    html = re.sub(r'(href\s*=\s*")([^"]*)(")', lambda m: m.group(1) + to_proxy(m.group(2)) + m.group(3), html, flags=re.IGNORECASE)
    html = re.sub(r"(href\s*=\s*')([^']*)(')", lambda m: m.group(1) + to_proxy(m.group(2)) + m.group(3), html, flags=re.IGNORECASE)
    
    return html

@app.get("/")
async def proxy(request: Request, url: str = ""):
    if not url:
        return {"status": "ok", "message": "Proxy is running. Use /?url=<target>"}

    target = _safe_url(url)
    
    # Forward headers (strip proxy-specific ones)
    fwd = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "connection", "accept-encoding")}
    
    try:
        r = await client.get(target, headers=fwd)
    except httpx.HTTPError as e:
        raise HTTPException(502, f"upstream error: {e}")

    ctype = (r.headers.get("content-type") or "text/plain").lower()
    body = r.content

    # If it's HTML, rewrite links so they go through the proxy
    if "text/html" in ctype:
        proxy_root = str(request.base_url).rstrip("/")
        body = _rewrite_html(body.decode("utf-8", "replace"), target, proxy_root).encode("utf-8")
        ctype = "text/html; charset=utf-8"

    out = Resp(content=body, status_code=r.status_code)
    
    # Copy safe headers
    for k, v in r.headers.items():
        lk = k.lower()
        if lk not in STRIP_HEADERS and lk not in HOP_BY_HOP:
            out.headers[k] = v

    # CRITICAL: Force these headers so Vidly works
    out.headers["X-Frame-Options"] = "ALLOWALL"
    out.headers["Content-Security-Policy"] = "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; frame-ancestors *;"
    out.headers["Access-Control-Allow-Origin"] = "*"
    out.headers["Content-Type"] = ctype

    return out

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
