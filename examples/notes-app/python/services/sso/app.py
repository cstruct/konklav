"""The login application, on http://localhost:8000.

Konklav has no user interface. Its authorization endpoint hands the browser
to this login page, which signs the person in through Konklav's own API
and accepts the request. The page runs in the browser:

- Konklav's session for the person is bound to the page's DPoP key, and its
  refresh token is an HttpOnly cookie that scripts can't read. Its access
  token lives in page memory only.
- That cookie is the single sign-on: the next app that sends the browser
  here finds the person signed in and is answered without a prompt.

This process serves the page and proxies Konklav's subject-facing surface
under the same origin (`/v1`, `/.well-known`), so the cookie, the page and
Konklav's issuer share one origin, as Konklav expects of a login application.
"""

import os
import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from example import WEB, WEB_ROOT, security_headers

KONKLAV = os.environ["KONKLAV_SUBJECT_URL"]
PAGES = WEB_ROOT / "sso"

CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

# Hop-by-hop headers, and ones httpx recomputes.
SKIPPED = {"host", "connection", "keep-alive", "transfer-encoding", "content-length", "content-encoding", "upgrade"}

http = httpx.AsyncClient(base_url=KONKLAV, timeout=30.0)


async def page(_: Request) -> Response:
    return FileResponse(PAGES / "login.html", headers=security_headers(CSP))


async def proxy(request: Request) -> Response:
    """Passes a request to Konklav as is, and its answer back, cookies and
    redirects included."""
    headers = [(k, v) for k, v in request.headers.items() if k not in SKIPPED]
    headers.append(("accept-encoding", "identity"))
    upstream = await http.request(
        request.method,
        request.url.path,
        params=request.query_params,
        headers=headers,
        content=await request.body(),
    )
    response = Response(upstream.content, status_code=upstream.status_code)
    response.raw_headers = [
        (k.encode(), v.encode()) for k, v in upstream.headers.multi_items() if k.lower() not in SKIPPED
    ]
    response.headers["content-length"] = str(len(upstream.content))
    return response


METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]

app = Starlette(
    routes=[
        Route("/", page),
        Route("/login", page),
        Mount("/static", StaticFiles(directory=PAGES)),
        Mount("/shared", StaticFiles(directory=WEB)),
        Route("/v1/{path:path}", proxy, methods=METHODS),
        Route("/.well-known/{path:path}", proxy, methods=METHODS),
        Route("/readyz", proxy),
    ],
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
