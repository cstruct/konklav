"""The app's frontend, on http://localhost:3000: static files only.

The page is a public OIDC client (`app`). It signs in through Konklav with
the code flow and PKCE, binds its tokens to a DPoP key, keeps the tokens in
memory, and calls the app's backend with them. See static/app.js.
"""

import json
import os

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from example import WEB, WEB_ROOT, security_headers

PAGES = WEB_ROOT / "app"
ISSUER = os.environ["ISSUER"]
API_URL = os.environ["API_URL"]
CONFIG = {"issuer": ISSUER, "client_id": os.environ["CLIENT_ID"], "api": API_URL}

# Scripts only from this origin; fetches only to Konklav and the API.
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    f"connect-src 'self' {ISSUER} {API_URL}; base-uri 'none'; frame-ancestors 'none'"
)


async def page(_: Request) -> Response:
    return FileResponse(PAGES / "index.html", headers=security_headers(CSP))


async def config(_: Request) -> Response:
    return JSONResponse(CONFIG)


app = Starlette(
    routes=[
        Route("/", page),
        Route("/callback", page),
        Route("/config.json", config),
        Mount("/static", StaticFiles(directory=PAGES)),
        Mount("/shared", StaticFiles(directory=WEB)),
    ],
)

if __name__ == "__main__":
    print(json.dumps(CONFIG))
    uvicorn.run(app, host="0.0.0.0", port=3000)
