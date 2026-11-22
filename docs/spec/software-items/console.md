# Console

Contracts of `konklav-console` (`items/console`), the browser UI for
operating the control plane. It talks to Konklav only through the
subject-facing and control-plane surfaces.

r[item.console.same-origin]
The console MUST reach Konklav on its own origin: the subject-facing
surface at `/v1` and the control-plane surface at `/control/v1`. Whatever
serves the console (the development server, or a reverse proxy in a
deployment) routes those prefixes, so the browser's refresh cookie stays
first-party and Konklav needs no CORS.

r[item.console.content-security-policy]
The console's page MUST declare a Content-Security-Policy that lets scripts,
styles, images and connections come from its own origin only, with no
inline script or style and no `eval` beyond compiling WebAssembly, and that
forbids a `<base>` and form submission. The built console MUST work under
that policy.

r[item.console.response-headers]
Whatever serves the console MUST send what a page cannot declare for
itself: `Content-Security-Policy: frame-ancestors 'none'`, so no other page
can frame the console, and `X-Content-Type-Options: nosniff`. It MUST serve
`index.html` with `Cache-Control: no-store`, so a browser always gets the
current policy and bundle names.

r[item.console.token-in-memory]
The console MUST keep the operator's access token, and the bootstrap token
when one is used, in memory only, never in browser storage. A reload MUST
restore a session only through the refresh cookie.

r[item.console.dpop]
The console MUST bind its sessions to a non-extractable WebCrypto P-256 key
and send a DPoP proof with every request, so its access tokens are
sender-constrained. It MUST keep the key in IndexedDB, so a reload can
still refresh the bound session.

r[item.console.capability-gating]
The console MUST show which control-plane areas the operator lacks a
capability for, naming that capability, instead of offering actions the
control plane would refuse or failing without saying why.
