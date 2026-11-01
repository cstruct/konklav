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

r[item.console.token-in-memory]
The console MUST keep the operator's access token, and the bootstrap token
when one is used, in memory only, never in browser storage. A reload MUST
restore a session only through the refresh cookie.

r[item.console.capability-gating]
The console MUST show which control-plane areas the operator lacks a
capability for, naming that capability, instead of offering actions the
control plane would refuse or failing without saying why.
