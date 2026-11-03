# API Software Item

Stable implementation contracts owned by `konklav-api`, which defines the
transport types of Konklav's HTTP surfaces, starting with the control-plane
surface.

r[item.api.transport-only]
`konklav-api` MUST hold only transport types and what clients need to read
them, such as each error code's HTTP status. It MUST NOT perform I/O or depend
on `konklav-store`, `konklav-server` or any other software item that does, so
that clients can depend on it without pulling in the server.

r[item.api.both-directions]
Every transport type in `konklav-api` MUST serialize and deserialize to the
same JSON, so that the server and its clients read and write one shape.

r[item.api.schemas]
Every transport type in `konklav-api` MUST describe itself as an OpenAPI
schema, so that API documents are generated from the types the server
actually uses.

r[item.api.document]
The server MUST generate the control-plane surface's API document from its
routes and `konklav-api`'s types, and the copy committed at
`items/server/openapi/control-plane.json` MUST match what the code generates.
The document is shipped in the repository, not served by the control
listener.

r[item.api.capabilities]
Every operation in the control-plane API document MUST name the capability
its route's guard requires, as `x-konklav-capability`, taken from the same
list that guards the route. The batch operation, which any operator may
send since each of its operations is guarded on its own, MUST NOT name one.

r[item.api.responses]
The server's tests MUST check the control-plane responses they receive against
the committed API document, failing on a body that doesn't match the
operation's schema for its status or on a status the document doesn't list.
