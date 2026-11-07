# Software-Item Specs

This directory holds Tracey-managed implementation specs for individual
software items. They sit below the product specs in `../` and capture stable
implementation contracts that one software item owns.

Use this directory for:

- stable contracts that one software item provides to others
- boundary behavior that several software items depend on
- implementation obligations that are too specific for product specs but
  too important to live only in a README

Do not use it for product behavior, design rationale (see
`../../architecture/`), onboarding material, or local implementation
details.

Rule naming convention: `item.<software-item>.*`.

Planned software items (see
[`../../architecture/overview.md`](../../architecture/overview.md)):

- [`api`](api.md)
- `core`
- [`store`](store.md)
- [`authz`](authz.md)
- `authn`
- `bootstrap`
- `server`
- [`token`](token.md)
- [`relying`](relying.md)
- [`console`](console.md)
- [`relying-client`](relying-client.md)
- [`py`](py.md) (built separately by maturin)
- [`py-control-plane`](py-control-plane.md) (pure Python, built by uv)
- [`py-fastapi`](py-fastapi.md) (pure Python, built by uv)
- [`axum`](axum.md)
- `cli`
- `test-support` (test-only)

Specs are added as each item is built.
