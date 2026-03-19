# Federation And Protocols

This file defines requirements for external identity providers and protocol support.

## Federation

r[federation.provider.abstraction]
The platform MUST provide a provider abstraction for brokering identities from external sources without leaking provider-specific behavior into the core domain model.

r[federation.peer.self-federation]
The platform MUST support federation between distinct deployments of itself, allowing one deployment to act as an upstream identity provider or broker for another without requiring provider-specific integration code.

r[federation.peer.loop-prevention]
Federation between deployments of the platform MUST prevent ambiguous trust chains and authentication loops across recursive or bidirectional federation links.

r[federation.identity.linking]
Federated identities MUST link into the internal subject model in a way that supports both just-in-time provisioning and pre-provisioned account binding.

r[federation.directory.sync-modes]
Federation support MUST allow both on-demand attribute hydration and scheduled synchronization so tenants can choose the right consistency model for their providers.

## Protocols

r[protocol.oidc.broker-support]
The platform MUST include OpenID Connect support for acting as or brokering against modern identity providers and applications.

r[protocol.saml.broker-support]
The platform MUST include SAML support for interoperability with enterprise identity providers and service providers that have not moved to OIDC.

r[protocol.logout.propagation]
Single logout behavior MUST define how local session termination and upstream federation logout requests are propagated across participating systems.
