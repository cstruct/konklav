//! Which control-plane areas an operator may use.

use std::collections::BTreeSet;

/// Covers every other capability.
pub const CONTROL_ALL: &str = "conclave:control:all";

/// The control-plane capabilities the console's areas need.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    Subjects,
    Tenants,
    Authz,
    Sessions,
    Keys,
    Invites,
    Clients,
}

impl Capability {
    pub const ALL: [Self; 7] = [
        Self::Subjects,
        Self::Tenants,
        Self::Authz,
        Self::Sessions,
        Self::Invites,
        Self::Clients,
        Self::Keys,
    ];

    /// The `conclave:` action that grants it.
    #[must_use]
    pub const fn action(self) -> &'static str {
        match self {
            Self::Subjects => "conclave:subjects:manage",
            Self::Tenants => "conclave:tenants:manage",
            Self::Authz => "conclave:authz:manage",
            Self::Sessions => "conclave:sessions:manage",
            Self::Keys => "conclave:keys:manage",
            Self::Invites => "conclave:invites:manage",
            Self::Clients => "conclave:clients:manage",
        }
    }

    /// What it lets an operator do, for the console's overview.
    #[must_use]
    pub const fn describes(self) -> &'static str {
        match self {
            Self::Subjects => "Subjects and their credentials",
            Self::Tenants => "Tenants and memberships",
            Self::Authz => "Catalog, templates, roles, assignments and entitlements",
            Self::Sessions => "Listing and revoking sessions",
            Self::Keys => "Signing keys",
            Self::Invites => "Inviting people by email",
            Self::Clients => "OIDC clients",
        }
    }
}

/// The capabilities an operator holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Grants {
    /// Signed in with the bootstrap token, which the control plane accepts
    /// for everything.
    bootstrap: bool,
    held: BTreeSet<String>,
}

impl Grants {
    #[must_use]
    pub fn bootstrap() -> Self {
        Self {
            bootstrap: true,
            held: BTreeSet::new(),
        }
    }

    /// From the capabilities `GET /v1/capabilities` lists.
    #[must_use]
    pub fn held(actions: impl IntoIterator<Item = String>) -> Self {
        Self {
            bootstrap: false,
            held: actions.into_iter().collect(),
        }
    }

    /// Whether the control plane would let the operator use `capability`'s
    /// area, as its guard decides: the capability itself or `control:all`.
    // r[impl item.console.capability-gating]
    #[must_use]
    pub fn allows(&self, capability: Capability) -> bool {
        self.bootstrap || self.held.contains(CONTROL_ALL) || self.held.contains(capability.action())
    }

    /// The capabilities held, as listed, for display.
    pub fn listed(&self) -> impl Iterator<Item = &str> {
        self.held.iter().map(String::as_str)
    }

    #[must_use]
    pub fn is_bootstrap(&self) -> bool {
        self.bootstrap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // r[verify item.console.capability-gating]
    #[test]
    fn areas_need_their_capability_or_control_all() {
        let people = Grants::held(["conclave:subjects:manage".to_owned()]);
        assert!(people.allows(Capability::Subjects));
        assert!(!people.allows(Capability::Sessions));

        let root = Grants::held([CONTROL_ALL.to_owned()]);
        assert!(Capability::ALL.iter().all(|c| root.allows(*c)));

        assert!(
            Capability::ALL
                .iter()
                .all(|c| Grants::bootstrap().allows(*c))
        );
        assert!(
            Capability::ALL
                .iter()
                .all(|c| !Grants::default().allows(*c))
        );
    }

    #[test]
    fn unrelated_actions_grant_nothing() {
        let grants = Grants::held(["conclave:import".to_owned(), "workspace:read".to_owned()]);
        assert!(Capability::ALL.iter().all(|c| !grants.allows(*c)));
    }
}
