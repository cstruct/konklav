use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! define_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema), schema(value_type = String, format = Uuid))]
        pub struct $name(Uuid);

        impl $name {
            /// Generates a new time-ordered (UUID v7) identifier.
            #[cfg(feature = "generate")]
            #[must_use]
            pub fn new_v7() -> Self {
                Self(Uuid::now_v7())
            }

            #[must_use]
            pub const fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl From<Uuid> for $name {
            fn from(uuid: Uuid) -> Self {
                Self(uuid)
            }
        }

        impl From<$name> for Uuid {
            fn from(id: $name) -> Self {
                id.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::from_str(s).map(Self)
            }
        }
    };
}

define_id!(
    /// Identifies a tenant. Callers may supply their own UUID v7 values when
    /// creating tenants.
    TenantId
);
define_id!(
    /// Identifies a subject for its whole lifetime.
    SubjectId
);
define_id!(
    /// Identifies a membership of one subject in one tenant.
    MembershipId
);
define_id!(
    /// Identifies a session.
    SessionId
);
define_id!(
    /// Identifies a credential. For secret keys it is also the login
    /// identifier.
    CredentialId
);

define_id!(
    /// Identifies a share of one tenant's scope with another tenant.
    /// Callers supply it when offering the share.
    ShareId
);

#[cfg(all(test, feature = "generate"))]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_display_and_from_str() {
        let id = TenantId::new_v7();
        assert_eq!(id.to_string().parse::<TenantId>().unwrap(), id);
    }

    #[test]
    fn serializes_as_a_bare_uuid_string() {
        let uuid = Uuid::now_v7();
        let json = serde_json::to_string(&SubjectId::from(uuid)).unwrap();
        assert_eq!(json, format!("\"{uuid}\""));
    }

    #[test]
    fn new_ids_are_time_ordered() {
        let first = SessionId::new_v7();
        let second = SessionId::new_v7();
        assert!(first < second);
    }
}
