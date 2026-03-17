use serde::Serialize;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct BuiltInControlPlaneCapability {
    pub key: &'static str,
    pub description: &'static str,
    pub grant_surface: &'static str,
}

const BUILT_IN_CONTROL_PLANE_CAPABILITIES: [BuiltInControlPlaneCapability; 6] = [
    BuiltInControlPlaneCapability {
        key: "tenant.assume",
        description: "Assume delegated access into a descendant tenant",
        grant_surface: "assumption_grants",
    },
    BuiltInControlPlaneCapability {
        key: "tenant.create",
        description: "Create a tenant in the Conclave control plane",
        grant_surface: "built_in",
    },
    BuiltInControlPlaneCapability {
        key: "tenant.suspend",
        description: "Suspend a tenant in the Conclave control plane",
        grant_surface: "built_in",
    },
    BuiltInControlPlaneCapability {
        key: "subject.invite",
        description: "Invite a subject through the Conclave control plane",
        grant_surface: "built_in",
    },
    BuiltInControlPlaneCapability {
        key: "subject.disable",
        description: "Disable a subject through the Conclave control plane",
        grant_surface: "built_in",
    },
    BuiltInControlPlaneCapability {
        key: "federation.configure",
        description: "Configure federation resources in the Conclave control plane",
        grant_surface: "built_in",
    },
];

// r[impl authz.control-plane.capability.built-in]
pub fn built_in_capabilities() -> &'static [BuiltInControlPlaneCapability] {
    &BUILT_IN_CONTROL_PLANE_CAPABILITIES
}

#[cfg(test)]
mod tests {
    use super::built_in_capabilities;

    // r[verify authz.control-plane.capability.built-in]
    #[test]
    fn exposes_assumption_and_control_plane_capabilities() {
        let capabilities = built_in_capabilities();

        assert!(capabilities
            .iter()
            .any(|entry| entry.key == "tenant.assume"));
        assert!(capabilities
            .iter()
            .any(|entry| entry.key == "tenant.create"));
    }
}
