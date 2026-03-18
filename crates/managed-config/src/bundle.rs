use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use conclave_core::DynError;
use facet::Facet;
use serde::{Deserialize, Serialize};

use crate::authz::{ActionCatalogConfig, RoleConfig, TemplateConfig};
use crate::tenants::{AssumptionGrantConfig, MembershipConfig, SubjectConfig, TenantConfig};

#[derive(Clone, Debug)]
pub struct LoadedManagedConfig {
    pub managed: ManagedConfig,
    pub source: String,
}

#[derive(Clone, Debug, Facet, PartialEq, Serialize, Deserialize)]
pub struct ManagedConfig {
    pub catalog: ActionCatalogConfig,
    #[facet(default)]
    pub templates: Vec<TemplateConfig>,
    #[facet(default)]
    pub roles: Vec<RoleConfig>,
    #[facet(default)]
    pub tenants: Vec<TenantConfig>,
    #[facet(default)]
    pub subjects: Vec<SubjectConfig>,
    #[facet(default)]
    pub memberships: Vec<MembershipConfig>,
    #[facet(default)]
    pub assumption_grants: Vec<AssumptionGrantConfig>,
}

#[derive(Clone, Debug, Default, Facet, PartialEq, Serialize, Deserialize)]
struct ManagedConfigFragment {
    #[facet(default)]
    pub catalog: Option<ActionCatalogConfig>,
    #[facet(default)]
    pub templates: Vec<TemplateConfig>,
    #[facet(default)]
    pub roles: Vec<RoleConfig>,
    #[facet(default)]
    pub tenants: Vec<TenantConfig>,
    #[facet(default)]
    pub subjects: Vec<SubjectConfig>,
    #[facet(default)]
    pub memberships: Vec<MembershipConfig>,
    #[facet(default)]
    pub assumption_grants: Vec<AssumptionGrantConfig>,
}

impl ManagedConfig {
    pub fn load_from_str(input: &str) -> Result<Self, DynError> {
        Ok(facet_styx::from_str(input)?)
    }

    pub fn schema() -> String {
        facet_styx::schema_from_type::<Self>()
    }

    // r[impl config.managed.bundle-interface]
    // r[impl config.managed.fragment-assembly]
    pub fn load_from_dir(path: impl AsRef<Path>) -> Result<LoadedManagedConfig, DynError> {
        let dir = path.as_ref();
        let paths = collect_styx_paths(dir)?;
        let mut merged = ManagedConfigFragment::default();
        let mut names = Vec::with_capacity(paths.len());

        for path in paths {
            let contents = fs::read_to_string(&path)?;
            let fragment: ManagedConfigFragment = facet_styx::from_str(&contents)?;
            merged.merge(fragment);
            names.push(path.file_name().unwrap().to_string_lossy().into_owned());
        }

        let managed = merged.into_managed_config()?;
        let source = format!("dir:{} ({})", dir.display(), names.join(","));

        Ok(LoadedManagedConfig { managed, source })
    }
}

impl ManagedConfigFragment {
    fn merge(&mut self, other: Self) {
        if let Some(catalog) = other.catalog {
            if let Some(existing) = &mut self.catalog {
                existing.actions.extend(catalog.actions);
            } else {
                self.catalog = Some(catalog);
            }
        }

        self.templates.extend(other.templates);
        self.roles.extend(other.roles);
        self.tenants.extend(other.tenants);
        self.subjects.extend(other.subjects);
        self.memberships.extend(other.memberships);
        self.assumption_grants.extend(other.assumption_grants);
    }

    fn into_managed_config(self) -> Result<ManagedConfig, DynError> {
        let catalog = self.catalog.ok_or_else(|| {
            Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                "managed config requires a catalog block",
            )) as DynError
        })?;

        Ok(ManagedConfig {
            catalog,
            templates: self.templates,
            roles: self.roles,
            tenants: self.tenants,
            subjects: self.subjects,
            memberships: self.memberships,
            assumption_grants: self.assumption_grants,
        })
    }
}

fn collect_styx_paths(dir: &Path) -> Result<Vec<PathBuf>, DynError> {
    let mut paths = Vec::new();

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if !entry.file_type()?.is_file() {
            continue;
        }

        if path.extension().and_then(|ext| ext.to_str()) != Some("styx") {
            continue;
        }

        if path.file_name().and_then(|name| name.to_str()) == Some("server.styx") {
            continue;
        }

        paths.push(path);
    }

    paths.sort();

    if paths.is_empty() {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no managed *.styx files found in {}", dir.display()),
        )));
    }

    Ok(paths)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::ManagedConfig;

    // r[verify config.managed.bundle-interface]
    // r[verify config.managed.fragment-assembly]
    #[test]
    fn loads_and_deep_merges_styx_files_from_directory() {
        let dir = temp_dir("managed-config-merge");
        fs::write(
            dir.join("00-authz.styx"),
            r#"
catalog {
    actions (
        {name "tenant:user:read"}
    )
}
"#,
        )
        .expect("authz file should write");
        fs::write(
            dir.join("10-authz-extra.styx"),
            r#"
catalog {
    actions (
        {name "tenant:user:write"}
    )
}
templates (
    {
        tenant "root",
        key "doctor",
        policies (
            {effect allow, action "tenant:user:read"}
        )
    }
)
"#,
        )
        .expect("extra authz file should write");
        fs::write(
            dir.join("20-tenants.styx"),
            r#"
tenants (
    {id "tenant-a"}
)
"#,
        )
        .expect("tenant file should write");
        fs::write(
            dir.join("server.styx"),
            r#"
server {
    host "127.0.0.1"
    port 8080
}
"#,
        )
        .expect("server config should write");

        let loaded = ManagedConfig::load_from_dir(&dir).expect("managed config should load");

        assert_eq!(loaded.managed.catalog.actions.len(), 2);
        assert_eq!(loaded.managed.templates.len(), 1);
        assert_eq!(loaded.managed.tenants.len(), 1);
        assert!(loaded.source.contains("00-authz.styx"));
        assert!(loaded.source.contains("20-tenants.styx"));

        fs::remove_dir_all(dir).expect("temp dir should be removed");
    }

    fn temp_dir(prefix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("{prefix}-{unique}"));
        fs::create_dir_all(&dir).expect("temp dir should create");
        dir
    }
}
