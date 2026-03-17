pub type DynError = Box<dyn std::error::Error + Send + Sync>;

pub type ActionName = String;
pub type CatalogRevision = u32;
pub type PolicyRevision = u64;

pub type RoleKey = String;
pub type ScopeId = String;
pub type ScopeKind = String;
pub type SubjectId = String;
pub type TemplateKey = String;
pub type TenantId = String;
