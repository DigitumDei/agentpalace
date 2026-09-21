//! Durable, secret-free access-control records for the demo hub.
//!
//! [`AccessPolicy`] is the operator-editable document.  Provider bindings and
//! owner IDs live in [`IdentityBindingStore`] and are intentionally not part
//! of that document, so changing a role or mailbox cannot rewrite provenance.

use std::collections::{BTreeSet, HashSet};

use agentpalace_core::{OwnerId, SubjectBinding};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

/// Current on-disk schema version for `access.json`.
pub const ACCESS_SCHEMA_VERSION: u32 = 1;

/// Roles in descending administrative order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessRole {
    /// May administer membership as well as use the shared palace.
    Admin,
    /// May perform explicitly inventoried writes, but cannot administer users.
    Write,
    /// May perform explicitly inventoried reads only.
    Readonly,
}

impl AccessRole {
    /// Whether this role may administer editable membership.
    pub const fn is_admin(self) -> bool { matches!(self, Self::Admin) }
}

/// A normalized editable membership entry from `access.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipEntry {
    /// Normalized mailbox: surrounding whitespace removed and domain lowercased.
    pub email: String,
    /// Current editable role.
    pub role: AccessRole,
    /// Disabled entries retain their history without admitting the mailbox.
    pub enabled: bool,
}

/// Versioned editable access policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccessPolicy {
    /// On-disk schema version.
    pub schema_version: u32,
    /// Monotonically increasing optimistic-concurrency revision.
    pub revision: u64,
    /// Editable memberships; immutable provider bindings are elsewhere.
    pub users: Vec<MembershipEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAccessPolicy {
    schema_version: u32,
    revision: u64,
    users: Vec<MembershipEntry>,
}

impl<'de> Deserialize<'de> for AccessPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        let raw = RawAccessPolicy::deserialize(deserializer)?;
        Self::new(raw.schema_version, raw.revision, raw.users).map_err(serde::de::Error::custom)
    }
}

impl AccessPolicy {
    /// Construct and normalize a policy, rejecting malformed or ambiguous entries.
    pub fn new(schema_version: u32, revision: u64, users: Vec<MembershipEntry>) -> Result<Self, AccessPolicyError> {
        if schema_version != ACCESS_SCHEMA_VERSION { return Err(AccessPolicyError::UnsupportedSchema(schema_version)); }
        if revision == 0 { return Err(AccessPolicyError::InvalidRevision); }
        let mut seen = BTreeSet::new();
        let users = users.into_iter().map(|mut entry| {
            entry.email = normalize_email(&entry.email)?;
            if !seen.insert(entry.email.clone()) { return Err(AccessPolicyError::DuplicateEmail(entry.email)); }
            Ok(entry)
        }).collect::<Result<Vec<_>, AccessPolicyError>>()?;
        Ok(Self { schema_version, revision, users })
    }

    /// Parse a policy document and apply the same validation as file loading.
    pub fn from_json(input: &str) -> Result<Self, AccessPolicyError> {
        serde_json::from_str(input).map_err(|error| AccessPolicyError::InvalidDocument(error.to_string()))
    }

    /// Return the currently enabled role for a normalized mailbox.
    pub fn role_for_email(&self, email: &str) -> Result<Option<AccessRole>, AccessPolicyError> {
        let email = normalize_email(email)?;
        Ok(self.users.iter().find(|entry| entry.email == email && entry.enabled).map(|entry| entry.role))
    }

    /// Reject a change which would remove the final enabled administrator.
    pub fn ensure_enabled_admin_remains(&self) -> Result<(), AccessPolicyError> {
        if self.users.iter().any(|entry| entry.enabled && entry.role.is_admin()) { Ok(()) } else { Err(AccessPolicyError::LastEnabledAdmin) }
    }

    /// Validate an optimistic-concurrency update against this revision.
    pub fn check_revision(&self, expected: u64) -> Result<(), AccessPolicyError> {
        (expected == self.revision).then_some(()).ok_or(AccessPolicyError::RevisionConflict { expected, actual: self.revision })
    }
}

/// Normalize only surrounding whitespace and the domain portion of an email.
/// Local-part dots and plus tags are deliberately preserved.
pub fn normalize_email(input: &str) -> Result<String, AccessPolicyError> {
    let trimmed = input.trim();
    let (local, domain) = trimmed.split_once('@').ok_or(AccessPolicyError::InvalidEmail(input.into()))?;
    if local.is_empty() || domain.is_empty() || domain.contains('@') || local.chars().any(|c| c.is_ascii_whitespace() || c.is_ascii_control()) {
        return Err(AccessPolicyError::InvalidEmail(input.into()));
    }
    if !local.bytes().all(|c| c.is_ascii_alphanumeric() || b".!#$%&'*+-/=?^_`{|}~".contains(&c)) || local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return Err(AccessPolicyError::InvalidEmail(input.into()));
    }
    let labels = domain.split('.').collect::<Vec<_>>();
    if labels.len() < 2 || labels.iter().any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-') || !label.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')) {
        return Err(AccessPolicyError::InvalidEmail(input.into()));
    }
    Ok(format!("{local}@{}", domain.to_ascii_lowercase()))
}

/// Immutable binding between a stable owner ID and an external identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityBinding {
    /// Stable owner ID used for provenance and coordination.
    pub owner_id: OwnerId,
    /// Immutable issuer/subject binding; never edited through membership APIs.
    pub subject_binding: SubjectBinding,
    /// Mailbox observed when the binding was established, for audit context only.
    pub email_at_binding: String,
}

/// Versioned store kept separately from editable memberships.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityBindingStore {
    /// On-disk schema version.
    pub schema_version: u32,
    /// Immutable binding records.
    pub bindings: Vec<IdentityBinding>,
}

impl IdentityBindingStore {
    /// Construct the separate immutable binding store and validate its records.
    pub fn new(schema_version: u32, bindings: Vec<IdentityBinding>) -> Result<Self, AccessPolicyError> {
        if schema_version != ACCESS_SCHEMA_VERSION { return Err(AccessPolicyError::UnsupportedSchema(schema_version)); }
        let mut owners = BTreeSet::new();
        let mut subjects = HashSet::new();
        for binding in &bindings {
            binding.subject_binding.validate().map_err(|error| AccessPolicyError::InvalidBinding(error.to_string()))?;
            normalize_email(&binding.email_at_binding)?;
            if !owners.insert(binding.owner_id.clone()) { return Err(AccessPolicyError::DuplicateOwner(binding.owner_id.to_string())); }
            if !subjects.insert(binding.subject_binding.clone()) { return Err(AccessPolicyError::DuplicateSubject); }
        }
        Ok(Self { schema_version, bindings })
    }
}

/// Effective ceiling recorded for a hub-issued agent grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantCeiling {
    /// Stable owner to whom the grant belongs.
    pub owner_id: OwnerId,
    /// Maximum role the grant may exercise; current policy can only reduce it.
    pub role: AccessRole,
}

/// Actor kinds used by access-policy audit records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditActor {
    /// Authenticated administrator performing an API edit.
    Admin { owner_id: OwnerId },
    /// Operator/file event from coordinated manual editing; not a fabricated Google action.
    Operator { name: String },
    /// File watcher or startup recovery event without a human identity.
    File,
}

/// Secret-free audit record for one policy revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessAuditRecord {
    /// Resulting policy revision.
    pub revision: u64,
    /// Actor category and stable identifier where one exists.
    pub actor: AuditActor,
    /// RFC 3339 event time supplied by the persistence layer.
    pub occurred_at: String,
    /// Membership state before the edit.
    pub before: Option<MembershipEntry>,
    /// Membership state after the edit.
    pub after: Option<MembershipEntry>,
}

/// Validation failures for access-control records.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AccessPolicyError {
    /// Unknown schema version.
    #[error("unsupported access schema version {0}")]
    UnsupportedSchema(u32),
    /// Revisions start at one.
    #[error("access policy revision must be greater than zero")]
    InvalidRevision,
    /// Email is not accepted by the policy grammar.
    #[error("invalid email address: {0}")]
    InvalidEmail(String),
    /// Two entries normalize to the same mailbox.
    #[error("duplicate normalized email: {0}")]
    DuplicateEmail(String),
    /// No enabled administrator would remain.
    #[error("at least one enabled admin must remain")]
    LastEnabledAdmin,
    /// If-Match/revision did not match.
    #[error("access policy revision conflict: expected {expected}, actual {actual}")]
    RevisionConflict { expected: u64, actual: u64 },
    /// JSON was malformed or violated the closed schema.
    #[error("invalid access policy document: {0}")]
    InvalidDocument(String),
    /// An immutable binding failed core provenance validation.
    #[error("invalid immutable identity binding: {0}")]
    InvalidBinding(String),
    /// An owner ID was bound more than once.
    #[error("duplicate immutable owner ID: {0}")]
    DuplicateOwner(String),
    /// An issuer/subject pair was bound more than once.
    #[error("duplicate immutable issuer/subject binding")]
    DuplicateSubject,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(email: &str, role: AccessRole) -> MembershipEntry { MembershipEntry { email: email.into(), role, enabled: true } }

    #[test]
    fn normalizes_only_outer_whitespace_and_domain_case() {
        let policy = AccessPolicy::new(1, 1, vec![entry("  A.b+tag@Example.COM ", AccessRole::Readonly)]).expect("valid");
        assert_eq!(policy.users[0].email, "A.b+tag@example.com");
    }

    #[test]
    fn rejects_alias_collisions_unknown_fields_and_invalid_email() {
        assert!(matches!(AccessPolicy::new(1, 1, vec![entry("a+b@example.com", AccessRole::Write), entry("a+b@example.com", AccessRole::Readonly)]), Err(AccessPolicyError::DuplicateEmail(_))));
        assert!(AccessPolicy::from_json(r#"{"schema_version":1,"revision":1,"users":[],"secret":"nope"}"#).is_err());
        assert!(normalize_email("a..b@example.com").is_err());
    }

    #[test]
    fn serialized_models_have_no_secret_bearing_fields() {
        let policy = AccessPolicy::new(1, 1, vec![entry("admin@example.com", AccessRole::Admin)]).expect("valid");
        let json = serde_json::to_string(&policy).expect("json");
        assert!(!json.contains("token") && !json.contains("secret") && !json.contains("credential"));
    }

    #[test]
    fn immutable_bindings_are_separate_and_unique() {
        let binding = IdentityBinding {
            owner_id: OwnerId::new("owner-1").expect("owner"),
            subject_binding: SubjectBinding::parse("https://accounts.google.com", "subject-1").expect("subject"),
            email_at_binding: "person@example.com".into(),
        };
        assert!(IdentityBindingStore::new(1, vec![binding.clone(), binding]).is_err());
    }

    #[test]
    fn last_enabled_admin_and_revision_are_protected() {
        let policy = AccessPolicy::new(1, 7, vec![entry("admin@example.com", AccessRole::Admin)]).expect("valid");
        assert!(policy.ensure_enabled_admin_remains().is_ok());
        let empty = AccessPolicy::new(1, 8, vec![entry("admin@example.com", AccessRole::Write)]).expect("valid");
        assert_eq!(empty.ensure_enabled_admin_remains(), Err(AccessPolicyError::LastEnabledAdmin));
        assert_eq!(policy.check_revision(6), Err(AccessPolicyError::RevisionConflict { expected: 6, actual: 7 }));
    }
}
