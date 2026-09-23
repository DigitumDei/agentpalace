//! Durable, fail-closed access policy for the demo hub.
//!
//! Policy updates use a cross-process advisory lock, revision compare-and-swap,
//! validation before replacement, and an fsynced sibling file followed by an
//! atomic replacement. Identity bindings are separate from editable email roles.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use agentpalace_core::{
    AuthenticatedOwner, EmailAtWrite, Issuer, OwnerId, Subject, SubjectBinding,
};
use fs4::FileExt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{AdmissionIdentity, VerifiedIdentity};

/// A user's effective hub role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessRole {
    /// May administer the hub's access list.
    Admin,
    /// May read and write authorized demo data.
    Write,
    /// May read authorized demo data.
    Readonly,
}

/// One email-address policy row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessEntry {
    /// The role granted while the entry is enabled.
    pub role: AccessRole,
    /// Disabled entries remain in the policy but cannot authenticate.
    pub enabled: bool,
    /// Explicit administrator attestation for a non-Gmail mailbox.
    #[serde(default)]
    pub mailbox_proven: bool,
}

/// One-time initial administrator used only when the policy file is absent.
#[derive(Debug, Clone)]
pub struct BootstrapAdmin {
    /// The configured tester email address.
    pub email: String,
    /// Operator-attested mailbox proof for a non-Gmail tester address.
    pub mailbox_proven: bool,
}

/// Current validated policy view returned by reads and successful edits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessPolicySnapshot {
    /// Monotonic compare-and-swap revision.
    pub revision: u64,
    /// Canonical email address to role mapping.
    pub users: BTreeMap<String, AccessEntry>,
}

/// Effective admission and role for a verified upstream identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    /// Provider-neutral owner identity used by the rest of the gateway.
    pub admission: AdmissionIdentity,
    /// Current role from the durable policy.
    pub role: AccessRole,
}

/// Errors from loading, validating, coordinating, or updating access policy.
#[derive(Debug, Error)]
pub enum AccessPolicyError {
    /// An existing policy or binding file could not be read.
    #[error("access policy storage is unavailable")]
    Storage(#[source] io::Error),
    /// A policy edit used a stale revision.
    #[error("access policy revision conflict: expected {expected}, found {actual}")]
    RevisionConflict {
        /// Revision supplied by the caller.
        expected: u64,
        /// Current durable revision.
        actual: u64,
    },
    /// A malformed or unsafe policy was rejected.
    #[error("invalid access policy: {0}")]
    Invalid(String),
    /// The last enabled administrator cannot be disabled or demoted.
    #[error("the access policy must retain at least one enabled administrator")]
    LastEnabledAdmin,
    /// The subject is already bound to another immutable owner ID.
    #[error("issuer/subject is already bound to a different owner")]
    BindingConflict,
    /// The email no longer matches the immutable binding's recorded email.
    #[error("verified email changed; an administrator must update the identity binding")]
    EmailChanged,
}

/// Persistent policy store. File locks coordinate other processes using these paths.
pub struct AccessPolicyStore {
    policy_path: PathBuf,
    bindings_path: PathBuf,
    audit_path: PathBuf,
    lock_path: PathBuf,
    bootstrap_marker_path: PathBuf,
    process_lock: Mutex<()>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    format: u32,
    revision: u64,
    users: BTreeMap<String, AccessEntry>,
    #[serde(default)]
    audit: Vec<AuditEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingsFile {
    format: u32,
    bindings: BTreeMap<String, BindingRecord>,
    #[serde(default)]
    audit: Vec<AuditEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingRecord {
    owner_id: OwnerId,
    email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditEntry {
    actor: String,
    occurred_at: String,
    action: String,
    before: serde_json::Value,
    after: serde_json::Value,
}

impl AccessPolicyStore {
    /// Open the store, creating a tester admin only when the policy file is missing.
    /// An existing malformed or unreadable file always fails closed.
    pub fn open(
        policy_path: impl Into<PathBuf>,
        bindings_path: impl Into<PathBuf>,
        audit_path: impl Into<PathBuf>,
        bootstrap: Option<BootstrapAdmin>,
    ) -> Result<Self, AccessPolicyError> {
        let policy_path = policy_path.into();
        let store = Self {
            lock_path: policy_path.with_extension("json.lock"),
            bootstrap_marker_path: policy_path.with_extension("json.bootstrap-used"),
            policy_path,
            bindings_path: bindings_path.into(),
            audit_path: audit_path.into(),
            process_lock: Mutex::new(()),
        };
        {
            let _guard = store.process_lock.lock().map_err(|_| storage("policy mutex poisoned"))?;
            let _file_lock = store.lock_file()?;
            match store.read_policy() {
                Ok(_) => {}
                Err(AccessPolicyError::Storage(error))
                    if error.kind() == io::ErrorKind::NotFound =>
                {
                    match fs::symlink_metadata(&store.bootstrap_marker_path) {
                        Ok(_) => {
                            return Err(AccessPolicyError::Invalid(
                                "initial bootstrap has already been used".into(),
                            ));
                        }
                        Err(marker_error) if marker_error.kind() == io::ErrorKind::NotFound => {}
                        Err(marker_error) => return Err(AccessPolicyError::Storage(marker_error)),
                    }
                    let bootstrap = bootstrap.ok_or(AccessPolicyError::Storage(error))?;
                    let email = normalize_email(&bootstrap.email)?;
                    let mut users = BTreeMap::new();
                    users.insert(
                        email.clone(),
                        AccessEntry {
                            role: AccessRole::Admin,
                            enabled: true,
                            mailbox_proven: bootstrap.mailbox_proven,
                        },
                    );
                    let mut policy =
                        PolicyFile { format: 1, revision: 1, users, audit: Vec::new() };
                    policy.audit.push(AuditEntry {
                        actor: "bootstrap".into(),
                        occurred_at: timestamp(),
                        action: "bootstrap_admin_created".into(),
                        before: serde_json::Value::Null,
                        after: serde_json::to_value(&policy.users).map_err(json_storage)?,
                    });
                    store.write_policy(&policy)?;
                    write_json_atomic(
                        &store.bootstrap_marker_path,
                        &serde_json::json!({
                            "created_at": timestamp(),
                        }),
                    )?;
                }
                Err(error) => return Err(error),
            }
            match store.read_bindings() {
                Ok(_) => {}
                Err(AccessPolicyError::Storage(error))
                    if error.kind() == io::ErrorKind::NotFound =>
                {
                    let bindings = BTreeMap::new();
                    store.write_bindings(&BindingsFile {
                        format: 1,
                        bindings: bindings.clone(),
                        audit: vec![AuditEntry {
                            actor: "bootstrap".into(),
                            occurred_at: timestamp(),
                            action: "bindings_initialized".into(),
                            before: serde_json::Value::Null,
                            after: serde_json::to_value(&bindings).map_err(json_storage)?,
                        }],
                    })?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(store)
    }

    /// Resolve an identity against the latest durable policy on every call.
    pub fn resolve(
        &self,
        identity: &VerifiedIdentity,
    ) -> Result<Option<PolicyDecision>, AccessPolicyError> {
        let _guard = self.guard()?;
        let _file_lock = self.lock_file()?;
        let policy = self.read_policy()?;
        let email = match normalize_email(&identity.email) {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };
        let binding = SubjectBinding::parse(identity.issuer.clone(), identity.subject.clone())
            .map_err(|error| AccessPolicyError::Invalid(error.to_string()))?;
        let key = binding_key(&binding);
        let mut bindings = self.read_bindings()?;
        if bindings.bindings.get(&key).is_some_and(|record| record.email != email) {
            return Err(AccessPolicyError::EmailChanged);
        }
        let Some(entry) = policy.users.get(&email).filter(|entry| entry.enabled) else {
            return Ok(None);
        };
        if !mailbox_is_proven(&email, entry.mailbox_proven) {
            return Ok(None);
        }
        let owner_id = match bindings.bindings.get(&key) {
            Some(record) => record.owner_id.clone(),
            None => {
                if bindings
                    .bindings
                    .iter()
                    .any(|(existing_key, record)| existing_key != &key && record.email == email)
                {
                    return Err(AccessPolicyError::BindingConflict);
                }
                stable_owner_id(&binding)
            }
        };
        let owner = AuthenticatedOwner::new(
            owner_id.clone(),
            Issuer::new(identity.issuer.clone())
                .map_err(|error| AccessPolicyError::Invalid(error.to_string()))?,
            Subject::new(identity.subject.clone())
                .map_err(|error| AccessPolicyError::Invalid(error.to_string()))?,
            EmailAtWrite::new(identity.email.clone())
                .map_err(|error| AccessPolicyError::Invalid(error.to_string()))?,
        );
        if !bindings.bindings.contains_key(&key) {
            let before = serde_json::to_value(&bindings.bindings).map_err(json_storage)?;
            bindings
                .bindings
                .insert(key, BindingRecord { owner_id: owner_id.clone(), email: email.clone() });
            let after = serde_json::to_value(&bindings.bindings).map_err(json_storage)?;
            bindings.audit.push(AuditEntry {
                actor: "oidc-admission".into(),
                occurred_at: timestamp(),
                action: "subject_bound".into(),
                before: before.clone(),
                after,
            });
            self.write_bindings(&bindings)?;
            let _ = self.append_audit(
                "oidc-admission",
                "subject_bound",
                before,
                serde_json::json!({"issuer": binding.issuer.as_str(), "subject": binding.subject.as_str(),
                    "owner_id": owner_id.as_str(), "email": email}),
            );
        }
        Ok(Some(PolicyDecision {
            admission: AdmissionIdentity::new(owner_id, owner),
            role: entry.role,
        }))
    }

    /// Return the current role for an immutable owner ID, reloading disk state.
    pub fn role_for_owner(
        &self,
        owner_id: &OwnerId,
    ) -> Result<Option<AccessRole>, AccessPolicyError> {
        let _guard = self.guard()?;
        let _file_lock = self.lock_file()?;
        let policy = self.read_policy()?;
        let bindings = self.read_bindings()?;
        let email = bindings
            .bindings
            .values()
            .find(|binding| &binding.owner_id == owner_id)
            .map(|binding| binding.email.as_str());
        Ok(email.and_then(|email| {
            policy
                .users
                .get(email)
                .filter(|entry| entry.enabled && mailbox_is_proven(email, entry.mailbox_proven))
                .map(|entry| entry.role)
        }))
    }

    /// Resolve a normalized policy email to its already-bound immutable owner ID.
    /// An address that has never completed a successful admission has no owner yet.
    pub fn owner_id_for_email(&self, email: &str) -> Result<Option<OwnerId>, AccessPolicyError> {
        let email = normalize_email(email)?;
        let _guard = self.guard()?;
        let _file_lock = self.lock_file()?;
        let bindings = self.read_bindings()?;
        Ok(bindings
            .bindings
            .values()
            .find(|binding| binding.email == email)
            .map(|binding| binding.owner_id.clone()))
    }

    /// Read and validate the latest policy snapshot.
    pub fn snapshot(&self) -> Result<AccessPolicySnapshot, AccessPolicyError> {
        let _guard = self.guard()?;
        let _file_lock = self.lock_file()?;
        let policy = self.read_policy()?;
        Ok(AccessPolicySnapshot { revision: policy.revision, users: policy.users })
    }

    /// Replace the email-to-role map after revision and last-admin checks.
    pub fn replace(
        &self,
        expected_revision: u64,
        actor: &str,
        users: BTreeMap<String, AccessEntry>,
    ) -> Result<AccessPolicySnapshot, AccessPolicyError> {
        let _guard = self.guard()?;
        let _file_lock = self.lock_file()?;
        let mut policy = self.read_policy()?;
        if policy.revision != expected_revision {
            return Err(AccessPolicyError::RevisionConflict {
                expected: expected_revision,
                actual: policy.revision,
            });
        }
        let users = canonicalize_users(users)?;
        validate_users(&users)?;
        if !users.values().any(|entry| entry.enabled && entry.role == AccessRole::Admin) {
            return Err(AccessPolicyError::LastEnabledAdmin);
        }
        let before = serde_json::to_value(&policy.users).map_err(json_storage)?;
        let after = serde_json::to_value(&users).map_err(json_storage)?;
        policy.revision = policy
            .revision
            .checked_add(1)
            .ok_or_else(|| AccessPolicyError::Invalid("revision overflow".into()))?;
        policy.users = users;
        policy.audit.push(AuditEntry {
            actor: validate_actor(actor)?,
            occurred_at: timestamp(),
            action: "policy_replaced".into(),
            before,
            after,
        });
        self.write_policy(&policy)?;
        Ok(AccessPolicySnapshot { revision: policy.revision, users: policy.users })
    }

    /// Bind an issuer/subject pair to its immutable owner ID.
    pub fn bind_subject(
        &self,
        binding: SubjectBinding,
        owner_id: OwnerId,
        email: &str,
        actor: &str,
    ) -> Result<(), AccessPolicyError> {
        binding.validate().map_err(|error| AccessPolicyError::Invalid(error.to_string()))?;
        let email = normalize_email(email)?;
        let actor = validate_actor(actor)?;
        let _guard = self.guard()?;
        let _file_lock = self.lock_file()?;
        let mut bindings = self.read_bindings()?;
        let key = binding_key(&binding);
        if let Some(existing) = bindings.bindings.get(&key) {
            return if existing.owner_id == owner_id && existing.email == email {
                Ok(())
            } else {
                Err(AccessPolicyError::BindingConflict)
            };
        }
        if bindings
            .bindings
            .values()
            .any(|existing| existing.email == email || existing.owner_id == owner_id)
        {
            return Err(AccessPolicyError::BindingConflict);
        }
        let before = serde_json::to_value(&bindings.bindings).map_err(json_storage)?;
        bindings
            .bindings
            .insert(key, BindingRecord { owner_id: owner_id.clone(), email: email.clone() });
        let after = serde_json::to_value(&bindings.bindings).map_err(json_storage)?;
        bindings.audit.push(AuditEntry {
            actor: actor.clone(),
            occurred_at: timestamp(),
            action: "subject_bound".into(),
            before: before.clone(),
            after,
        });
        self.write_bindings(&bindings)?;
        let _ = self.append_audit(&actor, "subject_bound", before,
            serde_json::json!({"issuer": binding.issuer.as_str(), "subject": binding.subject.as_str(),
                "owner_id": owner_id.as_str(), "email": email}));
        Ok(())
    }

    /// Explicitly update the email attached to an immutable subject binding.
    pub fn update_binding_email(
        &self,
        binding: &SubjectBinding,
        expected_email: &str,
        new_email: &str,
        actor: &str,
    ) -> Result<(), AccessPolicyError> {
        let expected_email = normalize_email(expected_email)?;
        let new_email = normalize_email(new_email)?;
        let actor = validate_actor(actor)?;
        let _guard = self.guard()?;
        let _file_lock = self.lock_file()?;
        let mut bindings = self.read_bindings()?;
        let target_key = binding_key(binding);
        let existing_email = bindings
            .bindings
            .get(&target_key)
            .ok_or(AccessPolicyError::BindingConflict)?
            .email
            .clone();
        if existing_email != expected_email {
            return Err(AccessPolicyError::EmailChanged);
        }
        if bindings
            .bindings
            .iter()
            .any(|(key, other)| key != &target_key && other.email == new_email)
        {
            return Err(AccessPolicyError::BindingConflict);
        }
        let before = serde_json::to_value(&bindings.bindings).map_err(json_storage)?;
        let record = bindings.bindings.get_mut(&target_key).expect("checked above");
        record.email = new_email.clone();
        let after = serde_json::to_value(&bindings.bindings).map_err(json_storage)?;
        bindings.audit.push(AuditEntry {
            actor: actor.clone(),
            occurred_at: timestamp(),
            action: "subject_email_updated".into(),
            before: before.clone(),
            after,
        });
        self.write_bindings(&bindings)?;
        let _ = self.append_audit(
            &actor,
            "subject_email_updated",
            before,
            serde_json::json!({"email": new_email}),
        );
        Ok(())
    }

    fn guard(&self) -> Result<std::sync::MutexGuard<'_, ()>, AccessPolicyError> {
        self.process_lock.lock().map_err(|_| storage("policy mutex poisoned"))
    }

    fn read_policy(&self) -> Result<PolicyFile, AccessPolicyError> {
        let bytes = read_bounded(&self.policy_path)?;
        let policy: PolicyFile = serde_json::from_slice(&bytes)
            .map_err(|error| AccessPolicyError::Invalid(error.to_string()))?;
        if policy.format != 1 || policy.revision == 0 {
            return Err(AccessPolicyError::Invalid("unsupported policy format or revision".into()));
        }
        validate_users(&policy.users)?;
        let users_value = serde_json::to_value(&policy.users).map_err(json_storage)?;
        validate_audit_chain(&policy.audit, &users_value, policy.revision)?;
        if !policy.users.values().any(|entry| entry.enabled && entry.role == AccessRole::Admin) {
            return Err(AccessPolicyError::LastEnabledAdmin);
        }
        Ok(policy)
    }

    fn read_bindings(&self) -> Result<BindingsFile, AccessPolicyError> {
        let bytes = read_bounded(&self.bindings_path)?;
        let bindings: BindingsFile = serde_json::from_slice(&bytes)
            .map_err(|error| AccessPolicyError::Invalid(error.to_string()))?;
        if bindings.format != 1 {
            return Err(AccessPolicyError::Invalid("unsupported binding format".into()));
        }
        let value = serde_json::to_value(&bindings.bindings).map_err(json_storage)?;
        validate_audit_chain(&bindings.audit, &value, bindings.audit.len() as u64)?;
        let mut owners = std::collections::BTreeSet::new();
        let mut emails = std::collections::BTreeSet::new();
        for (key, record) in &bindings.bindings {
            let email = normalize_email(&record.email)?;
            if email != record.email
                || !emails.insert(email)
                || !owners.insert(record.owner_id.clone())
            {
                return Err(AccessPolicyError::Invalid(
                    "duplicate or non-canonical identity binding".into(),
                ));
            }
            let Some((issuer, subject)) = key.split_once('\0') else {
                return Err(AccessPolicyError::Invalid("identity binding key is malformed".into()));
            };
            let binding = SubjectBinding::parse(issuer, subject)
                .map_err(|error| AccessPolicyError::Invalid(error.to_string()))?;
            if binding_key(&binding) != *key {
                return Err(AccessPolicyError::Invalid(
                    "identity binding key is not canonical".into(),
                ));
            }
        }
        Ok(bindings)
    }

    fn write_policy(&self, policy: &PolicyFile) -> Result<(), AccessPolicyError> {
        validate_users(&policy.users)?;
        write_json_atomic(&self.policy_path, policy)
    }

    fn write_bindings(&self, bindings: &BindingsFile) -> Result<(), AccessPolicyError> {
        write_json_atomic(&self.bindings_path, bindings)
    }

    fn append_audit(
        &self,
        actor: &str,
        action: &str,
        before: serde_json::Value,
        after: serde_json::Value,
    ) -> Result<(), AccessPolicyError> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.audit_path)
            .map_err(AccessPolicyError::Storage)?;
        serde_json::to_writer(
            &mut file,
            &AuditEntry {
                actor: actor.into(),
                occurred_at: timestamp(),
                action: action.into(),
                before,
                after,
            },
        )
        .map_err(json_storage)?;
        file.write_all(b"\n").and_then(|_| file.sync_all()).map_err(AccessPolicyError::Storage)
    }

    fn lock_file(&self) -> Result<PolicyFileLock, AccessPolicyError> {
        if let Some(parent) = self.lock_path.parent() {
            fs::create_dir_all(parent).map_err(AccessPolicyError::Storage)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&self.lock_path)
            .map_err(AccessPolicyError::Storage)?;
        file.lock_exclusive().map_err(AccessPolicyError::Storage)?;
        Ok(PolicyFileLock { _file: file })
    }
}

struct PolicyFileLock {
    // Keeping the handle alive holds the advisory lock; dropping it releases the OS lock.
    _file: File,
}

fn validate_audit_chain(
    audit: &[AuditEntry],
    current: &serde_json::Value,
    revision: u64,
) -> Result<(), AccessPolicyError> {
    if audit.is_empty() || audit.len() as u64 != revision {
        return Err(AccessPolicyError::Invalid(
            "audit history does not match policy revision".into(),
        ));
    }
    let mut prior_after: Option<&serde_json::Value> = None;
    for event in audit {
        if event.actor.trim().is_empty()
            || event.actor.len() > 256
            || event.actor.chars().any(char::is_control)
            || event.occurred_at.parse::<u64>().is_err()
            || event.action.trim().is_empty()
        {
            return Err(AccessPolicyError::Invalid("policy audit event is malformed".into()));
        }
        match prior_after {
            None if !event.before.is_null() => {
                return Err(AccessPolicyError::Invalid(
                    "first audit event must have a null before value".into(),
                ));
            }
            Some(previous) if &event.before != previous => {
                return Err(AccessPolicyError::Invalid(
                    "policy audit history is discontinuous".into(),
                ));
            }
            _ => {}
        }
        prior_after = Some(&event.after);
    }
    if prior_after != Some(current) {
        return Err(AccessPolicyError::Invalid(
            "policy changed without a matching operator audit event".into(),
        ));
    }
    Ok(())
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, AccessPolicyError> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(AccessPolicyError::Storage)?
        .take(4 * 1024 * 1024)
        .read_to_end(&mut bytes)
        .map_err(AccessPolicyError::Storage)?;
    if bytes.len() >= 4 * 1024 * 1024 {
        return Err(AccessPolicyError::Invalid("policy file is too large".into()));
    }
    Ok(bytes)
}

fn normalize_email(value: &str) -> Result<String, AccessPolicyError> {
    let value = value.trim();
    let Some((local, domain)) = value.rsplit_once('@') else {
        return Err(AccessPolicyError::Invalid("email must contain one @".into()));
    };
    if local.is_empty()
        || domain.is_empty()
        || local.contains('@')
        || domain.contains('@')
        || value.chars().any(|ch| ch.is_ascii_control() || ch.is_ascii_whitespace())
    {
        return Err(AccessPolicyError::Invalid("email address is malformed".into()));
    }
    let normalized = format!("{local}@{}", domain.to_ascii_lowercase());
    EmailAtWrite::new(normalized.clone())
        .map_err(|error| AccessPolicyError::Invalid(error.to_string()))?;
    Ok(normalized)
}

fn canonicalize_users(
    users: BTreeMap<String, AccessEntry>,
) -> Result<BTreeMap<String, AccessEntry>, AccessPolicyError> {
    let mut canonical = BTreeMap::new();
    for (email, entry) in users {
        let email = normalize_email(&email)?;
        if canonical.insert(email.clone(), entry).is_some() {
            return Err(AccessPolicyError::Invalid(format!(
                "duplicate email after normalization: {email}"
            )));
        }
    }
    Ok(canonical)
}

fn validate_users(users: &BTreeMap<String, AccessEntry>) -> Result<(), AccessPolicyError> {
    for email in users.keys() {
        if normalize_email(email)? != *email {
            return Err(AccessPolicyError::Invalid("email keys must be canonical".into()));
        }
    }
    Ok(())
}

fn mailbox_is_proven(email: &str, mailbox_proven: bool) -> bool {
    email.rsplit_once('@').is_some_and(|(_, domain)| domain.eq_ignore_ascii_case("gmail.com"))
        || mailbox_proven
}

fn binding_key(binding: &SubjectBinding) -> String {
    format!("{}\0{}", binding.issuer.as_str(), binding.subject.as_str())
}

fn stable_owner_id(binding: &SubjectBinding) -> OwnerId {
    let digest = blake3::hash(binding_key(binding).as_bytes());
    OwnerId::new(format!("owner-{}", &digest.to_hex()[..48])).expect("fixed safe owner id")
}

fn validate_actor(actor: &str) -> Result<String, AccessPolicyError> {
    let actor = actor.trim();
    if actor.is_empty() || actor.len() > 256 || actor.chars().any(char::is_control) {
        return Err(AccessPolicyError::Invalid("audit actor is malformed".into()));
    }
    Ok(actor.to_owned())
}

fn timestamp() -> String {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs().to_string()
}

fn storage(message: &str) -> AccessPolicyError {
    AccessPolicyError::Storage(io::Error::other(message))
}
fn json_storage(error: serde_json::Error) -> AccessPolicyError {
    storage(&error.to_string())
}

fn write_json_atomic<T: Serialize + serde::de::DeserializeOwned>(
    path: &Path,
    value: &T,
) -> Result<(), AccessPolicyError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(AccessPolicyError::Storage)?;
    let bytes = serde_json::to_vec_pretty(value).map_err(json_storage)?;
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(AccessPolicyError::Storage)?;
    file.write_all(&bytes)
        .and_then(|_| file.as_file().sync_all())
        .map_err(AccessPolicyError::Storage)?;
    let _: T = serde_json::from_slice(&bytes).map_err(json_storage)?;
    file.persist(path).map_err(|error| storage(&error.error.to_string()))?;
    sync_directory(parent).map_err(AccessPolicyError::Storage)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}
#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::BTreeMap,
        sync::atomic::{AtomicU64, Ordering},
    };

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "agentpalace-access-policy-{}-{}",
                std::process::id(),
                TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed),
            ));
            fs::create_dir_all(&path).expect("create test directory");
            Self(path)
        }
        fn paths(&self) -> (PathBuf, PathBuf, PathBuf) {
            (self.0.join("access.json"), self.0.join("bindings.json"), self.0.join("audit.jsonl"))
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn open(dir: &TestDir, email: &str) -> AccessPolicyStore {
        let (policy, bindings, audit) = dir.paths();
        AccessPolicyStore::open(
            policy,
            bindings,
            audit,
            Some(BootstrapAdmin { email: email.into(), mailbox_proven: false }),
        )
        .expect("open policy store")
    }

    fn entry(role: AccessRole, enabled: bool) -> AccessEntry {
        AccessEntry { role, enabled, mailbox_proven: false }
    }

    fn identity(email: &str, subject: &str) -> VerifiedIdentity {
        VerifiedIdentity {
            email: email.into(),
            subject: subject.into(),
            issuer: "https://accounts.google.com".into(),
        }
    }

    #[test]
    fn bootstrap_only_creates_admin_for_a_missing_policy() {
        let dir = TestDir::new();
        let store = open(&dir, " Tester@GMAIL.COM ");
        let snapshot = store.snapshot().expect("snapshot");
        assert_eq!(snapshot.revision, 1);
        assert_eq!(snapshot.users.keys().next().expect("admin"), "Tester@gmail.com");

        let (policy, bindings, audit) = dir.paths();
        let reopened = AccessPolicyStore::open(
            policy.clone(),
            bindings,
            audit,
            Some(BootstrapAdmin { email: "attacker@gmail.com".into(), mailbox_proven: false }),
        )
        .expect("reopen");
        assert_eq!(
            reopened
                .snapshot()
                .expect("snapshot")
                .users
                .keys()
                .next()
                .expect("test operation should succeed"),
            "Tester@gmail.com"
        );
        let second_bindings = dir.0.join("b2.json");
        let second_audit = dir.0.join("a2.json");
        assert!(
            AccessPolicyStore::open(
                policy.clone(),
                second_bindings.clone(),
                second_audit.clone(),
                None
            )
            .is_ok()
        );
        fs::remove_file(&policy).expect("remove policy after bootstrap");
        assert!(matches!(
            AccessPolicyStore::open(
                policy,
                second_bindings,
                second_audit,
                Some(BootstrapAdmin { email: "attacker@gmail.com".into(), mailbox_proven: false }),
            ),
            Err(AccessPolicyError::Invalid(_))
        ));
    }

    #[test]
    fn non_gmail_bootstrap_requires_explicit_mailbox_proof() {
        let dir = TestDir::new();
        let (policy, bindings, audit) = dir.paths();
        let denied = AccessPolicyStore::open(
            policy.clone(),
            bindings.clone(),
            audit.clone(),
            Some(BootstrapAdmin { email: "tester@example.org".into(), mailbox_proven: false }),
        )
        .expect("test operation should succeed");
        assert!(
            denied
                .resolve(&identity("tester@example.org", "workspace-subject"))
                .expect("test operation should succeed")
                .is_none()
        );

        fs::remove_file(&policy).expect("test operation should succeed");
        fs::remove_file(&bindings).expect("test operation should succeed");
        fs::remove_file(policy.with_extension("json.bootstrap-used"))
            .expect("test operation should succeed");
        let proven = AccessPolicyStore::open(
            policy,
            bindings,
            audit,
            Some(BootstrapAdmin { email: "tester@example.org".into(), mailbox_proven: true }),
        )
        .expect("test operation should succeed");
        assert!(
            proven
                .resolve(&identity("tester@example.org", "workspace-subject"))
                .expect("test operation should succeed")
                .is_some()
        );
    }

    #[test]
    fn existing_malformed_policy_never_bootstraps() {
        let dir = TestDir::new();
        let (policy, bindings, audit) = dir.paths();
        fs::write(&policy, b"{ malformed").expect("write malformed file");
        assert!(matches!(
            AccessPolicyStore::open(
                policy.clone(),
                bindings,
                audit,
                Some(BootstrapAdmin { email: "admin@gmail.com".into(), mailbox_proven: false })
            ),
            Err(AccessPolicyError::Invalid(_))
        ));
        assert_eq!(fs::read(&policy).expect("still malformed"), b"{ malformed");
    }

    #[test]
    fn normalization_preserves_local_part_and_does_not_fold_aliases() {
        assert_eq!(
            normalize_email(" User.Name+tag@GMAIL.COM ").expect("test operation should succeed"),
            "User.Name+tag@gmail.com"
        );
        assert_ne!(
            normalize_email("User.Name+tag@gmail.com").expect("test operation should succeed"),
            normalize_email("username@gmail.com").expect("test operation should succeed")
        );
        let dir = TestDir::new();
        let store = open(&dir, "Person@gmail.com");
        assert!(
            store
                .resolve(&identity("person@gmail.com", "s1"))
                .expect("test operation should succeed")
                .is_none()
        );
        assert!(
            store
                .resolve(&identity("Person@gmail.com", "s1"))
                .expect("test operation should succeed")
                .is_some()
        );
    }

    #[test]
    fn revision_cas_and_last_enabled_admin_are_enforced() {
        let dir = TestDir::new();
        let store = open(&dir, "admin@gmail.com");
        let initial = store.snapshot().expect("test operation should succeed");
        assert!(matches!(
            store.replace(initial.revision, "admin@gmail.com", BTreeMap::new()),
            Err(AccessPolicyError::LastEnabledAdmin)
        ));
        let mut users = initial.users.clone();
        users.insert("writer@gmail.com".into(), entry(AccessRole::Write, true));
        let changed = store
            .replace(initial.revision, "admin@gmail.com", users.clone())
            .expect("test operation should succeed");
        assert_eq!(changed.revision, initial.revision + 1);
        assert!(matches!(
            store.replace(initial.revision, "admin@gmail.com", users),
            Err(AccessPolicyError::RevisionConflict { .. })
        ));
    }

    #[test]
    fn roles_are_live_and_identity_binding_survives_restart() {
        let dir = TestDir::new();
        let store = open(&dir, "admin@gmail.com");
        let identity = identity("admin@gmail.com", "stable-subject");
        let first = store
            .resolve(&identity)
            .expect("test operation should succeed")
            .expect("test operation should succeed");
        assert_eq!(first.role, AccessRole::Admin);
        let owner_id = first.admission.owner.id.clone();
        assert_eq!(
            store.role_for_owner(&owner_id).expect("test operation should succeed"),
            Some(AccessRole::Admin)
        );

        let mut users = store.snapshot().expect("test operation should succeed").users;
        users.insert("backup@gmail.com".into(), entry(AccessRole::Admin, true));
        users.insert("admin@gmail.com".into(), entry(AccessRole::Readonly, true));
        let changed =
            store.replace(1, "admin@gmail.com", users).expect("test operation should succeed");
        assert_eq!(
            store.role_for_owner(&owner_id).expect("test operation should succeed"),
            Some(AccessRole::Readonly)
        );

        let (policy, bindings, audit) = dir.paths();
        let restarted = AccessPolicyStore::open(policy, bindings, audit, None)
            .expect("test operation should succeed");
        let second = restarted
            .resolve(&identity)
            .expect("test operation should succeed")
            .expect("test operation should succeed");
        assert_eq!(second.admission.owner.id, owner_id);
        assert_eq!(
            restarted.role_for_owner(&owner_id).expect("test operation should succeed"),
            Some(AccessRole::Readonly)
        );
        assert_eq!(changed.revision, 2);
    }

    #[test]
    fn subject_reassignment_is_rejected_and_email_change_requires_explicit_update() {
        let dir = TestDir::new();
        let store = open(&dir, "admin@gmail.com");
        let original = identity("admin@gmail.com", "stable-subject");
        let resolved = store
            .resolve(&original)
            .expect("test operation should succeed")
            .expect("test operation should succeed");
        let binding = resolved.admission.subject_binding.clone();
        assert!(matches!(
            store.resolve(&identity("admin@gmail.com", "replacement-subject")),
            Err(AccessPolicyError::BindingConflict)
        ));
        assert!(matches!(
            store.resolve(&identity("new@gmail.com", "stable-subject")),
            Err(AccessPolicyError::EmailChanged)
        ));

        let mut users = store.snapshot().expect("test operation should succeed").users;
        users.insert("new@gmail.com".into(), entry(AccessRole::Write, true));
        store.replace(1, "admin@gmail.com", users).expect("test operation should succeed");
        store
            .update_binding_email(&binding, "admin@gmail.com", "new@gmail.com", "admin@gmail.com")
            .expect("test operation should succeed");
        let updated = store
            .resolve(&identity("new@gmail.com", "stable-subject"))
            .expect("test operation should succeed")
            .expect("test operation should succeed");
        assert_eq!(updated.admission.owner.id, resolved.admission.owner.id);
    }

    #[test]
    fn embedded_binding_audit_survives_an_unwritable_sidecar_audit_path() {
        let dir = TestDir::new();
        let (policy, bindings, audit) = dir.paths();
        fs::create_dir_all(&audit).expect("make audit sidecar path unwritable as a file");
        let store = AccessPolicyStore::open(
            policy,
            bindings.clone(),
            audit,
            Some(BootstrapAdmin { email: "admin@gmail.com".into(), mailbox_proven: false }),
        )
        .expect("test operation should succeed");
        let admitted = store
            .resolve(&identity("admin@gmail.com", "audit-subject"))
            .expect("test operation should succeed")
            .expect("test operation should succeed");
        assert_eq!(
            store.owner_id_for_email("admin@gmail.com").expect("test operation should succeed"),
            Some(admitted.admission.owner.id)
        );
        let durable: BindingsFile =
            serde_json::from_slice(&fs::read(bindings).expect("test operation should succeed"))
                .expect("test operation should succeed");
        assert_eq!(
            durable.audit.last().expect("test operation should succeed").action,
            "subject_bound"
        );
    }

    #[test]
    fn direct_operator_file_edit_requires_a_chained_actor_audit_and_new_revision() {
        let dir = TestDir::new();
        let store = open(&dir, "admin@gmail.com");
        let (policy_path, _, _) = dir.paths();
        let original: PolicyFile =
            serde_json::from_slice(&fs::read(&policy_path).expect("policy file"))
                .expect("valid policy");
        let before = serde_json::to_value(&original.users).expect("serialize prior users");
        let mut edited = original.clone();
        edited.users.insert("writer@gmail.com".into(), entry(AccessRole::Write, true));
        edited.revision += 1;

        fs::write(
            &policy_path,
            serde_json::to_vec(&edited).expect("test operation should succeed"),
        )
        .expect("unrecorded edit");
        assert!(matches!(store.snapshot(), Err(AccessPolicyError::Invalid(_))));

        let mut repaired = original.clone();
        repaired.users = edited.users;
        repaired.revision += 1;
        let after = serde_json::to_value(&repaired.users).expect("test operation should succeed");
        repaired.audit.push(AuditEntry {
            actor: "operator@example.org".into(),
            occurred_at: timestamp(),
            action: "operator_file_edit".into(),
            before,
            after,
        });
        fs::write(
            &policy_path,
            serde_json::to_vec(&repaired).expect("test operation should succeed"),
        )
        .expect("audited operator edit");
        assert_eq!(store.snapshot().expect("test operation should succeed").revision, 2);
        assert!(matches!(
            store.replace(1, "admin@gmail.com", repaired.users),
            Err(AccessPolicyError::RevisionConflict { actual: 2, .. })
        ));
    }

    #[test]
    fn non_gmail_mailboxes_require_explicit_proof() {
        let dir = TestDir::new();
        let store = open(&dir, "admin@gmail.com");
        assert!(
            store
                .resolve(&identity("person@example.org", "external-subject"))
                .expect("test operation should succeed")
                .is_none()
        );
        let mut users = store.snapshot().expect("test operation should succeed").users;
        users.insert(
            "person@example.org".into(),
            AccessEntry { role: AccessRole::Write, enabled: true, mailbox_proven: true },
        );
        store.replace(1, "admin@gmail.com", users).expect("test operation should succeed");
        assert!(
            store
                .resolve(&identity("person@example.org", "external-subject"))
                .expect("test operation should succeed")
                .is_some()
        );
    }

    #[test]
    fn malformed_verified_identity_does_not_persist_a_binding_and_audit_has_actor_and_changes() {
        let dir = TestDir::new();
        let store = open(&dir, "admin@gmail.com");
        let mut invalid = identity("admin@gmail.com", "valid-subject");
        invalid.subject = "invalid subject".into();
        assert!(matches!(store.resolve(&invalid), Err(AccessPolicyError::Invalid(_))));
        let (_, bindings, _) = dir.paths();
        let parsed: BindingsFile =
            serde_json::from_slice(&fs::read(bindings).expect("test operation should succeed"))
                .expect("test operation should succeed");
        assert!(parsed.bindings.is_empty());

        let mut users = store.snapshot().expect("test operation should succeed").users;
        users.insert("writer@gmail.com".into(), entry(AccessRole::Write, true));
        store.replace(1, "admin@gmail.com", users).expect("test operation should succeed");
        let (policy, _, _) = dir.paths();
        let contents = fs::read_to_string(policy).expect("test operation should succeed");
        assert!(contents.contains("admin@gmail.com"));
        assert!(contents.contains("writer@gmail.com"));
        assert!(!contents.contains("client_secret"));
    }
}
