//! Shared provider-neutral provenance and authenticated owner types.
//!
//! This module introduces foundational domain types for Demo Hub (issue #159 / #160)
//! and the engine-level provenance contract derived from issue #157.
//!
//! # Core Architectural Invariants
//!
//! In accordance with `docs/Demo-Hub-Design.md` and `docs/Demo-Hub-REST-Inventory.md`:
//! 1. **Authenticated Human Owner:** The verified account holder identity established
//!    exclusively at authentication time (`owner.id`, `issuer`, `subject`, `email_at_write`).
//!    Never accepted from writable request payload fields.
//! 2. **Caller-Asserted Agent:** The agent or harness identity claimed in request payloads
//!    (`added_by`, `created_by`, `sender`, `actor`).
//! 3. **Original Source Author & References:** File paths, repository commits, and external
//!    citations associated with ingested content.
//! 4. **Storage Origin:** Distinguishes records created locally from those federated or
//!    replicated from remote palace instances.
//! 5. **Server Time:** Canonical UTC timestamp assigned by the server at write time,
//!    serialized using RFC 3339 conventions.
//! 6. **Legacy / Unknown Representation:** First-class representation for legacy installations
//!    lacking authenticated owner metadata, without fabricating ownership.
//! 7. **Separation of Concerns:** Evidence status (claim truth/verification) and execution
//!    authority (roles/permissions) are kept strictly outside this slice.

use std::fmt::{Display, Formatter};
use std::ops::Deref;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

/// Maximum length in bytes/characters for an [`OwnerId`].
pub const MAX_OWNER_ID_CHARS: usize = 128;

/// Maximum length in bytes/characters for an [`Issuer`] identifier or URL.
pub const MAX_ISSUER_CHARS: usize = 256;

/// Maximum length in bytes/characters for a provider-specific [`Subject`].
pub const MAX_SUBJECT_CHARS: usize = 256;

/// Maximum length in bytes/characters for an [`EmailAtWrite`] address (RFC 5321).
pub const MAX_EMAIL_CHARS: usize = 254;

/// Minimum length in bytes/characters for an [`EmailAtWrite`] address (e.g. `a@b`).
pub const MIN_EMAIL_CHARS: usize = 3;

/// Maximum length in bytes/characters for a caller-asserted [`AgentName`].
pub const MAX_AGENT_NAME_CHARS: usize = 128;

/// Maximum length in bytes/characters for an original [`SourceAuthor`].
pub const MAX_SOURCE_AUTHOR_CHARS: usize = 256;

/// Maximum length in bytes/characters for an original [`SourceReference`].
pub const MAX_SOURCE_REF_CHARS: usize = 2048;

/// Maximum length in bytes/characters for a [`StorageOrigin`] identifier.
pub const MAX_ORIGIN_ID_CHARS: usize = 256;

/// Maximum length in bytes/characters for an original record identifier.
pub const MAX_RECORD_ID_CHARS: usize = 256;

/// Maximum length in bytes/characters for an operation / idempotency receipt key.
pub const MAX_OPERATION_ID_CHARS: usize = 128;

/// Maximum length in bytes/characters for an RFC 3339 timestamp string.
pub const MAX_RFC3339_CHARS: usize = 64;

/// Maximum number of source references attached to a single provenance envelope.
pub const MAX_SOURCE_REFS: usize = 128;

/// Error returned when validating or parsing provenance fields.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProvenanceError {
    /// Field was empty when a non-empty value is required.
    #[error("{field} cannot be empty")]
    EmptyField {
        /// Name of the missing field.
        field: &'static str,
    },

    /// Value exceeded the maximum allowed length.
    #[error("{field} exceeds maximum length of {max} characters (got {len})")]
    ValueTooLong {
        /// Name of the overflowing field.
        field: &'static str,
        /// Actual length encountered.
        len: usize,
        /// Maximum permitted length.
        max: usize,
    },

    /// Value contains an invalid character.
    #[error("{field} contains invalid character `{ch}`")]
    InvalidCharacter {
        /// Name of the invalid field.
        field: &'static str,
        /// The offending character.
        ch: char,
    },

    /// Email address is malformed.
    #[error("invalid email address `{0}`")]
    InvalidEmail(String),

    /// RFC 3339 recording timestamp string is malformed or invalid.
    #[error("invalid RFC 3339 recording timestamp: {0}")]
    InvalidRecordingTime(String),

    /// Storage origin is malformed or invalid.
    #[error("invalid storage origin: {0}")]
    InvalidStorageOrigin(String),

    /// Too many source references in envelope.
    #[error("source references count ({count}) exceeds maximum allowed ({max})")]
    TooManySourceRefs {
        /// Actual count encountered.
        count: usize,
        /// Maximum permitted count.
        max: usize,
    },

    /// Rejection of unauthenticated or spoofed owner claims in writable request fields.
    #[error("authenticated owner cannot be claimed in writable request payloads: {0}")]
    UnauthenticatedOwnerClaim(String),
}

// ─── Owner identity and provider binding ─────────────────────────────────────

fn validate_owner_id(s: &str) -> Result<(), ProvenanceError> {
    if s.is_empty() {
        return Err(ProvenanceError::EmptyField { field: "owner_id" });
    }
    if s.len() > MAX_OWNER_ID_CHARS {
        return Err(ProvenanceError::ValueTooLong {
            field: "owner_id",
            len: s.len(),
            max: MAX_OWNER_ID_CHARS,
        });
    }
    for ch in s.chars() {
        if !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.')) {
            return Err(ProvenanceError::InvalidCharacter {
                field: "owner_id",
                ch,
            });
        }
    }
    Ok(())
}

/// Immutable, provider-neutral authenticated human owner identity.
///
/// Established exclusively at authentication time by the gateway/server from
/// verified credentials (e.g. Google ID token subject or OIDC claims).
/// Remains stable across credential rotation and email address renames.
/// Never accepted from writable request payload fields.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OwnerId(String);

impl OwnerId {
    /// Construct and validate a new [`OwnerId`].
    pub fn new(value: impl Into<String>) -> Result<Self, ProvenanceError> {
        let s = value.into();
        validate_owner_id(&s)?;
        Ok(Self(s))
    }

    /// View as string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for OwnerId {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for OwnerId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for OwnerId {
    type Err = ProvenanceError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<String> for OwnerId {
    type Error = ProvenanceError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for OwnerId {
    type Error = ProvenanceError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

fn validate_issuer(s: &str) -> Result<(), ProvenanceError> {
    if s.is_empty() {
        return Err(ProvenanceError::EmptyField { field: "issuer" });
    }
    if s.len() > MAX_ISSUER_CHARS {
        return Err(ProvenanceError::ValueTooLong {
            field: "issuer",
            len: s.len(),
            max: MAX_ISSUER_CHARS,
        });
    }
    for ch in s.chars() {
        if !ch.is_ascii_graphic() {
            return Err(ProvenanceError::InvalidCharacter {
                field: "issuer",
                ch,
            });
        }
    }
    Ok(())
}

/// Identity provider or authority that issued the authenticated credential.
///
/// Provider-neutral (e.g. `<https://accounts.google.com>`, `<https://github.com/login/oauth>`,
/// or an internal OIDC issuer URL).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Issuer(String);

impl Issuer {
    /// Construct and validate a new [`Issuer`].
    pub fn new(value: impl Into<String>) -> Result<Self, ProvenanceError> {
        let s = value.into();
        validate_issuer(&s)?;
        Ok(Self(s))
    }

    /// View as string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for Issuer {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for Issuer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Issuer {
    type Err = ProvenanceError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

fn validate_subject(s: &str) -> Result<(), ProvenanceError> {
    if s.is_empty() {
        return Err(ProvenanceError::EmptyField { field: "subject" });
    }
    if s.len() > MAX_SUBJECT_CHARS {
        return Err(ProvenanceError::ValueTooLong {
            field: "subject",
            len: s.len(),
            max: MAX_SUBJECT_CHARS,
        });
    }
    for ch in s.chars() {
        if !ch.is_ascii_graphic() {
            return Err(ProvenanceError::InvalidCharacter {
                field: "subject",
                ch,
            });
        }
    }
    Ok(())
}

/// Provider-specific immutable subject identifier.
///
/// Provider-neutral identifier unique to the issuer (e.g. Google subject `"104928190283019283019"`).
/// Kept stable across credential rotation and account renames.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Subject(String);

impl Subject {
    /// Construct and validate a new [`Subject`].
    pub fn new(value: impl Into<String>) -> Result<Self, ProvenanceError> {
        let s = value.into();
        validate_subject(&s)?;
        Ok(Self(s))
    }

    /// View as string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for Subject {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for Subject {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Subject {
    type Err = ProvenanceError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// Provider-neutral issuer/subject pair binding an external identity to an internal owner.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubjectBinding {
    /// Identity provider issuer.
    pub issuer: Issuer,
    /// Provider subject identifier.
    pub subject: Subject,
}

impl SubjectBinding {
    /// Create a new [`SubjectBinding`].
    pub fn new(issuer: Issuer, subject: Subject) -> Self {
        Self { issuer, subject }
    }

    /// Parse and construct a new [`SubjectBinding`] from string values.
    pub fn parse(
        issuer: impl Into<String>,
        subject: impl Into<String>,
    ) -> Result<Self, ProvenanceError> {
        Ok(Self {
            issuer: Issuer::new(issuer)?,
            subject: Subject::new(subject)?,
        })
    }
}

fn validate_email(s: &str) -> Result<(), ProvenanceError> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(ProvenanceError::EmptyField {
            field: "email_at_write",
        });
    }
    if trimmed.len() < MIN_EMAIL_CHARS {
        return Err(ProvenanceError::InvalidEmail(format!(
            "email too short: `{trimmed}`"
        )));
    }
    if trimmed.len() > MAX_EMAIL_CHARS {
        return Err(ProvenanceError::ValueTooLong {
            field: "email_at_write",
            len: trimmed.len(),
            max: MAX_EMAIL_CHARS,
        });
    }
    for ch in trimmed.chars() {
        if ch.is_ascii_whitespace() || ch.is_ascii_control() {
            return Err(ProvenanceError::InvalidCharacter {
                field: "email_at_write",
                ch,
            });
        }
    }
    let mut parts = trimmed.split('@');
    let local = parts.next();
    let domain = parts.next();
    let extra = parts.next();

    match (local, domain, extra) {
        (Some(l), Some(d), None)
            if !l.is_empty() && !d.is_empty() && !d.starts_with('.') && !d.ends_with('.') =>
        {
            Ok(())
        }
        _ => Err(ProvenanceError::InvalidEmail(trimmed.to_string())),
    }
}

/// User email address captured at the time a record or mutation was committed.
///
/// Used for human display, auditing, and contact in collaborative environments.
/// Because emails can change or be recycled, the immutable [`OwnerId`] and
/// [`Subject`] remain authoritative for identity and authorization.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EmailAtWrite(String);

impl EmailAtWrite {
    /// Construct and validate a new [`EmailAtWrite`].
    pub fn new(value: impl Into<String>) -> Result<Self, ProvenanceError> {
        let s = value.into();
        validate_email(&s)?;
        Ok(Self(s.trim().to_string()))
    }

    /// View as string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for EmailAtWrite {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for EmailAtWrite {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for EmailAtWrite {
    type Err = ProvenanceError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// Verified authenticated human owner identity.
///
/// Represents an authenticated account holder whose identity is verified by
/// credential context (such as an OAuth / OIDC ID token at login).
///
/// Serialization wire format matches the approved Demo Hub contract:
/// ```json
/// {
///   "id": "usr_01J8Y...",
///   "issuer": "https://accounts.google.com",
///   "subject": "104928190283019283019",
///   "email_at_write": "tester@example.com"
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuthenticatedOwner {
    /// Immutable, system-generated owner identifier.
    pub id: OwnerId,
    /// Identity provider issuer URL or identifier.
    pub issuer: Issuer,
    /// Provider-specific immutable subject identifier.
    pub subject: Subject,
    /// Human-readable email captured at write time.
    pub email_at_write: EmailAtWrite,
}

impl AuthenticatedOwner {
    /// Create a new [`AuthenticatedOwner`].
    pub fn new(
        id: OwnerId,
        issuer: Issuer,
        subject: Subject,
        email_at_write: EmailAtWrite,
    ) -> Self {
        Self {
            id,
            issuer,
            subject,
            email_at_write,
        }
    }

    /// Parse and construct an [`AuthenticatedOwner`] from string values.
    pub fn parse(
        id: impl Into<String>,
        issuer: impl Into<String>,
        subject: impl Into<String>,
        email_at_write: impl Into<String>,
    ) -> Result<Self, ProvenanceError> {
        Ok(Self {
            id: OwnerId::new(id)?,
            issuer: Issuer::new(issuer)?,
            subject: Subject::new(subject)?,
            email_at_write: EmailAtWrite::new(email_at_write)?,
        })
    }

    /// Extract the subject binding.
    pub fn subject_binding(&self) -> SubjectBinding {
        SubjectBinding {
            issuer: self.issuer.clone(),
            subject: self.subject.clone(),
        }
    }
}

/// Metadata attached to authenticated private server token entries.
pub type OwnerMetadata = AuthenticatedOwner;

/// Explicit sentinel type representing legacy or unknown ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct LegacyUnknownOwner;

/// First-class owner representation supporting both authenticated owners and
/// explicitly unknown/legacy installations.
///
/// Compatible wire representations:
/// - Explicit unknown: `{"status": "unknown"}` or JSON `null`
/// - Authenticated: `{"id": "...", "issuer": "...", "subject": "...", "email_at_write": "..."}`
///   or with explicit `{"status": "authenticated", ...}`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OwnerIdentity {
    /// Explicitly unknown owner (e.g. legacy static-token deployments).
    Unknown,
    /// Authenticated human owner with verified identity context.
    Authenticated(AuthenticatedOwner),
}

impl OwnerIdentity {
    /// Return the explicit unknown owner representation.
    pub fn unknown() -> Self {
        Self::Unknown
    }

    /// Returns `true` if this owner is authenticated.
    pub fn is_authenticated(&self) -> bool {
        matches!(self, Self::Authenticated(_))
    }

    /// Returns `true` if this owner is unknown or legacy.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }

    /// View the authenticated owner, if present.
    pub fn authenticated_owner(&self) -> Option<&AuthenticatedOwner> {
        match self {
            Self::Authenticated(owner) => Some(owner),
            Self::Unknown => None,
        }
    }

    /// View the immutable owner ID, if authenticated.
    pub fn owner_id(&self) -> Option<&OwnerId> {
        match self {
            Self::Authenticated(owner) => Some(&owner.id),
            Self::Unknown => None,
        }
    }
}

impl Serialize for OwnerIdentity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Unknown => {
                #[derive(Serialize)]
                struct UnknownWire {
                    status: &'static str,
                }
                UnknownWire { status: "unknown" }.serialize(serializer)
            }
            Self::Authenticated(owner) => owner.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for OwnerIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawOwnerHelper {
            #[serde(default)]
            status: Option<String>,
            #[serde(default)]
            id: Option<String>,
            #[serde(default)]
            issuer: Option<String>,
            #[serde(default)]
            subject: Option<String>,
            #[serde(default)]
            email_at_write: Option<String>,
        }

        let value = Option::<serde_json::Value>::deserialize(deserializer)?;
        let Some(val) = value else {
            return Ok(Self::Unknown);
        };

        if val.is_null() {
            return Ok(Self::Unknown);
        }

        let helper: RawOwnerHelper =
            serde_json::from_value(val).map_err(serde::de::Error::custom)?;

        if let Some(status) = helper.status.as_deref() {
            if status == "unknown" || status == "legacy" {
                return Ok(Self::Unknown);
            }
        }

        if let (Some(id), Some(issuer), Some(subject), Some(email_at_write)) = (
            helper.id,
            helper.issuer,
            helper.subject,
            helper.email_at_write,
        ) {
            let owner = AuthenticatedOwner::parse(id, issuer, subject, email_at_write)
                .map_err(serde::de::Error::custom)?;
            Ok(Self::Authenticated(owner))
        } else if helper.status.as_deref() == Some("unknown") {
            Ok(Self::Unknown)
        } else {
            Err(serde::de::Error::custom(
                "invalid owner identity: expected {status: \"unknown\"} or authenticated owner object with id, issuer, subject, email_at_write",
            ))
        }
    }
}

impl From<AuthenticatedOwner> for OwnerIdentity {
    fn from(owner: AuthenticatedOwner) -> Self {
        Self::Authenticated(owner)
    }
}

impl From<Option<AuthenticatedOwner>> for OwnerIdentity {
    fn from(opt: Option<AuthenticatedOwner>) -> Self {
        match opt {
            Some(owner) => Self::Authenticated(owner),
            None => Self::Unknown,
        }
    }
}

impl From<OwnerIdentity> for Option<AuthenticatedOwner> {
    fn from(identity: OwnerIdentity) -> Self {
        match identity {
            OwnerIdentity::Authenticated(owner) => Some(owner),
            OwnerIdentity::Unknown => None,
        }
    }
}

// ─── Agent attribution ────────────────────────────────────────────────────────

fn validate_agent_name(s: &str) -> Result<(), ProvenanceError> {
    if s.is_empty() {
        return Err(ProvenanceError::EmptyField { field: "agent_name" });
    }
    if s.len() > MAX_AGENT_NAME_CHARS {
        return Err(ProvenanceError::ValueTooLong {
            field: "agent_name",
            len: s.len(),
            max: MAX_AGENT_NAME_CHARS,
        });
    }
    for ch in s.chars() {
        if !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | ':')) {
            return Err(ProvenanceError::InvalidCharacter {
                field: "agent_name",
                ch,
            });
        }
    }
    Ok(())
}

/// Name of the caller-asserted agent or runtime harness.
///
/// Stored in request payloads (`added_by`, `created_by`, `sender`, `actor`).
/// Remains caller-asserted unless independently verified.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AgentName(String);

impl AgentName {
    /// Construct and validate a new [`AgentName`].
    pub fn new(value: impl Into<String>) -> Result<Self, ProvenanceError> {
        let s = value.into();
        validate_agent_name(&s)?;
        Ok(Self(s))
    }

    /// View as string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for AgentName {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for AgentName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for AgentName {
    type Err = ProvenanceError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// Assurance level for an agent attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentAssurance {
    /// Identity claimed by the caller or request body without independent cryptographic verification.
    #[default]
    CallerAsserted,
}

/// Caller-asserted agent attribution.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentAttribution {
    /// Name of the acting agent or harness.
    pub agent_name: AgentName,
    /// Assurance level of this attribution.
    #[serde(default)]
    pub assurance: AgentAssurance,
}

impl AgentAttribution {
    /// Create a new caller-asserted agent attribution.
    pub fn caller_asserted(agent_name: impl Into<String>) -> Result<Self, ProvenanceError> {
        Ok(Self {
            agent_name: AgentName::new(agent_name)?,
            assurance: AgentAssurance::CallerAsserted,
        })
    }

    /// Create with explicit assurance level.
    pub fn new(agent_name: AgentName, assurance: AgentAssurance) -> Self {
        Self {
            agent_name,
            assurance,
        }
    }
}

// ─── Source author and references ─────────────────────────────────────────────

fn validate_source_author(s: &str) -> Result<(), ProvenanceError> {
    if s.is_empty() {
        return Err(ProvenanceError::EmptyField {
            field: "source_author",
        });
    }
    if s.len() > MAX_SOURCE_AUTHOR_CHARS {
        return Err(ProvenanceError::ValueTooLong {
            field: "source_author",
            len: s.len(),
            max: MAX_SOURCE_AUTHOR_CHARS,
        });
    }
    for ch in s.chars() {
        if ch.is_ascii_control() {
            return Err(ProvenanceError::InvalidCharacter {
                field: "source_author",
                ch,
            });
        }
    }
    Ok(())
}

/// Original author of the source content, distinct from the submitting owner.
///
/// Examples: git commit author ("Alice <alice@example.com>"), document author,
/// or external publication author.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SourceAuthor(String);

impl SourceAuthor {
    /// Construct and validate an original [`SourceAuthor`].
    pub fn new(value: impl Into<String>) -> Result<Self, ProvenanceError> {
        let s = value.into();
        let trimmed = s.trim();
        validate_source_author(trimmed)?;
        Ok(Self(trimmed.to_string()))
    }

    /// View as string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for SourceAuthor {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for SourceAuthor {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SourceAuthor {
    type Err = ProvenanceError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

fn validate_source_reference(s: &str) -> Result<(), ProvenanceError> {
    if s.is_empty() {
        return Err(ProvenanceError::EmptyField {
            field: "source_reference",
        });
    }
    if s.len() > MAX_SOURCE_REF_CHARS {
        return Err(ProvenanceError::ValueTooLong {
            field: "source_reference",
            len: s.len(),
            max: MAX_SOURCE_REF_CHARS,
        });
    }
    for ch in s.chars() {
        if ch.is_ascii_control() {
            return Err(ProvenanceError::InvalidCharacter {
                field: "source_reference",
                ch,
            });
        }
    }
    Ok(())
}

/// Reference to an original source artifact, commit, file path, URL, or citation.
///
/// Distinct from the submitting owner and server storage identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SourceReference(String);

impl SourceReference {
    /// Construct and validate a [`SourceReference`].
    pub fn new(value: impl Into<String>) -> Result<Self, ProvenanceError> {
        let s = value.into();
        let trimmed = s.trim();
        validate_source_reference(trimmed)?;
        Ok(Self(trimmed.to_string()))
    }

    /// View as string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for SourceReference {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for SourceReference {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SourceReference {
    type Err = ProvenanceError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

// ─── Storage origin ───────────────────────────────────────────────────────────

fn validate_origin_id(s: &str) -> Result<(), ProvenanceError> {
    if s.is_empty() {
        return Err(ProvenanceError::EmptyField { field: "origin_id" });
    }
    if s.len() > MAX_ORIGIN_ID_CHARS {
        return Err(ProvenanceError::ValueTooLong {
            field: "origin_id",
            len: s.len(),
            max: MAX_ORIGIN_ID_CHARS,
        });
    }
    for ch in s.chars() {
        if !ch.is_ascii_graphic() {
            return Err(ProvenanceError::InvalidCharacter {
                field: "origin_id",
                ch,
            });
        }
    }
    Ok(())
}

/// Storage origin identifying where a record was originally created.
///
/// Distinguishes records created directly on this local palace node/host
/// from those federated, imported, or replicated from remote instances.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StorageOrigin {
    /// Created directly on this local palace node or instance.
    Local {
        /// Local instance or node identifier (e.g. `"local"` or host origin name).
        origin_id: String,
    },
    /// Ingested or synchronized from a remote or federated palace.
    Federated {
        /// Remote origin identity or URL.
        origin_id: String,
        /// Upstream record identifier on the originating node, if preserved.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        original_record_id: Option<String>,
    },
}

impl StorageOrigin {
    /// Create a local storage origin with the default `"local"` identifier.
    pub fn local_default() -> Self {
        Self::Local {
            origin_id: "local".to_string(),
        }
    }

    /// Create a local storage origin with a specific node/palace identifier.
    pub fn local(origin_id: impl Into<String>) -> Result<Self, ProvenanceError> {
        let id = origin_id.into();
        validate_origin_id(&id)?;
        Ok(Self::Local { origin_id: id })
    }

    /// Create a federated storage origin.
    pub fn federated(
        origin_id: impl Into<String>,
        original_record_id: Option<String>,
    ) -> Result<Self, ProvenanceError> {
        let id = origin_id.into();
        validate_origin_id(&id)?;
        if let Some(ref rec_id) = original_record_id {
            if rec_id.len() > MAX_RECORD_ID_CHARS {
                return Err(ProvenanceError::ValueTooLong {
                    field: "original_record_id",
                    len: rec_id.len(),
                    max: MAX_RECORD_ID_CHARS,
                });
            }
        }
        Ok(Self::Federated {
            origin_id: id,
            original_record_id,
        })
    }

    /// View the origin identifier.
    pub fn origin_id(&self) -> &str {
        match self {
            Self::Local { origin_id } => origin_id,
            Self::Federated { origin_id, .. } => origin_id,
        }
    }

    /// Returns `true` if this is a local origin.
    pub fn is_local(&self) -> bool {
        matches!(self, Self::Local { .. })
    }

    /// Returns `true` if this is a federated origin.
    pub fn is_federated(&self) -> bool {
        matches!(self, Self::Federated { .. })
    }
}

// ─── Recording time ───────────────────────────────────────────────────────────

/// Server-assigned UTC recording time.
///
/// Enforces RFC 3339 serialization wire format and UTC normalization.
/// Reuses the `time` crate conventions from `agentpalace-core`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordingTime(OffsetDateTime);

impl RecordingTime {
    /// Create a new recording time with current server UTC time.
    pub fn now_utc() -> Self {
        Self(OffsetDateTime::now_utc())
    }

    /// Construct from an existing [`OffsetDateTime`], normalized to UTC.
    pub fn from_offset_date_time(dt: OffsetDateTime) -> Self {
        Self(dt.to_offset(time::UtcOffset::UTC))
    }

    /// Parse an RFC 3339 string into UTC recording time.
    pub fn from_rfc3339(s: &str) -> Result<Self, ProvenanceError> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(ProvenanceError::EmptyField {
                field: "recording_time",
            });
        }
        if trimmed.len() > MAX_RFC3339_CHARS {
            return Err(ProvenanceError::ValueTooLong {
                field: "recording_time",
                len: trimmed.len(),
                max: MAX_RFC3339_CHARS,
            });
        }
        let parsed =
            OffsetDateTime::parse(trimmed, &time::format_description::well_known::Rfc3339)
                .map_err(|e| ProvenanceError::InvalidRecordingTime(e.to_string()))?;
        Ok(Self(parsed.to_offset(time::UtcOffset::UTC)))
    }

    /// View inner [`OffsetDateTime`].
    pub fn as_offset_date_time(&self) -> OffsetDateTime {
        self.0
    }

    /// Format as RFC 3339 string.
    pub fn to_rfc3339(&self) -> String {
        self.0
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
    }
}

impl Display for RecordingTime {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_rfc3339())
    }
}

impl FromStr for RecordingTime {
    type Err = ProvenanceError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_rfc3339(s)
    }
}

impl Serialize for RecordingTime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_rfc3339())
    }
}

impl<'de> Deserialize<'de> for RecordingTime {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        RecordingTime::from_rfc3339(&s).map_err(serde::de::Error::custom)
    }
}

// ─── Owner-scoped operation keys ──────────────────────────────────────────────

/// An idempotency or receipt key scoped to an authenticated owner.
///
/// Scoping receipt lookups and idempotency keys to `(owner_id, operation_id)`
/// ensures that one user's retries or client-supplied IDs cannot collide with
/// or replay another user's operations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OwnerScopedKey {
    /// Authenticated owner ID, or None for legacy/unauthenticated scopes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<OwnerId>,
    /// Raw operation or idempotency key.
    pub raw_key: String,
}

impl OwnerScopedKey {
    /// Construct a new [`OwnerScopedKey`].
    pub fn new(
        owner_id: Option<OwnerId>,
        raw_key: impl Into<String>,
    ) -> Result<Self, ProvenanceError> {
        let key = raw_key.into();
        let trimmed = key.trim();
        if trimmed.is_empty() {
            return Err(ProvenanceError::EmptyField { field: "raw_key" });
        }
        if trimmed.len() > MAX_OPERATION_ID_CHARS {
            return Err(ProvenanceError::ValueTooLong {
                field: "raw_key",
                len: trimmed.len(),
                max: MAX_OPERATION_ID_CHARS,
            });
        }
        Ok(Self {
            owner_id,
            raw_key: trimmed.to_string(),
        })
    }

    /// Generate composite key string suitable for storage indexes.
    ///
    /// If an owner is present: `"{owner_id}:{raw_key}"`.
    /// For legacy/unknown owners: `"legacy:{raw_key}"`.
    pub fn composite_key(&self) -> String {
        match &self.owner_id {
            Some(owner) => format!("{}:{}", owner.as_str(), self.raw_key),
            None => format!("legacy:{}", self.raw_key),
        }
    }
}

// ─── Provenance envelope ──────────────────────────────────────────────────────

/// Comprehensive provenance metadata envelope for Demo Hub records.
///
/// Unites all provenance dimensions required by Demo Hub design and Issue #160:
/// - Immutable authenticated owner identity ([`OwnerIdentity`])
/// - Caller-asserted agent attribution ([`AgentAttribution`])
/// - Server-assigned recording timestamp ([`RecordingTime`])
/// - Storage origin ([`StorageOrigin`])
/// - Owner-scoped idempotency receipt key (`operation_id`)
/// - Original source author ([`SourceAuthor`])
/// - Original source references ([`SourceReference`])
///
/// Note: Evidence status (claim truth/verification) and execution authority
/// (roles/permissions) are intentionally excluded from this slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceEnvelope {
    /// Authenticated owner identity, or explicitly unknown/legacy.
    pub owner: OwnerIdentity,
    /// Caller-asserted agent or runtime harness identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<AgentAttribution>,
    /// Server-assigned recording timestamp in UTC.
    pub recorded_at: RecordingTime,
    /// Storage origin (local or federated).
    pub origin: StorageOrigin,
    /// Optional owner-scoped operation / idempotency key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    /// Original source author, distinct from the submitting owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_author: Option<SourceAuthor>,
    /// Original source references (file paths, commit SHAs, URLs, citations).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<SourceReference>,
}

impl ProvenanceEnvelope {
    /// Create a new provenance envelope with mandatory core fields.
    pub fn new(owner: OwnerIdentity, recorded_at: RecordingTime, origin: StorageOrigin) -> Self {
        Self {
            owner,
            actor: None,
            recorded_at,
            origin,
            operation_id: None,
            source_author: None,
            source_refs: Vec::new(),
        }
    }

    /// Attach caller-asserted agent attribution.
    pub fn with_actor(mut self, actor: AgentAttribution) -> Self {
        self.actor = Some(actor);
        self
    }

    /// Attach owner-scoped operation / idempotency receipt key.
    pub fn with_operation_id(
        mut self,
        operation_id: impl Into<String>,
    ) -> Result<Self, ProvenanceError> {
        let op = operation_id.into();
        if op.len() > MAX_OPERATION_ID_CHARS {
            return Err(ProvenanceError::ValueTooLong {
                field: "operation_id",
                len: op.len(),
                max: MAX_OPERATION_ID_CHARS,
            });
        }
        self.operation_id = Some(op);
        Ok(self)
    }

    /// Attach original source author.
    pub fn with_source_author(mut self, source_author: SourceAuthor) -> Self {
        self.source_author = Some(source_author);
        self
    }

    /// Attach original source references.
    pub fn with_source_refs(
        mut self,
        refs: Vec<SourceReference>,
    ) -> Result<Self, ProvenanceError> {
        if refs.len() > MAX_SOURCE_REFS {
            return Err(ProvenanceError::TooManySourceRefs {
                count: refs.len(),
                max: MAX_SOURCE_REFS,
            });
        }
        self.source_refs = refs;
        Ok(self)
    }

    /// Validate the envelope's bounded constraints.
    pub fn validate(&self) -> Result<(), ProvenanceError> {
        if self.source_refs.len() > MAX_SOURCE_REFS {
            return Err(ProvenanceError::TooManySourceRefs {
                count: self.source_refs.len(),
                max: MAX_SOURCE_REFS,
            });
        }
        if let Some(ref op_id) = self.operation_id {
            if op_id.len() > MAX_OPERATION_ID_CHARS {
                return Err(ProvenanceError::ValueTooLong {
                    field: "operation_id",
                    len: op_id.len(),
                    max: MAX_OPERATION_ID_CHARS,
                });
            }
        }
        Ok(())
    }
}

/// Reject unauthenticated owner claims originating from writable request payloads.
///
/// In accordance with the Demo Hub design invariant:
/// "Never accept authenticated owner claims from writable request fields."
/// Caller payloads must never specify or override `owner` fields.
pub fn reject_payload_owner_claim<T>(claimed: Option<T>) -> Result<(), ProvenanceError> {
    if claimed.is_some() {
        Err(ProvenanceError::UnauthenticatedOwnerClaim(
            "owner identity must be established via authenticated token context, not request payload".to_string(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn owner_id_validation_and_bounds() {
        let valid = OwnerId::new("usr_01J8Y9K2E4").unwrap();
        assert_eq!(valid.as_str(), "usr_01J8Y9K2E4");
        assert_eq!(valid.to_string(), "usr_01J8Y9K2E4");

        assert_eq!(
            OwnerId::new("").unwrap_err(),
            ProvenanceError::EmptyField { field: "owner_id" }
        );

        let long_id = "a".repeat(MAX_OWNER_ID_CHARS + 1);
        assert_eq!(
            OwnerId::new(long_id).unwrap_err(),
            ProvenanceError::ValueTooLong {
                field: "owner_id",
                len: MAX_OWNER_ID_CHARS + 1,
                max: MAX_OWNER_ID_CHARS,
            }
        );

        assert!(matches!(
            OwnerId::new("user with space").unwrap_err(),
            ProvenanceError::InvalidCharacter { field: "owner_id", ch: ' ' }
        ));
    }

    #[test]
    fn issuer_and_subject_validation() {
        let issuer = Issuer::new("https://accounts.google.com").unwrap();
        assert_eq!(issuer.as_str(), "https://accounts.google.com");

        let subject = Subject::new("104928190283019283019").unwrap();
        assert_eq!(subject.as_str(), "104928190283019283019");

        let binding = SubjectBinding::new(issuer, subject);
        assert_eq!(binding.issuer.as_str(), "https://accounts.google.com");
        assert_eq!(binding.subject.as_str(), "104928190283019283019");

        assert_eq!(
            Issuer::new("").unwrap_err(),
            ProvenanceError::EmptyField { field: "issuer" }
        );
        assert_eq!(
            Subject::new("").unwrap_err(),
            ProvenanceError::EmptyField { field: "subject" }
        );
    }

    #[test]
    fn email_at_write_validation() {
        let email = EmailAtWrite::new("writer@example.com").unwrap();
        assert_eq!(email.as_str(), "writer@example.com");

        assert!(EmailAtWrite::new("invalid-no-at").is_err());
        assert!(EmailAtWrite::new("@example.com").is_err());
        assert!(EmailAtWrite::new("writer@").is_err());
        assert!(EmailAtWrite::new("writer@.com").is_err());
        assert!(EmailAtWrite::new("has space@example.com").is_err());
        assert!(EmailAtWrite::new("").is_err());
    }

    #[test]
    fn authenticated_owner_wire_json() {
        let owner = AuthenticatedOwner::parse(
            "usr_01J8Y",
            "https://accounts.google.com",
            "104928190283019283019",
            "tester@example.com",
        )
        .unwrap();

        let serialized = serde_json::to_string(&owner).unwrap();
        assert_eq!(
            serialized,
            r#"{"id":"usr_01J8Y","issuer":"https://accounts.google.com","subject":"104928190283019283019","email_at_write":"tester@example.com"}"#
        );

        let roundtrip: AuthenticatedOwner = serde_json::from_str(&serialized).unwrap();
        assert_eq!(roundtrip, owner);
    }

    #[test]
    fn owner_identity_wire_compatibility() {
        // Unknown representation
        let unknown = OwnerIdentity::Unknown;
        let unknown_json = serde_json::to_string(&unknown).unwrap();
        assert_eq!(unknown_json, r#"{"status":"unknown"}"#);

        let from_unknown_status: OwnerIdentity =
            serde_json::from_str(r#"{"status":"unknown"}"#).unwrap();
        assert_eq!(from_unknown_status, OwnerIdentity::Unknown);

        let from_null: OwnerIdentity = serde_json::from_str("null").unwrap();
        assert_eq!(from_null, OwnerIdentity::Unknown);

        // Authenticated representation
        let owner = AuthenticatedOwner::parse(
            "usr_01J8Y",
            "https://accounts.google.com",
            "104928190283019283019",
            "tester@example.com",
        )
        .unwrap();
        let authenticated = OwnerIdentity::Authenticated(owner.clone());

        let auth_json = serde_json::to_string(&authenticated).unwrap();
        assert_eq!(
            auth_json,
            r#"{"id":"usr_01J8Y","issuer":"https://accounts.google.com","subject":"104928190283019283019","email_at_write":"tester@example.com"}"#
        );

        let from_bare: OwnerIdentity = serde_json::from_str(&auth_json).unwrap();
        assert_eq!(from_bare, OwnerIdentity::Authenticated(owner.clone()));

        let from_tagged: OwnerIdentity = serde_json::from_str(
            r#"{"status":"authenticated","id":"usr_01J8Y","issuer":"https://accounts.google.com","subject":"104928190283019283019","email_at_write":"tester@example.com"}"#,
        )
        .unwrap();
        assert_eq!(from_tagged, OwnerIdentity::Authenticated(owner));
    }

    #[test]
    fn agent_attribution_validation_and_serde() {
        let actor = AgentAttribution::caller_asserted("codex").unwrap();
        assert_eq!(actor.agent_name.as_str(), "codex");
        assert_eq!(actor.assurance, AgentAssurance::CallerAsserted);

        let json = serde_json::to_string(&actor).unwrap();
        assert_eq!(json, r#"{"agent_name":"codex","assurance":"caller_asserted"}"#);

        let parsed: AgentAttribution = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, actor);
    }

    #[test]
    fn source_author_and_references() {
        let author = SourceAuthor::new("Alice <alice@example.com>").unwrap();
        assert_eq!(author.as_str(), "Alice <alice@example.com>");

        let source_ref = SourceReference::new("crates/agentpalace-core/src/lib.rs").unwrap();
        assert_eq!(source_ref.as_str(), "crates/agentpalace-core/src/lib.rs");

        assert!(SourceAuthor::new("   ").is_err());
        assert!(SourceReference::new("\t").is_err());
    }

    #[test]
    fn storage_origin_local_and_federated() {
        let local_def = StorageOrigin::local_default();
        assert!(local_def.is_local());
        assert!(!local_def.is_federated());
        assert_eq!(local_def.origin_id(), "local");

        let local_actuarius = StorageOrigin::local("actuarius").unwrap();
        assert_eq!(local_actuarius.origin_id(), "actuarius");
        assert_eq!(
            serde_json::to_string(&local_actuarius).unwrap(),
            r#"{"kind":"local","origin_id":"actuarius"}"#
        );

        let fed = StorageOrigin::federated("https://remote.palace", Some("rec_42".to_string()))
            .unwrap();
        assert!(fed.is_federated());
        assert!(!fed.is_local());
        assert_eq!(fed.origin_id(), "https://remote.palace");
        assert_eq!(
            serde_json::to_string(&fed).unwrap(),
            r#"{"kind":"federated","origin_id":"https://remote.palace","original_record_id":"rec_42"}"#
        );
    }

    #[test]
    fn recording_time_rfc3339() {
        let ts = RecordingTime::from_rfc3339("2026-09-17T11:04:27Z").unwrap();
        assert_eq!(ts.to_rfc3339(), "2026-09-17T11:04:27Z");

        let json = serde_json::to_string(&ts).unwrap();
        assert_eq!(json, r#""2026-09-17T11:04:27Z""#);

        let parsed: RecordingTime = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ts);

        assert!(RecordingTime::from_rfc3339("invalid-date").is_err());
        assert!(RecordingTime::from_rfc3339("").is_err());
    }

    #[test]
    fn owner_scoped_key_generation() {
        let owner_id = OwnerId::new("usr_01J8Y").unwrap();
        let key = OwnerScopedKey::new(Some(owner_id), "op_add_drawer_1").unwrap();
        assert_eq!(key.composite_key(), "usr_01J8Y:op_add_drawer_1");

        let legacy_key = OwnerScopedKey::new(None, "op_legacy_2").unwrap();
        assert_eq!(legacy_key.composite_key(), "legacy:op_legacy_2");
    }

    #[test]
    fn provenance_envelope_full_flow() {
        let owner = AuthenticatedOwner::parse(
            "usr_01J8Y",
            "https://accounts.google.com",
            "104928190283019283019",
            "tester@example.com",
        )
        .unwrap();
        let recorded_at = RecordingTime::from_rfc3339("2026-09-17T11:04:27Z").unwrap();
        let origin = StorageOrigin::local_default();

        let envelope = ProvenanceEnvelope::new(owner.into(), recorded_at, origin)
            .with_actor(AgentAttribution::caller_asserted("codex").unwrap())
            .with_operation_id("owner-scoped-idempotency-key")
            .unwrap()
            .with_source_author(SourceAuthor::new("Bob").unwrap())
            .with_source_refs(vec![SourceReference::new("git:commit:910be1b").unwrap()])
            .unwrap();

        envelope.validate().unwrap();

        let json = serde_json::to_string(&envelope).unwrap();
        let deserialized: ProvenanceEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, envelope);
        assert!(deserialized.owner.is_authenticated());
        assert_eq!(deserialized.actor.unwrap().agent_name.as_str(), "codex");
    }

    #[test]
    fn reject_payload_owner_claim_enforces_server_side_attribution() {
        assert!(reject_payload_owner_claim::<String>(None).is_ok());
        assert!(matches!(
            reject_payload_owner_claim(Some("spoofed_owner")),
            Err(ProvenanceError::UnauthenticatedOwnerClaim(_))
        ));
    }
}
