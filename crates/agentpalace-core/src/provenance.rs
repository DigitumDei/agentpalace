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

use serde::de::{self, Deserializer, Visitor};
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

    /// Owner-scoping mismatch on operation key or envelope.
    #[error("owner scoping mismatch: expected {expected}, got {actual}")]
    OwnerScopeMismatch {
        /// Expected owner identifier or scope.
        expected: String,
        /// Actual owner identifier or scope.
        actual: String,
    },

    /// Identifier uses a reserved sentinel value.
    #[error("{field} `{value}` is a reserved sentinel identifier and cannot be used for authenticated owners")]
    ReservedIdentifier {
        /// Name of the field.
        field: &'static str,
        /// Reserved value attempted.
        value: String,
    },
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
    let s_lower = s.to_ascii_lowercase();
    if matches!(s_lower.as_str(), "legacy" | "unknown" | "none" | "null") {
        return Err(ProvenanceError::ReservedIdentifier {
            field: "owner_id",
            value: s.to_string(),
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
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

impl<'de> Deserialize<'de> for OwnerId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OwnerIdVisitor;

        impl<'de> Visitor<'de> for OwnerIdVisitor {
            type Value = OwnerId;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a valid owner ID string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                OwnerId::new(v).map_err(de::Error::custom)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                OwnerId::new(v).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(OwnerIdVisitor)
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
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

impl<'de> Deserialize<'de> for Issuer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IssuerVisitor;

        impl<'de> Visitor<'de> for IssuerVisitor {
            type Value = Issuer;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a valid issuer string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Issuer::new(v).map_err(de::Error::custom)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Issuer::new(v).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(IssuerVisitor)
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
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

impl<'de> Deserialize<'de> for Subject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SubjectVisitor;

        impl<'de> Visitor<'de> for SubjectVisitor {
            type Value = Subject;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a valid subject string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Subject::new(v).map_err(de::Error::custom)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Subject::new(v).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(SubjectVisitor)
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
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

impl<'de> Deserialize<'de> for EmailAtWrite {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EmailAtWriteVisitor;

        impl<'de> Visitor<'de> for EmailAtWriteVisitor {
            type Value = EmailAtWrite;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a valid email address string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                EmailAtWrite::new(v).map_err(de::Error::custom)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                EmailAtWrite::new(v).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(EmailAtWriteVisitor)
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

#[derive(Deserialize)]
struct RawOwnerIdentity {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    id: Option<OwnerId>,
    #[serde(default)]
    issuer: Option<Issuer>,
    #[serde(default)]
    subject: Option<Subject>,
    #[serde(default)]
    email_at_write: Option<EmailAtWrite>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawOwnerIdentityEnum {
    Object(RawOwnerIdentity),
    Str(String),
    Null,
}

impl<'de> Deserialize<'de> for OwnerIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match RawOwnerIdentityEnum::deserialize(deserializer)? {
            RawOwnerIdentityEnum::Null => Ok(Self::Unknown),
            RawOwnerIdentityEnum::Str(s) => {
                let s_lower = s.to_ascii_lowercase();
                if s_lower == "unknown" || s_lower == "legacy" {
                    Ok(Self::Unknown)
                } else {
                    Err(de::Error::custom(format!(
                        "unrecognized owner identity string `{s}`: expected 'unknown' or 'legacy'"
                    )))
                }
            }
            RawOwnerIdentityEnum::Object(raw) => {
                let has_any_auth = raw.id.is_some()
                    || raw.issuer.is_some()
                    || raw.subject.is_some()
                    || raw.email_at_write.is_some();
                let full_auth = match (raw.id, raw.issuer, raw.subject, raw.email_at_write) {
                    (Some(id), Some(issuer), Some(subject), Some(email)) => {
                        Some(AuthenticatedOwner::new(id, issuer, subject, email))
                    }
                    _ => None,
                };

                match raw.status.as_deref() {
                    Some(status) => {
                        let status_lower = status.to_ascii_lowercase();
                        match status_lower.as_str() {
                            "unknown" | "legacy" => {
                                if has_any_auth {
                                    Err(de::Error::custom(format!(
                                        "contradictory owner identity: status '{status}' cannot be combined with authenticated owner fields (id, issuer, subject, email_at_write)"
                                    )))
                                } else {
                                    Ok(Self::Unknown)
                                }
                            }
                            "authenticated" => match full_auth {
                                Some(owner) => Ok(Self::Authenticated(owner)),
                                None => Err(de::Error::custom(
                                    "incomplete authenticated owner: status 'authenticated' requires all fields: id, issuer, subject, email_at_write",
                                )),
                            },
                            _ => Err(de::Error::custom(format!(
                                "unrecognized owner identity status '{status}': expected 'unknown', 'legacy', or 'authenticated'"
                            ))),
                        }
                    }
                    None => match full_auth {
                        Some(owner) => Ok(Self::Authenticated(owner)),
                        None if has_any_auth => Err(de::Error::custom(
                            "incomplete owner identity: authenticated owner object requires all fields: id, issuer, subject, email_at_write",
                        )),
                        None => Err(de::Error::custom(
                            "invalid owner identity: expected {status: \"unknown\"} or authenticated owner object with id, issuer, subject, email_at_write",
                        )),
                    },
                }
            }
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
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

impl<'de> Deserialize<'de> for AgentName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AgentNameVisitor;

        impl<'de> Visitor<'de> for AgentNameVisitor {
            type Value = AgentName;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a valid agent name string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                AgentName::new(v).map_err(de::Error::custom)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                AgentName::new(v).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(AgentNameVisitor)
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
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

impl<'de> Deserialize<'de> for SourceAuthor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SourceAuthorVisitor;

        impl<'de> Visitor<'de> for SourceAuthorVisitor {
            type Value = SourceAuthor;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a valid source author string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                SourceAuthor::new(v).map_err(de::Error::custom)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                SourceAuthor::new(v).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(SourceAuthorVisitor)
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
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

impl<'de> Deserialize<'de> for SourceReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SourceReferenceVisitor;

        impl<'de> Visitor<'de> for SourceReferenceVisitor {
            type Value = SourceReference;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a valid source reference string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                SourceReference::new(v).map_err(de::Error::custom)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                SourceReference::new(v).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(SourceReferenceVisitor)
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
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

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum RawStorageOrigin {
    Local {
        origin_id: String,
    },
    Federated {
        origin_id: String,
        #[serde(default)]
        original_record_id: Option<String>,
    },
}

impl<'de> Deserialize<'de> for StorageOrigin {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawStorageOrigin::deserialize(deserializer)?;
        match raw {
            RawStorageOrigin::Local { origin_id } => {
                StorageOrigin::local(origin_id).map_err(de::Error::custom)
            }
            RawStorageOrigin::Federated {
                origin_id,
                original_record_id,
            } => StorageOrigin::federated(origin_id, original_record_id).map_err(de::Error::custom),
        }
    }
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
/// Enforces RFC 3339 serialization wire format, UTC normalization, and the invariant
/// that only RFC 3339-representable timestamps (UTC year `0000..=9999`) can be constructed.
/// Reuses the `time` crate conventions from `agentpalace-core`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordingTime(OffsetDateTime);

impl RecordingTime {
    /// Validates that an [`OffsetDateTime`] can be normalized to UTC and represented in RFC 3339 format.
    ///
    /// The normalized UTC timestamp must have a 4-digit calendar year in the range `0000..=9999`
    /// and successfully format as RFC 3339.
    fn validate_and_normalize(dt: OffsetDateTime) -> Result<OffsetDateTime, ProvenanceError> {
        let utc = dt
            .checked_to_offset(time::UtcOffset::UTC)
            .ok_or_else(|| {
                ProvenanceError::InvalidRecordingTime(format!(
                    "recording time year {} with offset {} cannot be represented in UTC RFC 3339 range (0000..=9999)",
                    dt.year(),
                    dt.offset()
                ))
            })?;
        let year = utc.year();
        if !(0..=9999).contains(&year) {
            return Err(ProvenanceError::InvalidRecordingTime(format!(
                "UTC recording time year {year} is out of RFC 3339 representable range (0000..=9999)"
            )));
        }
        utc.format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| ProvenanceError::InvalidRecordingTime(e.to_string()))?;
        Ok(utc)
    }

    /// Create a new recording time with current server UTC time.
    pub fn now_utc() -> Self {
        Self(OffsetDateTime::now_utc())
    }

    /// Construct from an existing [`OffsetDateTime`], normalized to UTC.
    ///
    /// Returns [`ProvenanceError::InvalidRecordingTime`] if the normalized UTC timestamp
    /// is not representable in RFC 3339 format (i.e. UTC year outside `0000..=9999`).
    pub fn from_offset_date_time(dt: OffsetDateTime) -> Result<Self, ProvenanceError> {
        let utc = Self::validate_and_normalize(dt)?;
        Ok(Self(utc))
    }

    /// Parse an RFC 3339 string into UTC recording time.
    ///
    /// Validates length bounds, RFC 3339 format, and that the normalized UTC timestamp
    /// is within the representable RFC 3339 range (UTC year `0000..=9999`).
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
        let utc = Self::validate_and_normalize(parsed)?;
        Ok(Self(utc))
    }

    /// View inner [`OffsetDateTime`].
    pub fn as_offset_date_time(&self) -> OffsetDateTime {
        self.0
    }

    /// Convert into inner [`OffsetDateTime`].
    pub fn into_offset_date_time(self) -> OffsetDateTime {
        self.0
    }

    /// Format as RFC 3339 string.
    ///
    /// Propagates any formatting error instead of substituting Unix epoch fallback.
    pub fn to_rfc3339(&self) -> Result<String, ProvenanceError> {
        self.0
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| ProvenanceError::InvalidRecordingTime(e.to_string()))
    }
}

impl TryFrom<OffsetDateTime> for RecordingTime {
    type Error = ProvenanceError;

    fn try_from(dt: OffsetDateTime) -> Result<Self, Self::Error> {
        Self::from_offset_date_time(dt)
    }
}

impl From<RecordingTime> for OffsetDateTime {
    fn from(rt: RecordingTime) -> Self {
        rt.0
    }
}

impl Display for RecordingTime {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let formatted = self.to_rfc3339().map_err(|_| std::fmt::Error)?;
        f.write_str(&formatted)
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
        let formatted = self
            .to_rfc3339()
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&formatted)
    }
}

impl<'de> Deserialize<'de> for RecordingTime {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        RecordingTime::from_rfc3339(&s).map_err(de::Error::custom)
    }
}

// ─── Owner-scoped operation keys ──────────────────────────────────────────────

/// An idempotency or receipt key scoped to an authenticated owner.
///
/// Scoping receipt lookups and idempotency keys to `(owner_id, operation_id)`
/// ensures that one user's retries or client-supplied IDs cannot collide with
/// or replay another user's operations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct OwnerScopedKey {
    /// Authenticated owner ID, or None for legacy/unauthenticated scopes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<OwnerId>,
    /// Raw operation or idempotency key.
    pub raw_key: String,
}

impl OwnerScopedKey {
    /// Construct and validate a new [`OwnerScopedKey`].
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

    /// Validate bounded invariants.
    pub fn validate(&self) -> Result<(), ProvenanceError> {
        let trimmed = self.raw_key.trim();
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
        if let Some(ref owner) = self.owner_id {
            validate_owner_id(owner.as_str())?;
        }
        Ok(())
    }

    /// View raw operation key string.
    pub fn raw_key(&self) -> &str {
        &self.raw_key
    }

    /// View owner ID, if scoped to an authenticated owner.
    pub fn owner_id(&self) -> Option<&OwnerId> {
        self.owner_id.as_ref()
    }

    /// Generate composite key string suitable for storage indexes.
    ///
    /// If an owner is present: `"{owner_id}:{raw_key}"`.
    /// For legacy/unknown owners: `"legacy:{raw_key}"`.
    ///
    /// Because sentinel identifiers (`legacy`, `unknown`, `none`, `null`) are
    /// strictly reserved and rejected as authenticated [`OwnerId`] values, the
    /// `"legacy:"` prefix is unambiguous and collision-free.
    pub fn composite_key(&self) -> String {
        match &self.owner_id {
            Some(owner) => format!("{}:{}", owner.as_str(), self.raw_key),
            None => format!("legacy:{}", self.raw_key),
        }
    }
}

impl Display for OwnerScopedKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.composite_key())
    }
}

impl FromStr for OwnerScopedKey {
    type Err = ProvenanceError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(ProvenanceError::EmptyField { field: "raw_key" });
        }
        if let Some((prefix, rest)) = trimmed.split_once(':') {
            let prefix_lower = prefix.to_ascii_lowercase();
            if prefix_lower == "legacy" || prefix_lower == "unknown" {
                Self::new(None, rest)
            } else {
                let owner = OwnerId::new(prefix)?;
                Self::new(Some(owner), rest)
            }
        } else {
            Self::new(None, trimmed)
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawScopedKeyHelper {
    Struct {
        #[serde(default)]
        owner_id: Option<OwnerId>,
        raw_key: String,
    },
    Str(String),
}

impl<'de> Deserialize<'de> for OwnerScopedKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawScopedKeyHelper::deserialize(deserializer)?;
        match raw {
            RawScopedKeyHelper::Struct { owner_id, raw_key } => {
                OwnerScopedKey::new(owner_id, raw_key).map_err(de::Error::custom)
            }
            RawScopedKeyHelper::Str(s) => {
                OwnerScopedKey::from_str(&s).map_err(de::Error::custom)
            }
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
/// - Owner-scoped idempotency receipt key ([`OwnerScopedKey`])
/// - Original source author ([`SourceAuthor`])
/// - Original source references ([`SourceReference`])
///
/// Note: Evidence status (claim truth/verification) and execution authority
/// (roles/permissions) are intentionally excluded from this slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    pub operation_id: Option<OwnerScopedKey>,
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

    /// Attach owner-scoped operation / idempotency receipt key from raw string.
    ///
    /// Automatically normalizes the key (rejecting empty/whitespace-only values and bounding length)
    /// and scopes it to the envelope's authenticated owner identity (or legacy if unknown).
    pub fn with_operation_id(
        mut self,
        raw_key: impl Into<String>,
    ) -> Result<Self, ProvenanceError> {
        let key = OwnerScopedKey::new(self.owner.owner_id().cloned(), raw_key)?;
        self.operation_id = Some(key);
        Ok(self)
    }

    /// Attach explicit [`OwnerScopedKey`], validating that its owner scope matches this envelope.
    pub fn with_operation_key(mut self, key: OwnerScopedKey) -> Result<Self, ProvenanceError> {
        key.validate()?;
        self.check_owner_scope(&key)?;
        self.operation_id = Some(key);
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

    /// View the owner-scoped operation key, if present.
    pub fn operation_id(&self) -> Option<&OwnerScopedKey> {
        self.operation_id.as_ref()
    }

    fn check_owner_scope(&self, key: &OwnerScopedKey) -> Result<(), ProvenanceError> {
        match (&self.owner, &key.owner_id) {
            (OwnerIdentity::Authenticated(owner), Some(op_owner)) => {
                if &owner.id != op_owner {
                    return Err(ProvenanceError::OwnerScopeMismatch {
                        expected: owner.id.to_string(),
                        actual: op_owner.to_string(),
                    });
                }
            }
            (OwnerIdentity::Authenticated(owner), None) => {
                return Err(ProvenanceError::OwnerScopeMismatch {
                    expected: owner.id.to_string(),
                    actual: "unscoped/legacy".to_string(),
                });
            }
            (OwnerIdentity::Unknown, Some(op_owner)) => {
                return Err(ProvenanceError::OwnerScopeMismatch {
                    expected: "unknown".to_string(),
                    actual: op_owner.to_string(),
                });
            }
            (OwnerIdentity::Unknown, None) => {}
        }
        Ok(())
    }

    /// Validate the envelope's bounded constraints and owner-scoping invariants.
    pub fn validate(&self) -> Result<(), ProvenanceError> {
        if self.source_refs.len() > MAX_SOURCE_REFS {
            return Err(ProvenanceError::TooManySourceRefs {
                count: self.source_refs.len(),
                max: MAX_SOURCE_REFS,
            });
        }
        if let Some(ref key) = self.operation_id {
            key.validate()?;
            self.check_owner_scope(key)?;
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct RawProvenanceEnvelope {
    owner: OwnerIdentity,
    #[serde(default)]
    actor: Option<AgentAttribution>,
    recorded_at: RecordingTime,
    origin: StorageOrigin,
    #[serde(default)]
    operation_id: Option<OwnerScopedKey>,
    #[serde(default)]
    source_author: Option<SourceAuthor>,
    #[serde(default)]
    source_refs: Vec<SourceReference>,
}

impl<'de> Deserialize<'de> for ProvenanceEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawProvenanceEnvelope::deserialize(deserializer)?;
        let mut envelope = ProvenanceEnvelope {
            owner: raw.owner,
            actor: raw.actor,
            recorded_at: raw.recorded_at,
            origin: raw.origin,
            operation_id: raw.operation_id,
            source_author: raw.source_author,
            source_refs: raw.source_refs,
        };

        // If operation_id was deserialized without an owner_id (e.g. from a raw string),
        // scope it to the envelope's owner if authenticated.
        if let Some(ref mut op) = envelope.operation_id {
            if op.owner_id.is_none() {
                if let Some(owner_id) = envelope.owner.owner_id() {
                    op.owner_id = Some(owner_id.clone());
                }
            }
        }

        envelope.validate().map_err(de::Error::custom)?;
        Ok(envelope)
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
        assert_eq!(ts.to_rfc3339().unwrap(), "2026-09-17T11:04:27Z");
        assert_eq!(ts.to_string(), "2026-09-17T11:04:27Z");

        let json = serde_json::to_string(&ts).unwrap();
        assert_eq!(json, r#""2026-09-17T11:04:27Z""#);

        let parsed: RecordingTime = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ts);

        assert!(RecordingTime::from_rfc3339("invalid-date").is_err());
        assert!(RecordingTime::from_rfc3339("").is_err());
    }

    #[test]
    fn recording_time_boundary_and_range_validation() {
        // Legitimate Unix epoch (1970-01-01T00:00:00Z) formats and serializes correctly
        let epoch = RecordingTime::from_offset_date_time(OffsetDateTime::UNIX_EPOCH).unwrap();
        assert_eq!(epoch.to_rfc3339().unwrap(), "1970-01-01T00:00:00Z");
        assert_eq!(epoch.to_string(), "1970-01-01T00:00:00Z");
        assert_eq!(
            serde_json::to_string(&epoch).unwrap(),
            r#""1970-01-01T00:00:00Z""#
        );

        // Lower boundary: year 0000 UTC
        let min_dt = time::Date::from_calendar_date(0, time::Month::January, 1)
            .unwrap()
            .midnight()
            .assume_utc();
        let min_rt = RecordingTime::from_offset_date_time(min_dt).unwrap();
        assert_eq!(min_rt.to_rfc3339().unwrap(), "0000-01-01T00:00:00Z");
        assert_ne!(min_rt.to_rfc3339().unwrap(), "1970-01-01T00:00:00Z");

        // Upper boundary: year 9999 UTC
        let max_dt = time::Date::from_calendar_date(9999, time::Month::December, 31)
            .unwrap()
            .with_time(time::Time::from_hms(23, 59, 59).unwrap())
            .assume_utc();
        let max_rt = RecordingTime::from_offset_date_time(max_dt).unwrap();
        assert_eq!(max_rt.to_rfc3339().unwrap(), "9999-12-31T23:59:59Z");
        assert_ne!(max_rt.to_rfc3339().unwrap(), "1970-01-01T00:00:00Z");

        // OffsetDateTime::MAX is within year 9999 and RFC 3339-representable; it must be accepted
        let max_od_rt = RecordingTime::from_offset_date_time(OffsetDateTime::MAX).unwrap();
        assert_eq!(max_od_rt.as_offset_date_time(), OffsetDateTime::MAX);
        assert!(max_od_rt.to_rfc3339().unwrap().starts_with("9999-12-31T23:59:59"));
        assert_ne!(max_od_rt.to_rfc3339().unwrap(), "1970-01-01T00:00:00Z");
        assert!(RecordingTime::try_from(OffsetDateTime::MAX).is_ok());

        // Out-of-range construction: OffsetDateTime::MIN (year -9999) must be rejected
        let min_err = RecordingTime::from_offset_date_time(OffsetDateTime::MIN).unwrap_err();
        assert!(matches!(min_err, ProvenanceError::InvalidRecordingTime(_)));
        assert!(RecordingTime::try_from(OffsetDateTime::MIN).is_err());

        // Negative year (year -1 / 1 BCE) must be rejected
        let neg_year_dt = time::Date::from_calendar_date(-1, time::Month::December, 31)
            .unwrap()
            .midnight()
            .assume_utc();
        let neg_err = RecordingTime::from_offset_date_time(neg_year_dt).unwrap_err();
        assert!(matches!(neg_err, ProvenanceError::InvalidRecordingTime(_)));
        assert!(RecordingTime::try_from(neg_year_dt).is_err());

        // Constructible offset-crossing: local year 0000 with positive offset shifting into UTC year -1
        let shift_neg_offset = time::UtcOffset::from_whole_seconds(3600).unwrap();
        let shift_neg_dt = time::Date::from_calendar_date(0, time::Month::January, 1)
            .unwrap()
            .with_time(time::Time::from_hms(0, 30, 0).unwrap())
            .assume_offset(shift_neg_offset);
        let shift_neg_err = RecordingTime::from_offset_date_time(shift_neg_dt).unwrap_err();
        assert!(matches!(shift_neg_err, ProvenanceError::InvalidRecordingTime(_)));
        assert!(RecordingTime::try_from(shift_neg_dt).is_err());

        // Constructible offset-crossing: local year 9999 with negative offset shifting into UTC year 10000
        let shift_pos_offset = time::UtcOffset::from_whole_seconds(-3600).unwrap();
        let shift_pos_dt = time::Date::from_calendar_date(9999, time::Month::December, 31)
            .unwrap()
            .with_time(time::Time::from_hms(23, 30, 0).unwrap())
            .assume_offset(shift_pos_offset);
        let shift_pos_err = RecordingTime::from_offset_date_time(shift_pos_dt).unwrap_err();
        assert!(matches!(shift_pos_err, ProvenanceError::InvalidRecordingTime(_)));
        assert!(RecordingTime::try_from(shift_pos_dt).is_err());

        // Parsed RFC 3339 timezone shift that pushes UTC into year -1 must be rejected
        // 0000-01-01T00:30:00+01:00 is -0001-12-31T23:30:00Z in UTC
        let shift_neg = RecordingTime::from_rfc3339("0000-01-01T00:30:00+01:00");
        assert!(shift_neg.is_err(), "Must reject RFC 3339 shifting into negative UTC year");

        // Parsed RFC 3339 timezone shift that pushes UTC into year 10000 must be rejected
        // 9999-12-31T23:30:00-01:00 is 10000-01-01T00:30:00Z in UTC
        let shift_pos = RecordingTime::from_rfc3339("9999-12-31T23:30:00-01:00");
        assert!(shift_pos.is_err(), "Must reject RFC 3339 shifting into 5-digit UTC year");

        // Serde deserialization must reject out-of-range timestamps rather than defaulting to 1970-01-01
        assert!(serde_json::from_str::<RecordingTime>(r#""-0001-12-31T23:59:59Z""#).is_err());
        assert!(serde_json::from_str::<RecordingTime>(r#""0000-01-01T00:30:00+01:00""#).is_err());
        assert!(serde_json::from_str::<RecordingTime>(r#""10000-01-01T00:00:00Z""#).is_err());
        assert!(serde_json::from_str::<RecordingTime>(r#""9999-12-31T23:30:00-01:00""#).is_err());

        // now_utc produces a valid RFC 3339 timestamp that formats without fallback
        let now = RecordingTime::now_utc();
        let formatted = now.to_rfc3339().unwrap();
        assert!(formatted.ends_with('Z'));
        assert_ne!(formatted, "1970-01-01T00:00:00Z");
    }

    #[test]
    fn owner_scoped_key_generation_and_serde() {
        let owner_id = OwnerId::new("usr_01J8Y").unwrap();
        let key = OwnerScopedKey::new(Some(owner_id.clone()), "op_add_drawer_1").unwrap();
        assert_eq!(key.composite_key(), "usr_01J8Y:op_add_drawer_1");
        assert_eq!(key.raw_key(), "op_add_drawer_1");
        assert_eq!(key.owner_id(), Some(&owner_id));

        let legacy_key = OwnerScopedKey::new(None, "op_legacy_2").unwrap();
        assert_eq!(legacy_key.composite_key(), "legacy:op_legacy_2");
        assert_eq!(legacy_key.raw_key(), "op_legacy_2");
        assert_eq!(legacy_key.owner_id(), None);

        // Deserialization from struct
        let json_struct = r#"{"owner_id":"usr_01J8Y","raw_key":"op_add_drawer_1"}"#;
        let from_struct: OwnerScopedKey = serde_json::from_str(json_struct).unwrap();
        assert_eq!(from_struct, key);

        // Deserialization from scoped string
        let from_str: OwnerScopedKey = serde_json::from_str(r#""usr_01J8Y:op_add_drawer_1""#).unwrap();
        assert_eq!(from_str, key);

        // Deserialization from legacy string
        let from_legacy_str: OwnerScopedKey = serde_json::from_str(r#""legacy:op_legacy_2""#).unwrap();
        assert_eq!(from_legacy_str, legacy_key);
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
        let op = deserialized.operation_id().unwrap();
        assert_eq!(op.raw_key(), "owner-scoped-idempotency-key");
        assert_eq!(op.composite_key(), "usr_01J8Y:owner-scoped-idempotency-key");
    }

    #[test]
    fn reject_payload_owner_claim_enforces_server_side_attribution() {
        assert!(reject_payload_owner_claim::<String>(None).is_ok());
        assert!(matches!(
            reject_payload_owner_claim(Some("spoofed_owner")),
            Err(ProvenanceError::UnauthenticatedOwnerClaim(_))
        ));
    }

    // ─── Negative Wire-Format Validation Tests ─────────────────────────────────

    #[test]
    fn negative_wire_owner_id_validation() {
        // Empty string
        assert!(serde_json::from_str::<OwnerId>(r#""""#).is_err());
        // Oversized (> 128)
        let long_id = format!(r#""{}""#, "a".repeat(MAX_OWNER_ID_CHARS + 1));
        assert!(serde_json::from_str::<OwnerId>(&long_id).is_err());
        // Invalid characters
        assert!(serde_json::from_str::<OwnerId>(r#""usr with space""#).is_err());
        assert!(serde_json::from_str::<OwnerId>(r#""usr@invalid""#).is_err());
    }

    #[test]
    fn negative_wire_issuer_and_subject_validation() {
        // Issuer empty
        assert!(serde_json::from_str::<Issuer>(r#""""#).is_err());
        // Issuer oversized (> 256)
        let long_issuer = format!(r#""https://example.com/{}""#, "a".repeat(MAX_ISSUER_CHARS));
        assert!(serde_json::from_str::<Issuer>(&long_issuer).is_err());
        // Issuer non-graphic / whitespace
        assert!(serde_json::from_str::<Issuer>(r#""https://exam ple.com""#).is_err());

        // Subject empty
        assert!(serde_json::from_str::<Subject>(r#""""#).is_err());
        // Subject oversized (> 256)
        let long_sub = format!(r#""{}""#, "a".repeat(MAX_SUBJECT_CHARS + 1));
        assert!(serde_json::from_str::<Subject>(&long_sub).is_err());
        // Subject non-graphic / whitespace
        assert!(serde_json::from_str::<Subject>(r#""sub with space""#).is_err());
    }

    #[test]
    fn negative_wire_email_at_write_validation() {
        // Empty string
        assert!(serde_json::from_str::<EmailAtWrite>(r#""""#).is_err());
        // Whitespace only
        assert!(serde_json::from_str::<EmailAtWrite>(r#""   ""#).is_err());
        // Missing @
        assert!(serde_json::from_str::<EmailAtWrite>(r#""not-an-email""#).is_err());
        // Missing local part
        assert!(serde_json::from_str::<EmailAtWrite>(r#""@example.com""#).is_err());
        // Missing domain
        assert!(serde_json::from_str::<EmailAtWrite>(r#""user@""#).is_err());
        // Domain starts with dot
        assert!(serde_json::from_str::<EmailAtWrite>(r#""user@.com""#).is_err());
        // Oversized (> 254)
        let long_email = format!(r#""user@{}""#, "a".repeat(MAX_EMAIL_CHARS));
        assert!(serde_json::from_str::<EmailAtWrite>(&long_email).is_err());
    }

    #[test]
    fn negative_wire_agent_name_validation() {
        // Empty string
        assert!(serde_json::from_str::<AgentName>(r#""""#).is_err());
        // Whitespace
        assert!(serde_json::from_str::<AgentName>(r#""agent name""#).is_err());
        // Invalid characters
        assert!(serde_json::from_str::<AgentName>(r#""agent!""#).is_err());
        // Oversized (> 128)
        let long_name = format!(r#""{}""#, "a".repeat(MAX_AGENT_NAME_CHARS + 1));
        assert!(serde_json::from_str::<AgentName>(&long_name).is_err());
    }

    #[test]
    fn negative_wire_source_author_and_reference_validation() {
        // SourceAuthor empty or whitespace
        assert!(serde_json::from_str::<SourceAuthor>(r#""""#).is_err());
        assert!(serde_json::from_str::<SourceAuthor>(r#""   ""#).is_err());
        // SourceAuthor control character
        assert!(serde_json::from_str::<SourceAuthor>(r#""Alice\u0000Bob""#).is_err());
        // SourceAuthor oversized (> 256)
        let long_author = format!(r#""{}""#, "a".repeat(MAX_SOURCE_AUTHOR_CHARS + 1));
        assert!(serde_json::from_str::<SourceAuthor>(&long_author).is_err());

        // SourceReference empty or whitespace
        assert!(serde_json::from_str::<SourceReference>(r#""""#).is_err());
        assert!(serde_json::from_str::<SourceReference>(r#"" \t ""#).is_err());
        // SourceReference control char
        assert!(serde_json::from_str::<SourceReference>(r#""path/\u0001/file""#).is_err());
        // SourceReference oversized (> 2048)
        let long_ref = format!(r#""{}""#, "a".repeat(MAX_SOURCE_REF_CHARS + 1));
        assert!(serde_json::from_str::<SourceReference>(&long_ref).is_err());
    }

    #[test]
    fn negative_wire_storage_origin_validation() {
        // Local with empty origin_id
        assert!(serde_json::from_str::<StorageOrigin>(r#"{"kind":"local","origin_id":""}"#).is_err());
        // Local with whitespace origin_id
        assert!(serde_json::from_str::<StorageOrigin>(r#"{"kind":"local","origin_id":"has space"}"#).is_err());
        // Local oversized origin_id (> 256)
        let long_id = "a".repeat(MAX_ORIGIN_ID_CHARS + 1);
        let json = format!(r#"{{"kind":"local","origin_id":"{long_id}"}}"#);
        assert!(serde_json::from_str::<StorageOrigin>(&json).is_err());

        // Federated with empty origin_id
        assert!(serde_json::from_str::<StorageOrigin>(r#"{"kind":"federated","origin_id":""}"#).is_err());
        // Federated with oversized original_record_id (> 256)
        let long_rec = "r".repeat(MAX_RECORD_ID_CHARS + 1);
        let fed_json = format!(r#"{{"kind":"federated","origin_id":"https://remote.palace","original_record_id":"{long_rec}"}}"#);
        assert!(serde_json::from_str::<StorageOrigin>(&fed_json).is_err());
    }

    #[test]
    fn negative_wire_owner_scoped_key_validation() {
        // Struct with empty raw_key
        assert!(serde_json::from_str::<OwnerScopedKey>(r#"{"raw_key":""}"#).is_err());
        // Struct with whitespace raw_key
        assert!(serde_json::from_str::<OwnerScopedKey>(r#"{"raw_key":"   "}"#).is_err());
        // Struct with oversized raw_key (> 128)
        let long_key = "k".repeat(MAX_OPERATION_ID_CHARS + 1);
        let json = format!(r#"{{"raw_key":"{long_key}"}}"#);
        assert!(serde_json::from_str::<OwnerScopedKey>(&json).is_err());

        // String with empty value
        assert!(serde_json::from_str::<OwnerScopedKey>(r#""""#).is_err());
        // String with whitespace
        assert!(serde_json::from_str::<OwnerScopedKey>(r#""   ""#).is_err());
        // String with oversized value
        let str_json = format!(r#""{long_key}""#);
        assert!(serde_json::from_str::<OwnerScopedKey>(&str_json).is_err());
    }

    #[test]
    fn negative_wire_provenance_envelope_operation_id_validation() {
        let base_json = r#"{
            "owner": {"status": "unknown"},
            "recorded_at": "2026-09-17T11:04:27Z",
            "origin": {"kind": "local", "origin_id": "local"},
            "operation_id": "   "
        }"#;
        // Whitespace operation_id must be rejected
        assert!(serde_json::from_str::<ProvenanceEnvelope>(base_json).is_err());

        let empty_json = r#"{
            "owner": {"status": "unknown"},
            "recorded_at": "2026-09-17T11:04:27Z",
            "origin": {"kind": "local", "origin_id": "local"},
            "operation_id": ""
        }"#;
        // Empty operation_id must be rejected
        assert!(serde_json::from_str::<ProvenanceEnvelope>(empty_json).is_err());

        let long_op = "x".repeat(MAX_OPERATION_ID_CHARS + 1);
        let oversized_json = format!(r#"{{
            "owner": {{"status": "unknown"}},
            "recorded_at": "2026-09-17T11:04:27Z",
            "origin": {{"kind": "local", "origin_id": "local"}},
            "operation_id": "{long_op}"
        }}"#);
        // Oversized operation_id must be rejected
        assert!(serde_json::from_str::<ProvenanceEnvelope>(&oversized_json).is_err());
    }

    #[test]
    fn negative_wire_provenance_envelope_owner_scope_mismatch() {
        // Authenticated owner with operation_id claiming a different owner_id
        let mismatch_json = r#"{
            "owner": {
                "id": "usr_01J8Y",
                "issuer": "https://accounts.google.com",
                "subject": "104928190283019283019",
                "email_at_write": "tester@example.com"
            },
            "recorded_at": "2026-09-17T11:04:27Z",
            "origin": {"kind": "local", "origin_id": "local"},
            "operation_id": {
                "owner_id": "usr_other_hacker",
                "raw_key": "op_steal"
            }
        }"#;
        assert!(serde_json::from_str::<ProvenanceEnvelope>(mismatch_json).is_err());

        // Unknown owner with operation_id claiming an authenticated owner_id
        let unknown_with_auth_op = r#"{
            "owner": {"status": "unknown"},
            "recorded_at": "2026-09-17T11:04:27Z",
            "origin": {"kind": "local", "origin_id": "local"},
            "operation_id": {
                "owner_id": "usr_claimed",
                "raw_key": "op_legacy"
            }
        }"#;
        assert!(serde_json::from_str::<ProvenanceEnvelope>(unknown_with_auth_op).is_err());
    }

    #[test]
    fn negative_wire_provenance_envelope_source_refs_bound() {
        let refs: Vec<String> = (0..=MAX_SOURCE_REFS)
            .map(|i| format!(r#""ref_{i}""#))
            .collect();
        let refs_json = refs.join(",");
        let json = format!(r#"{{
            "owner": {{"status": "unknown"}},
            "recorded_at": "2026-09-17T11:04:27Z",
            "origin": {{"kind": "local", "origin_id": "local"}},
            "source_refs": [{refs_json}]
        }}"#);
        // Exceeds MAX_SOURCE_REFS (128) -> deserialization must fail
        assert!(serde_json::from_str::<ProvenanceEnvelope>(&json).is_err());
    }

    #[test]
    fn builder_rejects_empty_and_whitespace_operation_id() {
        let owner = OwnerIdentity::Unknown;
        let recorded_at = RecordingTime::from_rfc3339("2026-09-17T11:04:27Z").unwrap();
        let origin = StorageOrigin::local_default();
        let envelope = ProvenanceEnvelope::new(owner, recorded_at, origin);

        assert!(matches!(
            envelope.clone().with_operation_id(""),
            Err(ProvenanceError::EmptyField { field: "raw_key" })
        ));
        assert!(matches!(
            envelope.clone().with_operation_id("   "),
            Err(ProvenanceError::EmptyField { field: "raw_key" })
        ));
        assert!(matches!(
            envelope.with_operation_id("a".repeat(MAX_OPERATION_ID_CHARS + 1)),
            Err(ProvenanceError::ValueTooLong { field: "raw_key", .. })
        ));
    }

    #[test]
    fn negative_owner_id_sentinel_rejection() {
        for sentinel in &["legacy", "unknown", "none", "null", "LEGACY", "UNKNOWN", "None", "Null"] {
            assert!(matches!(
                OwnerId::new(*sentinel),
                Err(ProvenanceError::ReservedIdentifier { field: "owner_id", .. })
            ));
            assert!(OwnerId::from_str(sentinel).is_err());
            let json = format!(r#""{sentinel}""#);
            assert!(serde_json::from_str::<OwnerId>(&json).is_err());
        }
    }

    #[test]
    fn owner_scoped_key_collision_tests() {
        // Unknown owner with key "x" produces composite key "legacy:x"
        let unknown_key = OwnerScopedKey::new(None, "x").unwrap();
        assert_eq!(unknown_key.composite_key(), "legacy:x");

        // Authenticated owner with key "x" produces "{owner_id}:x"
        let auth_id = OwnerId::new("usr_01J8Y").unwrap();
        let auth_key = OwnerScopedKey::new(Some(auth_id.clone()), "x").unwrap();
        assert_eq!(auth_key.composite_key(), "usr_01J8Y:x");

        // They can never collide
        assert_ne!(unknown_key.composite_key(), auth_key.composite_key());

        // Sentinel owner IDs cannot be created to forge legacy keys
        assert!(OwnerId::new("legacy").is_err());
        assert!(OwnerId::new("unknown").is_err());

        // Both legacy and unknown string prefixes parse cleanly to None owner_id
        let from_legacy_str: OwnerScopedKey = serde_json::from_str(r#""legacy:x""#).unwrap();
        assert_eq!(from_legacy_str.owner_id(), None);
        assert_eq!(from_legacy_str.raw_key(), "x");

        let from_unknown_str: OwnerScopedKey = serde_json::from_str(r#""unknown:x""#).unwrap();
        assert_eq!(from_unknown_str.owner_id(), None);
        assert_eq!(from_unknown_str.raw_key(), "x");

        let from_legacy_upper: OwnerScopedKey = serde_json::from_str(r#""LEGACY:x""#).unwrap();
        assert_eq!(from_legacy_upper.owner_id(), None);
        assert_eq!(from_legacy_upper.raw_key(), "x");

        // Authenticated scoped string parses to Some(owner_id)
        let from_auth_str: OwnerScopedKey = serde_json::from_str(r#""usr_01J8Y:x""#).unwrap();
        assert_eq!(from_auth_str.owner_id(), Some(&auth_id));
        assert_eq!(from_auth_str.raw_key(), "x");

        // Deserializing struct with sentinel owner_id must be rejected
        assert!(serde_json::from_str::<OwnerScopedKey>(r#"{"owner_id":"legacy","raw_key":"x"}"#).is_err());
        assert!(serde_json::from_str::<OwnerScopedKey>(r#"{"owner_id":"unknown","raw_key":"x"}"#).is_err());
    }

    #[test]
    fn negative_owner_identity_deserialization_tests() {
        // 1. Unknown / unrecognized status values must be rejected even when all fields exist
        let bogus_status_with_fields = r#"{
            "status": "some_bogus_status",
            "id": "usr_01J8Y",
            "issuer": "https://accounts.google.com",
            "subject": "104928190283019283019",
            "email_at_write": "tester@example.com"
        }"#;
        assert!(serde_json::from_str::<OwnerIdentity>(bogus_status_with_fields).is_err());

        assert!(serde_json::from_str::<OwnerIdentity>(r#"{"status":"active"}"#).is_err());
        assert!(serde_json::from_str::<OwnerIdentity>(r#"{"status":"verified"}"#).is_err());
        assert!(serde_json::from_str::<OwnerIdentity>(r#""some_bogus_status""#).is_err());

        // 2. Contradictory object shapes: status "unknown" or "legacy" with authenticated fields must be rejected
        assert!(serde_json::from_str::<OwnerIdentity>(
            r#"{"status":"unknown","id":"usr_01J8Y"}"#
        ).is_err());

        assert!(serde_json::from_str::<OwnerIdentity>(
            r#"{"status":"unknown","issuer":"https://accounts.google.com"}"#
        ).is_err());

        assert!(serde_json::from_str::<OwnerIdentity>(
            r#"{"status":"unknown","subject":"104928190283019283019"}"#
        ).is_err());

        assert!(serde_json::from_str::<OwnerIdentity>(
            r#"{"status":"unknown","email_at_write":"tester@example.com"}"#
        ).is_err());

        let unknown_with_all = r#"{
            "status": "unknown",
            "id": "usr_01J8Y",
            "issuer": "https://accounts.google.com",
            "subject": "104928190283019283019",
            "email_at_write": "tester@example.com"
        }"#;
        assert!(serde_json::from_str::<OwnerIdentity>(unknown_with_all).is_err());

        let legacy_with_all = r#"{
            "status": "legacy",
            "id": "usr_01J8Y",
            "issuer": "https://accounts.google.com",
            "subject": "104928190283019283019",
            "email_at_write": "tester@example.com"
        }"#;
        assert!(serde_json::from_str::<OwnerIdentity>(legacy_with_all).is_err());

        // 3. Incomplete authenticated shapes must be rejected
        assert!(serde_json::from_str::<OwnerIdentity>(
            r#"{"status":"authenticated","id":"usr_01J8Y"}"#
        ).is_err());
        assert!(serde_json::from_str::<OwnerIdentity>(
            r#"{"status":"authenticated"}"#
        ).is_err());
        assert!(serde_json::from_str::<OwnerIdentity>(
            r#"{"id":"usr_01J8Y"}"#
        ).is_err());
        assert!(serde_json::from_str::<OwnerIdentity>("{}").is_err());
        assert!(serde_json::from_str::<OwnerIdentity>(r#""""#).is_err());

        // 4. Positive fail-closed compatibility checks
        assert_eq!(
            serde_json::from_str::<OwnerIdentity>(r#"{"status":"legacy"}"#).unwrap(),
            OwnerIdentity::Unknown
        );
        assert_eq!(
            serde_json::from_str::<OwnerIdentity>(r#"{"status":"UNKNOWN"}"#).unwrap(),
            OwnerIdentity::Unknown
        );
        assert_eq!(
            serde_json::from_str::<OwnerIdentity>(r#"{"status":"LEGACY"}"#).unwrap(),
            OwnerIdentity::Unknown
        );
        assert_eq!(
            serde_json::from_str::<OwnerIdentity>(r#""unknown""#).unwrap(),
            OwnerIdentity::Unknown
        );
        assert_eq!(
            serde_json::from_str::<OwnerIdentity>(r#""legacy""#).unwrap(),
            OwnerIdentity::Unknown
        );
        assert_eq!(
            serde_json::from_str::<OwnerIdentity>(r#""UNKNOWN""#).unwrap(),
            OwnerIdentity::Unknown
        );
        assert_eq!(
            serde_json::from_str::<OwnerIdentity>(r#""LEGACY""#).unwrap(),
            OwnerIdentity::Unknown
        );

        let tagged_upper = r#"{
            "status": "AUTHENTICATED",
            "id": "usr_01J8Y",
            "issuer": "https://accounts.google.com",
            "subject": "104928190283019283019",
            "email_at_write": "tester@example.com"
        }"#;
        assert!(matches!(
            serde_json::from_str::<OwnerIdentity>(tagged_upper).unwrap(),
            OwnerIdentity::Authenticated(_)
        ));
    }
}
