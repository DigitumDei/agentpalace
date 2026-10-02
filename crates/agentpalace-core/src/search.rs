use serde::{Deserialize, Serialize};
use time::{Date, OffsetDateTime};

use crate::locator::SourceLocator;
use crate::PersistedProvenance;
use crate::{DrawerId, EmbeddingProfile, RoomId, WingId};

time::serde::format_description!(date_only, Date, "[year]-[month]-[day]");

/// Durable repository-view metadata for project-mined rows.
///
/// Replaces the `hall = "view:<name>"` convention with explicit, queryable
/// columns.  `None` on a `DrawerRecord` means the row is not project-mined
/// (e.g. a conversation, diary entry, or authored drawer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryViewMetadata {
    /// Stable repository identity (normalised git remote URL, or `wing:<wing>`).
    pub repo_id: String,
    /// View name: `None` for canonical (default-branch) snapshots, `Some(...)` for
    /// a named branch or detached-HEAD view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view_name: Option<String>,
    /// Absolute project checkout path on the palace host that owns this row.
    pub source_path: String,
    /// Git commit hash at mine time (`git rev-parse HEAD`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_commit: Option<String>,
    /// Base/integration ref (the default branch name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_ref: Option<String>,
    /// Merge-base commit between the view and the base ref.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_base: Option<String>,
    /// Stable worktree identity (canonicalised checkout path hash).
    pub worktree_id: String,
    /// Path state: `"present"` or `"deleted"`.  `"deleted"` marks a tombstone row
    /// whose source file has been removed from the checkout.
    pub path_state: String,
}

/// Canonical drawer row shape for future storage adapters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DrawerRecord {
    pub id: DrawerId,
    pub wing: WingId,
    pub room: RoomId,
    pub hall: Option<String>,
    #[serde(with = "date_only::option", default)]
    pub date: Option<Date>,
    pub source_file: String,
    pub chunk_index: u32,
    pub ingest_mode: String,
    pub extract_mode: Option<String>,
    pub added_by: String,
    #[serde(with = "time::serde::rfc3339")]
    pub filed_at: OffsetDateTime,
    pub importance: Option<f32>,
    pub emotional_weight: Option<f32>,
    pub weight: Option<f32>,
    pub content: String,
    pub content_hash: String,
    #[serde(default)]
    pub embedding: Vec<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<SourceLocator>,
    /// Repository-view metadata for project-mined rows.  Absent for non-project
    /// rows and for legacy rows that predate this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view_metadata: Option<RepositoryViewMetadata>,
    /// Durable domain provenance; `None` means this legacy row has unknown ownership.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<PersistedProvenance>,
}

/// Stable priority order used by plain-text and AAAK layer rendering.
pub fn compare_layer_drawers(left: &DrawerRecord, right: &DrawerRecord) -> std::cmp::Ordering {
    fn source_label(source: &str) -> &str {
        std::path::Path::new(source).file_name().and_then(|name| name.to_str()).unwrap_or(source)
    }
    right
        .importance
        .or(right.emotional_weight)
        .or(right.weight)
        .unwrap_or(3.0)
        .partial_cmp(&left.importance.or(left.emotional_weight).or(left.weight).unwrap_or(3.0))
        .unwrap_or(std::cmp::Ordering::Equal)
        .then_with(|| left.room.as_str().cmp(right.room.as_str()))
        .then_with(|| right.date.cmp(&left.date))
        .then_with(|| right.filed_at.cmp(&left.filed_at))
        .then_with(|| source_label(&left.source_file).cmp(source_label(&right.source_file)))
        .then_with(|| left.chunk_index.cmp(&right.chunk_index))
        .then_with(|| left.id.as_str().cmp(right.id.as_str()))
}

/// Search request contract shared by CLI, MCP, and library APIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchQuery {
    pub text: String,
    pub wing: Option<WingId>,
    pub room: Option<RoomId>,
    /// Optional view/ref name to scope search to a specific branch view.
    /// When `None`, search uses canonical snapshots and excludes branch views.
    /// Set to a branch name to compose that branch's changed paths over its
    /// canonical snapshot. `"canonical"` is an explicit equivalent of `None`.
    /// Set to `"full"` to search every stored repository view independently.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view: Option<String>,
    pub limit: usize,
    pub profile: EmbeddingProfile,
    /// How much weight drawer age carries in ranking. `None` uses the runtime's
    /// configured default. Never changes the reported similarity score.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freshness: Option<Freshness>,
}

/// Ranking intent for drawer age.
///
/// Age is context, not proof: a newer drawer is never assumed to supersede an
/// older one. `Balanced` and `Recent` add a small bounded lift to newer drawers
/// that are otherwise near-equal matches; `Relevant` is pure semantic order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Freshness {
    /// Pure semantic order; age has no effect.
    #[default]
    Relevant,
    /// Small lift for newer near-equal matches.
    Balanced,
    /// Larger lift, for "what is the latest state of X" questions.
    Recent,
}

impl Freshness {
    /// All modes, in increasing order of age weight.
    pub const ALL: [Self; 3] = [Self::Relevant, Self::Balanced, Self::Recent];

    /// Wire and config name of this mode.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Relevant => "relevant",
            Self::Balanced => "balanced",
            Self::Recent => "recent",
        }
    }

    /// Parse a wire or config name.
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|mode| mode.as_str() == value)
    }

    /// Maximum score lift a drawer can receive for being the newest in its group.
    pub fn weight(self) -> f32 {
        match self {
            Self::Relevant => 0.0,
            Self::Balanced => 0.05,
            Self::Recent => 0.20,
        }
    }
}

/// Search result contract shared by CLI, MCP, and library APIs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drawer_id: Option<DrawerId>,
    pub wing: WingId,
    pub room: RoomId,
    #[serde(rename = "similarity")]
    pub score: f32,
    #[serde(rename = "text")]
    pub content: String,
    pub source_file: String,
    /// `true` when the result comes from a locator-backed row whose source file
    /// changed since mining.  Absent (serialised) unless true, so existing JSON
    /// shapes remain byte-identical for non-stale results.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stale: bool,
    /// Content hash of the drawer, present only when the result is from a
    /// duplicate check that needs exact-match detection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    /// View/ref name this result belongs to, if mined from a specific branch view.
    /// Absent for canonical results.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view: Option<String>,
    /// Redacted durable provenance when the result came from a provenance-aware drawer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<serde_json::Value>,
    /// When the drawer was written to the palace (UTC). For mined rows this is
    /// the mining time, not when the underlying content was authored. Absent
    /// when the origin did not report it (for example an older remote).
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub filed_at: Option<OffsetDateTime>,
    /// Authored or event date recorded with the drawer, when one is known.
    /// Distinct from `filed_at`; absent means no authored date was recorded.
    #[serde(default, with = "date_only::option", skip_serializing_if = "Option::is_none")]
    pub date: Option<Date>,
    /// How the drawer was written (`mcp`, `diary`, `projects`, `convos`, ...).
    /// Mined modes mean `filed_at` reflects ingest time, not authorship.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingest_mode: Option<String>,
}

/// Ingest modes written by bulk mining. Their `filed_at` is ingest time, so it
/// says nothing about when the underlying content was authored.
pub const MINED_INGEST_MODES: [&str; 3] = ["projects", "projects-branch", "convos"];

/// Whether `ingest_mode` is a bulk-mining mode (see [`MINED_INGEST_MODES`]).
pub fn is_mined_ingest_mode(ingest_mode: &str) -> bool {
    MINED_INGEST_MODES.contains(&ingest_mode)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use serde_json::json;
    use time::macros::{date, datetime};

    use super::{DrawerRecord, Freshness, SearchQuery, SearchResult};
    use crate::{DrawerId, RoomId, WingId};

    #[test]
    fn search_result_uses_phase0_field_names() {
        let result = SearchResult {
            drawer_id: None,
            wing: WingId::new("project_alpha").unwrap(),
            room: RoomId::new("backend").unwrap(),
            score: 0.49,
            content: "auth migration parity".to_owned(),
            source_file: "team.txt".to_owned(),
            stale: false,
            content_hash: None,
            view: None,
            provenance: None,
            filed_at: None,
            date: None,
            ingest_mode: None,
        };

        let value = serde_json::to_value(&result).unwrap();
        let object = value.as_object().unwrap();

        assert_eq!(object.get("wing"), Some(&json!("project_alpha")));
        assert_eq!(object.get("room"), Some(&json!("backend")));
        assert_eq!(object.get("text"), Some(&json!("auth migration parity")));
        assert_eq!(object.get("source_file"), Some(&json!("team.txt")));
        assert!(object.get("drawer_id").is_none());
        let similarity = object.get("similarity").and_then(|value| value.as_f64()).unwrap();
        assert!((similarity - 0.49).abs() < 1e-6, "unexpected similarity: {similarity}");
        // `stale` must be absent when false so byte-parity is preserved.
        assert!(object.get("stale").is_none(), "stale should be absent when false");
        // `view` must be absent when None so byte-parity is preserved for non-view results.
        assert!(object.get("view").is_none(), "view should be absent when None");
    }

    #[test]
    fn search_result_stale_present_only_when_true() {
        let non_stale = SearchResult {
            drawer_id: None,
            wing: WingId::new("w").unwrap(),
            room: RoomId::new("r").unwrap(),
            score: 0.5,
            content: "text".to_owned(),
            source_file: "f.txt".to_owned(),
            stale: false,
            content_hash: None,
            view: None,
            provenance: None,
            filed_at: None,
            date: None,
            ingest_mode: None,
        };
        let stale = SearchResult { stale: true, ..non_stale.clone() };
        let non_stale_json = serde_json::to_value(&non_stale).unwrap();
        let stale_json = serde_json::to_value(&stale).unwrap();
        assert!(non_stale_json.as_object().unwrap().get("stale").is_none());
        assert_eq!(stale_json.as_object().unwrap().get("stale"), Some(&json!(true)));
    }

    #[test]
    fn search_result_temporal_fields_are_absent_when_unknown_and_rfc3339_when_present() {
        let unknown = SearchResult {
            drawer_id: None,
            wing: WingId::new("w").unwrap(),
            room: RoomId::new("r").unwrap(),
            score: 0.5,
            content: "text".to_owned(),
            source_file: "f.txt".to_owned(),
            stale: false,
            content_hash: None,
            view: None,
            provenance: None,
            filed_at: None,
            date: None,
            ingest_mode: None,
        };
        let value = serde_json::to_value(&unknown).unwrap();
        let object = value.as_object().unwrap();
        for key in ["filed_at", "date", "ingest_mode"] {
            assert!(object.get(key).is_none(), "{key} must be absent when unknown");
        }

        // A non-UTC offset is preserved as written; the instant is unambiguous.
        let known = SearchResult {
            filed_at: Some(datetime!(2026-09-30 23:30:00 -02:00)),
            date: Some(date!(2026 - 09 - 30)),
            ingest_mode: Some("mcp".to_owned()),
            ..unknown
        };
        let value = serde_json::to_value(&known).unwrap();
        assert_eq!(value.get("filed_at"), Some(&json!("2026-09-30T23:30:00-02:00")));
        assert_eq!(value.get("date"), Some(&json!("2026-09-30")));
        assert_eq!(value.get("ingest_mode"), Some(&json!("mcp")));
        let round_trip: SearchResult = serde_json::from_value(value).unwrap();
        assert_eq!(round_trip, known);
        assert_eq!(
            round_trip.filed_at.unwrap().to_offset(time::UtcOffset::UTC),
            datetime!(2026-10-01 01:30:00 UTC)
        );
    }

    #[test]
    fn search_query_without_freshness_serializes_without_key() {
        let query = SearchQuery {
            text: "q".to_owned(),
            wing: None,
            room: None,
            view: None,
            limit: 5,
            profile: crate::EmbeddingProfile::Balanced,
            freshness: None,
        };
        let value = serde_json::to_value(&query).unwrap();
        assert!(value.get("freshness").is_none());
        let with = SearchQuery { freshness: Some(Freshness::Recent), ..query };
        assert_eq!(serde_json::to_value(&with).unwrap().get("freshness"), Some(&json!("recent")));
        assert_eq!(Freshness::parse("balanced"), Some(Freshness::Balanced));
        assert_eq!(Freshness::parse("latest"), None);
    }

    #[test]
    fn drawer_record_serializes_as_json_strings_for_time_fields() {
        let record = DrawerRecord {
            id: DrawerId::new("project_alpha/backend/0001").unwrap(),
            wing: WingId::new("project_alpha").unwrap(),
            room: RoomId::new("backend").unwrap(),
            hall: Some("auth".to_owned()),
            date: Some(date!(2026 - 04 - 11)),
            source_file: "auth.py".to_owned(),
            chunk_index: 0,
            ingest_mode: "phase0".to_owned(),
            extract_mode: Some("full".to_owned()),
            added_by: "tester".to_owned(),
            filed_at: datetime!(2026-04-11 09:45:00 UTC),
            importance: Some(0.8),
            emotional_weight: Some(0.2),
            weight: Some(1.0),
            content: "payload".to_owned(),
            content_hash: "hash".to_owned(),
            embedding: vec![0.1, 0.2],
            locator: None,
            view_metadata: None,
            provenance: None,
        };

        let value = serde_json::to_value(&record).unwrap();

        assert_eq!(value.get("date"), Some(&json!("2026-04-11")));
        assert_eq!(value.get("filed_at"), Some(&json!("2026-04-11T09:45:00Z")));

        let embedding = value.get("embedding").and_then(|value| value.as_array()).unwrap();
        let first = embedding[0].as_f64().unwrap();
        let second = embedding[1].as_f64().unwrap();
        assert!((first - 0.1).abs() < 1e-6, "unexpected embedding[0]: {first}");
        assert!((second - 0.2).abs() < 1e-6, "unexpected embedding[1]: {second}");
    }
}
