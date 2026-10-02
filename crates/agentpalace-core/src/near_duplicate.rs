//! Classification of near-duplicate matches found when filing a drawer.
//!
//! A semantic similarity above the duplicate threshold does not by itself mean
//! the new content is a copy. Recurring snapshots (status reports, monitoring
//! runs) share one line template and differ only in their numbers and
//! timestamps; refusing them as duplicates loses the newest state. This module
//! tells a new version of a series apart from a copy or a paraphrase, using
//! only the text, the content hash, and the filing metadata of each match.

use time::{Duration, OffsetDateTime};

/// Minimum age of an earlier same-source drawer before a timestamp-only
/// re-file of the same template counts as a new run of a series.
pub const SERIES_MIN_AGE: Duration = Duration::hours(6);

/// How an incoming drawer relates to an existing drawer that scored at or
/// above the duplicate threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuplicateRelation {
    /// Byte-identical content (equal content hash). Always refused.
    Exact,
    /// A new run of a recurring snapshot. Accepted.
    SeriesUpdate(SeriesReason),
    /// A paraphrase or near-copy. Refused unless the caller forces it.
    NearDuplicate,
}

/// Why a match was classified as a series update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeriesReason {
    /// Same template, but the non-timestamp numbers differ.
    ValuesChanged,
    /// Same template and same full source, filed at least [`SERIES_MIN_AGE`] earlier.
    SameSourceLater,
}

impl DuplicateRelation {
    /// Wire name of the relation (`exact`, `series_update`, `near_duplicate`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::SeriesUpdate(_) => "series_update",
            Self::NearDuplicate => "near_duplicate",
        }
    }

    /// Wire name of the series reason, when this is a series update.
    pub fn reason(self) -> Option<&'static str> {
        match self {
            Self::SeriesUpdate(SeriesReason::ValuesChanged) => Some("values_changed"),
            Self::SeriesUpdate(SeriesReason::SameSourceLater) => Some("same_source_later"),
            Self::Exact | Self::NearDuplicate => None,
        }
    }

    /// Whether this relation prevents filing. `force` is the caller's
    /// `allow_near_duplicate`; it never bypasses an exact match.
    pub fn blocks(self, force: bool) -> bool {
        match self {
            Self::Exact => true,
            Self::SeriesUpdate(_) => false,
            Self::NearDuplicate => !force,
        }
    }
}

/// Whether a match with wire relation `relation` prevents filing. A match with
/// no relation comes from an older peer that cannot classify, so it blocks.
pub fn relation_blocks(relation: Option<&str>, allow_near_duplicate: bool) -> bool {
    match relation {
        Some("series_update") => false,
        Some("near_duplicate") => !allow_near_duplicate,
        _ => true,
    }
}

/// The drawer being filed.
#[derive(Debug, Clone, Copy)]
pub struct IncomingDrawer<'a> {
    pub content: &'a str,
    pub content_hash: &'a str,
    /// Target wing; `None` when the caller has no wing (for example `check_duplicate`).
    pub wing: Option<&'a str>,
    /// Full stored source label; `None` or empty when the caller gave none.
    pub source_file: Option<&'a str>,
    pub now: OffsetDateTime,
}

/// An existing drawer that matched at or above the duplicate threshold.
#[derive(Debug, Clone, Copy)]
pub struct DuplicateCandidate<'a> {
    pub content: &'a str,
    pub content_hash: &'a str,
    pub wing: &'a str,
    /// Full stored `source_file`, not the base-name label shown in search results.
    pub source_file: &'a str,
    pub filed_at: Option<OffsetDateTime>,
}

/// Classify one match. Rules apply in order: exact hash, changed values,
/// same full source filed at least [`SERIES_MIN_AGE`] earlier, otherwise near-duplicate.
pub fn classify_duplicate(
    incoming: &IncomingDrawer<'_>,
    candidate: &DuplicateCandidate<'_>,
) -> DuplicateRelation {
    if incoming.content_hash == candidate.content_hash {
        return DuplicateRelation::Exact;
    }
    let incoming_mask = mask_template(incoming.content);
    let candidate_mask = mask_template(candidate.content);
    if incoming_mask.template != candidate_mask.template {
        return DuplicateRelation::NearDuplicate;
    }
    if incoming_mask.numbers != candidate_mask.numbers {
        return DuplicateRelation::SeriesUpdate(SeriesReason::ValuesChanged);
    }
    let same_source = match (incoming.wing, incoming.source_file) {
        (Some(wing), Some(source)) if !source.is_empty() => {
            wing == candidate.wing && source == candidate.source_file
        }
        _ => false,
    };
    let old_enough = candidate
        .filed_at
        .is_some_and(|filed_at| incoming.now - filed_at >= SERIES_MIN_AGE);
    if same_source && old_enough {
        return DuplicateRelation::SeriesUpdate(SeriesReason::SameSourceLater);
    }
    DuplicateRelation::NearDuplicate
}

/// Text with its numbers and timestamps masked out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskedTemplate {
    /// Lowercased, whitespace-collapsed text with timestamps as `<t>` and
    /// other numbers as `<n>`.
    pub template: String,
    /// The non-timestamp numbers, in order of appearance.
    pub numbers: Vec<String>,
}

/// Mask timestamps and numbers so two runs of one template compare equal.
///
/// ISO-style dates (`dddd-dd-dd`), clock times (`hh:mm[:ss[.f]]`), the `T`
/// separator between them, and a trailing `Z` or `±hh:mm` offset become `<t>`.
/// Every other digit run, including a decimal such as `12.5`, becomes `<n>`.
/// A `-` directly before a number is its sign (so `-1.5` and `1.5` share a
/// template) unless it follows a letter or digit, as in `web-01` or `10-20`.
pub fn mask_template(text: &str) -> MaskedTemplate {
    let chars: Vec<char> =
        text.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase().chars().collect();
    let mut template = String::with_capacity(chars.len());
    let mut numbers = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        let signed = chars[index] == '-'
            && chars.get(index + 1).is_some_and(char::is_ascii_digit)
            && index.checked_sub(1).is_none_or(|prev| !chars[prev].is_alphanumeric())
            && match_timestamp(&chars, index + 1).is_none();
        if !signed && !chars[index].is_ascii_digit() {
            template.push(chars[index]);
            index += 1;
            continue;
        }
        if let Some(end) = match_timestamp(&chars, index) {
            template.push_str("<t>");
            index = end;
            continue;
        }
        let start = index;
        index = digits_end(&chars, if signed { index + 1 } else { index });
        if chars.get(index) == Some(&'.') && chars.get(index + 1).is_some_and(char::is_ascii_digit)
        {
            index = digits_end(&chars, index + 1);
        }
        numbers.push(chars[start..index].iter().collect());
        template.push_str("<n>");
    }
    MaskedTemplate { template, numbers }
}

fn digits_end(chars: &[char], start: usize) -> usize {
    let mut index = start;
    while chars.get(index).is_some_and(char::is_ascii_digit) {
        index += 1;
    }
    index
}

/// Match exactly `count` digits at `start`, returning the end index.
fn fixed_digits(chars: &[char], start: usize, count: usize) -> Option<usize> {
    let end = start + count;
    (end <= chars.len() && chars[start..end].iter().all(char::is_ascii_digit)).then_some(end)
}

fn match_date(chars: &[char], start: usize) -> Option<usize> {
    let index = fixed_digits(chars, start, 4)?;
    (chars.get(index) == Some(&'-')).then_some(())?;
    let index = fixed_digits(chars, index + 1, 2)?;
    (chars.get(index) == Some(&'-')).then_some(())?;
    let index = fixed_digits(chars, index + 1, 2)?;
    (!chars.get(index).is_some_and(char::is_ascii_digit)).then_some(index)
}

fn match_time(chars: &[char], start: usize) -> Option<usize> {
    let hour_end = digits_end(chars, start);
    if hour_end == start || hour_end - start > 2 || chars.get(hour_end) != Some(&':') {
        return None;
    }
    let mut index = fixed_digits(chars, hour_end + 1, 2)?;
    let seconds_end =
        (chars.get(index) == Some(&':')).then(|| fixed_digits(chars, index + 1, 2)).flatten();
    if let Some(seconds_end) = seconds_end {
        index = seconds_end;
        if chars.get(index) == Some(&'.') && chars.get(index + 1).is_some_and(char::is_ascii_digit) {
            index = digits_end(chars, index + 1);
        }
    }
    if chars.get(index).is_some_and(char::is_ascii_digit) {
        return None;
    }
    Some(match_offset(chars, index).unwrap_or(index))
}

fn match_offset(chars: &[char], start: usize) -> Option<usize> {
    match chars.get(start) {
        Some('z') => (!chars.get(start + 1).is_some_and(|c| c.is_alphanumeric())).then_some(start + 1),
        Some('+' | '-') => {
            let index = fixed_digits(chars, start + 1, 2)?;
            (chars.get(index) == Some(&':')).then_some(())?;
            let index = fixed_digits(chars, index + 1, 2)?;
            (!chars.get(index).is_some_and(char::is_ascii_digit)).then_some(index)
        }
        _ => None,
    }
}

fn match_timestamp(chars: &[char], start: usize) -> Option<usize> {
    if let Some(date_end) = match_date(chars, start) {
        // A date may be followed by `T` or a space and a clock time.
        let time_end = matches!(chars.get(date_end), Some('t' | ' '))
            .then(|| match_time(chars, date_end + 1))
            .flatten();
        return Some(time_end.unwrap_or(date_end));
    }
    match_time(chars, start)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use time::macros::datetime;

    use super::{
        DuplicateCandidate, DuplicateRelation, IncomingDrawer, SeriesReason, classify_duplicate,
        mask_template,
    };
    use crate::hash_text;

    #[test]
    fn masks_iso_dates_times_offsets_and_decimals() {
        let masked = mask_template(
            "Snapshot 2026-09-30T14:05:09.123Z  host web-01:\n cpu 12.5% mem 4096 MB at 09:15 (+02:00 local 2026-09-30 16:05:09+02:00)",
        );
        assert_eq!(
            masked.template,
            "snapshot <t> host web-<n>: cpu <n>% mem <n> mb at <t> (+<t> local <t>)"
        );
        assert_eq!(masked.numbers, vec!["01", "12.5", "4096"]);
    }

    #[test]
    fn a_leading_minus_is_the_numbers_sign_but_a_hyphen_is_not() {
        let negative = mask_template("temp -1.5 c on web-01, range 10-20, offset -02:00");
        let positive = mask_template("temp 1.5 c on web-01, range 10-20, offset -02:00");
        assert_eq!(negative.template, positive.template);
        assert_eq!(negative.template, "temp <n> c on web-<n>, range <n>-<n>, offset -<t>");
        assert_eq!(negative.numbers, vec!["-1.5", "01", "10", "20"]);
        assert_eq!(positive.numbers, vec!["1.5", "01", "10", "20"]);
        assert_eq!(mask_template("-3 errors").numbers, vec!["-3"]);
    }

    #[test]
    fn a_value_crossing_zero_is_a_series_update() {
        let before = "ops balance -1.5 at node-a";
        let after = "ops balance 1.5 at node-a";
        let (before_hash, after_hash) = (hash_text(before), hash_text(after));
        assert_eq!(
            classify_duplicate(
                &incoming(after, &after_hash, None),
                &candidate(before, &before_hash, "", datetime!(2026-10-01 11:00:00 UTC))
            ),
            DuplicateRelation::SeriesUpdate(SeriesReason::ValuesChanged)
        );
    }

    #[test]
    fn masking_is_case_and_whitespace_insensitive() {
        assert_eq!(mask_template("CPU  12\n\nok"), mask_template("cpu 12 ok"));
    }

    fn incoming<'a>(
        content: &'a str,
        hash: &'a str,
        source: Option<&'a str>,
    ) -> IncomingDrawer<'a> {
        IncomingDrawer {
            content,
            content_hash: hash,
            wing: Some("wing_ops"),
            source_file: source,
            now: datetime!(2026-10-01 12:00:00 UTC),
        }
    }

    fn candidate<'a>(
        content: &'a str,
        hash: &'a str,
        source: &'a str,
        filed_at: time::OffsetDateTime,
    ) -> DuplicateCandidate<'a> {
        DuplicateCandidate {
            content,
            content_hash: hash,
            wing: "wing_ops",
            source_file: source,
            filed_at: Some(filed_at),
        }
    }

    #[test]
    fn classifier_rules_apply_in_order() {
        let old_at = datetime!(2026-09-27 12:00:00 UTC);
        let recent_at = datetime!(2026-10-01 09:00:00 UTC);
        let base = "web-01 2026-09-27T12:00:00Z cpu 40% disk 71%";
        let base_hash = hash_text(base);

        // Exact copy.
        assert_eq!(
            classify_duplicate(
                &incoming(base, &base_hash, None),
                &candidate(base, &base_hash, "", old_at)
            ),
            DuplicateRelation::Exact
        );

        // Digits changed: a new run of the series.
        let changed = "web-01 2026-10-01T12:00:00Z cpu 55% disk 72%";
        let changed_hash = hash_text(changed);
        assert_eq!(
            classify_duplicate(
                &incoming(changed, &changed_hash, None),
                &candidate(base, &base_hash, "", old_at)
            ),
            DuplicateRelation::SeriesUpdate(SeriesReason::ValuesChanged)
        );

        // Only the timestamp changed, within 6h of the earlier run: near-duplicate.
        let ts_only = "web-01 2026-10-01T12:00:00Z cpu 40% disk 71%";
        let ts_hash = hash_text(ts_only);
        assert_eq!(
            classify_duplicate(
                &incoming(ts_only, &ts_hash, Some("/ops/web-01.log")),
                &candidate(base, &base_hash, "/ops/web-01.log", recent_at)
            ),
            DuplicateRelation::NearDuplicate
        );

        // Same template and same full source, more than 6h later: series update.
        assert_eq!(
            classify_duplicate(
                &incoming(ts_only, &ts_hash, Some("/ops/web-01.log")),
                &candidate(base, &base_hash, "/ops/web-01.log", old_at)
            ),
            DuplicateRelation::SeriesUpdate(SeriesReason::SameSourceLater)
        );

        // Same base name, different full path: not one series.
        assert_eq!(
            classify_duplicate(
                &incoming(ts_only, &ts_hash, Some("/ops/a/web-01.log")),
                &candidate(base, &base_hash, "/ops/b/web-01.log", old_at)
            ),
            DuplicateRelation::NearDuplicate
        );

        // Paraphrase under the same source, older than 6h: still near-duplicate.
        let paraphrase = "web-01 at 2026-09-27T12:00:00Z had cpu 40% and disk 71%";
        let paraphrase_hash = hash_text(paraphrase);
        assert_eq!(
            classify_duplicate(
                &incoming(paraphrase, &paraphrase_hash, Some("/ops/web-01.log")),
                &candidate(base, &base_hash, "/ops/web-01.log", old_at)
            ),
            DuplicateRelation::NearDuplicate
        );
    }

    #[test]
    fn blocking_never_lets_force_bypass_exact() {
        assert!(DuplicateRelation::Exact.blocks(true));
        assert!(DuplicateRelation::NearDuplicate.blocks(false));
        assert!(!DuplicateRelation::NearDuplicate.blocks(true));
        assert!(!DuplicateRelation::SeriesUpdate(SeriesReason::ValuesChanged).blocks(false));
    }
}
