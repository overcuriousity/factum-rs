//! Mechanical repair and validation of the model's pass output; no model, database or network involved.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use super::questions::{Archetype, NewQuestion, Question, RatedExample, Rating};

/// Cuts the first JSON object out of a model reply (fences and prose dropped) and repairs trailing commas,
/// single-quoted or bare keys and a cut-off tail. `None` when there is no `{`.
pub fn repair_json(text: &str) -> Option<String> {
    repair_from(text, text.find('{')?)
}

/// Like `repair_json`, but the document may start with `[` or `{`, whichever comes first.
fn repair_json_or_array(text: &str) -> Option<String> {
    repair_from(text, text.find(['{', '['])?)
}

fn is_bare(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '+')
}

/// Drops whitespace and one comma at the end of `out`.
fn trim_trailing_comma(out: &mut String) {
    out.truncate(out.trim_end().len());
    if out.ends_with(',') {
        out.pop();
    }
}

fn repair_from(text: &str, start: usize) -> Option<String> {
    let chars: Vec<char> = text[start..].chars().collect();
    let mut out = String::new();
    let mut stack: Vec<char> = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '"' | '\'' => {
                out.push('"');
                i += 1;
                while i < chars.len() && chars[i] != c {
                    match chars[i] {
                        '\\' if i + 1 < chars.len() => {
                            i += 1;
                            if chars[i] == '\'' {
                                out.push('\'');
                            } else {
                                out.push('\\');
                                out.push(chars[i]);
                            }
                        }
                        '"' => out.push_str("\\\""),
                        '\n' => out.push_str("\\n"),
                        '\r' => out.push_str("\\r"),
                        '\t' => out.push_str("\\t"),
                        ch => out.push(ch),
                    }
                    i += 1;
                }
                out.push('"');
            }
            '{' | '[' => {
                stack.push(if c == '{' { '}' } else { ']' });
                out.push(c);
            }
            '}' | ']' => {
                trim_trailing_comma(&mut out);
                // a mismatched closer closes whatever is open
                out.push(stack.pop().unwrap_or(c));
                if stack.is_empty() {
                    return Some(out);
                }
            }
            c if is_bare(c) => {
                let begin = i;
                while i < chars.len() && is_bare(chars[i]) {
                    i += 1;
                }
                let word: String = chars[begin..i].iter().collect();
                let next = chars[i..].iter().find(|ch| !ch.is_whitespace());
                if next == Some(&':') {
                    out.push('"');
                    out.push_str(&word);
                    out.push('"');
                } else {
                    out.push_str(&word);
                }
                continue;
            }
            c => out.push(c),
        }
        i += 1;
    }
    // cut-off tail: close what is open, giving a dangling key a null value
    trim_trailing_comma(&mut out);
    if out.ends_with(':') {
        out.push_str("null");
    }
    while let Some(closer) = stack.pop() {
        out.push(closer);
    }
    Some(out)
}

/// What call two of a pass returns, after parsing.
pub struct PassOutput {
    /// (question id, entry id)
    pub answered: Vec<(i64, i64)>,
    pub withdraw: Vec<i64>,
    pub new: Vec<(String, Archetype, Vec<i64>)>,
}

fn int_list(v: Option<&Value>) -> Vec<i64> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_i64).collect())
        .unwrap_or_default()
}

/// Repair, then read the three arrays; missing arrays are empty, items with non-integer ids are skipped.
pub fn parse_pass_output(text: &str) -> Result<PassOutput, String> {
    let repaired = repair_json(text).ok_or("no JSON object in the reply")?;
    let value: Value = serde_json::from_str(&repaired).map_err(|e| format!("unreadable JSON: {e}"))?;
    let answered = value["answered"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|item| Some((item["question"].as_i64()?, item["entry"].as_i64()?)))
                .collect()
        })
        .unwrap_or_default();
    let new = value["new"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|item| {
                    let text = item["text"].as_str()?.trim();
                    if text.is_empty() {
                        return None;
                    }
                    let archetype = Archetype::parse(item["archetype"].as_str().unwrap_or(""));
                    Some((text.to_string(), archetype, int_list(item.get("rests_on"))))
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(PassOutput {
        answered,
        withdraw: int_list(value.get("withdraw")),
        new,
    })
}

/// (entry id, keywords, context, importance)
pub type EnrichmentItem = (i64, Vec<String>, String, u8);

/// Reads `[{"entry": id, "keywords": [...], "context": "...", "importance": n}]` (a wrapping object with one
/// array field is accepted too). Importance is clamped into `u8`; range checks and unknown ids are the caller's.
pub fn parse_enrichment_output(text: &str) -> Result<Vec<EnrichmentItem>, String> {
    let repaired = repair_json_or_array(text).ok_or("no JSON in the reply")?;
    let value: Value = serde_json::from_str(&repaired).map_err(|e| format!("unreadable JSON: {e}"))?;
    let items = match &value {
        Value::Array(a) => a,
        Value::Object(o) => o.values().find_map(Value::as_array).ok_or("no array in the reply")?,
        _ => return Err("no array in the reply".into()),
    };
    Ok(items
        .iter()
        .filter_map(|item| {
            let entry = item["entry"].as_i64()?;
            let importance = item["importance"].as_i64()?;
            let keywords = item["keywords"]
                .as_array()
                .map(|a| a.iter().filter_map(|k| k.as_str().map(str::to_string)).collect())
                .unwrap_or_default();
            let context = item["context"].as_str().unwrap_or("").to_string();
            Some((entry, keywords, context, importance.clamp(0, i64::from(u8::MAX)) as u8))
        })
        .collect())
}

pub struct ValidationContext<'a> {
    /// open questions of the case
    pub open: &'a [Question],
    pub existing_entry_ids: &'a HashSet<i64>,
    /// entries added since the last pass
    pub new_entry_ids: &'a HashSet<i64>,
    /// creation time of each entry, same format as `Question::created_utc`
    pub entry_created: &'a HashMap<i64, String>,
    /// answered and withdrawn questions of the case
    pub resolved: &'a [Question],
    pub minus_examples: &'a [RatedExample],
    /// most questions that may be open at once
    pub cap: usize,
}

pub struct Validated {
    pub answered: Vec<(i64, i64)>,
    pub withdraw: Vec<i64>,
    pub new: Vec<NewQuestion>,
    /// one short reason per discarded item, for the pass log
    pub dropped: Vec<String>,
}

/// Spec 4.7 steps 3 to 7. Archetypes were already normalised by `Archetype::parse`.
pub fn validate(out: PassOutput, ctx: &ValidationContext) -> Validated {
    let entry_exists = |id: &i64| ctx.existing_entry_ids.contains(id) || ctx.new_entry_ids.contains(id);
    let mut dropped = Vec::new();
    let mut answered: Vec<(i64, i64)> = Vec::new();
    for (qid, eid) in out.answered {
        let Some(q) = ctx.open.iter().find(|q| q.id == qid) else {
            dropped.push(format!("answered: question {qid} is not open"));
            continue;
        };
        if answered.iter().any(|(a, _)| *a == qid) {
            dropped.push(format!("answered: question {qid} listed twice"));
        } else if !entry_exists(&eid) {
            dropped.push(format!("answered: question {qid} cites unknown entry {eid}"));
        } else if !ctx.new_entry_ids.contains(&eid) && ctx.entry_created.get(&eid).is_none_or(|c| *c <= q.created_utc) {
            dropped.push(format!("answered: entry {eid} is not newer than question {qid}"));
        } else {
            answered.push((qid, eid));
        }
    }
    let mut withdraw: Vec<i64> = Vec::new();
    for qid in out.withdraw {
        let Some(q) = ctx.open.iter().find(|q| q.id == qid) else {
            dropped.push(format!("withdraw: question {qid} is not open"));
            continue;
        };
        if q.rating == Rating::Plus {
            dropped.push(format!("withdraw: question {qid} is rated plus"));
        } else if answered.iter().any(|(a, _)| *a == qid) || withdraw.contains(&qid) {
            dropped.push(format!("withdraw: question {qid} is already handled in this pass"));
        } else {
            withdraw.push(qid);
        }
    }

    let known: Vec<&str> = ctx
        .open
        .iter()
        .chain(ctx.resolved)
        .map(|q| q.text.as_str())
        .chain(ctx.minus_examples.iter().map(|e| e.text.as_str()))
        .collect();
    let mut accepted: Vec<NewQuestion> = Vec::new();
    for (text, archetype, rests_on) in out.new {
        let mut valid: Vec<i64> = Vec::new();
        for id in rests_on {
            if entry_exists(&id) && !valid.contains(&id) {
                valid.push(id);
            }
        }
        if valid.is_empty() {
            dropped.push(format!("new: \"{text}\" rests on no known entry"));
        } else if known.iter().any(|k| is_duplicate(&text, k)) || accepted.iter().any(|q| is_duplicate(&text, &q.text))
        {
            dropped.push(format!("new: \"{text}\" duplicates an existing or earlier question"));
        } else {
            accepted.push(NewQuestion {
                text,
                archetype,
                rests_on: valid,
            });
        }
    }
    let open_after = ctx.open.len().saturating_sub(answered.len() + withdraw.len());
    let room = ctx.cap.saturating_sub(open_after);
    for q in accepted.split_off(room.min(accepted.len())) {
        dropped.push(format!(
            "new: \"{}\" exceeds the cap of {} open questions",
            q.text, ctx.cap
        ));
    }
    Validated {
        answered,
        withdraw,
        new: accepted,
        dropped,
    }
}

/// Token overlap high enough to count as the same question.
pub fn is_duplicate(text: &str, other_text: &str) -> bool {
    jaccard(text, other_text) >= 0.6
}

fn tokens(s: &str) -> HashSet<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.chars().count() > 3)
        .map(str::to_lowercase)
        .collect()
}

/// Jaccard similarity of the lowercased alphanumeric tokens longer than three characters; 0 when either side has none.
pub fn jaccard(a: &str, b: &str) -> f32 {
    let (a, b) = (tokens(a), tokens(b));
    let union = a.union(&b).count();
    if union == 0 {
        return 0.0;
    }
    a.intersection(&b).count() as f32 / union as f32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::companion::questions::{QuestionState, Rating};

    fn question(id: i64, text: &str, created: &str, rating: Rating) -> Question {
        Question {
            id,
            case_id: 1,
            text: text.into(),
            archetype: Archetype::Coverage,
            state: QuestionState::Open,
            rating,
            created_pass_id: None,
            resolved_pass_id: None,
            resolved_entry_id: None,
            position: id,
            created_utc: created.into(),
            resolved_utc: None,
            rests_on: vec![1],
        }
    }

    fn ids(v: &[i64]) -> HashSet<i64> {
        v.iter().copied().collect()
    }

    fn new_item(text: &str, rests_on: &[i64]) -> (String, Archetype, Vec<i64>) {
        (text.into(), Archetype::Document, rests_on.to_vec())
    }

    fn output(answered: &[(i64, i64)], withdraw: &[i64], new: Vec<(String, Archetype, Vec<i64>)>) -> PassOutput {
        PassOutput {
            answered: answered.to_vec(),
            withdraw: withdraw.to_vec(),
            new,
        }
    }

    #[test]
    fn repair_strips_fences_and_prose() {
        assert_eq!(
            repair_json("Here is the JSON:\n```json\n{\"a\":1}\n```").unwrap(),
            "{\"a\":1}"
        );
    }

    #[test]
    fn repair_closes_truncated_tail() {
        let r = repair_json("{\"new\":[{\"text\":\"x\",\"rests_on\":[1,2").unwrap();
        assert!(serde_json::from_str::<serde_json::Value>(&r).is_ok());
    }

    #[test]
    fn repair_fixes_trailing_commas_and_bare_keys() {
        let r = repair_json("{answered: [], 'withdraw': [3,],}").unwrap();
        let v: serde_json::Value = serde_json::from_str(&r).unwrap();
        assert_eq!(v["withdraw"][0], 3);
        assert!(v["answered"].as_array().unwrap().is_empty());
    }

    #[test]
    fn parse_defaults_missing_arrays() {
        let p = parse_pass_output("{\"new\":[]}").unwrap();
        assert!(p.answered.is_empty());
        assert!(p.withdraw.is_empty());
    }

    #[test]
    fn validate_drops_unknown_ids_and_keeps_reasons() {
        let open = [question(
            5,
            "Who owns the server?",
            "2026-01-01T00:00:00.000Z",
            Rating::None,
        )];
        let (existing, new) = (ids(&[10]), ids(&[10]));
        let created = HashMap::new();
        let ctx = ValidationContext {
            open: &open,
            existing_entry_ids: &existing,
            new_entry_ids: &new,
            entry_created: &created,
            resolved: &[],
            minus_examples: &[],
            cap: 7,
        };
        let v = validate(output(&[(99, 10)], &[], vec![]), &ctx);
        assert!(v.answered.is_empty());
        assert_eq!(v.dropped.len(), 1);
        assert!(v.dropped[0].contains("99"));
    }

    #[test]
    fn validate_requires_new_entry_or_later_entry_for_answered() {
        let open = [question(
            5,
            "Who owns the server?",
            "2026-01-02T00:00:00.000Z",
            Rating::None,
        )];
        let (existing, new) = (ids(&[10, 11, 12]), ids(&[12]));
        let created = HashMap::from([
            (10, "2026-01-01T00:00:00.000Z".to_string()),
            (11, "2026-01-03T00:00:00.000Z".to_string()),
            (12, "2026-01-04T00:00:00.000Z".to_string()),
        ]);
        let ctx = ValidationContext {
            open: &open,
            existing_entry_ids: &existing,
            new_entry_ids: &new,
            entry_created: &created,
            resolved: &[],
            minus_examples: &[],
            cap: 7,
        };
        let older = validate(output(&[(5, 10)], &[], vec![]), &ctx);
        assert!(older.answered.is_empty());
        assert_eq!(older.dropped.len(), 1);
        assert_eq!(validate(output(&[(5, 11)], &[], vec![]), &ctx).answered, vec![(5, 11)]);
        assert_eq!(validate(output(&[(5, 12)], &[], vec![]), &ctx).answered, vec![(5, 12)]);
    }

    #[test]
    fn validate_ignores_withdraw_of_plus() {
        let open = [
            question(1, "Who owns the server?", "2026-01-01T00:00:00.000Z", Rating::Plus),
            question(
                2,
                "Where is the backup stored?",
                "2026-01-01T00:00:00.000Z",
                Rating::None,
            ),
        ];
        let existing = ids(&[10]);
        let created = HashMap::new();
        let ctx = ValidationContext {
            open: &open,
            existing_entry_ids: &existing,
            new_entry_ids: &existing,
            entry_created: &created,
            resolved: &[],
            minus_examples: &[],
            cap: 7,
        };
        let v = validate(output(&[], &[1, 2], vec![]), &ctx);
        assert_eq!(v.withdraw, vec![2]);
        assert_eq!(v.dropped.len(), 1);
    }

    #[test]
    fn validate_drops_new_without_valid_rests_on() {
        let existing = ids(&[10]);
        let created = HashMap::new();
        let ctx = ValidationContext {
            open: &[],
            existing_entry_ids: &existing,
            new_entry_ids: &existing,
            entry_created: &created,
            resolved: &[],
            minus_examples: &[],
            cap: 7,
        };
        let v = validate(
            output(
                &[],
                &[],
                vec![
                    new_item("Which account logged in first?", &[77]),
                    new_item("Who installed the plugin?", &[77, 10]),
                ],
            ),
            &ctx,
        );
        assert_eq!(v.new.len(), 1);
        assert_eq!(v.new[0].rests_on, vec![10]);
        assert_eq!(v.dropped.len(), 1);
        assert!(v.dropped[0].contains("Which account logged in first?"));
    }

    #[test]
    fn validate_detects_duplicates_by_jaccard() {
        let open = [question(
            1,
            "Which vhost serves the compromised site?",
            "2026-01-01T00:00:00.000Z",
            Rating::None,
        )];
        let existing = ids(&[10]);
        let created = HashMap::new();
        let ctx = ValidationContext {
            open: &open,
            existing_entry_ids: &existing,
            new_entry_ids: &existing,
            entry_created: &created,
            resolved: &[],
            minus_examples: &[],
            cap: 7,
        };
        let v = validate(
            output(
                &[],
                &[],
                vec![
                    new_item("Which vhost is serving the compromised site", &[10]),
                    new_item("Who installed the plugin recently?", &[10]),
                    new_item("Who installed the plugin recently", &[10]),
                ],
            ),
            &ctx,
        );
        assert_eq!(v.new.len(), 1);
        assert_eq!(v.new[0].text, "Who installed the plugin recently?");
        assert_eq!(v.dropped.len(), 2);
    }

    #[test]
    fn validate_detects_duplicates_against_minus_examples() {
        let minus = [RatedExample {
            id: 1,
            text: "Is the firewall configuration documented?".into(),
            rating: Rating::Minus,
            archetype: Archetype::Document,
            source_case_id: 2,
        }];
        let existing = ids(&[10]);
        let created = HashMap::new();
        let ctx = ValidationContext {
            open: &[],
            existing_entry_ids: &existing,
            new_entry_ids: &existing,
            entry_created: &created,
            resolved: &[],
            minus_examples: &minus,
            cap: 7,
        };
        let v = validate(
            output(
                &[],
                &[],
                vec![new_item("Is the firewall configuration documented?", &[10])],
            ),
            &ctx,
        );
        assert!(v.new.is_empty());
        assert_eq!(v.dropped.len(), 1);
    }

    #[test]
    fn jaccard_ignores_short_tokens_and_case() {
        assert_eq!(jaccard("The Server IS down", "the server was up"), 0.5);
        assert_eq!(jaccard("a an of", "to be it"), 0.0);
        assert!(is_duplicate("Backup SERVER location", "backup server location"));
    }

    #[test]
    fn validate_enforces_cap_on_newest() {
        let open: Vec<Question> = (1..=6)
            .map(|i| {
                question(
                    i,
                    &format!("Unrelated open question number{i} alpha{i}"),
                    "2026-01-01T00:00:00.000Z",
                    Rating::None,
                )
            })
            .collect();
        let existing = ids(&[10]);
        let created = HashMap::new();
        let ctx = ValidationContext {
            open: &open,
            existing_entry_ids: &existing,
            new_entry_ids: &existing,
            entry_created: &created,
            resolved: &[],
            minus_examples: &[],
            cap: 7,
        };
        let v = validate(
            output(
                &[],
                &[],
                vec![
                    new_item("First fresh topic gamma", &[10]),
                    new_item("Second distinct subject delta", &[10]),
                    new_item("Third separate matter epsilon", &[10]),
                ],
            ),
            &ctx,
        );
        assert_eq!(v.new.len(), 1);
        assert_eq!(v.new[0].text, "First fresh topic gamma");
        assert_eq!(v.dropped.len(), 2);
    }

    #[test]
    fn validate_accepts_rests_on_superseded_entry() {
        let existing = ids(&[10, 11]);
        let created = HashMap::new();
        let ctx = ValidationContext {
            open: &[],
            existing_entry_ids: &existing,
            new_entry_ids: &ids(&[11]),
            entry_created: &created,
            resolved: &[],
            minus_examples: &[],
            cap: 7,
        };
        let v = validate(
            output(&[], &[], vec![new_item("What did the original entry claim?", &[10])]),
            &ctx,
        );
        assert_eq!(v.new.len(), 1);
        assert!(v.dropped.is_empty());
    }
}
