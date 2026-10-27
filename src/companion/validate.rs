//! Mechanical repair and validation of the model's pass output; no model, database or network involved.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use super::questions::{Archetype, NewQuestion, Question, RatedExample, Rating};

/// Cuts the first JSON object out of a model reply (fences and prose dropped) and repairs trailing commas,
/// single-quoted or bare keys and a cut-off tail. A `{` in the prose before the object is skipped: the first
/// candidate whose repair parses wins, else the repair from the first `{`. A candidate inside an earlier, closed one
/// is not tried, so a broken object never gives way to one of its own items; after a `{` that is never closed (a
/// stray brace in prose, or a cut-off object whose repair fails) the later candidates are tried. `None` when there is
/// no `{`.
pub fn repair_json(text: &str) -> Option<String> {
    repair_first_parsing(text, &['{'], |_| true)
}

fn repair_first_parsing(text: &str, open: &[char], accept: impl Fn(&Value) -> bool) -> Option<String> {
    let mut first = None;
    let mut end = 0;
    for (start, _) in text.match_indices(open) {
        if start < end {
            continue;
        }
        let (repaired, consumed, closed) = repair_from(text, start);
        if serde_json::from_str::<Value>(&repaired).is_ok_and(|value| accept(&value)) {
            return Some(repaired);
        }
        if closed {
            end = start + text[start..].chars().take(consumed).map(char::len_utf8).sum::<usize>();
        }
        first.get_or_insert(repaired);
    }
    first
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

/// `out` ends with a string in the place of an object key: after `{` or `,`.
fn ends_with_key(out: &str) -> bool {
    let Some(body) = out.strip_suffix('"') else {
        return false;
    };
    // the opening quote: the last `"` not escaped by an odd number of backslashes
    let bytes = body.as_bytes();
    let mut i = bytes.len();
    while i > 0 {
        i -= 1;
        if bytes[i] == b'"' && bytes[..i].iter().rev().take_while(|&&b| b == b'\\').count() % 2 == 0 {
            return matches!(body[..i].trim_end().chars().last(), Some('{' | ','));
        }
    }
    false
}

/// The repaired document from `start`, the number of characters it consumed, and whether its outermost bracket was
/// closed in the text (rather than by the repair).
fn repair_from(text: &str, start: usize) -> (String, usize, bool) {
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
                    return (out, i + 1, true);
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
                } else if i == chars.len()
                    && let Some(literal) = ["true", "false", "null"].iter().find(|l| l.starts_with(word.as_str()))
                {
                    // cut off inside a literal
                    out.push_str(literal);
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
    if stack.last() == Some(&'}') && ends_with_key(&out) {
        out.push(':');
    }
    if out.ends_with(':') {
        out.push_str("null");
    }
    while let Some(closer) = stack.pop() {
        out.push(closer);
    }
    (out, chars.len(), false)
}

/// What call two of a pass returns, after parsing.
/// One item of the pass output: an open question by its id, or a new question without one.
#[derive(Clone, Debug, PartialEq)]
pub struct OutputQuestion {
    pub id: Option<i64>,
    /// empty keeps an open question's wording
    pub text: String,
    pub archetype: Archetype,
    pub rests_on: Vec<i64>,
    /// the entry that answers an open question
    pub answered_by: Option<i64>,
}

fn int_list(v: Option<&Value>) -> Vec<i64> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_i64).collect())
        .unwrap_or_default()
}

/// Repair, then read the `questions` array; items that are not objects are skipped. An object without the array is
/// not the pass output (it may be one item of a broken one), so a reply cannot drop every question by leaving it out.
pub fn parse_pass_output(text: &str) -> Result<Vec<OutputQuestion>, String> {
    let is_output = |value: &Value| value["questions"].is_array();
    let repaired = repair_first_parsing(text, &['{'], is_output).ok_or("no JSON object in the reply")?;
    let value: Value = serde_json::from_str(&repaired).map_err(|e| format!("unreadable JSON: {e}"))?;
    let items = value["questions"]
        .as_array()
        .ok_or("the JSON object has no questions array")?;
    Ok(items
        .iter()
        .filter(|item| item.is_object())
        .map(|item| OutputQuestion {
            id: item["id"].as_i64(),
            text: item["text"].as_str().unwrap_or("").trim().to_string(),
            archetype: Archetype::parse(item["archetype"].as_str().unwrap_or("")),
            rests_on: int_list(item.get("rests_on")),
            answered_by: item["answered_by"].as_i64(),
        })
        .collect())
}

/// (entry id, keywords, context, importance)
pub type EnrichmentItem = (i64, Vec<String>, String, u8);

/// The array of enrichment items: the document itself or the first array field of an object.
fn enrichment_items(value: &Value) -> Option<&Vec<Value>> {
    match value {
        Value::Array(a) => Some(a),
        Value::Object(o) => o.values().find_map(Value::as_array),
        _ => None,
    }
}

/// Reads `{"entries": [{"id": id, "keywords": [...], "context": "...", "importance": n}]}`; a bare array, another
/// name for the array and `"entry"` for `"id"` are accepted too. Importance is clamped into `u8`; range checks and
/// unknown ids are the caller's.
pub fn parse_enrichment_output(text: &str) -> Result<Vec<EnrichmentItem>, String> {
    // a document whose array holds objects, not e.g. the keyword list of one item
    let is_output = |value: &Value| enrichment_items(value).is_some_and(|items| items.iter().all(Value::is_object));
    let repaired = repair_first_parsing(text, &['{', '['], is_output).ok_or("no JSON in the reply")?;
    let value: Value = serde_json::from_str(&repaired).map_err(|e| format!("unreadable JSON: {e}"))?;
    let items = enrichment_items(&value).ok_or("no array in the reply")?;
    Ok(items
        .iter()
        .filter_map(|item| {
            let entry = item["id"].as_i64().or_else(|| item["entry"].as_i64())?;
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

#[derive(Default)]
pub struct Validated {
    pub answered: Vec<(i64, i64)>,
    pub withdraw: Vec<i64>,
    /// (question id, new wording, the entries it rests on now)
    pub rephrased: Vec<(i64, String, Vec<i64>)>,
    pub new: Vec<NewQuestion>,
    /// one short reason per discarded item, for the pass log
    pub dropped: Vec<String>,
}

/// Spec 4.7 steps 3 to 7. The output lists the questions open after the pass: an open question it leaves out is
/// withdrawn, unless the investigator rated it plus. Archetypes were already normalised by `Archetype::parse`.
pub fn validate(out: Vec<OutputQuestion>, ctx: &ValidationContext) -> Validated {
    let entry_exists = |id: &i64| ctx.existing_entry_ids.contains(id) || ctx.new_entry_ids.contains(id);
    let known: Vec<&str> = ctx
        .resolved
        .iter()
        .map(|q| q.text.as_str())
        .chain(ctx.minus_examples.iter().map(|e| e.text.as_str()))
        .collect();
    let mut v = Validated::default();
    let mut listed: HashSet<i64> = HashSet::new();
    for item in out {
        let mut rests_on: Vec<i64> = Vec::new();
        for id in item.rests_on {
            if entry_exists(&id) && !rests_on.contains(&id) {
                rests_on.push(id);
            }
        }
        let text = item.text;
        let Some(qid) = item.id else {
            // an open question restated without its id is kept as it is
            if let Some(q) = ctx.open.iter().find(|q| is_duplicate(&text, &q.text)) {
                listed.insert(q.id);
            } else if text.is_empty() {
                v.dropped.push("new: a question without text".into());
            } else if rests_on.is_empty() {
                v.dropped.push(format!("new: \"{text}\" rests on no known entry"));
            } else if known.iter().any(|k| is_duplicate(&text, k)) || v.new.iter().any(|q| is_duplicate(&text, &q.text))
            {
                v.dropped
                    .push(format!("new: \"{text}\" duplicates an existing or earlier question"));
            } else {
                v.new.push(NewQuestion {
                    text,
                    archetype: item.archetype,
                    rests_on,
                });
            }
            continue;
        };
        let Some(q) = ctx.open.iter().find(|q| q.id == qid) else {
            v.dropped.push(format!("question {qid} is not open"));
            continue;
        };
        if !listed.insert(qid) {
            v.dropped.push(format!("question {qid} listed twice"));
        } else if let Some(eid) = item.answered_by {
            if !entry_exists(&eid) {
                v.dropped
                    .push(format!("answered: question {qid} cites unknown entry {eid}"));
            } else if !ctx.new_entry_ids.contains(&eid)
                && ctx.entry_created.get(&eid).is_none_or(|c| *c <= q.created_utc)
            {
                v.dropped
                    .push(format!("answered: entry {eid} is not newer than question {qid}"));
            } else {
                v.answered.push((qid, eid));
            }
        } else if !text.is_empty() && text != q.text {
            let rests_on = if rests_on.is_empty() {
                q.rests_on.clone()
            } else {
                rests_on
            };
            v.rephrased.push((qid, text, rests_on));
        }
    }
    v.withdraw = ctx
        .open
        .iter()
        .filter(|q| !listed.contains(&q.id) && q.rating != Rating::Plus)
        .map(|q| q.id)
        .collect();
    let open_after = ctx.open.len() - v.answered.len() - v.withdraw.len();
    let room = ctx.cap.saturating_sub(open_after);
    for q in v.new.split_off(room.min(v.new.len())) {
        v.dropped.push(format!(
            "new: \"{}\" exceeds the cap of {} open questions",
            q.text, ctx.cap
        ));
    }
    v
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

    /// A new question of the output.
    fn new_item(text: &str, rests_on: &[i64]) -> OutputQuestion {
        OutputQuestion {
            id: None,
            text: text.into(),
            archetype: Archetype::Document,
            rests_on: rests_on.to_vec(),
            answered_by: None,
        }
    }

    /// An open question kept, with `text` its wording (empty keeps it) or answered by `answered_by`.
    fn kept(id: i64, text: &str, answered_by: Option<i64>) -> OutputQuestion {
        OutputQuestion {
            id: Some(id),
            answered_by,
            ..new_item(text, &[])
        }
    }

    /// Validates against open questions created on 2 January, entries 10 to 12 created on the 1st, 3rd and 4th, of
    /// which 12 is new, and the minus examples.
    fn check(open: &[Question], minus: &[RatedExample], out: Vec<OutputQuestion>) -> Validated {
        let (existing, new) = (ids(&[10, 11, 12]), ids(&[12]));
        let created = HashMap::from([
            (10, "2026-01-01T00:00:00.000Z".to_string()),
            (11, "2026-01-03T00:00:00.000Z".to_string()),
            (12, "2026-01-04T00:00:00.000Z".to_string()),
        ]);
        let ctx = ValidationContext {
            open,
            existing_entry_ids: &existing,
            new_entry_ids: &new,
            entry_created: &created,
            resolved: &[],
            minus_examples: minus,
            cap: 7,
        };
        validate(out, &ctx)
    }

    fn open_question(id: i64, text: &str, rating: Rating) -> Question {
        question(id, text, "2026-01-02T00:00:00.000Z", rating)
    }

    #[test]
    fn repair_strips_fences_and_prose() {
        assert_eq!(
            repair_json("Here is the JSON:\n```json\n{\"a\":1}\n```").unwrap(),
            "{\"a\":1}"
        );
        assert_eq!(
            repair_json("Fill the {placeholders} first, then:\n{\"a\":1}").unwrap(),
            "{\"a\":1}"
        );
    }

    #[test]
    fn repair_closes_truncated_tail() {
        for cut in [
            "{\"new\":[{\"text\":\"x\",\"rests_on\":[1,2",
            "{\"new\":[{\"text\":\"x\",\"rests_on\"",
            "{\"answered\":[], \"done\": tr",
            "{\"new\":[{\"text\":\"a \\\"b\\\"\", \"archetype\"",
        ] {
            let r = repair_json(cut).unwrap();
            assert!(serde_json::from_str::<serde_json::Value>(&r).is_ok(), "{cut} -> {r}");
        }
    }

    #[test]
    fn repair_skips_an_unclosed_brace_in_prose() {
        assert_eq!(repair_json("Use {x as the id, then:\n{\"a\":1}").unwrap(), "{\"a\":1}");
    }

    #[test]
    fn pass_output_is_not_taken_from_an_item_of_a_broken_object() {
        // the outer object is broken (a missing comma) and cut off; its first item parses on its own
        let text = "{\"questions\":[{\"id\":1,\"answered_by\":2}, {\"text\":\"a\" \"rests_on\":[1]";
        assert!(parse_pass_output(text).is_err());
        assert!(parse_pass_output("{\"id\":1,\"answered_by\":2}").is_err());
    }

    #[test]
    fn enrichment_prefers_id_and_skips_keyword_arrays() {
        let items =
            parse_enrichment_output("{\"entries\":[{\"id\":3,\"entry\":9,\"keywords\":[\"a\"],\"importance\":4}]}")
                .unwrap();
        assert_eq!(items, vec![(3, vec!["a".to_string()], String::new(), 4)]);
        // cut off and broken: no keyword list of an item is taken for the answer
        assert!(
            parse_enrichment_output("{\"entries\":[{\"id\":3,\"keywords\":[\"a\" \"b\"]")
                .unwrap_or_default()
                .is_empty()
        );
    }

    #[test]
    fn repair_fixes_trailing_commas_and_bare_keys() {
        let r = repair_json("{answered: [], 'withdraw': [3,],}").unwrap();
        let v: serde_json::Value = serde_json::from_str(&r).unwrap();
        assert_eq!(v["withdraw"][0], 3);
        assert!(v["answered"].as_array().unwrap().is_empty());
    }

    #[test]
    fn parse_reads_items_and_requires_the_array() {
        let text = "{\"questions\":[{\"id\":3,\"text\":\" b \"}, 7, {\"text\":\"a\",\"rests_on\":[1]}]}";
        let coverage = |q| OutputQuestion {
            archetype: Archetype::Coverage,
            ..q
        };
        assert_eq!(
            parse_pass_output(text).unwrap(),
            vec![coverage(kept(3, "b", None)), coverage(new_item("a", &[1]))]
        );
        assert!(parse_pass_output("{\"answered\":[]}").is_err());
    }

    #[test]
    fn unlisted_questions_are_withdrawn_except_plus() {
        let open = [
            open_question(1, "Who owns the server?", Rating::Plus),
            open_question(2, "Where is the backup stored?", Rating::None),
            open_question(3, "Which tool imaged the disk?", Rating::None),
        ];
        let v = check(&open, &[], vec![kept(3, "", None), kept(99, "", None)]);
        assert_eq!(v.withdraw, vec![2]);
        assert!(v.rephrased.is_empty());
        assert_eq!(v.dropped, vec!["question 99 is not open".to_string()]);
    }

    #[test]
    fn answered_needs_a_new_or_later_entry() {
        let open = [open_question(5, "Who owns the server?", Rating::None)];
        for (entry, answered) in [(10, false), (11, true), (12, true), (99, false)] {
            let v = check(&open, &[], vec![kept(5, "", Some(entry))]);
            assert_eq!(v.answered == [(5, entry)], answered, "entry {entry}");
            assert!(v.withdraw.is_empty(), "a refused answer keeps the question");
        }
    }

    #[test]
    fn rephrasing_keeps_or_replaces_rests_on() {
        let open = [
            open_question(1, "Who owns the server?", Rating::Plus),
            open_question(2, "Where is the backup stored?", Rating::None),
        ];
        let mut moved = kept(2, "Where is the backup of 12 March stored?", None);
        moved.rests_on = vec![12, 99];
        let v = check(&open, &[], vec![kept(1, "Who owns the web server?", None), moved]);
        assert_eq!(
            v.rephrased,
            vec![
                (1, "Who owns the web server?".to_string(), vec![1]),
                (2, "Where is the backup of 12 March stored?".to_string(), vec![12]),
            ]
        );
        assert!(v.withdraw.is_empty());
    }

    #[test]
    fn new_questions_need_rests_on_and_no_duplicate() {
        let open = [open_question(
            1,
            "Which vhost serves the compromised site?",
            Rating::None,
        )];
        let minus = [RatedExample {
            id: 1,
            text: "Is the firewall configuration documented?".into(),
            rating: Rating::Minus,
            archetype: Archetype::Document,
            source_case_id: 2,
        }];
        let v = check(
            &open,
            &minus,
            vec![
                new_item("Which vhost is serving the compromised site", &[10]),
                new_item("Which account logged in first?", &[77]),
                new_item("Who installed the plugin recently?", &[77, 10]),
                new_item("Who installed the plugin recently", &[10]),
                new_item("Is the firewall configuration documented?", &[10]),
            ],
        );
        assert!(
            v.withdraw.is_empty(),
            "restated without its id, the open question is kept"
        );
        assert_eq!(v.new.len(), 1);
        assert_eq!(
            (v.new[0].text.as_str(), &v.new[0].rests_on[..]),
            ("Who installed the plugin recently?", &[10][..])
        );
        assert_eq!(v.dropped.len(), 3);
    }

    #[test]
    fn jaccard_ignores_short_tokens_and_case() {
        assert_eq!(jaccard("The Server IS down", "the server was up"), 0.5);
        assert_eq!(jaccard("a an of", "to be it"), 0.0);
        assert!(is_duplicate("Backup SERVER location", "backup server location"));
    }

    #[test]
    fn cap_drops_the_newest() {
        let open: Vec<Question> = (1..=6)
            .map(|i| open_question(i, &format!("Unrelated open question number{i} alpha{i}"), Rating::None))
            .collect();
        let mut out: Vec<OutputQuestion> = (1..=6).map(|i| kept(i, "", None)).collect();
        out.extend([
            new_item("First fresh topic gamma", &[10]),
            new_item("Second distinct subject delta", &[10]),
            new_item("Third separate matter epsilon", &[10]),
        ]);
        let v = check(&open, &[], out);
        assert_eq!(v.new.len(), 1);
        assert_eq!(v.new[0].text, "First fresh topic gamma");
        assert_eq!(v.dropped.len(), 2);
    }
}
