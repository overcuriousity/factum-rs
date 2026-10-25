//! When a case gets its next pass: a quiet period after the last change, a minimum spacing between passes, forced
//! passes at once, a case's first pass after the quiet period (so it can be opted out first), the selected case
//! first. Pure: the caller supplies the clock.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A case runs this long after its last change.
pub const QUIET_PERIOD: Duration = Duration::from_secs(30);
/// Between two passes of the same case.
pub const MIN_SPACING: Duration = Duration::from_secs(60);

#[derive(Default)]
struct Pending {
    /// unset once a pass has seen the change
    last_change: Option<Instant>,
    last_pass: Option<Instant>,
    /// due now and full, regardless of changes and spacing
    forced: bool,
    /// the next pass is full, after the quiet period
    full: bool,
}

#[derive(Default)]
pub struct Scheduler {
    cases: HashMap<i64, Pending>,
    selected: Option<i64>,
}

impl Scheduler {
    pub fn new() -> Self {
        Self::default()
    }

    /// A change restarts the quiet period of the case.
    pub fn changed(&mut self, case_id: i64, now: Instant) {
        self.cases.entry(case_id).or_default().last_change = Some(now);
    }

    /// Due now, full.
    pub fn force(&mut self, case_id: i64) {
        self.cases.entry(case_id).or_default().forced = true;
    }

    pub fn select(&mut self, case_id: Option<i64>) {
        self.selected = case_id;
    }

    /// A case the companion has not seen before: full, after the quiet period, so it can be opted out before any
    /// of its content is sent.
    pub fn first_seen(&mut self, case_id: i64, now: Instant) {
        let pending = self.cases.entry(case_id).or_default();
        pending.last_change = Some(now);
        pending.full = true;
    }

    /// The pass ran (or was given up): the changes so far are seen and the spacing starts.
    pub fn passed(&mut self, case_id: i64, now: Instant) {
        let pending = self.cases.entry(case_id).or_default();
        pending.last_change = None;
        pending.last_pass = Some(now);
        pending.forced = false;
        pending.full = false;
    }

    /// A change not yet seen by a pass, or a forced pass, is waiting.
    pub fn is_pending(&self, case_id: i64) -> bool {
        self.cases
            .get(&case_id)
            .is_some_and(|p| p.forced || p.last_change.is_some())
    }

    /// Forgets the case, pending changes included.
    pub fn clear(&mut self, case_id: i64) {
        self.cases.remove(&case_id);
    }

    /// The case to run now and whether its pass must be full: forced cases first, then the selected case, then
    /// the others by oldest change.
    pub fn next_due(&self, now: Instant) -> Option<(i64, bool)> {
        self.cases
            .iter()
            .filter(|(_, p)| p.forced || self.settled(p, now))
            .min_by_key(|(id, p)| (!p.forced, self.selected != Some(**id), p.last_change, **id))
            .map(|(id, p)| (*id, p.forced || p.full))
    }

    fn settled(&self, p: &Pending, now: Instant) -> bool {
        let Some(change) = p.last_change else { return false };
        now.saturating_duration_since(change) >= QUIET_PERIOD
            && p.last_pass
                .is_none_or(|pass| now.saturating_duration_since(pass) >= MIN_SPACING)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn quiet_period_and_spacing() {
        let mut s = Scheduler::new();
        let t0 = Instant::now();
        s.changed(1, t0);
        assert_eq!(s.next_due(t0 + secs(29)), None);
        assert_eq!(s.next_due(t0 + secs(30)), Some((1, false)));
        s.passed(1, t0 + secs(30));
        s.changed(1, t0 + secs(31));
        assert_eq!(s.next_due(t0 + secs(61)), None);
        assert_eq!(s.next_due(t0 + secs(90)), Some((1, false)));
    }

    #[test]
    fn selected_case_comes_first() {
        let mut s = Scheduler::new();
        let t0 = Instant::now();
        s.changed(2, t0);
        s.changed(1, t0 + secs(1));
        s.select(Some(1));
        assert_eq!(s.next_due(t0 + secs(40)), Some((1, false)));
    }

    #[test]
    fn burst_of_changes_is_one_pass() {
        let mut s = Scheduler::new();
        let t0 = Instant::now();
        for offset in [0, 10, 20] {
            s.changed(1, t0 + secs(offset));
        }
        assert_eq!(s.next_due(t0 + secs(49)), None);
        assert_eq!(s.next_due(t0 + secs(50)), Some((1, false)));
        s.passed(1, t0 + secs(50));
        assert_eq!(s.next_due(t0 + secs(500)), None);
    }

    #[test]
    fn force_is_due_immediately_and_first_seen_after_the_quiet_period_both_full() {
        let now = Instant::now();
        let mut s = Scheduler::new();
        s.force(1);
        assert_eq!(s.next_due(now), Some((1, true)));
        let mut s = Scheduler::new();
        s.first_seen(1, now);
        assert_eq!(s.next_due(now + secs(29)), None);
        assert_eq!(s.next_due(now + QUIET_PERIOD), Some((1, true)));
    }

    #[test]
    fn nothing_due_without_changes() {
        assert_eq!(Scheduler::new().next_due(Instant::now()), None);
    }
}
