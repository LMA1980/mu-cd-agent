//! Integration-gate progress tracking.
//!
//! Expands the contract's `integration_tests` selector (`"all"` or an explicit list) against
//! the tests this agent can execute, and produces per-test
//! [`IntegrationTestProgress`] updates: `Pending` for every test at gate start, then
//! `Running`, then `Passed`/`Failed` with `duration_ms`. The aggregate
//! `IntegrationTestReport` remains the final verdict and is sent separately.

#![deny(unsafe_code)]

use std::time::Instant;

use mu_cd_ipc::{IntegrationTestProgress, TestState};

use crate::error::AgentError;
use crate::watchdog::now_epoch_ms;

/// Built-in test: the candidate's systemd unit reaches `ActiveState=active`.
pub const TEST_SYSTEMD_UNIT_ACTIVE: &str = "systemd_unit_active";
/// Built-in test: the candidate's local health endpoint accepts connections.
pub const TEST_HEALTH_ENDPOINT_READY: &str = "health_endpoint_ready";

/// One integration test the gate tracks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateTest {
    pub name: String,
    /// A failure of a critical test blocks promotion (`[C]` in the console).
    pub critical: bool,
}

impl GateTest {
    pub fn new(name: impl Into<String>, critical: bool) -> Self {
        Self {
            name: name.into(),
            critical,
        }
    }
}

/// Tests the agent can execute on every node: the post-swap watchdog checks.
pub fn builtin_catalog() -> Vec<GateTest> {
    vec![
        GateTest::new(TEST_SYSTEMD_UNIT_ACTIVE, true),
        GateTest::new(TEST_HEALTH_ENDPOINT_READY, true),
    ]
}

/// Mirror of the contract's `integration_tests` field.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum IntegrationTestSelection {
    /// `integration_tests: "all"`: every test in the catalog.
    #[default]
    All,
    /// `integration_tests: [a, b]`: only the named tests, in catalog order.
    Selected(Vec<String>),
}

impl IntegrationTestSelection {
    /// Builds a selection from the raw contract values (`["all"]` or a single `"all"` means all).
    pub fn from_names(names: &[String]) -> Self {
        if names.is_empty() || names.iter().any(|n| n.eq_ignore_ascii_case("all")) {
            Self::All
        } else {
            Self::Selected(names.to_vec())
        }
    }
}

/// Expands a selection against the catalog, failing closed if any requested test is unknown.
pub fn expand_integration_tests(
    selection: &IntegrationTestSelection,
    catalog: &[GateTest],
) -> Result<Vec<GateTest>, AgentError> {
    match selection {
        IntegrationTestSelection::All => Ok(catalog.to_vec()),
        IntegrationTestSelection::Selected(names) => {
            let mut missing = Vec::new();
            for n in names {
                if !catalog.iter().any(|t| &t.name == n) && !missing.contains(n) {
                    missing.push(n.clone());
                }
            }
            if !missing.is_empty() {
                return Err(AgentError::UnknownIntegrationTests(missing));
            }
            Ok(catalog
                .iter()
                .filter(|t| names.iter().any(|n| n == &t.name))
                .cloned()
                .collect())
        }
    }
}

#[derive(Debug)]
struct TrackedTest {
    test: GateTest,
    state: TestState,
    started: Option<Instant>,
    duration_ms: u64,
}

/// Tracks the live state of every test in one deployment's gate.
#[derive(Debug)]
pub struct GateTracker {
    deployment_id: String,
    tests: Vec<TrackedTest>,
}

impl GateTracker {
    pub fn new(deployment_id: impl Into<String>, tests: Vec<GateTest>) -> Self {
        Self {
            deployment_id: deployment_id.into(),
            tests: tests
                .into_iter()
                .map(|test| TrackedTest {
                    test,
                    state: TestState::Pending,
                    started: None,
                    duration_ms: 0,
                })
                .collect(),
        }
    }

    pub fn deployment_id(&self) -> &str {
        &self.deployment_id
    }

    /// Number of tracked tests.
    pub fn len(&self) -> usize {
        self.tests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tests.is_empty()
    }

    /// Current state of a test, if tracked.
    pub fn state_of(&self, name: &str) -> Option<TestState> {
        self.tests
            .iter()
            .find(|t| t.test.name == name)
            .map(|t| t.state)
    }

    fn progress(&self, t: &TrackedTest) -> IntegrationTestProgress {
        IntegrationTestProgress {
            deployment_id: self.deployment_id.clone(),
            test_name: t.test.name.clone(),
            critical: t.test.critical,
            state: t.state,
            duration_ms: t.duration_ms,
            timestamp_epoch_ms: now_epoch_ms(),
        }
    }

    /// `Pending` update for every test (emitted once at gate start).
    pub fn pending_updates(&self) -> Vec<IntegrationTestProgress> {
        self.tests.iter().map(|t| self.progress(t)).collect()
    }

    /// Moves one `Pending` test to `Running` and returns its update.
    pub fn start_test(&mut self, name: &str) -> Option<IntegrationTestProgress> {
        let i = self.tests.iter().position(|t| t.test.name == name)?;
        if self.tests[i].state != TestState::Pending {
            return None;
        }
        self.tests[i].state = TestState::Running;
        self.tests[i].started = Some(Instant::now());
        Some(self.progress(&self.tests[i]))
    }

    /// Moves every `Pending` test to `Running` and returns the updates.
    pub fn start_all(&mut self) -> Vec<IntegrationTestProgress> {
        let now = Instant::now();
        let mut idx = Vec::new();
        for (i, t) in self.tests.iter_mut().enumerate() {
            if t.state == TestState::Pending {
                t.state = TestState::Running;
                t.started = Some(now);
                idx.push(i);
            }
        }
        idx.into_iter()
            .map(|i| self.progress(&self.tests[i]))
            .collect()
    }

    /// Finishes one test; returns `None` if it is unknown or already terminal.
    pub fn finish(&mut self, name: &str, passed: bool) -> Option<IntegrationTestProgress> {
        let i = self.tests.iter().position(|t| t.test.name == name)?;
        let t = &mut self.tests[i];
        if t.state.is_terminal() {
            return None;
        }
        t.duration_ms = t
            .started
            .map(|s| s.elapsed().as_millis() as u64)
            .unwrap_or(0);
        t.state = if passed {
            TestState::Passed
        } else {
            TestState::Failed
        };
        Some(self.progress(&self.tests[i]))
    }

    /// Finishes every non-terminal test with the verdict returned by `passed_fn`.
    pub fn finish_remaining(
        &mut self,
        mut passed_fn: impl FnMut(&GateTest) -> bool,
    ) -> Vec<IntegrationTestProgress> {
        let pending: Vec<(String, bool)> = self
            .tests
            .iter()
            .filter(|t| !t.state.is_terminal())
            .map(|t| (t.test.name.clone(), passed_fn(&t.test)))
            .collect();
        pending
            .into_iter()
            .filter_map(|(n, p)| self.finish(&n, p))
            .collect()
    }

    /// Names of every test in `state`.
    pub fn names_in(&self, state: TestState) -> Vec<String> {
        self.tests
            .iter()
            .filter(|t| t.state == state)
            .map(|t| t.test.name.clone())
            .collect()
    }

    /// Names of every tracked test, in order.
    pub fn names(&self) -> Vec<String> {
        self.tests.iter().map(|t| t.test.name.clone()).collect()
    }

    /// Returns names of critical tests currently in [`TestState::Failed`].
    pub fn critical_failures(&self) -> Vec<String> {
        self.tests
            .iter()
            .filter(|t| t.test.critical && t.state == TestState::Failed)
            .map(|t| t.test.name.clone())
            .collect()
    }
}

/// Verdict for a built-in watchdog check given the last observed probe.
///
/// When no probe disagrees (lease expiry, warmup timeout or external rollback), the test
/// is reported as failed because the gate did not complete.
pub fn builtin_verdict(
    test_name: &str,
    last_systemd_active: Option<bool>,
    last_endpoint_ok: Option<bool>,
    gate_succeeded: bool,
) -> bool {
    if gate_succeeded {
        return true;
    }
    match test_name {
        // The other check failed while this one was fine: this check passed.
        TEST_SYSTEMD_UNIT_ACTIVE => matches!(
            (last_systemd_active, last_endpoint_ok),
            (Some(true), Some(false))
        ),
        TEST_HEALTH_ENDPOINT_READY => matches!(
            (last_systemd_active, last_endpoint_ok),
            (Some(false), Some(true))
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selection_from_names() {
        assert_eq!(
            IntegrationTestSelection::from_names(&["all".into()]),
            IntegrationTestSelection::All
        );
        assert_eq!(
            IntegrationTestSelection::from_names(&[]),
            IntegrationTestSelection::All
        );
        assert_eq!(
            IntegrationTestSelection::from_names(&["a".into()]),
            IntegrationTestSelection::Selected(vec!["a".into()])
        );
    }

    #[test]
    fn test_expand_all_and_selected() {
        let catalog = builtin_catalog();
        let all = expand_integration_tests(&IntegrationTestSelection::All, &catalog).unwrap();
        assert_eq!(all, catalog);

        let sel = expand_integration_tests(
            &IntegrationTestSelection::Selected(vec![TEST_HEALTH_ENDPOINT_READY.into()]),
            &catalog,
        )
        .unwrap();
        assert_eq!(sel, vec![GateTest::new(TEST_HEALTH_ENDPOINT_READY, true)]);

        // Fail closed on unknown test names rather than silently dropping
        let err = expand_integration_tests(
            &IntegrationTestSelection::Selected(vec![
                TEST_HEALTH_ENDPOINT_READY.into(),
                "not_on_node".into(),
            ]),
            &catalog,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            AgentError::UnknownIntegrationTests(ref missing) if missing == &vec!["not_on_node".to_string()]
        ));
    }

    #[test]
    fn test_tracker_lifecycle() {
        let mut g = GateTracker::new("dep-1", builtin_catalog());
        assert_eq!(g.len(), 2);
        assert!(!g.is_empty());
        assert_eq!(g.deployment_id(), "dep-1");

        let pending = g.pending_updates();
        assert_eq!(pending.len(), 2);
        assert!(pending
            .iter()
            .all(|p| p.state == TestState::Pending && p.duration_ms == 0 && p.critical));

        let running = g.start_all();
        assert_eq!(running.len(), 2);
        assert!(running.iter().all(|p| p.state == TestState::Running));
        assert!(g.start_all().is_empty(), "start_all is idempotent");

        let done = g.finish(TEST_SYSTEMD_UNIT_ACTIVE, true).unwrap();
        assert_eq!(done.state, TestState::Passed);
        assert!(g.finish(TEST_SYSTEMD_UNIT_ACTIVE, false).is_none());
        assert!(g.finish("unknown", true).is_none());

        let rest = g.finish_remaining(|_| false);
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].test_name, TEST_HEALTH_ENDPOINT_READY);
        assert_eq!(rest[0].state, TestState::Failed);
        assert_eq!(
            g.names_in(TestState::Failed),
            vec![TEST_HEALTH_ENDPOINT_READY]
        );
        assert_eq!(
            g.state_of(TEST_SYSTEMD_UNIT_ACTIVE),
            Some(TestState::Passed)
        );
        assert_eq!(g.names().len(), 2);
    }

    #[test]
    fn test_builtin_verdicts() {
        assert!(builtin_verdict(TEST_SYSTEMD_UNIT_ACTIVE, None, None, true));
        // Endpoint down, systemd up.
        assert!(builtin_verdict(
            TEST_SYSTEMD_UNIT_ACTIVE,
            Some(true),
            Some(false),
            false
        ));
        assert!(!builtin_verdict(
            TEST_HEALTH_ENDPOINT_READY,
            Some(true),
            Some(false),
            false
        ));
        // systemd down, endpoint up.
        assert!(builtin_verdict(
            TEST_HEALTH_ENDPOINT_READY,
            Some(false),
            Some(true),
            false
        ));
        assert!(!builtin_verdict(
            TEST_SYSTEMD_UNIT_ACTIVE,
            Some(false),
            Some(true),
            false
        ));
        // Lease expiry with healthy probes: gate incomplete, everything fails.
        assert!(!builtin_verdict(
            TEST_SYSTEMD_UNIT_ACTIVE,
            Some(true),
            Some(true),
            false
        ));
        assert!(!builtin_verdict("custom", None, None, false));
    }
}
