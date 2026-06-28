//! Lease-derived work budgets: a claimed lease is the single source of truth
//! for how long its work may run before it must abort.

/// Default lease granted to claimed work.
pub const DEFAULT_LEASE_MS: u64 = 30_000;

/// Upper bound on the safety margin reserved before lease expiry.
const MAX_ABORT_MARGIN_MS: u64 = 5_000;

/// How long work claimed under a `lease_ms` lease may run before it must abort,
/// reserving a margin of `min(5s, lease/10)` for cleanup.
pub fn lease_work_budget_ms(lease_ms: u64) -> u64 {
	let margin = MAX_ABORT_MARGIN_MS.min(lease_ms / 10);
	lease_ms.saturating_sub(margin)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn long_leases_reserve_the_capped_margin() {
		assert_eq!(lease_work_budget_ms(30_000), 27_000);
		assert_eq!(lease_work_budget_ms(100_000), 95_000);
	}

	#[test]
	fn short_leases_reserve_a_tenth() {
		assert_eq!(lease_work_budget_ms(10_000), 9_000);
		assert_eq!(lease_work_budget_ms(0), 0);
	}
}
