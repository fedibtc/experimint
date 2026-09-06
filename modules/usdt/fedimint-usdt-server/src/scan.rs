//! Guardian-local deposit-discovery scan state (spec:
//! docs/superpowers/specs/2026-09-06-usdt-deposit-discovery-design.md).
//!
//! DELIBERATELY IN-MEMORY, never consensus DB: per the sec-13
//! COMMIT-SAFETY rule, guardian-local tasks must not commit consensus DB
//! state, and candidates are rediscoverable hints (a restart just re-scans
//! the retention window). Nothing in any `process_*` consensus path may
//! ever read this state.

use std::collections::VecDeque;

use fedimint_core::secp256k1;
use fedimint_usdt_common::{TransferCandidate, UsdtAmount, is_potential_deposit};

use crate::rpc::TransferLog;

/// How far back candidates are retained (~7 days of 12s L1 blocks). Also
/// bounds the cold-start backfill: retention ÷ `scan_batch_blocks`
/// requests, once per process start. A client offline longer than this
/// falls back to the `recover` gap-limit walk.
pub const CANDIDATE_RETENTION_BLOCKS: u64 = 50_400;

/// Hard cap on retained candidates (oldest dropped first). Legitimate +
/// noise volume is tiny (predicate passes ~2^-16 of transfers); flushing
/// this cap requires one REAL on-chain USDT transfer per entry, so the
/// attack costs gas per entry and is visible on-chain.
pub const MAX_CANDIDATE_ENTRIES: usize = 4_096;

/// Response page cap for the `transfer_candidates` endpoint.
pub const MAX_TRANSFER_CANDIDATES_PER_RESPONSE: usize = 512;

/// This guardian's in-memory log of predicate-matching confirmed
/// transfers, in ascending block order, plus the scan's high-water mark.
#[derive(Debug, Default)]
pub struct CandidateLog {
    entries: VecDeque<TransferCandidate>,
    scanned_to: u64,
}

impl CandidateLog {
    /// Highest block this guardian's scan has fully covered (0 = none yet;
    /// doubles as the scanner task's cursor).
    #[must_use]
    pub fn scanned_to(&self) -> u64 {
        self.scanned_to
    }

    /// Appends one scanned batch's findings and advances the high-water
    /// mark, then prunes by retention (relative to the new mark) and by
    /// the entry cap (oldest first).
    pub fn record_scan(&mut self, up_to: u64, found: Vec<TransferCandidate>) {
        self.entries.extend(found);
        self.scanned_to = self.scanned_to.max(up_to);
        let floor = self.scanned_to.saturating_sub(CANDIDATE_RETENTION_BLOCKS);
        while self.entries.front().is_some_and(|c| c.block_number < floor) {
            self.entries.pop_front();
        }
        while self.entries.len() > MAX_CANDIDATE_ENTRIES {
            self.entries.pop_front();
        }
    }

    /// Candidates strictly above `since_block`, oldest first, capped at
    /// `limit`; plus the current high-water mark.
    #[must_use]
    pub fn since(&self, since_block: u64, limit: usize) -> (Vec<TransferCandidate>, u64) {
        let page = self
            .entries
            .iter()
            .filter(|c| c.block_number > since_block)
            .take(limit)
            .cloned()
            .collect();
        (page, self.scanned_to)
    }
}

/// The scan's per-batch filter: keep transfers with a nonzero value whose
/// recipient satisfies the discovery predicate. Pure (no RPC, no clock) so
/// it is unit-testable; value saturates into the `UsdtAmount` wire type.
#[must_use]
pub fn filter_scan_candidates(
    logs: &[TransferLog],
    group_public_key: &secp256k1::PublicKey,
) -> Vec<TransferCandidate> {
    logs.iter()
        .filter(|l| l.value > 0 && is_potential_deposit(group_public_key, &l.to))
        .map(|l| TransferCandidate {
            block_number: l.block_number,
            to: l.to,
            value: UsdtAmount(u64::try_from(l.value).unwrap_or(u64::MAX)),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use fedimint_core::secp256k1;
    use fedimint_usdt_common::{EvmAddress, TransferCandidate, UsdtAmount};

    use super::*;
    use crate::rpc::TransferLog;

    fn cand(block: u64) -> TransferCandidate {
        TransferCandidate {
            block_number: block,
            to: EvmAddress([0u8; 20]),
            value: UsdtAmount(1),
        }
    }

    fn tl(block: u64, to: EvmAddress, value: u128) -> TransferLog {
        TransferLog {
            block_number: block,
            to,
            value,
        }
    }

    /// A fixed, valid secp256k1 public key standing in for a federation's
    /// `group_public_key` in these tests.
    fn test_group_pk() -> secp256k1::PublicKey {
        secp256k1::SecretKey::from_slice(&[0x11; 32])
            .expect("valid scalar")
            .public_key(secp256k1::SECP256K1)
    }

    #[test]
    fn candidate_log_records_prunes_and_pages() {
        let mut log = CandidateLog::default();
        assert_eq!(log.scanned_to(), 0);
        log.record_scan(100, vec![cand(90), cand(95)]);
        log.record_scan(200, vec![cand(150)]);
        assert_eq!(log.scanned_to(), 200);
        let (page, scanned_to) = log.since(90, 10);
        assert_eq!(scanned_to, 200);
        assert_eq!(
            page.iter().map(|c| c.block_number).collect::<Vec<_>>(),
            vec![95, 150]
        );
        // paging: limit 1 returns the OLDEST entry above the cursor
        let (page, _) = log.since(0, 1);
        assert_eq!(page[0].block_number, 90);
        // retention: recording far ahead prunes old entries
        log.record_scan(90 + CANDIDATE_RETENTION_BLOCKS + 1, vec![]);
        let (page, _) = log.since(0, 10);
        assert!(page.iter().all(|c| c.block_number > 90));
    }

    #[test]
    fn candidate_log_caps_entries_dropping_oldest() {
        let mut log = CandidateLog::default();
        let flood: Vec<_> = (0..MAX_CANDIDATE_ENTRIES as u64 + 10)
            .map(|i| cand(1000 + i))
            .collect();
        // `scanned_to` tracks the batch's actual max block (not an
        // arbitrary far-future height), so retention pruning (floor =
        // scanned_to - CANDIDATE_RETENTION_BLOCKS) stays a no-op here and
        // this test isolates the entry-cap pruning path.
        let up_to = 1000 + MAX_CANDIDATE_ENTRIES as u64 + 9;
        log.record_scan(up_to, flood);
        let (page, _) = log.since(0, usize::MAX);
        assert_eq!(page.len(), MAX_CANDIDATE_ENTRIES);
        assert_eq!(page[0].block_number, 1010); // oldest 10 dropped
    }

    #[test]
    // The grind below is unbounded from clippy's point of view, but the
    // 16-bit predicate matches within a handful of iterations in practice
    // (see `is_potential_deposit`'s false-positive rate).
    #[allow(clippy::maybe_infinite_iter)]
    fn filter_scan_candidates_applies_predicate_and_value_gate() {
        let group_pk = test_group_pk();
        // grind a matching address by brute force over synthetic addresses
        let matching = (0u64..)
            .map(|i| {
                let mut a = [0u8; 20];
                a[..8].copy_from_slice(&i.to_be_bytes());
                EvmAddress(a)
            })
            .find(|a| fedimint_usdt_common::is_potential_deposit(&group_pk, a))
            .expect("some synthetic address matches");
        let non_matching = EvmAddress([0xEE; 20]); // assert it doesn't match, regenerate if it does
        assert!(!fedimint_usdt_common::is_potential_deposit(
            &group_pk,
            &non_matching
        ));
        let logs = vec![
            tl(5, matching, 1_000_000),
            tl(5, non_matching, 1_000_000), // predicate fails -> dropped
            tl(6, matching, 0),             // zero value -> dropped
            tl(7, matching, u128::from(u64::MAX) + 7), // saturates
        ];
        let out = filter_scan_candidates(&logs, &group_pk);
        assert_eq!(out.len(), 2);
        assert_eq!(out[1].value, UsdtAmount(u64::MAX));
    }
}
