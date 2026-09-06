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
// Re-exported so existing `scan::MAX_TRANSFER_CANDIDATES_PER_RESPONSE` call
// sites (server lib.rs, tests) keep working unchanged; the canonical
// definition lives in `fedimint-usdt-common` (next to the wire types) so the
// CLIENT can see it too -- it needs the exact cap to detect a full,
// possibly-truncated page (finding 3).
pub use fedimint_usdt_common::MAX_TRANSFER_CANDIDATES_PER_RESPONSE;

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
    ///
    /// `up_to` must be non-decreasing across calls: `scan_step` (the sole
    /// caller) only ever advances its scan cursor forward, so a batch's
    /// coverage can never regress. This is the meaningful half of what used
    /// to be a vacuous caller-side `debug_assert!(to >= from)` (that compared
    /// the CALLER's own local `from`/`to`, which are constructed to satisfy
    /// `to >= from` by construction and so could never fail) -- the
    /// assertion worth making lives here, against `record_scan`'s own prior
    /// state.
    pub fn record_scan(&mut self, up_to: u64, found: Vec<TransferCandidate>) {
        debug_assert!(
            up_to >= self.scanned_to,
            "scan batches must arrive in non-decreasing coverage order: \
             up_to={up_to} scanned_to={}",
            self.scanned_to
        );
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
    /// `limit`; plus an HONEST per-response high-water mark (finding 3).
    ///
    /// When the page is NOT truncated (fewer than `limit` matching entries
    /// exist), the second element is the log's real `scanned_to` -- this
    /// guardian has served every candidate it has ever found above
    /// `since_block`. When the page IS truncated (`limit` reached with more
    /// matching entries remaining), returning the full `scanned_to`
    /// unconditionally would be a lie: a caller that advances its cursor to
    /// it would skip every unserved candidate at or below the first omitted
    /// entry's block forever, since nothing above `since_block` would ever
    /// be re-queried. Instead, the returned mark is clamped to one below the
    /// first OMITTED entry's block -- `min(scanned_to, first_omitted.
    /// block_number - 1)` -- the highest height for which THIS response is
    /// actually complete. Several entries sharing that first-omitted block
    /// (a block with more matching transfers than fit in the remaining page)
    /// are all still short of the clamp, so the mark never claims coverage
    /// through a block this page only partially reports.
    ///
    /// Callers that need full coverage (not just one page) must page: keep
    /// re-querying at the returned mark until a response comes back
    /// untruncated (see `fedimint-usdt-client`'s `page_peer_candidates`).
    #[must_use]
    pub fn since(&self, since_block: u64, limit: usize) -> (Vec<TransferCandidate>, u64) {
        let mut matching = self.entries.iter().filter(|c| c.block_number > since_block);
        let page: Vec<TransferCandidate> = matching.by_ref().take(limit).cloned().collect();
        let scanned_to = match matching.next() {
            // Truncated: at least one matching entry beyond `limit` remains.
            // Clamp below its block so this response never overclaims.
            Some(first_omitted) => self
                .scanned_to
                .min(first_omitted.block_number.saturating_sub(1)),
            // Untruncated: every matching entry made it into `page`.
            None => self.scanned_to,
        };
        (page, scanned_to)
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

    /// Finding 3: a page that hits `limit` before exhausting the matching
    /// entries must clamp `scanned_to` below the first OMITTED entry's
    /// block, not report the log's full high-water mark -- a caller that
    /// advanced its cursor to the untruncated mark would never re-query the
    /// blocks this page didn't have room for.
    #[test]
    fn since_clamps_scanned_to_when_the_page_is_truncated() {
        let mut log = CandidateLog::default();
        let entries: Vec<_> = (0..10).map(|i| cand(100 + i)).collect(); // blocks 100..=109
        log.record_scan(500, entries);

        // limit 5: page holds blocks 100..=104, first omitted is block 105.
        let (page, scanned_to) = log.since(0, 5);
        assert_eq!(
            page.iter().map(|c| c.block_number).collect::<Vec<_>>(),
            vec![100, 101, 102, 103, 104]
        );
        // Must NOT claim coverage through 105 (the first omitted entry's
        // block) or the log's real mark (500) -- only through 104.
        assert_eq!(scanned_to, 104);
    }

    /// Finding 3: several entries sharing the first-omitted block (more
    /// matching transfers in one block than fit in the remaining page) must
    /// never let `scanned_to` reach that block -- every one of them is
    /// "omitted" from this page's point of view, so the response is
    /// incomplete as of one block EARLIER, not as of the straddled block
    /// itself.
    #[test]
    fn since_truncation_never_lets_scanned_to_reach_a_straddled_block() {
        let mut log = CandidateLog::default();
        // Three candidates land in block 100, one more in block 101.
        log.record_scan(500, vec![cand(100), cand(100), cand(100), cand(101)]);

        // limit 2 stops mid-block-100: the first omitted entry is ALSO at
        // block 100, so scanned_to must clamp strictly below 100.
        let (page, scanned_to) = log.since(0, 2);
        assert_eq!(page.len(), 2);
        assert!(
            scanned_to < 100,
            "scanned_to={scanned_to} must not reach the straddled block 100"
        );
    }

    /// Finding 3: when a page is NOT truncated (every matching entry fits),
    /// `since` must keep returning the log's real, full high-water mark --
    /// the honest-clamping behavior above must not degrade the common case.
    #[test]
    fn since_untruncated_page_returns_the_full_scanned_to_mark() {
        let mut log = CandidateLog::default();
        log.record_scan(500, vec![cand(100), cand(101)]);

        let (page, scanned_to) = log.since(0, 10);
        assert_eq!(page.len(), 2);
        assert_eq!(scanned_to, 500);
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
