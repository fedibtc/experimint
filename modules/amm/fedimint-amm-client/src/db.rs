//! Client-local database schema.
//!
//! This is deliberately small. Spec §8.2: `Balance` and `LpPosition` are
//! server-side records keyed by pubkey, so the client never needs to persist
//! anything about an *in-flight* swap beyond what the state machine executor
//! already persists as part of [`crate::swap::SwapStateMachine`] — there is
//! no separate "pending swaps" table, and no timeout/refund bookkeeping to
//! store (spec §6.3, §12: "no timeout and no refund path"). What a *finished*
//! swap settled at is a different question, and [`SwapOutcome`] is the only
//! place it survives once the executor drops the state machine.
//!
//! The one thing genuinely worth caching locally is the set of LP positions
//! this client has created or recovered, since [`crate::AmmClientModule::withdraw`]
//! needs to know a position's `tweak` (to re-derive its owner keypair) and
//! `PoolId` given only the position's public key. The `shares` field cached
//! here is informational only — [`crate::db::LpPositionRecord`]'s doc comment
//! and spec §6.1/§7.3 explain why the server, not this cache, is always
//! authoritative for how many shares a position actually holds at
//! settlement time.

use fedimint_amm_common::pool_id::PoolId;
use fedimint_core::Amount;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::AmountUnit;
use fedimint_core::secp256k1;
use serde::Serialize;
use strum_macros::EnumIter;

/// Mirrors the `DbKeyPrefix` shape used by `fedimint-dummy-client` and
/// `fedimint-lnv2-client`: a real prefix range for this module's own keys,
/// plus the two reserved ranges every client module must leave alone.
#[repr(u8)]
#[derive(Clone, Debug, EnumIter)]
pub enum DbKeyPrefix {
    LpPosition = 0x01,
    /// See [`RecoveredBalanceKey`] (fix pass 4, Critical 1).
    RecoveredBalance = 0x02,
    /// See [`SwapOutcome`].
    SwapOutcome = 0x03,
    /// Prefixes between 0xb0..=0xcf shall all be considered allocated for
    /// historical and future external use
    ExternalReservedStart = 0xb0,
    /// Prefixes between 0xd0..=0xff shall all be considered allocated for
    /// historical and future internal use
    CoreInternalReservedStart = 0xd0,
    /// Prefixes between 0xd0..=0xff shall all be considered allocated for
    /// historical and future internal use
    CoreInternalReservedEnd = 0xff,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Keyed identically to the server's own `LpPositionKey` (spec §5): a
/// position is uniquely identified by `(pool, owner_pk)`, and — because an
/// honest client grinds a fresh `owner_pk` per deposit (spec §8.3) — this key
/// never collides between two of this client's own positions.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Encodable, Decodable)]
pub struct LpPositionKey {
    pub pool: PoolId,
    pub owner_pk: secp256k1::PublicKey,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct LpPositionPrefixAll;

/// A locally cached view of one LP position this client owns.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Encodable, Decodable)]
pub struct LpPositionRecord {
    /// The tweak this position's `owner_pk` was ground from (spec §8). Needed
    /// to re-derive the owner keypair for [`crate::AmmClientModule::withdraw`];
    /// never published anywhere client-side, only round-tripped from the
    /// value used at deposit/recovery time.
    pub tweak: [u8; 16],
    /// Best-effort cache of the position's share count.
    ///
    /// This is populated from a *preview* computed with
    /// `fedimint_amm_common::math::mint_shares` at deposit time (spec §4: the
    /// same pure function `process_output`'s `DepositV0` arm settles with,
    /// fed this client's own snapshot of the pool's reserves), or from
    /// [`fedimint_amm_common::endpoints::LpRecoveryEntry::shares`] when
    /// restored via [`crate::AmmClientModule::recover`]. Both sources can go
    /// stale the moment another deposit or withdrawal touches the same pool,
    /// so this field is informational only: `WithdrawV0` settlement checks
    /// the position's real, current share count server-side (spec §7.3) and
    /// this cache plays no part in that check.
    pub shares: u64,
}

fedimint_core::impl_db_record!(
    key = LpPositionKey,
    value = LpPositionRecord,
    db_prefix = DbKeyPrefix::LpPosition,
);
fedimint_core::impl_db_lookup!(key = LpPositionKey, query_prefix = LpPositionPrefixAll);

/// A balance discovered by a [`crate::recover_with`] table scan (spec §8.2)
/// but not yet claimed (fix pass 4, Critical 1).
///
/// `ClientModuleInit::recover` — the framework's seed-restore hook — runs
/// *before* this module is registered in the client's module registry
/// (pinned `fedimint-client/src/client/builder.rs`: `register_module` is
/// only called on the non-recovering branch; a recovering module's instance
/// id is instead recorded in `module_recoveries` and only ever gains a
/// `ClientContext` handle, never a registry entry, for the remainder of that
/// client process's lifetime). Submitting a `ClaimBalanceV0` transaction from
/// inside `recover` therefore reaches `Client::get_module` — `.expect("Module
/// instance not found")` — and panics. So `recover` only ever writes this
/// marker; the actual claim happens later, once the module is registered and
/// [`crate::AmmClientModule::start`] runs (see that method's doc comment for
/// why `start` is the right place).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Encodable, Decodable)]
pub struct RecoveredBalanceKey {
    pub pubkey: secp256k1::PublicKey,
    pub unit: AmountUnit,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct RecoveredBalancePrefixAll;

/// The tweak `RecoveredBalanceKey::pubkey` was ground from (spec §8), needed
/// to re-derive the claiming keypair. No amount is stored here: the claim
/// path always re-reads the current balance immediately before claiming
/// (spec §6.1), the same reasoning [`crate::swap::await_own_balance`]
/// documents for the in-flight-swap case.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Encodable, Decodable)]
pub struct RecoveredBalanceRecord {
    pub tweak: [u8; 16],
}

fedimint_core::impl_db_record!(
    key = RecoveredBalanceKey,
    value = RecoveredBalanceRecord,
    db_prefix = DbKeyPrefix::RecoveredBalance,
);
fedimint_core::impl_db_lookup!(
    key = RecoveredBalanceKey,
    query_prefix = RecoveredBalancePrefixAll
);

/// The operation a [`crate::swap::SwapStateMachine`] belongs to.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Encodable, Decodable)]
pub struct SwapOutcomeKey(pub OperationId);

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct SwapOutcomePrefixAll;

/// What a swap did with the funds it took in, written the moment that
/// becomes knowable and never revised afterwards.
///
/// The executor persists a swap's *progress* — [`crate::swap::SwapState`] —
/// but discards it once the swap finishes, and no `SwapState` variant carries
/// the settled output amount to begin with. That amount is decided by the
/// guardians evaluating the curve, not by this client (see the crate-level
/// docs on why the client does no curve arithmetic), so nothing else on this
/// device can reconstruct it: the operation log's
/// [`crate::AmmOperationMeta::Swap`] is written before Tx1 is even submitted,
/// and re-reading the federation only ever answers "what is claimable now",
/// which is zero for every swap that already completed. Without this record a
/// caller rendering a transaction history could show what the user sold and
/// never what they got.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Encodable, Decodable)]
pub enum SwapOutcome {
    /// Tx1 was rejected: nothing was spent, no `Balance` was ever created,
    /// and nothing will ever be paid out.
    Tx1Rejected(String),
    /// The federation settled the swap at `amount_out` of the swapped-to
    /// unit.
    ///
    /// Written when Tx2 (`ClaimBalanceV0`) is built, which is both the first
    /// moment the amount is knowable — [`crate::swap::await_own_balance`] has
    /// just read it back off the federation — and the last moment it can
    /// still change. Reaching this state does not mean the e-cash is
    /// spendable yet: crediting it is the primary module's job and follows
    /// Tx2's acceptance. Ask the executor whether the operation still has
    /// active state machines to tell "claimed" from "claim in flight".
    Settled { amount_out: Amount },
}

fedimint_core::impl_db_record!(
    key = SwapOutcomeKey,
    value = SwapOutcome,
    db_prefix = DbKeyPrefix::SwapOutcome,
);
fedimint_core::impl_db_lookup!(key = SwapOutcomeKey, query_prefix = SwapOutcomePrefixAll);

#[cfg(test)]
mod tests {
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
    use fedimint_core::module::AmountUnit;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::secp256k1::{Keypair, SECP256K1};
    use futures::StreamExt;

    use super::*;

    fn db() -> Database {
        Database::new(MemDatabase::new(), ModuleDecoderRegistry::default())
    }

    fn test_pubkey(seed: u8) -> secp256k1::PublicKey {
        Keypair::from_seckey_slice(SECP256K1, &[seed; 32])
            .expect("a repeated non-zero byte is a valid secret key")
            .public_key()
    }

    #[tokio::test]
    async fn lp_position_round_trips() {
        let db = db();
        let mut dbtx = db.begin_transaction().await;
        let pool = PoolId::new(AmountUnit::new_custom(0), AmountUnit::new_custom(1))
            .expect("distinct units");
        let key = LpPositionKey {
            pool,
            owner_pk: test_pubkey(1),
        };
        let record = LpPositionRecord {
            tweak: [7u8; 16],
            shares: 1_234,
        };
        dbtx.insert_new_entry(&key, &record).await;
        assert_eq!(dbtx.get_value(&key).await, Some(record));
        dbtx.commit_tx().await;
    }

    #[tokio::test]
    async fn lp_positions_enumerate_under_prefix() {
        let db = db();
        let mut dbtx = db.begin_transaction().await;
        let pool_a = PoolId::new(AmountUnit::new_custom(0), AmountUnit::new_custom(1)).unwrap();
        let pool_b = PoolId::new(AmountUnit::new_custom(0), AmountUnit::new_custom(2)).unwrap();

        for (pool, seed) in [(pool_a, 1u8), (pool_a, 2u8), (pool_b, 3u8)] {
            dbtx.insert_new_entry(
                &LpPositionKey {
                    pool,
                    owner_pk: test_pubkey(seed),
                },
                &LpPositionRecord {
                    tweak: [seed; 16],
                    shares: 10,
                },
            )
            .await;
        }

        let all: Vec<_> = dbtx
            .find_by_prefix(&LpPositionPrefixAll)
            .await
            .collect()
            .await;
        assert_eq!(all.len(), 3);
        dbtx.commit_tx().await;
    }

    #[tokio::test]
    async fn swap_outcomes_round_trip_and_overwrite() {
        let db = db();
        let mut dbtx = db.begin_transaction().await;
        let key = SwapOutcomeKey(OperationId::new_random());

        dbtx.insert_entry(
            &key,
            &SwapOutcome::Settled {
                amount_out: Amount::from_msats(500),
            },
        )
        .await;
        assert_eq!(
            dbtx.get_value(&key).await,
            Some(SwapOutcome::Settled {
                amount_out: Amount::from_msats(500)
            })
        );

        // A Tx2 retry re-reads the balance before claiming it, so the record
        // must take the freshest read rather than reject a second write.
        dbtx.insert_entry(
            &key,
            &SwapOutcome::Settled {
                amount_out: Amount::from_msats(700),
            },
        )
        .await;
        assert_eq!(
            dbtx.get_value(&key).await,
            Some(SwapOutcome::Settled {
                amount_out: Amount::from_msats(700)
            }),
            "the later balance read must win"
        );

        let rejected = SwapOutcomeKey(OperationId::new_random());
        dbtx.insert_entry(&rejected, &SwapOutcome::Tx1Rejected("boom".to_string()))
            .await;
        assert_eq!(
            dbtx.get_value(&rejected).await,
            Some(SwapOutcome::Tx1Rejected("boom".to_string()))
        );
        dbtx.commit_tx().await;
    }

    #[tokio::test]
    async fn recovered_balance_round_trips() {
        let db = db();
        let mut dbtx = db.begin_transaction().await;
        let key = RecoveredBalanceKey {
            pubkey: test_pubkey(20),
            unit: AmountUnit::new_custom(1),
        };
        let record = RecoveredBalanceRecord { tweak: [11u8; 16] };
        dbtx.insert_new_entry(&key, &record).await;
        assert_eq!(dbtx.get_value(&key).await, Some(record));
        dbtx.commit_tx().await;
    }

    #[tokio::test]
    async fn recovered_balances_enumerate_under_prefix_and_are_removable() {
        let db = db();
        let mut dbtx = db.begin_transaction().await;

        for seed in [21u8, 22, 23] {
            dbtx.insert_new_entry(
                &RecoveredBalanceKey {
                    pubkey: test_pubkey(seed),
                    unit: AmountUnit::new_custom(0),
                },
                &RecoveredBalanceRecord { tweak: [seed; 16] },
            )
            .await;
        }

        let all: Vec<_> = dbtx
            .find_by_prefix(&RecoveredBalancePrefixAll)
            .await
            .collect()
            .await;
        assert_eq!(all.len(), 3);

        // The claim sweep removes an entry once it is claimed (or found
        // already gone) — pin that the key round-trips through removal, not
        // just insertion/lookup.
        let (removed_key, _) = all[0];
        dbtx.remove_entry(&removed_key).await;
        let remaining: Vec<_> = dbtx
            .find_by_prefix(&RecoveredBalancePrefixAll)
            .await
            .collect()
            .await;
        assert_eq!(remaining.len(), 2);
        dbtx.commit_tx().await;
    }
}
