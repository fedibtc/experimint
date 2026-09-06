# USDT Deposit Discovery (Ground Predicate + Guardian Log Scan) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Clients grind claim keys whose deposit addresses match a public predicate; guardians scan USDT `Transfer` logs, filter by that predicate, and serve matching candidates from a new guardian-local endpoint — so mobile clients discover deposits with zero EVM polling, while claiming stays the unchanged proof path.

**Architecture:** All changes live in `modules/usdt/`. `-common` gains the predicate + tweak-grind primitives (WASM-safe: `secp256k1` + `sha3` + `alloy-primitives`, all existing deps) and the new wire types/endpoint name. `-server` gains a `get_transfer_logs` RPC method, an in-memory `CandidateLog` fed by a new guardian-local scanner task (modeled on `spawn_block_hash_observer` / `spawn_residual_recovery_observer`), and a `transfer_candidates` endpoint at ApiVersion (0,1). `-client` grinds a tweak into `allocate_deposit`, adds a `discover_deposits` union-of-peers query with a persisted cursor, and extends recovery to re-grind. No consensus item, no consensus-config field, no server DB prefix, no wire input change ⇒ **no `MODULE_CONSENSUS_VERSION` bump**.

**Tech Stack:** Rust (edition 2024), fedimint module framework (pinned rev a50619eafc6), alloy (server RPC), secp256k1 + sha3 (common), `fedimint-testing` fixtures + `MockEvmRpc` + anvil for tests.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-09-06-usdt-deposit-discovery-design.md`.
- **No `MODULE_CONSENSUS_VERSION` bump** — this change must not touch consensus items, consensus config, server DB prefixes, or any `Encodable` enum used in consensus. If a task seems to need one, stop and re-read the spec.
- **Wire enums are append-only** (fedimint-derive encodes by positional index). This plan adds no variants to existing wire enums; do not "clean up" any while in there.
- **COMMIT-SAFETY (sec-13):** guardian-local background tasks open `db.begin_transaction_nc()` only and never commit consensus DB state. The scanner writes only to an in-memory `Arc<Mutex<CandidateLog>>`.
- Wrap every recurring server-side RPC await in `rpc_deadline(...)` (`fedimint-usdt-server/src/lib.rs:661`).
- `-common` and `-client` must stay WASM-clean: after touching them run
  `cargo check --target wasm32-unknown-unknown -p fedimint-usdt-common -p fedimint-usdt-client`.
- No floats, no `panic!`/`unwrap`/`expect` on consensus paths (this plan adds no consensus-path code, but the rule binds any incidental edits); `BTreeMap`/`BTreeSet` in anything consensus-adjacent.
- Every task ends in a commit with a conventional-commit subject and the trailers:
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` and
  `Claude-Session: https://claude.ai/code/session_01H6NeHwbEkGyjJxMJrYbHfU`.
- If `Cargo.lock` changes (it should not — no new deps), refresh `cargoHash` in `flake.nix`.
- Verification for every task: `cargo test -p <touched crates>` green, and before the final commit of the plan `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`.

## File Structure

```
modules/usdt/fedimint-usdt-common/src/lib.rs        # predicate, grind, fast CREATE2 path, wire types (Tasks 1-3)
modules/usdt/fedimint-usdt-common/src/endpoint_constants.rs  # TRANSFER_CANDIDATES_ENDPOINT (Task 3)
modules/usdt/fedimint-usdt-server/src/rpc.rs        # Transfer event, get_transfer_logs (Task 4)
modules/usdt/fedimint-usdt-server/src/scan.rs       # NEW: CandidateLog + filter_scan_candidates (Task 5)
modules/usdt/fedimint-usdt-server/src/lib.rs        # scanner task, Usdt field, endpoint, api version (Tasks 6-7)
modules/usdt/fedimint-usdt-server/src/config.rs     # UsdtConfigLocal.scan_batch_blocks (Task 6)
modules/usdt/fedimint-usdt-client/src/lib.rs        # grind in allocate_deposit, discover, recovery (Tasks 8-10)
modules/usdt/fedimint-usdt-client/src/api.rs        # transfer_candidates call (Task 9)
modules/usdt/fedimint-usdt-client/src/db.rs         # ScanCursorKey 0x06 (Task 9)
modules/usdt/fedimint-usdt-client/src/cli.rs        # discover-deposits command (Task 9)
modules/usdt/fedimint-usdt-tests/tests/common/mock.rs  # set_transfer_logs (Task 4)
modules/usdt/fedimint-usdt-tests/tests/tests.rs     # integration tests (Tasks 7, 11)
modules/usdt/fedimint-usdt-common/SECURITY.md       # discovery section (Task 11)
```

---

### Task 1: Scan predicate + fast CREATE2 path in `-common`

**Files:**
- Modify: `modules/usdt/fedimint-usdt-common/src/lib.rs` (constants near `DEPOSIT_ADDRESS_DOMAIN` at :506; helpers near `create2_simple_account` at :812; tests in the existing `mod tests`)

**Interfaces:**
- Produces: `pub const SCAN_PREDICATE_DOMAIN: &[u8]`, `pub const DEPOSIT_SCAN_TAG_BITS: u32`, `pub fn is_potential_deposit(&secp256k1::PublicKey, &EvmAddress) -> bool`, `pub fn deposit_init_code_hash(EvmAddress, EvmAddress) -> [u8; 32]`, `pub(crate)`→`pub fn create2_address(EvmAddress, [u8; 32], [u8; 32]) -> EvmAddress`

- [ ] **Step 0: Commit the spec + this plan** (first commit of the branch work):

```bash
git add docs/superpowers/specs/2026-09-06-usdt-deposit-discovery-design.md docs/superpowers/plans/2026-09-06-usdt-deposit-discovery.md
git commit -m "docs: design ground-predicate deposit discovery"
```

- [ ] **Step 1: Write the failing tests** in `-common`'s existing `mod tests`:

```rust
#[test]
fn scan_predicate_is_deterministic_and_rare() {
    let group_pk = test_group_pk(); // reuse the existing test-helper keypair in this mod; if none exists, build one from a fixed 32-byte secret
    let a = EvmAddress([0x11; 20]);
    assert_eq!(
        is_potential_deposit(&group_pk, &a),
        is_potential_deposit(&group_pk, &a)
    );
    // 16-bit predicate: out of 1000 arbitrary addresses, expect ~0 hits.
    let hits = (0u8..=255)
        .flat_map(|x| (0u8..4).map(move |y| EvmAddress([x ^ y; 20])))
        .filter(|addr| is_potential_deposit(&group_pk, addr))
        .count();
    assert!(hits <= 2, "predicate should hit ~1 in 2^16, got {hits}/1024");
}

#[test]
fn leading_zero_bits_boundaries() {
    assert!(has_leading_zero_bits(&[0x00, 0x00, 0xff], 16));
    assert!(!has_leading_zero_bits(&[0x00, 0x01, 0x00], 16));
    assert!(has_leading_zero_bits(&[0x00, 0x7f], 9));
    assert!(!has_leading_zero_bits(&[0x00, 0x80], 9));
}

#[test]
fn create2_fast_path_matches_slow_path() {
    // The refactor must not change any derived address: compare the
    // (init-code-hash) fast path against a from-scratch
    // `create2_from_code` computation for a couple of inputs.
    let owner = EvmAddress([0x22; 20]);
    let factory = EvmAddress([0x33; 20]);
    let impl_ = EvmAddress([0x44; 20]);
    let salt = [0x55u8; 32];
    let expected = {
        // inline duplicate of the pre-refactor body, kept only in this test
        use alloy_sol_types::{SolCall as _, SolValue as _};
        let initialize_calldata = ISimpleAccountInit::initializeCall {
            anOwner: alloy_primitives::Address::from(owner.0),
        }
        .abi_encode();
        let ctor_args = (
            alloy_primitives::Address::from(impl_.0),
            alloy_primitives::Bytes::from(initialize_calldata),
        )
            .abi_encode_params();
        let mut init_code = ERC1967_PROXY_CREATION_CODE.to_vec();
        init_code.extend_from_slice(&ctor_args);
        let derived =
            alloy_primitives::Address::from(factory.0).create2_from_code(salt, init_code);
        EvmAddress(derived.into_array())
    };
    let fast = create2_address(factory, salt, deposit_init_code_hash(impl_, owner));
    assert_eq!(fast, expected);
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p fedimint-usdt-common scan_predicate -- --nocapture`
Expected: FAIL to compile — `is_potential_deposit`, `has_leading_zero_bits`, `deposit_init_code_hash`, `create2_address` not found.

- [ ] **Step 3: Implement.** Next to `DEPOSIT_ADDRESS_DOMAIN` (lib.rs:506) add:

```rust
/// Domain-separation tag for the deposit-discovery scan predicate (see
/// [`is_potential_deposit`]). Mixed with the federation's `group_public_key`
/// so one grind cannot be amortized across federations.
pub const SCAN_PREDICATE_DOMAIN: &[u8] = b"fedimint-usdt-scan-v0";

/// Leading zero bits [`is_potential_deposit`]'s hash must have for a deposit
/// account to be discoverable by the guardians' Transfer-log scan. 16 bits
/// (walletv2's `is_potential_receive` difficulty): a ~sub-second client-side
/// grind, and a false-positive rate of `transfers × 2^-16` in the candidate
/// stream. A CONSTANT (not config): every guardian and client must agree on
/// it, and changing it would strand previously ground addresses out of the
/// stream (they would still be claimable via proof, but undiscoverable).
pub const DEPOSIT_SCAN_TAG_BITS: u32 = 16;
```

Next to `create2_simple_account` (lib.rs:812) add + refactor:

```rust
/// Whether `account` is discoverable by the guardians' deposit scan:
/// `keccak256(SCAN_PREDICATE_DOMAIN ‖ group_pk_compressed ‖ account)` has
/// [`DEPOSIT_SCAN_TAG_BITS`] leading zero bits. Pure, WASM-safe; guardians
/// evaluate it over every USDT `Transfer` log's `to` address, clients grind
/// claim-key tweaks until it holds (see [`find_scan_tweak`]). NOTE the
/// accepted privacy trade-off (SECURITY.md "Deposit discovery"): anyone
/// holding the public `group_public_key` can tag matching addresses as
/// probable deposits of this federation.
#[must_use]
pub fn is_potential_deposit(
    group_public_key: &secp256k1::PublicKey,
    account: &EvmAddress,
) -> bool {
    let mut hasher = Keccak256::new();
    hasher.update(SCAN_PREDICATE_DOMAIN);
    hasher.update(group_public_key.serialize());
    hasher.update(account.0);
    has_leading_zero_bits(&hasher.finalize(), DEPOSIT_SCAN_TAG_BITS)
}

/// `bits` leading zero bits check, byte-wise then a partial-byte mask.
fn has_leading_zero_bits(bytes: &[u8], bits: u32) -> bool {
    let full = (bits / 8) as usize;
    let rem = bits % 8;
    if bytes.len() < full + usize::from(rem > 0) {
        return false;
    }
    if bytes[..full].iter().any(|b| *b != 0) {
        return false;
    }
    rem == 0 || (bytes[full] >> (8 - rem)) == 0
}

/// `keccak256` of the deposit account's CREATE2 `initCode` — constant across
/// all claim keys of one federation (it depends only on the implementation
/// address and the group-key owner), extracted so the grinding hot loop pays
/// three short keccaks per candidate instead of hashing the ~10.7KB
/// `ERC1967_PROXY_CREATION_CODE` every iteration.
#[must_use]
pub fn deposit_init_code_hash(simple_account_impl: EvmAddress, owner: EvmAddress) -> [u8; 32] {
    use alloy_sol_types::{SolCall as _, SolValue as _};
    let initialize_calldata = ISimpleAccountInit::initializeCall {
        anOwner: alloy_primitives::Address::from(owner.0),
    }
    .abi_encode();
    let ctor_args = (
        alloy_primitives::Address::from(simple_account_impl.0),
        alloy_primitives::Bytes::from(initialize_calldata),
    )
        .abi_encode_params();
    let mut init_code = ERC1967_PROXY_CREATION_CODE.to_vec();
    init_code.extend_from_slice(&ctor_args);
    alloy_primitives::keccak256(&init_code).into()
}

/// EIP-1014 address from a precomputed init-code hash (the fast half of
/// [`create2_simple_account`]).
#[must_use]
pub fn create2_address(
    account_factory: EvmAddress,
    salt: [u8; 32],
    init_code_hash: [u8; 32],
) -> EvmAddress {
    let derived = alloy_primitives::Address::from(account_factory.0)
        .create2(salt, alloy_primitives::B256::from(init_code_hash));
    EvmAddress(derived.into_array())
}
```

and shrink `create2_simple_account`'s body to:

```rust
fn create2_simple_account(
    account_factory: EvmAddress,
    simple_account_impl: EvmAddress,
    owner: EvmAddress,
    salt: [u8; 32],
) -> EvmAddress {
    create2_address(
        account_factory,
        salt,
        deposit_init_code_hash(simple_account_impl, owner),
    )
}
```

- [ ] **Step 4: Run tests + parity guards**

Run: `cargo test -p fedimint-usdt-common`
Expected: PASS — including the pre-existing derivation tests (the CREATE2 refactor is behavior-preserving; `derive_deposit_account_matches_factory_get_address` in `-tests` re-verifies against a real factory later).

Run: `cargo check --target wasm32-unknown-unknown -p fedimint-usdt-common`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add modules/usdt/fedimint-usdt-common/src/lib.rs
git commit -m "feat(usdt-common): deposit-discovery scan predicate + fast CREATE2 path"
```

---

### Task 2: Tweak grinding in `-common`

**Files:**
- Modify: `modules/usdt/fedimint-usdt-common/src/lib.rs` (below `derive_deposit_account`)

**Interfaces:**
- Consumes: `is_potential_deposit`, `deposit_init_code_hash`, `create2_address`, `deposit_salt`, `evm_address` (Task 1 / existing)
- Produces: `pub const MAX_SCAN_GRIND_ITERATIONS: u64`, `pub fn scan_tweak_scalar(u64) -> secp256k1::Scalar`, `pub fn find_scan_tweak(&PublicKey, EvmAddress, EvmAddress, &PublicKey, u64, u64) -> anyhow::Result<Option<(u64, PublicKey, EvmAddress)>>`

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn find_scan_tweak_finds_matching_key_and_secret_agrees() {
    let secp = secp256k1::SECP256K1;
    let base_sk = secp256k1::SecretKey::from_slice(&[0x42; 32]).expect("valid");
    let base_pk = base_sk.public_key(secp);
    let group_pk = test_group_pk();
    let factory = EvmAddress([0x33; 20]);
    let impl_ = EvmAddress([0x44; 20]);

    let (tweak, pk, account) =
        find_scan_tweak(&group_pk, factory, impl_, &base_pk, 0, MAX_SCAN_GRIND_ITERATIONS)
            .expect("grind ok")
            .expect("tweak exists within 2^22 (P(miss) ~ e^-64)");

    // Predicate holds for the ground address...
    assert!(is_potential_deposit(&group_pk, &account));
    // ...the address is the real derivation for the ground pk...
    assert_eq!(account, derive_deposit_account(&group_pk, factory, impl_, &pk));
    // ...and the tweaked SECRET key matches the tweaked PUBLIC key.
    let sk = if tweak == 0 {
        base_sk
    } else {
        base_sk.add_tweak(&scan_tweak_scalar(tweak)).expect("tweak add")
    };
    assert_eq!(sk.public_key(secp), pk);
}

#[test]
fn find_scan_tweak_is_deterministic_and_resumable() {
    let base_pk = secp256k1::SecretKey::from_slice(&[0x42; 32])
        .expect("valid")
        .public_key(secp256k1::SECP256K1);
    let group_pk = test_group_pk();
    let factory = EvmAddress([0x33; 20]);
    let impl_ = EvmAddress([0x44; 20]);
    let full = find_scan_tweak(&group_pk, factory, impl_, &base_pk, 0, 1 << 22).expect("ok");
    // Chunked scan (256 at a time) lands on the identical tweak.
    let mut chunked = None;
    let mut start = 0;
    while chunked.is_none() && start < (1 << 22) {
        chunked =
            find_scan_tweak(&group_pk, factory, impl_, &base_pk, start, start + 256).expect("ok");
        start += 256;
    }
    assert_eq!(full, chunked);
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p fedimint-usdt-common find_scan_tweak`
Expected: FAIL to compile — `find_scan_tweak`, `scan_tweak_scalar`, `MAX_SCAN_GRIND_ITERATIONS` not found.

- [ ] **Step 3: Implement**

```rust
/// Hard cap on scan-tweak grinding. At [`DEPOSIT_SCAN_TAG_BITS`] = 16 the
/// probability of finding no tweak in 2^22 tries is e^{-64}: statistically
/// unreachable, but the loop must still be bounded.
pub const MAX_SCAN_GRIND_ITERATIONS: u64 = 1 << 22;

/// The additive tweak `t` as a secp256k1 scalar (for
/// `SecretKey::add_tweak` / `PublicKey::add_exp_tweak`).
#[must_use]
pub fn scan_tweak_scalar(tweak: u64) -> secp256k1::Scalar {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&tweak.to_be_bytes());
    secp256k1::Scalar::from_be_bytes(bytes).expect("a u64 is far below the curve order")
}

/// Scans tweaks `start..end` for the first `t` such that
/// `claim_pk = base_pk + t·G` derives a deposit account satisfying
/// [`is_potential_deposit`]. Returns `(t, claim_pk, account)`, or `None` if
/// no tweak in the range matches. Deterministic (recovery re-runs the same
/// scan) and resumable (callers chunk the range to stay responsive on
/// wasm). Hot loop cost per candidate: one point add + three short keccaks
/// (salt, CREATE2, predicate) — the init-code hash is precomputed via
/// [`deposit_init_code_hash`].
pub fn find_scan_tweak(
    group_public_key: &secp256k1::PublicKey,
    account_factory: EvmAddress,
    simple_account_impl: EvmAddress,
    base_pk: &secp256k1::PublicKey,
    start: u64,
    end: u64,
) -> anyhow::Result<Option<(u64, secp256k1::PublicKey, EvmAddress)>> {
    let end = end.min(MAX_SCAN_GRIND_ITERATIONS);
    if start >= end {
        return Ok(None);
    }
    let owner = evm_address(group_public_key);
    let init_code_hash = deposit_init_code_hash(simple_account_impl, owner);
    let mut pk = if start == 0 {
        *base_pk
    } else {
        base_pk
            .add_exp_tweak(secp256k1::SECP256K1, &scan_tweak_scalar(start))
            .context("tweak offset")?
    };
    for tweak in start..end {
        let account = create2_address(account_factory, deposit_salt(&pk), init_code_hash);
        if is_potential_deposit(group_public_key, &account) {
            return Ok(Some((tweak, pk, account)));
        }
        pk = pk
            .add_exp_tweak(secp256k1::SECP256K1, &secp256k1::Scalar::ONE)
            .context("tweak step")?;
    }
    Ok(None)
}
```

(`use anyhow::Context as _;` is already imported in this file; add it if not.)

- [ ] **Step 4: Run tests**

Run: `cargo test -p fedimint-usdt-common` and `cargo check --target wasm32-unknown-unknown -p fedimint-usdt-common`
Expected: PASS / clean. The determinism test grinds ~65k candidates twice — it should take well under a second in release, a few seconds in debug; if it exceeds ~30s something is wrong with the fast path (likely hashing the full init code per iteration).

- [ ] **Step 5: Commit**

```bash
git add modules/usdt/fedimint-usdt-common/src/lib.rs
git commit -m "feat(usdt-common): deterministic claim-key tweak grinding for the scan predicate"
```

---

### Task 3: Wire types + endpoint constant

**Files:**
- Modify: `modules/usdt/fedimint-usdt-common/src/lib.rs` (next to `AnchoredBlockResponse` at :1152)
- Modify: `modules/usdt/fedimint-usdt-common/src/endpoint_constants.rs`

**Interfaces:**
- Produces: `pub struct TransferCandidate { block_number: u64, to: EvmAddress, value: UsdtAmount }`, `pub struct TransferCandidatesRequest { since_block: u64 }`, `pub struct TransferCandidatesResponse { candidates: Vec<TransferCandidate>, scanned_to: u64 }`, `pub const TRANSFER_CANDIDATES_ENDPOINT: &str = "transfer_candidates"`

- [ ] **Step 1: Add the types** (derives match `AnchoredBlockResponse`'s: `Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encodable, Decodable`):

```rust
/// One plausible incoming deposit surfaced by a guardian's Transfer-log
/// scan (see `TRANSFER_CANDIDATES_ENDPOINT`): a confirmed USDT `Transfer`
/// whose `to` address satisfies [`is_potential_deposit`]. A HINT, not a
/// credit — the client matches `to` against its own derived addresses and,
/// on a match, runs the unchanged deposit-proof claim flow. False entries
/// (predicate collisions, or transfers unrelated to this federation) are
/// harmless: they simply fail to match any client key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encodable, Decodable)]
pub struct TransferCandidate {
    /// Confirmed block the transfer was observed in.
    pub block_number: u64,
    /// The transfer's recipient (a predicate-matching address).
    pub to: EvmAddress,
    /// Transferred amount (saturated to `u64`; USDT has 6 decimals).
    pub value: UsdtAmount,
}

/// Request for `TRANSFER_CANDIDATES_ENDPOINT`: candidates observed in
/// blocks strictly above `since_block` (the client's persisted cursor).
#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct TransferCandidatesRequest {
    pub since_block: u64,
}

/// Response for `TRANSFER_CANDIDATES_ENDPOINT`. `scanned_to` is the highest
/// block THIS guardian's scan has fully covered; the client advances its
/// cursor only to a height at least `max_evil + 1` responding guardians
/// have covered (so one honest guardian vouches for it).
#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct TransferCandidatesResponse {
    /// Ascending block order, capped server-side; re-query with a higher
    /// `since_block` to page.
    pub candidates: Vec<TransferCandidate>,
    pub scanned_to: u64,
}
```

- [ ] **Step 2: Add the endpoint constant** at the end of `endpoint_constants.rs`:

```rust
/// Streams plausible incoming deposits (confirmed USDT `Transfer`s whose
/// recipient satisfies `is_potential_deposit`) observed above the client's
/// cursor. GUARDIAN-LOCAL — deliberately NOT read from consensus DB, unlike
/// every other endpoint in this file: each guardian answers from its own
/// in-memory Transfer-log scan, so answers differ across peers (and are
/// empty right after a restart until the backfill catches up). Clients MUST
/// NOT use `request_current_consensus` here; they query peers individually
/// and union the responses (see
/// `fedimint-usdt-client`'s `discover_deposits`). Added at ApiVersion
/// (0, 1) — the deposit-discovery feature.
pub const TRANSFER_CANDIDATES_ENDPOINT: &str = "transfer_candidates";
```

- [ ] **Step 3: Verify + commit**

Run: `cargo check -p fedimint-usdt-common && cargo check --target wasm32-unknown-unknown -p fedimint-usdt-common`
Expected: clean.

```bash
git add modules/usdt/fedimint-usdt-common/src
git commit -m "feat(usdt-common): transfer-candidate wire types and endpoint name"
```

---

### Task 4: `get_transfer_logs` on the server EVM RPC (alloy + mock + anvil test)

**Files:**
- Modify: `modules/usdt/fedimint-usdt-server/src/rpc.rs` (sol! block at :95-158; trait at :182; `AlloyEvmRpc` impl; unit tests at bottom)
- Modify: `modules/usdt/fedimint-usdt-tests/tests/common/mock.rs`
- Modify: `modules/usdt/fedimint-usdt-tests/tests/evm_adapter.rs`

**Interfaces:**
- Produces: `pub struct TransferLog { pub block_number: u64, pub to: EvmAddress, pub value: u128 }` (in `rpc.rs`, re-exported from server lib if needed), trait method `async fn get_transfer_logs(&self, token: EvmAddress, from_block: u64, to_block: u64) -> anyhow::Result<Vec<TransferLog>>`, pure `fn transfer_logs_from_rpc(&[alloy::rpc::types::Log]) -> Vec<TransferLog>`, mock setter `MockEvmRpc::set_transfer_logs(token: EvmAddress, logs: Vec<TransferLog>)`

- [ ] **Step 1: Write the failing pure-decoder unit test** in `rpc.rs`'s test mod (model it on the existing `receipt_from_entrypoint_logs` tests there — build `alloy::rpc::types::Log` values by hand with `Transfer` topics):

```rust
#[test]
fn transfer_logs_from_rpc_decodes_to_and_value_and_skips_pending() {
    let to = alloy_primitives::Address::from([0xAB; 20]);
    let log = make_transfer_log(to, alloy_primitives::U256::from(1_500_000u64), Some(123));
    let pending = make_transfer_log(to, alloy_primitives::U256::from(1u64), None); // no block_number yet
    let decoded = transfer_logs_from_rpc(&[log, pending]);
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].block_number, 123);
    assert_eq!(decoded[0].to, EvmAddress([0xAB; 20]));
    assert_eq!(decoded[0].value, 1_500_000);
}
```

with a local `make_transfer_log(to, value, block_number)` helper that assembles the raw log (`topics = [Transfer::SIGNATURE_HASH, pad32(from), pad32(to)]`, `data = value.to_be_bytes::<32>()`).

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p fedimint-usdt-server transfer_logs_from_rpc`
Expected: FAIL to compile.

- [ ] **Step 3: Implement.** In the second `alloy::sol!` block (after `UserOperationEvent`, rpc.rs:157) add:

```rust
    /// Canonical ERC-20 `Transfer` event — the authoritative record of a
    /// token recipient on EVM (calldata scanning misses internal-call
    /// transfers such as exchange withdrawals), used by the guardian-local
    /// deposit-discovery scan.
    event Transfer(address indexed from, address indexed to, uint256 value);
```

Add the observation type + trait method (document free-tier ranges — this is the module's only multi-block `eth_getLogs`, bounded by the caller's `scan_batch_blocks`):

```rust
/// A decoded ERC-20 `Transfer` observed by
/// [`IServerEvmRpc::get_transfer_logs`]. Guardian-LOCAL observation data
/// (never consensus state): it feeds the in-memory candidate log served by
/// the `transfer_candidates` endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferLog {
    pub block_number: u64,
    pub to: EvmAddress,
    pub value: u128,
}
```

trait method (place after `get_erc20_basis_points_rate`):

```rust
    /// Every ERC-20 `Transfer` log of `token` in `from_block..=to_block`
    /// (`eth_getLogs` filtered on the contract address + Transfer topic).
    /// The ONLY multi-block `eth_getLogs` in the module: callers must keep
    /// the range within free-tier limits (see `UsdtConfigLocal::
    /// scan_batch_blocks`) and only request confirmed ranges.
    async fn get_transfer_logs(
        &self,
        token: EvmAddress,
        from_block: u64,
        to_block: u64,
    ) -> anyhow::Result<Vec<TransferLog>>;
```

`AlloyEvmRpc` impl (mirror the filter shape at rpc.rs:1089):

```rust
    async fn get_transfer_logs(
        &self,
        token: EvmAddress,
        from_block: u64,
        to_block: u64,
    ) -> anyhow::Result<Vec<TransferLog>> {
        let filter = Filter::new()
            .address(Address::from(token.0))
            .from_block(from_block)
            .to_block(to_block)
            .event_signature(Transfer::SIGNATURE_HASH);
        let logs = self
            .provider
            .get_logs(&filter)
            .await
            .with_context(|| format!("eth_getLogs Transfer scan {from_block}..={to_block}"))?;
        Ok(transfer_logs_from_rpc(&logs))
    }
```

pure decoder (mirror `receipt_from_entrypoint_logs`'s decode style):

```rust
/// Decodes raw `eth_getLogs` results into [`TransferLog`]s. Pure (no RPC),
/// unit-tested; skips logs that fail to decode as `Transfer` or lack a
/// block number (pending), and saturates `value` into `u128`.
fn transfer_logs_from_rpc(logs: &[alloy::rpc::types::Log]) -> Vec<TransferLog> {
    logs.iter()
        .filter_map(|log| {
            let block_number = log.block_number?;
            let decoded = Transfer::decode_log(&log.inner).ok()?;
            Some(TransferLog {
                block_number,
                to: EvmAddress(decoded.to.into_array()),
                value: u128::try_from(decoded.value).unwrap_or(u128::MAX),
            })
        })
        .collect()
}
```

(Adapt `decode_log`'s exact call/return shape to what `receipt_from_entrypoint_logs` at rpc.rs:1155 already does for `UserOperationEvent` — same alloy version, same pattern.)

- [ ] **Step 4: Mock.** In `mock.rs` add to `State` a `transfer_logs: BTreeMap<EvmAddress, Vec<TransferLog>>` field, a setter, and the trait impl:

```rust
    /// Scripts the Transfer logs returned by
    /// [`IServerEvmRpc::get_transfer_logs`] for `token` (filtered by the
    /// requested block range at read time).
    pub fn set_transfer_logs(&self, token: EvmAddress, logs: Vec<TransferLog>) {
        self.lock().transfer_logs.insert(token, logs);
    }
```

```rust
    async fn get_transfer_logs(
        &self,
        token: EvmAddress,
        from_block: u64,
        to_block: u64,
    ) -> anyhow::Result<Vec<TransferLog>> {
        Ok(self
            .lock()
            .transfer_logs
            .get(&token)
            .into_iter()
            .flatten()
            .filter(|l| (from_block..=to_block).contains(&l.block_number))
            .cloned()
            .collect())
    }
```

- [ ] **Step 5: Anvil adapter test** in `tests/evm_adapter.rs` (skip-if-no-anvil, mirroring the file's existing tests): deploy the test ERC-20 via the existing `common::anvil` helpers, transfer to a fixed address, then assert `AlloyEvmRpc::get_transfer_logs(usdt, 0, head)` contains a `TransferLog` with that recipient and amount, and that an unrelated token address range returns empty.

- [ ] **Step 6: Run tests**

Run: `cargo test -p fedimint-usdt-server && cargo test -p fedimint-usdt-tests --test evm_adapter`
Expected: PASS (adapter test SKIPs without anvil; run inside `nix develop` to exercise it).

- [ ] **Step 7: Commit**

```bash
git add modules/usdt/fedimint-usdt-server/src/rpc.rs modules/usdt/fedimint-usdt-tests/tests/common/mock.rs modules/usdt/fedimint-usdt-tests/tests/evm_adapter.rs
git commit -m "feat(usdt-server): Transfer-log range reads on the EVM RPC trait"
```

---

### Task 5: `CandidateLog` + candidate filtering (`scan.rs`)

**Files:**
- Create: `modules/usdt/fedimint-usdt-server/src/scan.rs`
- Modify: `modules/usdt/fedimint-usdt-server/src/lib.rs` (add `pub mod scan;` next to the other module decls)

**Interfaces:**
- Consumes: `TransferLog` (Task 4), `TransferCandidate`, `is_potential_deposit` (Tasks 1/3)
- Produces: `pub const CANDIDATE_RETENTION_BLOCKS: u64`, `pub const MAX_CANDIDATE_ENTRIES: usize`, `pub const MAX_TRANSFER_CANDIDATES_PER_RESPONSE: usize`, `pub struct CandidateLog` with `fn scanned_to(&self) -> u64`, `fn record_scan(&mut self, up_to: u64, found: Vec<TransferCandidate>)`, `fn since(&self, since_block: u64, limit: usize) -> (Vec<TransferCandidate>, u64)`, and `pub fn filter_scan_candidates(&[TransferLog], &secp256k1::PublicKey) -> Vec<TransferCandidate>`

- [ ] **Step 1: Write the failing tests** (in `scan.rs`'s own `#[cfg(test)] mod tests`):

```rust
#[test]
fn candidate_log_records_prunes_and_pages() {
    let mut log = CandidateLog::default();
    assert_eq!(log.scanned_to(), 0);
    log.record_scan(100, vec![cand(90), cand(95)]);
    log.record_scan(200, vec![cand(150)]);
    assert_eq!(log.scanned_to(), 200);
    let (page, scanned_to) = log.since(90, 10);
    assert_eq!(scanned_to, 200);
    assert_eq!(page.iter().map(|c| c.block_number).collect::<Vec<_>>(), vec![95, 150]);
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
    let flood: Vec<_> = (0..MAX_CANDIDATE_ENTRIES as u64 + 10).map(|i| cand(1000 + i)).collect();
    log.record_scan(1_000_000, flood);
    let (page, _) = log.since(0, usize::MAX);
    assert_eq!(page.len(), MAX_CANDIDATE_ENTRIES);
    assert_eq!(page[0].block_number, 1010); // oldest 10 dropped
}

#[test]
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
    assert!(!fedimint_usdt_common::is_potential_deposit(&group_pk, &non_matching));
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
```

(with tiny local helpers `cand(block)`, `tl(block, to, value)`, `test_group_pk()`.)

- [ ] **Step 2: Run to verify failure** — `cargo test -p fedimint-usdt-server scan::` — FAILs to compile.

- [ ] **Step 3: Implement `scan.rs`:**

```rust
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
```

- [ ] **Step 4: Run tests** — `cargo test -p fedimint-usdt-server scan` — PASS.

- [ ] **Step 5: Commit**

```bash
git add modules/usdt/fedimint-usdt-server/src/scan.rs modules/usdt/fedimint-usdt-server/src/lib.rs
git commit -m "feat(usdt-server): in-memory transfer-candidate log with retention and caps"
```

---

### Task 6: The scanner task + local config knob

**Files:**
- Modify: `modules/usdt/fedimint-usdt-server/src/lib.rs` (`Usdt` struct :1582, `Usdt::new` :3025, `new_for_test` :3149, new `spawn_transfer_scanner` next to `spawn_block_hash_observer` :3673)
- Modify: `modules/usdt/fedimint-usdt-server/src/config.rs` (`UsdtConfigLocal` :73, its custom `Debug` :95)
- Modify: config-gen sites the compiler flags (`trusted_dealer_gen` lib.rs:1149, `dkg.rs:313` — wherever `UsdtConfigLocal { .. }` is constructed)

**Interfaces:**
- Consumes: `CandidateLog`, `filter_scan_candidates`, constants (Task 5); `get_transfer_logs` (Task 4); existing `consensus_block_count`, `rpc_deadline`, `poll_interval_secs`
- Produces: `Usdt.transfer_candidates: Arc<Mutex<CandidateLog>>` (read by Task 7's endpoint), `UsdtConfigLocal.scan_batch_blocks: u64`

- [ ] **Step 1: Local config field.** In `UsdtConfigLocal` add (with serde default so existing guardian config JSON deserializes unchanged — this is the backwards-compatibility hinge for rolling upgrades):

```rust
    /// Blocks per `eth_getLogs` Transfer-scan request (deposit discovery).
    /// Guardian-local tuning: free public RPC tiers cap ranges anywhere
    /// from ~10 blocks to thousands; 50 is safe on the majors. Raise it on
    /// a self-hosted node to speed up cold-start backfill
    /// (`CANDIDATE_RETENTION_BLOCKS / scan_batch_blocks` requests).
    #[serde(default = "default_scan_batch_blocks")]
    pub scan_batch_blocks: u64,
```

with `pub fn default_scan_batch_blocks() -> u64 { 50 }` next to `default_evm_rpc_url()` (config.rs:116), the field added to the custom `Debug` impl, and `scan_batch_blocks: default_scan_batch_blocks()` at each `UsdtConfigLocal { .. }` construction site the compiler flags.

- [ ] **Step 2: Write the failing scan-step test.** Extract the per-tick scan advance as an associated function so it is testable without the spawned loop, and test it against `MockEvmRpc` in lib.rs's test mod (or `scan.rs`'s):

```rust
#[tokio::test]
async fn scan_step_backfills_from_retention_floor_and_advances_cursor() {
    let mock = std::sync::Arc::new(MockEvmRpc::new()); // the -tests crate's mock is not visible here; use the server test-mod's existing fake/mock rpc pattern — see this test mod's existing IServerEvmRpc test doubles
    // scripted: target = 100_000, empty log, batch = 50
    let log = Arc::new(Mutex::new(CandidateLog::default()));
    let advanced = Usdt::scan_step(&(mock.clone() as DynServerEvmRpc), &log, /*target=*/ 100_000, /*usdt*/ token, &group_pk, /*batch=*/ 50).await;
    assert!(advanced);
    // cold start: first batch begins at target - CANDIDATE_RETENTION_BLOCKS
    assert_eq!(log.lock().unwrap().scanned_to(), 100_000 - CANDIDATE_RETENTION_BLOCKS + 50);
}
```

(If the server test mod has no reusable `IServerEvmRpc` double, write a minimal inline one implementing only `get_transfer_logs` + `unimplemented!()` elsewhere, as other server unit tests in this file do for single-method needs.)

- [ ] **Step 3: Run to verify failure** — FAILs to compile (`scan_step` missing).

- [ ] **Step 4: Implement.** Add the struct field (documented like `residual_recovery_proposals`, lib.rs:1683-1695):

```rust
    /// This guardian's in-memory deposit-discovery candidate log
    /// (`scan::CandidateLog`), fed by the READ-ONLY
    /// [`Usdt::spawn_transfer_scanner`] task and served by the
    /// guardian-local `transfer_candidates` endpoint. NEVER consensus
    /// state: answers legitimately differ across guardians, and nothing in
    /// any `process_*` path reads it (sec-13 COMMIT-SAFETY).
    transfer_candidates: Arc<Mutex<scan::CandidateLog>>,
```

Wire it in `Usdt::new` (mirroring the other spawns; also add the plain `Arc::new(Mutex::new(CandidateLog::default()))` to `new_for_test` without spawning):

```rust
        let transfer_candidates = Arc::new(Mutex::new(scan::CandidateLog::default()));
        Self::spawn_transfer_scanner(
            &task_group,
            TransferScannerHandles {
                db: db.clone(),
                evm_rpc: evm_rpc.clone(),
                num_peers,
                confirmation_depth: cfg.consensus.confirmation_depth,
                usdt_contract: cfg.consensus.usdt_contract,
                group_public_key: cfg.consensus.group_public_key,
                scan_batch_blocks: cfg.private.local.scan_batch_blocks.max(1),
                transfer_candidates: transfer_candidates.clone(),
            },
        );
```

The task (handles struct mirrors `BlockHashObserverHandles`; height discipline copied from `spawn_block_hash_observer` lib.rs:3683-3731 — consensus height minus confirmation depth, `begin_transaction_nc` only):

```rust
    /// Spawns the guardian-local deposit-discovery scanner: walks confirmed
    /// block ranges (`consensus_block_count - confirmation_depth`, the same
    /// height discipline as `spawn_block_hash_observer` so every guardian
    /// converges on the same coverage) with ranged Transfer-log reads,
    /// filters by `is_potential_deposit`, and appends to the in-memory
    /// `CandidateLog`. READ-ONLY against the DB (`begin_transaction_nc`;
    /// sec-13) and restart-safe by design: state is rebuilt by re-scanning
    /// the retention window (`CANDIDATE_RETENTION_BLOCKS /
    /// scan_batch_blocks` bounded requests).
    fn spawn_transfer_scanner(task_group: &TaskGroup, handles: TransferScannerHandles) {
        let TransferScannerHandles {
            db,
            evm_rpc,
            num_peers,
            confirmation_depth,
            usdt_contract,
            group_public_key,
            scan_batch_blocks,
            transfer_candidates,
        } = handles;

        task_group.spawn_cancellable("usdt-transfer-scanner", async move {
            loop {
                let mut dbtx = db.begin_transaction_nc().await;
                let ccount = consensus_block_count(&mut dbtx.to_ref_nc(), num_peers).await;
                drop(dbtx);
                let target = ccount.saturating_sub(confirmation_depth);

                let caught_up = if target == 0 {
                    true // consensus hasn't observed the chain yet; wait
                } else {
                    !Self::scan_step(
                        &evm_rpc,
                        &transfer_candidates,
                        target,
                        usdt_contract,
                        &group_public_key,
                        scan_batch_blocks,
                    )
                    .await
                };

                // While behind (cold-start backfill / catch-up), pause only
                // briefly between batches; otherwise idle a full poll tick.
                let pause = if caught_up {
                    Duration::from_secs(poll_interval_secs())
                } else {
                    Duration::from_secs(1)
                };
                fedimint_core::runtime::sleep(pause).await;
            }
        });
    }

    /// One bounded scan advance toward `target`: reads the next
    /// `scan_batch_blocks`-sized range past the log's cursor (cold start:
    /// `target - CANDIDATE_RETENTION_BLOCKS`), filters, records. Returns
    /// whether it advanced (false = already caught up, or the RPC read
    /// failed and will be retried next tick). Extracted from the spawn
    /// loop so the advance/backfill/cursor logic is unit-testable.
    async fn scan_step(
        evm_rpc: &DynServerEvmRpc,
        transfer_candidates: &Arc<Mutex<scan::CandidateLog>>,
        target: u64,
        usdt_contract: fedimint_usdt_common::EvmAddress,
        group_public_key: &secp256k1::PublicKey,
        scan_batch_blocks: u64,
    ) -> bool {
        let cursor = transfer_candidates
            .lock()
            .expect("not poisoned")
            .scanned_to();
        let from = if cursor == 0 {
            target
                .saturating_sub(scan::CANDIDATE_RETENTION_BLOCKS)
                .max(1)
        } else {
            cursor.saturating_add(1)
        };
        if from > target {
            return false;
        }
        let to = from
            .saturating_add(scan_batch_blocks.saturating_sub(1))
            .min(target);
        match rpc_deadline(evm_rpc.get_transfer_logs(usdt_contract, from, to)).await {
            Ok(logs) => {
                let found = scan::filter_scan_candidates(&logs, group_public_key);
                transfer_candidates
                    .lock()
                    .expect("not poisoned")
                    .record_scan(to, found);
                true
            }
            Err(err) => {
                debug!(
                    target: "usdt",
                    err = %err.fmt_compact_anyhow(),
                    from, to,
                    "transfer-scan read failed, retrying next tick"
                );
                false
            }
        }
    }
```

- [ ] **Step 5: Run tests** — `cargo test -p fedimint-usdt-server` — PASS (including the Step 2 test).

- [ ] **Step 6: Commit**

```bash
git add modules/usdt/fedimint-usdt-server/src
git commit -m "feat(usdt-server): guardian-local transfer scanner feeding the candidate log"
```

---

### Task 7: The `transfer_candidates` endpoint + api version (0, 1)

**Files:**
- Modify: `modules/usdt/fedimint-usdt-server/src/lib.rs` (`api_endpoints` :2743, `supported_api_versions` :826)
- Modify: `modules/usdt/fedimint-usdt-tests/tests/tests.rs` (new integration test)

**Interfaces:**
- Consumes: `Usdt.transfer_candidates` (Task 6), wire types + endpoint name (Task 3), `MAX_TRANSFER_CANDIDATES_PER_RESPONSE` (Task 5), mock `set_transfer_logs` (Task 4)
- Produces: live `transfer_candidates` endpoint (consumed by Task 9's client)

- [ ] **Step 1: Write the failing integration test** in `tests.rs` (setup mirrors `deposit_becomes_claimable_usdt_ecash`'s fixtures/mock/ready boilerplate in this same file — copy its opening block verbatim):

```rust
/// The guardian scanner surfaces a predicate-matching confirmed transfer
/// through the `transfer_candidates` endpoint, and non-matching transfers
/// never appear.
#[tokio::test(flavor = "multi_thread")]
async fn transfer_scan_surfaces_ground_candidates() -> anyhow::Result<()> {
    // <fixtures + mock + await_usdt_ready setup copied from
    //  deposit_becomes_claimable_usdt_ecash>
    let usdt = /* the client's UsdtClientModule handle, as in that test */;

    // A ground (predicate-matching) address, straight from the client.
    let (_claim_keypair, account) = usdt.allocate_deposit().await?; // ground after Task 8
    // A non-matching address.
    let stray = EvmAddress([0xEE; 20]);
    assert!(!is_potential_deposit(&group_pk, &stray));

    mock.set_block_number(64);
    mock.set_transfer_logs(
        usdt_contract,
        vec![
            TransferLog { block_number: 10, to: account, value: 5_000_000 },
            TransferLog { block_number: 10, to: stray, value: 5_000_000 },
        ],
    );

    // Wait for consensus block count + the scanner to cover block 10, then
    // ask one guardian directly.
    let deadline = Duration::from_secs(60);
    let found = fedimint_core::runtime::timeout(deadline, async {
        loop {
            let resp = usdt.transfer_candidates_for_test(PeerId::from(0), 0).await;
            if let Ok(resp) = resp {
                if resp.candidates.iter().any(|c| c.to == account) {
                    assert!(resp.candidates.iter().all(|c| c.to != stray));
                    return resp;
                }
            }
            fedimint_core::runtime::sleep(Duration::from_millis(200)).await;
        }
    })
    .await?;
    assert!(found.scanned_to >= 10);
    Ok(())
}
```

(`transfer_candidates_for_test` is a thin public wrapper the client gains in Task 9; for THIS task, if implementing tasks in order, call the api-trait method added in Task 9 — or land this test in Task 9 if the executor prefers strictly compiling intermediate states. If landed here, add the one-line api-trait method from Task 9's Step 2 now and skip it there.)

- [ ] **Step 2: Implement the endpoint.** Append to `api_endpoints` (note the deviation comment — every other endpoint reads consensus DB):

```rust
            api_endpoint! {
                TRANSFER_CANDIDATES_ENDPOINT,
                ApiVersion::new(0, 1),
                async |module: &Usdt, _context, req: TransferCandidatesRequest| -> TransferCandidatesResponse {
                    // GUARDIAN-LOCAL, deliberately NOT consensus DB (unique
                    // among this module's endpoints): candidates come from
                    // this guardian's own in-memory Transfer-log scan, so
                    // answers differ across peers and clients union
                    // per-peer responses (never
                    // `request_current_consensus`). Bounded read of a
                    // size-capped buffer: no DB, no RPC, no amplification.
                    let (candidates, scanned_to) = module
                        .transfer_candidates
                        .lock()
                        .expect("not poisoned")
                        .since(req.since_block, scan::MAX_TRANSFER_CANDIDATES_PER_RESPONSE);
                    Ok(TransferCandidatesResponse { candidates, scanned_to })
                }
            },
```

- [ ] **Step 3: Advertise api (0, 1).** In `supported_api_versions` (lib.rs:833) change `&[(0, 0)]` to `&[(0, 1)]` (minor versions are additive: (0,1) serves (0,0) clients unchanged).

- [ ] **Step 4: Run** — `cargo test -p fedimint-usdt-server` then `cargo test -p fedimint-usdt-tests --test tests transfer_scan_surfaces` — PASS (the integration test needs Tasks 8-9 if it uses `allocate_deposit` grinding + the client api call; if executing strictly in order, mark it `#[ignore = "enabled in Task 9"]` here and un-ignore in Task 9's final step).

- [ ] **Step 5: Commit**

```bash
git add modules/usdt/fedimint-usdt-server/src/lib.rs modules/usdt/fedimint-usdt-tests/tests/tests.rs
git commit -m "feat(usdt-server): guardian-local transfer_candidates endpoint at api 0.1"
```

---

### Task 8: Client grinds discoverable claim keys

**Files:**
- Modify: `modules/usdt/fedimint-usdt-client/src/lib.rs` (`allocate_deposit` :498, new helper next to `claim_keypair_for_index` :435, `supported_api_versions` :1554)
- Modify: `modules/usdt/fedimint-usdt-tests/tests/tests.rs` (`client_deposit_address_matches_common_derivation`)

**Interfaces:**
- Consumes: `find_scan_tweak`, `scan_tweak_scalar`, `MAX_SCAN_GRIND_ITERATIONS`, `is_potential_deposit` (Tasks 1-2)
- Produces: `async fn ground_claim_keypair_for_index(&self, index: u64) -> anyhow::Result<(u64, Keypair, EvmAddress)>` (also used by Task 10's recovery), ground `allocate_deposit`

- [ ] **Step 1: Write the failing test** (extend `client_deposit_address_matches_common_derivation` in `tests.rs`, or add alongside it):

```rust
#[tokio::test(flavor = "multi_thread")]
async fn allocated_deposit_addresses_satisfy_scan_predicate() -> anyhow::Result<()> {
    // <fixtures + ready setup as in client_deposit_address_matches_common_derivation>
    let (claim_keypair, account) = usdt.allocate_deposit().await?;
    let cfg = usdt.config();
    // Discoverable...
    assert!(is_potential_deposit(&cfg.group_public_key, &account));
    // ...and still exactly the common derivation for the (tweaked) pk.
    assert_eq!(
        account,
        fedimint_usdt_common::config::derive_deposit_account(cfg, &claim_keypair.public_key())
    );
    Ok(())
}
```

- [ ] **Step 2: Run to verify failure** — the predicate assert fails (~65535/65536) with untweaked allocation.

- [ ] **Step 3: Implement.** Add the yielding grind helper (chunked so a wasm/mobile client stays responsive — walletv2's `next_valid_index` batching pattern):

```rust
    /// Chunk size between executor yields while grinding a scan tweak.
    const SCAN_GRIND_CHUNK: u64 = 256;

    /// The DISCOVERABLE claim keypair for seed index `index`: the base
    /// derived key plus the smallest additive tweak whose deposit address
    /// satisfies `is_potential_deposit` (deposit discovery; see the
    /// 2026-09-06 design spec). Deterministic from the seed — recovery
    /// re-runs the identical grind — and cheap (~2^16 point-adds +
    /// keccaks, sub-second), chunked with yields for wasm.
    async fn ground_claim_keypair_for_index(
        &self,
        index: u64,
    ) -> anyhow::Result<(u64, Keypair, EvmAddress)> {
        let base = self.claim_keypair_for_index(index);
        let base_pk = base.public_key();
        let cfg = &self.cfg;
        let mut start = 0u64;
        while start < MAX_SCAN_GRIND_ITERATIONS {
            let end = start.saturating_add(Self::SCAN_GRIND_CHUNK);
            if let Some((tweak, pk, account)) = find_scan_tweak(
                &cfg.group_public_key,
                cfg.account_factory,
                cfg.simple_account_impl,
                &base_pk,
                start,
                end,
            )? {
                let sk = if tweak == 0 {
                    base.secret_key()
                } else {
                    base.secret_key()
                        .add_tweak(&scan_tweak_scalar(tweak))
                        .context("claim-key tweak")?
                };
                let keypair = Keypair::from_secret_key(SECP256K1, &sk);
                debug_assert_eq!(keypair.public_key(), pk);
                return Ok((tweak, keypair, account));
            }
            start = end;
            // Yield between chunks (wasm responsiveness).
            fedimint_core::runtime::sleep(Duration::from_millis(0)).await;
        }
        bail!("no scan tweak within MAX_SCAN_GRIND_ITERATIONS; statistically unreachable")
    }
```

In `allocate_deposit`'s autocommit closure (lib.rs:531-546), replace

```rust
                        let claim_keypair = self.claim_keypair_for_index(index);
                        let account = self.deposit_address(&claim_keypair.public_key());
```

with

```rust
                        // Ground (discoverable) key: base index key + scan
                        // tweak. `ClaimKeyKey` stores the FINAL tweaked
                        // keypair, so the claim/sign path is unchanged.
                        // Re-ground on an autocommit retry: rare, and the
                        // grind is deterministic so retries are identical.
                        let (_tweak, claim_keypair, account) =
                            self.ground_claim_keypair_for_index(index).await?;
```

- [ ] **Step 4: SUPERSEDED — client stays at api (0, 0).** Originally: bump `supported_api_versions` (lib.rs:1554-1557) from `ApiVersion { major: 0, minor: 0 }` to `ApiVersion { major: 0, minor: 1 }`. Code review found this would EXCLUDE not-yet-upgraded (0, 0) guardians from module api-version discovery and disable the whole client module against a federation where no guardian has upgraded (`discover_common_module_api_version` in `fedimint-client-module`). The `transfer_candidates` call is made via raw, un-gated per-peer requests instead, so the client keeps declaring (0, 0); see the reverted comment left in place at lib.rs:1554.

- [ ] **Step 5: Run** — `cargo test -p fedimint-usdt-tests --test tests allocated_deposit`, plus `cargo test -p fedimint-usdt-tests --test tests deposit_becomes_claimable` (the full claim pipeline must be untouched by grinding — `ClaimKeyKey` carries the final keypair either way), plus the wasm check for `-client`.
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add modules/usdt/fedimint-usdt-client/src/lib.rs modules/usdt/fedimint-usdt-tests/tests/tests.rs
git commit -m "feat(usdt-client): grind discoverable claim keys in allocate_deposit"
```

---

### Task 9: Client discovery — api call, cursor, union, claim wrapper, CLI

**Files:**
- Modify: `modules/usdt/fedimint-usdt-client/src/api.rs`
- Modify: `modules/usdt/fedimint-usdt-client/src/db.rs`
- Modify: `modules/usdt/fedimint-usdt-client/src/lib.rs`
- Modify: `modules/usdt/fedimint-usdt-client/src/cli.rs`

**Interfaces:**
- Consumes: `TransferCandidatesRequest/Response`, `TRANSFER_CANDIDATES_ENDPOINT` (Task 3), server endpoint (Task 7), `ClaimKeyKey`
- Produces: `UsdtFederationApi::transfer_candidates(peer, since_block)`, `ScanCursorKey` (client DB 0x06), `pub fn safe_scan_cursor(&[u64], NumPeers) -> Option<u64>`, `pub async fn discover_deposits(&self) -> anyhow::Result<DiscoverySummary>`, `pub async fn submit_deposit_proof_for_account(...)`, `pub async fn discover_and_claim_deposits(...)`, CLI `discover-deposits [--claim]`

- [ ] **Step 1: Write the failing unit test for the cursor rule** (client lib.rs test mod):

```rust
#[test]
fn safe_scan_cursor_takes_max_evil_plus_one_th_highest() {
    let n4 = NumPeers::from(4); // threshold 3, max_evil 1
    // One lying/fast guardian claiming 1000 must not drag the cursor up:
    assert_eq!(safe_scan_cursor(&[1000, 90, 80, 70], n4), Some(90));
    // Fewer than max_evil+1 responses -> no safe cursor.
    assert_eq!(safe_scan_cursor(&[1000], n4), None);
    assert_eq!(safe_scan_cursor(&[], n4), None);
}
```

- [ ] **Step 2: Run to verify failure**, then implement, in order:

(a) `api.rs` — trait method + impl (single-peer pattern of `pool_state`, api.rs:137-145):

```rust
    /// Streams `peer`'s guardian-LOCAL view of plausible incoming deposits
    /// above `since_block` (deposit discovery). Unlike every other read in
    /// this trait, answers legitimately DIFFER across peers (each guardian
    /// scans independently) — callers union responses from several peers
    /// and advance their cursor with `safe_scan_cursor`.
    async fn transfer_candidates(
        &self,
        peer: PeerId,
        since_block: u64,
    ) -> FederationResult<TransferCandidatesResponse>;
```

```rust
    async fn transfer_candidates(
        &self,
        peer: PeerId,
        since_block: u64,
    ) -> FederationResult<TransferCandidatesResponse> {
        self.request_single_peer(
            TRANSFER_CANDIDATES_ENDPOINT.to_string(),
            ApiRequestErased::new(TransferCandidatesRequest { since_block }),
            peer,
        )
        .await
        .map_err(|e| {
            FederationError::new_one_peer(peer, TRANSFER_CANDIDATES_ENDPOINT, since_block, e)
        })
    }
```

(b) `db.rs` — new prefix (doc style of the file's other singletons):

```rust
    /// Singleton cursor: the highest block height the deposit-discovery
    /// scan (`crate::UsdtClientModule::discover_deposits`) has safely
    /// consumed candidates up to (see `safe_scan_cursor`).
    ScanCursor = 0x06,
```

```rust
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct ScanCursorKey;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct ScanCursorPrefixAll;

impl_db_record!(
    key = ScanCursorKey,
    value = u64,
    db_prefix = DbKeyPrefix::ScanCursor,
);

impl_db_lookup!(key = ScanCursorKey, query_prefix = ScanCursorPrefixAll);
```

Plus a `ScanCursor` arm in the client's `dump_database` (lib.rs:1480-1546).

(c) `lib.rs` — cursor rule + discovery:

```rust
/// The cursor a client may safely advance to after a discovery round:
/// the `(max_evil + 1)`-th highest `scanned_to` among responding
/// guardians, so at least one HONEST guardian has covered (and served us
/// its candidates for) every block up to it. `None` when too few peers
/// answered to clear that bar (keep the old cursor; candidates already
/// unioned are still reported).
#[must_use]
pub fn safe_scan_cursor(scanned_tos: &[u64], num_peers: NumPeers) -> Option<u64> {
    let mut sorted = scanned_tos.to_vec();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    sorted.get(num_peers.max_evil()).copied()
}

/// One discovered candidate matching a claim key this client holds.
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredDeposit {
    pub account: EvmAddress,
    pub claim_pk: secp256k1::PublicKey,
    pub block_number: u64,
    pub value: UsdtAmount,
}

/// Result of one [`UsdtClientModule::discover_deposits`] round.
#[derive(Debug, Clone, Serialize)]
pub struct DiscoverySummary {
    /// Candidates whose `to` matched a stored `ClaimKeyKey` — run the
    /// claim flow for these (`submit_deposit_proof_for_account`).
    pub matches: Vec<DiscoveredDeposit>,
    /// The (possibly advanced) persisted cursor after this round.
    pub cursor: u64,
    pub peers_answering: usize,
}
```

```rust
    /// One battery-cheap discovery round (mobile: call on app-foreground
    /// instead of polling any EVM RPC): queries every guardian's
    /// `transfer_candidates` stream above the persisted cursor, unions the
    /// responses, matches them against this client's stored claim keys,
    /// and advances the cursor by the `safe_scan_cursor` rule. Read-only
    /// apart from the cursor: claiming is the caller's (or
    /// [`Self::discover_and_claim_deposits`]'s) separate step. Guardians
    /// that fail (or predate api 0.1, during a rolling upgrade) are
    /// skipped; candidates above the safe cursor are simply re-served next
    /// round (matching is idempotent).
    pub async fn discover_deposits(&self) -> anyhow::Result<DiscoverySummary> {
        let since = {
            let mut dbtx = self.db.begin_transaction_nc().await;
            dbtx.get_value(&ScanCursorKey).await.unwrap_or(0)
        };
        let peers = self.all_peers();
        let num_peers = NumPeers::from(peers.len());
        let mut responses = Vec::new();
        for peer in peers {
            match self.module_api.transfer_candidates(peer, since).await {
                Ok(resp) => responses.push(resp),
                Err(err) => {
                    debug!(target: "usdt", %peer, err = %err, "transfer_candidates peer skipped");
                }
            }
        }

        let scanned: Vec<u64> = responses.iter().map(|r| r.scanned_to).collect();
        let cursor = safe_scan_cursor(&scanned, num_peers)
            .unwrap_or(since)
            .max(since);

        let mut seen = BTreeSet::new();
        let mut matches = Vec::new();
        let mut dbtx = self.db.begin_transaction_nc().await;
        for c in responses.iter().flat_map(|r| &r.candidates) {
            if !seen.insert((c.block_number, c.to, c.value)) {
                continue;
            }
            if let Some(keypair) = dbtx.get_value(&ClaimKeyKey(c.to)).await {
                matches.push(DiscoveredDeposit {
                    account: c.to,
                    claim_pk: keypair.public_key(),
                    block_number: c.block_number,
                    value: c.value,
                });
            }
        }
        drop(dbtx);

        if cursor > since {
            let mut dbtx = self.db.begin_transaction().await;
            dbtx.insert_entry(&ScanCursorKey, &cursor).await;
            dbtx.commit_tx().await;
        }

        Ok(DiscoverySummary {
            matches,
            cursor,
            peers_answering: responses.len(),
        })
    }
```

(d) Refactor `submit_deposit_proof` (lib.rs:854-884): extract everything after the keypair derivation into `submit_deposit_proof_with_keypair(claim_keypair, evm_rpc_url, max_deposit_fee, accept_high_fee)`; have `submit_deposit_proof(index, ...)` derive-and-delegate, and add:

```rust
    /// [`Self::submit_deposit_proof`] addressed by ACCOUNT (the form a
    /// discovery match yields) instead of seed index: looks up the stored
    /// claim key for `account` and runs the identical proof-fetch + submit
    /// flow. Errors if this client holds no claim key for `account`.
    pub async fn submit_deposit_proof_for_account(
        &self,
        account: EvmAddress,
        evm_rpc_url: Option<String>,
        max_deposit_fee: Option<UsdtAmount>,
        accept_high_fee: bool,
    ) -> anyhow::Result<OperationId> {
        let claim_keypair = {
            let mut dbtx = self.db.begin_transaction_nc().await;
            dbtx.get_value(&ClaimKeyKey(account))
                .await
                .with_context(|| format!("no claim key stored for {account}"))?
        };
        self.submit_deposit_proof_with_keypair(
            claim_keypair,
            evm_rpc_url,
            max_deposit_fee,
            accept_high_fee,
        )
        .await
    }

    /// Convenience: one discovery round, then a claim attempt per match.
    /// Per-match failures (e.g. already claimed -> stale delta, or fee cap
    /// exceeded) are reported, not fatal — a re-served candidate whose
    /// deposit was already credited is expected noise.
    pub async fn discover_and_claim_deposits(
        &self,
        evm_rpc_url: Option<String>,
        max_deposit_fee: Option<UsdtAmount>,
        accept_high_fee: bool,
    ) -> anyhow::Result<Vec<(DiscoveredDeposit, Result<OperationId, String>)>> {
        let summary = self.discover_deposits().await?;
        let mut out = Vec::new();
        for d in summary.matches {
            let res = self
                .submit_deposit_proof_for_account(
                    d.account,
                    evm_rpc_url.clone(),
                    max_deposit_fee,
                    accept_high_fee,
                )
                .await
                .map_err(|e| e.to_string());
            out.push((d, res));
        }
        Ok(out)
    }
```

(e) `cli.rs` — new subcommand (json-printing style of the existing handlers):

```rust
    /// Queries the guardians' deposit-discovery stream for transfers to
    /// this client's addresses; with `--claim`, immediately runs the
    /// deposit-proof claim flow for each match.
    DiscoverDeposits {
        #[clap(long, default_value_t = false)]
        claim: bool,
        #[clap(long)]
        evm_rpc_url: Option<String>,
        #[clap(long)]
        max_deposit_fee: Option<u64>,
        #[clap(long, default_value_t = false)]
        accept_high_fee: bool,
    },
```

- [ ] **Step 3: Run** — `cargo test -p fedimint-usdt-client && cargo test -p fedimint-usdt-tests --test tests` (un-ignore Task 7's `transfer_scan_surfaces_ground_candidates` now if it was parked), wasm check for `-client`.
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add modules/usdt/fedimint-usdt-client/src
git commit -m "feat(usdt-client): deposit discovery via guardian candidate streams"
```

---

### Task 10: Recovery over ground + legacy keys

**Files:**
- Modify: `modules/usdt/fedimint-usdt-client/src/lib.rs` (`recover_deposits_scan` :624-717 and its `FakeRecoveryApi` tests)

**Interfaces:**
- Consumes: `ground_claim_keypair_for_index`-equivalent grinding (via `find_scan_tweak` — the static scan fn can't use `&self`; pass the needed `UsdtClientConfig` through, mirroring how `module_root_secret` is passed)
- Produces: `recover_deposits` that finds both pre-feature (untweaked) and ground deposits

- [ ] **Step 1: Write the failing test** against the existing `FakeRecoveryApi` in the client test mod: seed the fake with a credited deposit at the GROUND pk of index 0 (computed in the test via `find_scan_tweak` from the same synthetic root secret + config the mod's other recovery tests use) and a credited deposit at the LEGACY (untweaked) pk of index 1; assert `recover_deposits_scan` recovers both, persists both `ClaimKeyKey`s, and advances `NextDepositIndexKey` to 2.

- [ ] **Step 2: Run to verify failure** — the ground-index deposit is missed by the current legacy-only walk.

- [ ] **Step 3: Implement.** `recover_deposits_scan` gains a `cfg: &UsdtClientConfig` parameter (threaded from `recover_deposits`). Inside the loop, replace the single-key probe with a two-key probe per index:

```rust
            let base_keypair = Self::claim_keypair_static(module_root_secret, index);
            // Probe BOTH forms at this index: the ground key (all
            // allocations since deposit discovery) and the legacy
            // untweaked key (allocations that predate it). When the ground
            // tweak is 0 the two coincide — probe once.
            let ground = Self::ground_claim_keypair_static(cfg, &base_keypair).await?;
            let mut probes: Vec<Keypair> = vec![ground.1];
            if ground.0 != 0 {
                probes.push(base_keypair);
            }
            let mut index_hit = false;
            for claim_keypair in probes {
                let claim_pk = claim_keypair.public_key();
                let status = api.deposit_status(claim_pk).await?;
                // <existing credited/check_uncredited handling, verbatim,
                //  operating on `claim_keypair`/`status`; set
                //  `index_hit = true` on the credited branch>
            }
            if index_hit {
                highest_used_index = Some(index);
                consecutive_misses = 0;
            } else {
                consecutive_misses += 1;
            }
```

where `ground_claim_keypair_static(cfg, base) -> anyhow::Result<(u64, Keypair, EvmAddress)>` is the static twin of Task 8's helper (extract the shared body; Task 8's `&self` method becomes a thin wrapper over it, exactly like `claim_keypair_for_index` / `claim_keypair_static`).

- [ ] **Step 4: Run** — `cargo test -p fedimint-usdt-client recover` — PASS, and the existing recovery tests still pass (legacy probes preserved). Run the hermetic recovery integration test too: `cargo test -p fedimint-usdt-tests --test recovery_e2e`.

- [ ] **Step 5: Commit**

```bash
git add modules/usdt/fedimint-usdt-client/src/lib.rs
git commit -m "feat(usdt-client): seed recovery re-grinds ground claim keys (legacy keys still probed)"
```

---

### Task 11: End-to-end + backwards-compat tests, SECURITY.md, final gates

**Files:**
- Modify: `modules/usdt/fedimint-usdt-tests/tests/tests.rs`
- Modify: `modules/usdt/fedimint-usdt-common/SECURITY.md`

- [ ] **Step 1: End-to-end hermetic test** (the acceptance test for the whole feature):

```rust
/// Full no-poll deposit flow: allocate (ground) -> on-chain transfer
/// appears in the guardians' scan -> client DISCOVERS it via the candidate
/// stream (no client-side EVM polling) -> claims via the unchanged proof
/// path -> e-cash minted.
#[tokio::test(flavor = "multi_thread")]
async fn deposit_is_discovered_via_scan_and_claimed() -> anyhow::Result<()> {
    // <fixtures + mock + ready setup as in deposit_becomes_claimable_usdt_ecash>
    let (claim_keypair, account) = usdt.allocate_deposit().await?;
    let deposit = UsdtAmount(25_000_000);
    mock.set_block_number(64);
    mock.set_transfer_logs(
        usdt_contract,
        vec![TransferLog { block_number: 10, to: account, value: u128::from(deposit.0) }],
    );

    // Discovery: poll discover_deposits until the candidate lands.
    let discovered = fedimint_core::runtime::timeout(Duration::from_secs(60), async {
        loop {
            let summary = usdt.discover_deposits().await.expect("discover ok");
            if let Some(d) = summary.matches.iter().find(|d| d.account == account) {
                return d.clone();
            }
            fedimint_core::runtime::sleep(Duration::from_millis(200)).await;
        }
    })
    .await?;
    assert_eq!(discovered.value, deposit);
    assert_eq!(discovered.claim_pk, claim_keypair.public_key());

    // Claim: unchanged proof path (hermetic synthetic-proof harness).
    credit_deposit_via_proof(&usdt, &mock, usdt_contract, &claim_keypair, account, deposit, TIMEOUT).await?;
    // <assert claimable/minted as deposit_becomes_claimable_usdt_ecash does>
    Ok(())
}
```

- [ ] **Step 2: Backwards-compat test** — legacy (un-ground) addresses keep working and stay out of the stream:

```rust
/// Pre-discovery deposits are untouched: an UNTWEAKED claim key's address
/// (predicate almost surely fails) never appears in the candidate stream,
/// but its proof-path claim still credits exactly as before.
#[tokio::test(flavor = "multi_thread")]
async fn legacy_untweaked_deposit_still_claims_and_stays_out_of_stream() -> anyhow::Result<()> {
    // <fixtures + mock + ready setup as above>
    // A fixed keypair standing in for a pre-feature allocation.
    let legacy = Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&[7u8; 32])?);
    let account = fedimint_usdt_common::config::derive_deposit_account(usdt.config(), &legacy.public_key());
    assert!(
        !is_potential_deposit(&usdt.config().group_public_key, &account),
        "chosen fixed key must not accidentally satisfy the predicate (1/2^16); pick another fixed secret if it does"
    );
    mock.set_block_number(64);
    mock.set_transfer_logs(
        usdt_contract,
        vec![TransferLog { block_number: 10, to: account, value: 9_000_000 }],
    );
    // Stream never lists it (give the scanner time to pass block 10)...
    // <poll a guardian's transfer_candidates until scanned_to >= 10, assert
    //  candidates never contain `account`>
    // ...but the proof path still credits it.
    credit_deposit_via_proof(&usdt, &mock, usdt_contract, &legacy, account, UsdtAmount(9_000_000), TIMEOUT).await?;
    Ok(())
}
```

- [ ] **Step 3: SECURITY.md.** Add a "Deposit discovery (Transfer-log scan)" section stating: the predicate and its 16-bit difficulty; the privacy trade-off (public tagging of probable deposit addresses given `group_public_key`); DoS economics (guardian work is O(blocks); stream inflation costs one on-chain transfer + 2^16 grind per entry; endpoint is a bounded read of a size-capped in-memory buffer); that candidates are hints only — crediting authority remains exclusively the anchored-ring proof path; that the guardian-local endpoint deliberately breaks the "any guardian answers identically" pattern and why clients union with `safe_scan_cursor`; and that the documented high-water-mark limitation means a re-deposit to a swept address can appear in the stream yet remain uncreditable (accepted). While in there, fix the stale references to the removed `credit_deposit`/`scan_pending_deposits` balance-poll flow (crediting is proof-driven).

- [ ] **Step 4: Full gates**

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo check --target wasm32-unknown-unknown -p fedimint-usdt-common -p fedimint-usdt-client -p fedimint-amm-common -p fedimint-amm-client
```

Expected: all green. `git diff master -- Cargo.lock` empty (no new deps ⇒ no `flake.nix` `cargoHash` refresh).

- [ ] **Step 5: Commit**

```bash
git add modules/usdt/fedimint-usdt-tests/tests/tests.rs modules/usdt/fedimint-usdt-common/SECURITY.md
git commit -m "test(usdt): end-to-end scan discovery + legacy-deposit compatibility; document discovery in SECURITY.md"
```

---

## Self-review notes

- **Spec coverage:** predicate + grind (T1-T2), wire/endpoint contract (T3, T7), guardian log scan + free-tier batching + retention/caps (T4-T6), guardian-local serving + union/cursor rule (T7, T9), unchanged claiming via `submit_deposit_proof_for_account` (T9), deterministic recovery incl. legacy keys (T10), backwards compat + privacy/DoS documentation (T11). No-consensus-bump constraint enforced globally. Complete.
- **Deliberate non-literal elements** (each anchored to a named, existing symbol the executor copies from): fixtures/mock setup blocks in integration tests ("as in `deposit_becomes_claimable_usdt_ecash`"); `make_transfer_log` raw-log assembly and the `Transfer::decode_log` call shape (mirror `receipt_from_entrypoint_logs` and its tests, rpc.rs:1155); the anvil adapter test body (mirror `tests/evm_adapter.rs`'s existing skip-if-no-anvil tests); Task 10's "existing credited/check_uncredited handling, verbatim" splice; the Step-2 scan-step test's mock handle (use the server test mod's existing `IServerEvmRpc` double pattern). Exact secp256k1 method names (`add_tweak`/`add_exp_tweak`/`Scalar::ONE`/`Keypair::from_secret_key`) and `NumPeers::{from, max_evil}` should be confirmed against the pinned crate versions at compile time — TDD ordering surfaces any drift immediately.
- **Type consistency check:** `TransferLog { block_number, to, value: u128 }` (server rpc) vs `TransferCandidate { block_number, to, value: UsdtAmount }` (wire) — conversion happens exactly once, in `filter_scan_candidates` (saturating). `scanned_to`/`since_block`/cursor are plain `u64` block heights everywhere. `ground_claim_keypair_for_index` (T8) is a wrapper over the static `ground_claim_keypair_static` introduced in T10 — when executing in order, T8 may inline the body and T10 extracts the static twin (mirroring `claim_keypair_for_index`/`claim_keypair_static`).
- **Ordering note:** Task 7's integration test exercises Task 8 (grinding) and Task 9 (client api call); the plan parks it `#[ignore]` until Task 9 to keep every intermediate commit green.
