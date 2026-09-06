# USDT Deposit Discovery: Ground Predicate + Guardian Transfer-Log Scan

**Date:** 2026-09-06
**Status:** approved (from 2026-09-06 design discussion)

## Problem

Deposit crediting is proof-driven (`UsdtInput::DepositProofV0`): the client
fetches an `eth_getProof` itself and pushes it. Nothing *discovers* deposits
for the client — a mobile client must poll public EVM RPCs to learn that its
deposit address was funded, which drains battery and leaks its addresses to
whichever RPC it polls. The previous guardian-side answer (an address
registration list + per-address `balanceOf` polling, the removed
`PendingCheck` path) was DoS-able: unauthenticated registration created
unbounded, free, perpetual per-address work for every guardian.

## Design (walletv2-style)

1. **Clients grind a discoverable claim key.** The claim key for seed index
   `i` becomes `claim_pk = base_pk(i) + t·G`, where `t` is the smallest
   tweak such that the derived CREATE2 deposit address satisfies a public
   predicate: `keccak256(SCAN_PREDICATE_DOMAIN ‖ group_public_key ‖
   address)` has `DEPOSIT_SCAN_TAG_BITS = 16` leading zero bits. One point
   add + three short keccaks per candidate ⇒ ~2^16 candidates in well under
   a second, even on mobile/wasm (chunked with yields, walletv2-style). The
   grind is deterministic from the seed, so recovery re-grinds the same
   keys. `group_public_key` is the federation-unique domain separator
   (stands in for `federation_id`, which is not plumbed into this module;
   the group key is already in both server consensus config and client
   config) — it prevents one grind from being amortized across federations.

2. **Guardians scan Transfer logs, not full blocks.** Each guardian runs a
   guardian-local background task that walks confirmed block ranges
   (`consensus_block_count − confirmation_depth`, same discipline as the
   block-hash observer) with `eth_getLogs` filtered on `(usdt_contract,
   Transfer topic)`, keeps every log whose `to` satisfies the predicate and
   whose value is nonzero, and appends it to an **in-memory** candidate log
   (retention `CANDIDATE_RETENTION_BLOCKS ≈ 7 days`, capped at
   `MAX_CANDIDATE_ENTRIES`). Logs (not blocks/receipts) because the
   recipient of an internal-call transfer is only visible in the event, and
   because logs are 1–2 orders of magnitude under free RPC tiers even for a
   large federation sharing one key.

3. **A new guardian-local endpoint streams candidates.**
   `transfer_candidates(since_block)` returns `(candidates, scanned_to)`
   from the in-memory log. It is deliberately **not** consensus-agreed
   (each guardian answers from its own scan), so the client queries peers
   individually and unions the responses; it advances its cursor only to
   the `(max_evil+1)`-th highest `scanned_to`, so at least one honest
   guardian vouches for full coverage up to the new cursor.

4. **Claiming is unchanged.** A discovered candidate whose `to` matches a
   stored `ClaimKeyKey` triggers the existing flow: one `eth_getProof`
   fetch + `submit_prebuilt_deposit_proof`. No consensus item, no input
   variant, no proof change. The client's steady state is zero EVM traffic;
   discovery is one cheap federation round per app-foreground.

## Why this is DoS-resistant

Guardian work is O(confirmed blocks), fixed by the chain — not O(attacker
registrations). Inflating the candidate stream requires grinding 2^16 per
entry **plus a real on-chain USDT transfer with real gas per entry**; the
endpoint itself is a bounded read (≤ `MAX_TRANSFER_CANDIDATES_PER_RESPONSE`
entries) of an in-memory, size-capped buffer.

## Backwards compatibility

- No `MODULE_CONSENSUS_VERSION` bump: no consensus item, no consensus
  config field, no server DB prefix, no wire input/output change.
- New endpoint at `ApiVersion (0, 1)`; server advertises api `(0,1)`,
  client requests `(0,1)`. Old clients (0,0) are untouched. New clients
  tolerate not-yet-upgraded guardians because per-peer failures are simply
  dropped from the union. Guardians can roll out one at a time.
- Old (un-ground) deposit addresses never match the predicate, so they
  never appear in the stream — but they remain claimable forever via the
  unchanged proof path, and `recover_deposits` checks both the legacy
  (untweaked) and ground key per index.
- Server DB, config-gen params, and consensus config are untouched. The
  only config change is a `#[serde(default)]` guardian-local
  `scan_batch_blocks` knob (existing config files deserialize unchanged).

## Accepted trade-offs

- **Privacy:** a predicate-matching address is publicly identifiable as
  (probably) this federation's deposit address by anyone holding the
  public `group_public_key`. Same trade-off walletv2 made for BTC; the
  alternative (registration) was DoS-able and leaked more (exact list).
- **False positives:** ~`transfers/day × 2^-16` noise entries (single
  digits per day on L1). Clients filter locally for free.
- **In-memory candidate log:** a guardian restart clears it; the scanner
  backfills the full retention window on startup (bounded: retention ÷
  batch ≈ ~1000 `eth_getLogs`). Chosen over a persisted table to respect
  the sec-13 COMMIT-SAFETY rule (guardian-local tasks never commit
  consensus DB state) without carving out an exception.
- **High-water-mark limitation survives:** a re-deposit to an already
  swept address below the old high-water mark will *appear* in the stream
  but remain uncreditable — documented, accepted (per SECURITY.md).
- **Clients offline longer than the retention window** fall back to the
  existing `recover` gap-limit walk.

## RPC budget (why free tiers hold)

Ethereum L1: ~7,200 blocks/day ÷ 50-block batches ≈ 144 `eth_getLogs`/day
per guardian; 15 guardians on one shared key ≈ ~2,200/day — one to two
orders of magnitude under Infura/Alchemy free tiers. Response volume:
all-of-USDT Transfer logs are ~100–200 MB/day/guardian worst case on L1.
Each guardian can also point `evm_rpc_url` at its own node, as today.
