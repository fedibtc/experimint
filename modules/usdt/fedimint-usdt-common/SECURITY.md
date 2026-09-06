# USDT-on-EVM module — security & trust model

Operator-facing summary of what this module trusts, what it deliberately
does **not** protect against, and what an operator/integrator must do about
it. This is a companion to `docs/usdt-module.md` (architecture) and
`docs/usdt-module-audit.md` (full threat model + accepted-risk register for
external auditors); this file exists so the load-bearing trust assumptions
and by-design limitations are not scattered across code comments only.
Findings referenced below (`sec-NN`) are from `security-review/`.

## Trust assumptions

### Per-guardian EVM RPC provider honesty and diversity (sec-15)

Deposit crediting and UserOp (sweep/withdrawal) settlement both ultimately
rest on answers from each guardian's configured EVM RPC endpoint: block-hash
reads (`get_block_hash`) that feed the consensus block-hash ring deposit
proofs are verified against, and `eth_getUserOperationReceipt` for UserOp
outcomes. Consensus only accepts a *threshold* of guardians reporting the
identical observation (block hash / receipt), which is the normal Fedimint
federation trust boundary — a threshold of guardians can already violate
custody/solvency in any module, by design. That baseline (threshold
collusion) is accepted, not a bug.

The **actionable** risk this module adds on top of that baseline is
operational: if a threshold of guardians happen to depend on the *same*
upstream RPC provider (or an attacker can MITM that shared path), a single
compromised/malicious provider can feed identical false answers to enough
guardians to poison the block-hash ring (letting a forged deposit proof
verify against a fabricated state root) or fake a UserOp outcome, without any
guardian misbehaving. **Operators SHOULD configure distinct, independent RPC
providers per guardian** (not all guardians on the same Alchemy/Infura
account, and ideally not the same vendor) so no single upstream party can
unilaterally forge a threshold's worth of observations.

In-code defenses already in place that narrow this surface (they reduce the
blast radius of a bad/malicious RPC answer; they do not replace provider
diversity):
- **Chain-id startup check** (`check_chain_id_at_startup` in
  `modules/fedimint-usdt-server/src/lib.rs`, added for sec-17/sec-15):
  guardian startup hard-fails if the RPC endpoint's reported `chain_id`
  definitively disagrees with the federation's configured `chain_id`; a
  transient RPC error or timeout only warns.
- **EntryPoint log cross-check** (`get_user_op_receipt` in
  `modules/fedimint-usdt-server/src/rpc.rs`): a bundler's
  `eth_getUserOperationReceipt` is treated as a hint, not authoritative —
  the guardian additionally fetches the `UserOperationEvent` log directly
  from the configured `EntryPoint` via a single-block `eth_getLogs`, and
  requires the log's indexed `userOpHash` and address to match before
  proposing a `UserOpConfirmed` outcome.
- **Confirmation depth + block-hash binding** on both deposit observations
  and UserOp receipts: observations are proposed only once the relevant
  block is `confirmation_depth` blocks old, and votes carry a block hash so
  observations from different forks cannot aggregate into a threshold.
- **HTTPS required for non-loopback RPC** (`AlloyEvmRpc::new` in
  `modules/fedimint-usdt-server/src/rpc.rs`): a plaintext `http://` endpoint
  on a non-loopback host is refused at startup unless the operator
  explicitly opts in via `FM_USDT_UNSAFE_ALLOW_HTTP=1`, closing the most
  direct MITM vector against a remote RPC.

None of the above amounts to an independent state/light-client proof of the
RPC's answer (e.g. `eth_getProof`, a Merkle/state proof) — that remains a
possible future hardening, not something this module implements today.

### Setup-leader config-gen parameters (sec-17)

During distributed config generation, the setup leader supplies
consensus-critical parameters for this module: `usdt_contract`,
`entry_point`, `account_factory`, `simple_account_impl`, `chain_id`, and
`confirmation_depth`, among others. Every guardian receives these params and
can inspect them before agreeing to DKG; a malicious or mistaken leader
could still propose unsafe values (e.g. a wrong chain id or an unsafely
shallow confirmation depth for a live chain).

Bounds validation (`fedimint_usdt_common::validate_usdt_params`, invoked
both at config-gen and again in `ServerModuleInit::validate_config` as
defense-in-depth) rejects
some unsafe configurations outright — notably a `confirmation_depth` below
the module's minimum safe production depth on any non-dev chain id, unless
the operator explicitly acknowledges the override via
`FM_USDT_UNSAFE_LOW_CONFIRMATION_DEPTH=1`. This bounds-checking narrows but
does not eliminate the leader-trust surface (contract addresses, for
example, are validated for shape but not for correctness — a leader
supplying the *wrong but well-formed* `usdt_contract` address is not
detected). **Operators should independently verify the rendered gen params
before completing DKG**, not rely solely on the bounds check.

### Broadcaster hot key

Each guardian runs a broadcaster EOA (`FM_USDT_BROADCASTER_PRIVATE_KEY` /
the configured `broadcaster_private_key`) that fronts gas and relays signed
`UserOp`s to the bundler/EntryPoint. This key is a hot key with real
operational responsibility, but it **cannot move federation funds**: all
deposit and pool accounts are `SimpleAccount`s owned by the DKG group public
key, and every `UserOp` must carry a valid threshold signature over that
group key before `EntryPoint` will execute it. Compromise of a broadcaster
key enables gas griefing (spending the guardian's ETH) or relay withholding
(refusing to submit/allowing ops to stall), not theft — any guardian's
broadcaster may submit a given op, so relay withholding by one broadcaster
does not block progress by itself. Treat it with the operational care due a
hot wallet: fund it minimally, monitor its balance, and prefer the
file-based secret fallback below over the process environment.

## By-design limitations (with operator mitigations)

### Deposit addresses are one-time-use; re-deposits to a swept address strand funds (sec-20)

Deposit crediting uses a raw-balance high-water mark: `DepositRecord.credited`
only ever increases, gated on a client-submitted, guardian-verified balance
proof's proven amount exceeding the previous credited amount
(`process_deposit_proof`, the `UsdtInput::DepositProofV0` arm of
`process_input`, in `modules/fedimint-usdt-server/src/lib.rs` — crediting is
proof-driven, not a guardian balance poll). Once a deposit has been credited
and fully swept, the account's on-chain balance returns to zero while
`credited` (and `swept`) stay at the old total. A later transfer to that same
address is invisible to the protocol unless a fresh proof proves a balance
exceeding the old high-water mark, and even then only the excess above that
mark becomes credited/sweepable — the address does not "reset."

**This is a documented, accepted limitation for this effort, not a bug
fix candidate.** Deposit addresses are intended to be used exactly once.
**Integrations and UIs MUST allocate a fresh deposit address per deposit
(the client's `allocate_deposit` already does this by default) and must
never present a previously-used deposit address to a user for a second
deposit.** There is currently no in-protocol recovery path for funds sent to
an already-swept address; recovering them requires coordinated, manual,
out-of-band guardian action outside this module. A useful (not yet
implemented) operator tool would surface a "stuck/reused address" condition
(on-chain balance > 0 while `credited == swept` for that account) so support
staff can detect and manually remediate it.

### Broadcaster fronts ETH while fees accrue in USDT; no on-chain reimbursement (sec-22)

All `UserOp`s currently run without a paymaster
(`paymaster_and_data: Vec::new()` in the sweep/withdrawal builders); the
guardian's broadcaster EOA fronts real ETH for the EntryPoint prefund and
`handleOps` gas. Deposit and withdrawal fees, in contrast, are charged and
accrue in USDT to the pool. There is no protocol-level or on-chain path that
converts pooled USDT fee revenue into ETH reimbursement for the
broadcaster.

**Operators MUST monitor broadcaster ETH balances and top them up
out-of-band.** The module's bootstrap readiness check
(`broadcaster_funded`, gated on the config-gen param
`broadcaster_min_balance_wei`, default 0.05 ETH) will report the federation
not-ready if a guardian's broadcaster balance falls below that threshold,
which gives an operational signal before the broadcaster runs dry — but it
is a readiness gate, not automatic replenishment. The dust-deposit sweep
gate (sec-02: `maybe_trigger_sweep` refuses to sweep unless the amount
credited to the user, net of the deploy+sweep gas fee, would be strictly
positive) limits how much of this ETH can be drained by spam deposits that
are never claimed, but it does not address the underlying economics gap for
legitimate traffic.

## Deposit discovery (Transfer-log scan)

Deposits no longer require a client to poll an EVM RPC for its own balance.
Instead, `allocate_deposit` grinds a claim-key tweak until the derived
account satisfies [`is_potential_deposit`] (`keccak256(SCAN_PREDICATE_DOMAIN
‖ group_public_key ‖ account)` has [`DEPOSIT_SCAN_TAG_BITS`] = 16 leading
zero bits — a sub-second client-side grind, capped at
`MAX_SCAN_GRIND_ITERATIONS` = 2^22 tries, statistically unreachable at
16 bits). Each guardian independently scans confirmed USDT `Transfer` logs,
keeps the ones whose `to` satisfies the same predicate in a bounded
in-memory `CandidateLog`, and serves them over the guardian-local
`transfer_candidates` endpoint; the client unions several guardians'
responses and matches `to` against its own stored claim keys
(`UsdtClientModule::discover_deposits`).

**Wire compatibility (no consensus bump).** `transfer_candidates` is called
via `request_single_peer`, which is not gated on module API versions, so
this ships without bumping `UsdtClientInit::supported_api_versions` (it
deliberately stays pinned at `(0, 0)`). A client built against this feature
works unmodified against an all-old (zero-upgraded) federation: the module
still loads and every other endpoint behaves as before, `discover_deposits`
just returns no candidates (each peer's request errors cleanly and is
skipped) until at least one guardian upgrades. Deposits remain fully
claimable via the proof path throughout any rolling upgrade.

**Privacy trade-off.** The predicate is public: anyone who knows a
federation's `group_public_key` (itself served over an unauthenticated
diagnostic endpoint) can evaluate `is_potential_deposit` against arbitrary
addresses and tag which ones are *probably* deposit accounts of that
federation, independent of whether they ever transact with it. This is an
accepted trade-off for no-poll discovery, not a bug: it does not reveal
*who* owns a tagged address, *whether* it has ever received funds, or *how
much* — only that an address's tweak happens to satisfy a public,
federation-wide predicate. Operators who need deposit-address unlinkability
from federation identity should not treat this predicate match as
confidential.

**DoS economics.** Guardian work is `O(blocks)`, not `O(candidates)`: the
scanner walks confirmed block ranges once regardless of how many transfers
match. Inflating the candidate stream costs an attacker one real on-chain
USDT transfer (visible, gas-costed) plus a `2^16`-try grind per planted
entry — there is no way to add candidates without both. The guardian-local
log is a size- and age-capped ring buffer
(`CANDIDATE_RETENTION_BLOCKS` = 50,400 blocks ≈ 7 days, hard-capped at
`MAX_CANDIDATE_ENTRIES` = 4,096 entries, oldest evicted first), and the
`transfer_candidates` endpoint is a bounded read of it
(`MAX_TRANSFER_CANDIDATES_PER_RESPONSE` = 512 per response, paged by
`since_block`) — an attacker cannot grow guardian memory or per-request
work without bound, only churn through the fixed cap at real on-chain cost.

**Candidates are hints, never authority.** Everything the scan produces —
the in-memory log, the `transfer_candidates` response, `discover_deposits`'s
`DiscoveredDeposit` matches — is guardian-LOCAL observation data, never
consensus DB, and never read by any `process_*` consensus path. A false or
adversarial candidate (a predicate collision, or a transfer engineered to
match) simply fails to match a real client claim key, or — if it does match
— still requires the client to independently produce a valid, anchored
[`DepositProof`] to actually credit anything (`process_deposit_proof`, the
`UsdtInput::DepositProofV0` arm of `process_input`). Discovery only ever
tells a client *where to look*; it can never mint a satoshi (or a
milli-USDT) by itself.

**Guardian-local, not "any guardian answers identically."** Every other
read in this module's API is a threshold-agreed consensus fact — any
single guardian's answer is authoritative because it is read from consensus
DB. `transfer_candidates` deliberately breaks that pattern: each guardian
scans independently (different node, different RPC endpoint, possibly
different progress), so two guardians can legitimately disagree, and a
single guardian could (via a compromised/lagging RPC, sec-15) omit or
delay real candidates. Clients therefore never trust one guardian: they
query several, union the `candidates` each returns, and only advance their
local scan cursor to `safe_scan_cursor` — the `(max_evil + 1)`-th highest
`scanned_to` among responding guardians — so the cursor only ever advances
past a height at least one HONEST guardian has vouched for. A guardian
withholding or lying about candidates can cause a client to see a deposit
late, never speed one up or forge one (see "candidates are hints" above).
Each per-response `scanned_to` is honest for THAT response only — a full
(`MAX_TRANSFER_CANDIDATES_PER_RESPONSE`-sized) page clamps it below the
first omitted entry's block rather than overclaiming the guardian's full
scan progress — so the client pages a truncated peer forward
(`page_peer_candidates`) before treating its mark as that peer's
contribution to `safe_scan_cursor`. Accepted residual: an attacker who
stuffs at least `MAX_TRANSFER_CANDIDATES_PER_RESPONSE` (512) REAL on-chain
predicate-matching transfers into a single block can pin every honest
guardian's per-page `scanned_to` below that block indefinitely (each
guardian's page always truncates at the same height), stalling the cursor
there until the retention cap (`CANDIDATE_RETENTION_BLOCKS`) eventually
evicts those entries — the cost is 512 real on-chain transfers (visible,
gas-costed) per block targeted, not a free griefing vector.

**Interaction with the one-time-use limitation (accepted).** Because
`DepositRecord.credited` is a high-water mark (see "Deposit addresses are
one-time-use" above), a re-deposit to an already-swept address can appear
in the candidate stream — the scan predicate only looks at `to` and
`value`, with no notion of "already spent" — yet remain uncreditable
because the fresh proof's proven balance never exceeds the old high-water
mark. The stream is a hint, not a promise of creditability; this is the
same accepted limitation as the underlying high-water mark, not a new one.

**Dedup is coarse (accepted).** `discover_deposits` dedups unioned
candidates by `(block_number, to, value)`, so two distinct on-chain
transfers of the identical amount to the identical address in the identical
block collapse into one `DiscoveredDeposit` entry. This is harmless:
crediting is balance-delta-based via the proof path (`process_deposit_proof`
credits whatever the proof proves the *current* balance to be, not "one
unit per candidate"), so a client that only sees one hint for two identical
transfers still ends up claiming the full on-chain balance once it submits
a proof.

## Secrets handling

`FM_USDT_BROADCASTER_PRIVATE_KEY` and `FM_USDT_EVM_RPC_API_KEY` are secrets.
Passing secrets as plain environment variables makes them visible to other
same-user processes via `/proc/<pid>/environ`; both now support a
file-based fallback, mirroring the repo's existing `_FILE` convention (see
`fedimintd`'s bitcoind password handling):

- `FM_USDT_BROADCASTER_PRIVATE_KEY_FILE` — path to a file whose (trimmed)
  contents are the broadcaster private key.
- `FM_USDT_EVM_RPC_API_KEY_FILE` — path to a file whose (trimmed) contents
  are the RPC API key.

Resolution order (`env_secret_or_file` in `fedimint-core/src/envs.rs`): the
inline `_ENV` var wins if set to a non-empty value; otherwise the `_FILE`
var is read (trimmed) if set; otherwise there is no override and the
module falls back to whatever is configured elsewhere (e.g.
`broadcaster_private_key` in the encrypted private config, or no API key
appended to the RPC URL). Only *which* source supplied the secret is
logged, at `debug`; the secret value itself is never logged.

Independent of the above, RPC URLs and any embedded API key are redacted in
`Debug` output, logs, and error messages (`redact_rpc_url` /
`impl Debug for AlloyEvmRpc` in `modules/fedimint-usdt-server/src/rpc.rs`,
sec-18), and a remote (non-loopback) `http://` RPC endpoint is refused at
startup unless explicitly overridden (see the RPC provider section above).

## Client claim/refund keys (misc #9)

The client stores deposit claim keypairs and withdrawal refund keypairs in
its local database in plaintext (`ClaimKeyKey` / `RefundKeyKey` in
`modules/fedimint-usdt-client/src/db.rs`, values are raw `Keypair`s — the
client database has no separate secrets vault for these). This is
acceptable because both key families are **deterministic functions of the
client's module root secret and a seed-derivation index** (see
`claim_keypair_for_index` / the withdrawal refund keypair derivation in
`modules/fedimint-usdt-client/src/lib.rs`): they are recoverable from the
seed alone (plus, for uncredited deposits, a fresh federation scan — see
`recover_deposits`), not solely from the on-disk DB. Integrators should
still be aware that **the client DB is not a secret-free artifact**: anyone
with read access to it can reconstruct spending authority over any
deposit/refund account it has recorded, exactly as they could with the seed
itself. Treat client DB backups with the same care as the seed.
