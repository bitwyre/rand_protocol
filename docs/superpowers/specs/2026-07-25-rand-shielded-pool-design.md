# Rand shielded pool — implementation design

**Date:** 2026-07-25
**Status:** approved, not started
**Papers:** `whitepaper/rand_protocol.tex`, `whitepaper/security_analysis.tex`, `whitepaper/zusdt.tex`

The papers establish *what* Rand is and *why*. This document is the implementation-facing
counterpart: account layouts, instruction signatures, circuit constraints, and build order.
Where the papers state a design target, this document states what must be measured before
that target can be trusted.

---

## 1. Scope

Rand is a set of Solana programs plus an off-chain relayer daemon. It is **not** a chain,
**not** a validator client, and **not** a zkVM.

In scope for v1:

- Multi-asset shielded pool over native USD stablecoin mints and wrapped SOL
- Fixed 2-in-2-out transfer circuit, Groth16 over BN254
- Relayer market with in-circuit SHRUGG fees
- zUSDT reserve program (fully reserved, same-chain)

Explicitly out of scope:

- General sBPF proving (a zkSVM) — withdrawn, see `rand_protocol.tex` §7
- Recursive proof aggregation and any GPU proving market — dropped by decision
- Any second chain, rollup, or cross-chain bridge
- Fractional or algorithmic stablecoin mechanics — superseded by full reserving

---

## 2. Programs

| Program | Responsibility |
|---|---|
| `shielded-pool` | commitment tree, nullifier set, asset vaults, deposit/withdraw/transfer |
| `verifier` | Groth16 verification over `alt_bn128`, called via CPI from the pool |
| `zusdt-reserve` | locks native USDT, mints/burns zUSDT 1:1, sole mint authority |

The relayer daemon is off-chain and holds no privileged position: it signs as fee payer and
nothing more.

### Why the verifier is a separate program

It is the component expected to be replaced. The post-quantum migration described in
`security_analysis.tex` §Residual Quantum Attack means swapping the argument system, and
isolating it behind a CPI boundary means that swap does not touch pool state or its upgrade
authority. Keeping it inline would make a routine cryptographic migration into a migration
of the custody program.

---

## 3. Account layout

### `PoolState` (one per deployment, PDA seed `["pool"]`)

```rust
pub struct PoolState {
    pub authority: Pubkey,          // upgrade/config authority
    pub tree: Pubkey,               // concurrent Merkle tree account
    pub recent_roots: [[u8; 32]; 64], // ring buffer
    pub recent_roots_head: u8,
    pub verifying_key: Pubkey,      // Groth16 VK account
    pub deposit_cap: u64,           // per-asset cap, raised on operating history
    pub paused: bool,               // emergency halt, authority-only
}
```

`recent_roots` is the concurrency mechanism from `rand_protocol.tex` §Concurrency. A proof is
valid against any of the last 64 roots. Without this, two transfers proven against the same
root in one slot would invalidate each other, which on a chain admitting many transactions per
slot is the common case rather than the edge case.

### Commitment tree

Use `spl-account-compression`'s concurrent Merkle tree. Depth 32, buffer 64, canopy tuned to
proof size. **Do not hand-roll this** — it is audited, and it exists precisely for the
many-writers-per-slot problem.

### `AssetVault` (PDA seed `["vault", mint]`)

An SPL token account owned by the pool PDA, one per supported mint. Asset identity enters the
circuit as a `u64` index into a registry rather than a pubkey, to keep the circuit field-friendly.

### Nullifiers (PDA seed `["nf", nullifier_bytes]`)

No account data. Existence is the spent bit; creation fails if the account exists, which is the
double-spend check. Chosen over an indexed Merkle tree because:

- non-membership needs no in-circuit proof, keeping the circuit small
- distinct spends touch distinct accounts, so they never serialise against each other
- rent per spend is bounded and doubles as spam pricing

A Bloom filter is **not** acceptable: a false positive permanently freezes a legitimate note.

---

## 4. Circuit

Fixed 2-in-2-out. Public inputs, in order:

```
[ root, nf_1, nf_2, cm_3, cm_4, asset_id, fee ]
```

Note and derivations:

```
note = (value, asset_id, owner_pk, rho)
cm   = Poseidon(value, asset_id, owner_pk, rho)
nf   = Poseidon(nk, rho)
```

Constraints:

1. For each input: Merkle membership of `cm` under `root`
2. For each input: `nf` correctly derived from `nk` and `rho`
3. For each input: spend authority over `owner_pk` (ML-DSA verification in-circuit)
4. For each output: `cm` well-formed
5. `Σ inputs = Σ outputs + fee`, all with matching `asset_id`
6. Output note ciphertexts bound to their commitments

Poseidon rather than SHA-256 because it is ~2 orders of magnitude cheaper in constraints, and
rather than Pedersen because Pedersen hiding falls to a quantum adversary while commitments are
published permanently.

**One anonymity set across all assets.** `asset_id` lives inside the note. Separate pools per
asset would fragment the set, and a pool with few participants provides no privacy regardless
of proof soundness.

---

## 5. Instructions

```
shielded-pool:
  initialize(deposit_cap)
  register_asset(mint, asset_id)
  deposit(asset_id, amount, commitment)        // transparent in, shielded out
  transfer(proof, public_inputs)               // fully shielded
  withdraw(proof, public_inputs, recipient)    // shielded in, transparent out
  set_paused(bool)                             // authority only

zusdt-reserve:
  initialize()
  mint(amount)     // lock native USDT, mint zUSDT, atomic
  redeem(amount)   // burn zUSDT, release USDT, atomic
```

`transfer` is the hot path and must fit one transaction: 256-byte proof + public inputs +
accounts, inside 1232 bytes; verification + tree append + nullifier creation inside the compute
budget.

---

## 6. Relayer protocol

1. User builds the transfer locally and proves it (~2s, commodity CPU)
2. User publishes `(proof, public_inputs)` to a relayer endpoint or public queue
3. Relayer checks `fee · p_SHRUGG > cost_SOL`, then signs as fee payer and submits
4. Pool pays the relayer the in-circuit `fee` on success

The relayer cannot alter the operation — every public input is bound by the proof — so its only
choices are submit or decline. Declining leaves the operation available to every other relayer,
which is why censorship is weak here.

**The user must not sign as fee payer.** Doing so defeats the entire system; see the
deanonymisation theorem in `rand_protocol.tex` §Rationale for a Shielded Fee Token. Client
libraries should make self-paying impossible rather than merely discouraged.

---

## 7. Must be measured before committing to the design

These are the assumptions this design rests on that were **not** verified from live sources.
Treating any of them as settled would be a mistake.

| Assumption | Why it matters | If wrong |
|---|---|---|
| `alt_bn128` CU cost for a Groth16 verify | whether `transfer` fits one transaction | split verify and tree append across two txs bound by a session account |
| CU headroom after a concurrent-tree append | same | reduce canopy, or split as above |
| `spl-account-compression` depth-32 / buffer-64 limits | tree capacity and slot concurrency | lower depth, or a custom tree (expensive, needs audit) |
| Client Groth16 proving time for this constraint count | whether self-proving holds | mobile clients delegate proving, which leaks to the delegate and reopens note-discovery questions |
| Rent per nullifier account | whether the PDA approach is affordable at volume | migrate to indexed nullifier tree with in-circuit non-membership |
| ZK ElGamal Proof program status | only affects the Token-2022 comparison in the papers | correct the related-work section |

The first two are the load-bearing ones: the entire choice of Groth16 over STARKs follows from
single-transaction verification, so if that does not hold the tradeoff should be revisited
rather than patched.

---

## 8. Known-unsolved

**Note discovery.** v1 uses trial decryption with a short ciphertext prefix so non-matching
outputs are cheap to reject. This scales linearly in pool activity and will not serve light
clients. Fuzzy message detection is the intended path; a viewing-key indexer is rejected as a
protocol component because it reconstitutes the observer the system exists to defeat.

**Anonymity set size.** Privacy is weakest at launch, exactly when users are most likely to
assume otherwise. This needs to be communicated in the UI, not just in the papers.

**Boundary correlation.** Deposits and withdrawals are transparent. Correlating an entry with a
similar-magnitude exit remains the most effective attack, and no amount of proof strength
addresses it. Amount quantisation and timing separation are partial mitigations.

**Trusted setup.** Groth16 needs a per-circuit ceremony. Must be public and multi-party;
security holds if any single participant is honest. Blocks mainnet.

---

## 9. Build order

1. Circuit + local prover, with test vectors — everything downstream depends on its shape
2. Verifier program, **measure CU immediately** — §7 rows 1–2 decide whether the design holds
3. Pool program: deposit and withdraw only, transparent both ends
4. Add `transfer`; wire concurrent tree and recent-root window
5. Relayer daemon and fee settlement
6. `zusdt-reserve`
7. Wallet: note management, trial decryption, ML-KEM
8. Trusted setup ceremony
9. Audits, then mainnet with deposit caps

Step 2 is the go/no-go gate. Do not build steps 3–9 on an unmeasured assumption that
verification fits a transaction.

---

## 10. Decisions and their rationale

| Decision | Alternative rejected | Why |
|---|---|---|
| Solana programs | own L1 / L2 / rollup | native stablecoins, no bridge, no security budget, no liquidity bootstrap |
| Groth16 / BN254 | STARK on-chain | 1232-byte tx limit makes STARK upload ~200 txs per transfer |
| PQ confidentiality, classical soundness | uniform PQ | ciphertexts are irrevocably exposed; verifiers are upgradeable |
| Nullifier PDAs | indexed Merkle tree | no in-circuit non-membership, full write parallelism |
| Poseidon | Pedersen | PQ hiding, and far cheaper in-circuit |
| One multi-asset pool | pool per asset | shared anonymity set |
| Users self-prove | GPU prover network | ~2s on a laptop; a proving market would be unnecessary machinery |
| zUSDT fully reserved | fractional with absorbers | removes the death-spiral class entirely |
| Same-chain reserve | lock on Solana, mint elsewhere | full reserving degraded to `min(reserve, bridge)` otherwise |
| Single token | ATLAS + SHRUGG | nothing to stake once Solana provides consensus |

---

## 11. Accepted risks

- **Safety ceiling is Solana's.** A reorg of finalised history could reorder nullifier
  creation and permit a double-spend. No independent defence; accepted for native assets and
  no security budget.
- **Pool is a public honeypot.** Its balance is readable, so the reward for a soundness break
  is known in advance. Mitigated by deposit caps, audits, and fast invariant monitoring.
- **Quantum forgery before verifier upgrade.** Bounded by pool size, detectable by supply
  audit, fixed by upgrading. Cannot decrypt history.
- **Tether can freeze the zUSDT reserve.** Unavoidable when wrapping a centrally-administered
  asset. Mitigated by reserve sharding. zUSDT offers privacy from observers, not from the issuer.
