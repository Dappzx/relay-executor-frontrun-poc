# PoC — RelayExecutor.execute() front-run via unbound `callResolver`

**Result: PASS (mechanism reproduces exactly as described in Finding 1).**
**But: the real-world precondition — observable pending `execute()` txs — is NOT
supported by live-chain measurements. See "Likelihood: what the live chain says".**

Finding: `RelayExecutor.execute()` is permissionless and the oracle-signed
`ExecuteAndWithdrawRequest` digest does not bind `callResolver`,
`callResolverData`, or `msg.sender`. `_runCalls()` hands the entire net order
balance to the caller-supplied resolver; `_finalizeWithdraw()` only requires
`>= outAmountMinimum`. A party that observes a solver's pending `execute()` tx
can copy `(request, oracle, signature)`, substitute its own resolver, and keep
everything above `outAmountMinimum`. Source: `audit-relay.md` Finding 1.

## How to run

```bash
export PATH="$HOME/.foundry/bin:$PATH"   # forge 1.9.0; already installed here
cd ~/workspace/bounty-hunt/poc-relay-executor
forge test
```

No fork, no RPC URL, no funds, no network access needed at test time.
`forge test` alone: **3 passed, 0 failed.**

## What the test proves (exact numbers)

`test/RelayExecutorFrontRun.t.sol` deploys the **real, unmodified** Relay
contracts (`src/` is a verbatim copy of `RelayHub`, `RelayAllocator`,
`RelayExecutor`, `Utils`, `ERC20View`, `ICallResolver` from
`relay-settlement-main/smart-contracts/contracts/`, OpenZeppelin 5.3.0
(only the 20 contracts imported by the PoC, under
`lib/openzeppelin-contracts/contracts/`) and forge-std 1.9.0 vendored under
`lib/` from codeload zips — no `git clone`).

Scenario (all amounts in Hub token units; mock 1:1 DEX, see Limits):

| Quantity | Value |
|---|---|
| Order balance minted to `orderAddress` | 1000 tokenIn |
| Signed `outAmountMinimum` | 950 tokenOut |
| Honest solver output (control test) | 1000 tokenOut |
| **Attacker-extracted spread** | **50 tokenIn (5% of the order)** |
| Withdrawal actually submitted after attack | 950 tokenOut (the signed minimum) |
| Attacker roles / privileges used | none (plain EOA + its own resolver) |

`test_frontRunnerStealsSolverSpread`:
1. Oracle-signed request built for the solver's honest resolver; attacker only
   *observes* `(request, oracle, signature)` (in the test this is just the
   same variables — the point is the attacker never needs the oracle key or
   any signature of its own).
2. Attacker (unrelated EOA) calls `execute()` first with `MaliciousResolver`,
   which swaps only `outAmountMinimum` (950) and sends the remaining 50
   tokenIn to the attacker. Tx **succeeds**.
3. Asserts: attacker balance = 50; submitted withdrawal hash equals the
   keccak of the **signed** `WithdrawRequest` (amount 950, signed receiver,
   signed nonce/depository) — the attacker cannot redirect the withdrawal
   itself, only the spread; `usedRequests[digest] == true`; order drained.
4. Solver's own tx with the honest resolver then **reverts** with
   `RequestAlreadyExecuted(digest)`; solver gets 0.

`test_honestSolverKeepsFullOutputWithoutFrontRun` (control): same setup, no
front-run → 1000 tokenOut withdrawn, attacker gets 0.

`test_tamperedSignedFieldInvalidatesSignature`: changing a signed field
(`outAmountMinimum` 950 → 951) after signing reverts with
`InvalidSignature` — the signature binds the minimum, but nothing binds the
resolver or the caller.

## Limits of this PoC (read before submitting)

- **Mock DEX, not a real swap.** `MockHubSwap` swaps 1:1 inside the Hub (it
  mints tokenOut; it needs `OPERATOR_ROLE`, granted by the test owner as the
  upstream Relay test suite does). In production the attacker must source
  `outAmountMinimum` of tokenOut — e.g. by swapping only part of the funded
  input on a real Relay Chain DEX, or from its own inventory. The PoC proves
  the *executor-side* mechanics (unbound resolver, minimum-only check,
  single-use digest); it does not prove a profitable real swap exists for any
  particular token pair.
- **Local chain, no mempool.** The "front-run" is simulated by call order
  inside one test (attacker tx first, solver tx second). No pending-tx
  observation, gas bidding, or sequencer race is demonstrated.
- **No fees in the scenario** (`fees = []`). With fees, the spread would be
  `orderBalance − fees − outAmountMinimum`; fees still go to the signed
  recipients in both flows.
- **Same-chain, 1:1 tokens.** `inChainId == outChainId ==
  "ethereum-mainnet"`, distinct token ids. Cross-chain withdrawal mechanics
  after `_finalizeWithdraw` (Allocator MPC signing, Depository release) are
  out of scope — the submitted withdrawal hash is verified, not executed
  onward.

## Likelihood: what the live chain says (checked 2026-11-16, read-only)

These measurements weaken the L2 assumption in the audit; the mechanism is
real, but the opportunity to use it in production looks thin:

1. **Fixed gas price — no gas auction.** Public RPC `eth_gasPrice` returns
   `0x7` (7 wei) and `eth_maxPriorityFeePerGas` returns `0x0`; every observed
   on-chain tx also pays gasPrice 7. The audit's "resubmit with higher gas"
   does **not** apply on Relay Chain. Ordering would be arrival/sequencer
   order, so a front-runner would have to reach the sequencer first — a
   latency race, not a bidding race.
2. **No public mempool via the public RPC.** `txpool_content` returns
   `-32004 Method txpool_content not supported`; `eth_getBlockByNumber(
   "pending")` returns a synthetic block. No public statement was found in
   the Relay docs or the `relay-settlement` repo about solver submission
   paths (public vs private RPC/relayer); the docs
   (docs.relay.link/references/protocol/how-it-works) describe the solver
   submitting attestations/withdrawals on Relay Chain but say nothing about
   mempool visibility. So the "public mempool" premise is **unproven** —
   consistent with a private sequencer mempool, but that specific stack
   claim was not verified from an authoritative source.
3. **Almost no live `execute()` traffic to front-run.** Prod executor
   `0x6747c7e64b90dccc0d54f865cbd9513156adbc0c` (from
   `deployments/contracts/prod.json`) has **5 txs ever, 3 of them `execute()`**
   (selector `0x432994b7`, confirmed via `cast sig` and one tx fetched by
   hash: `0x5a3462…`, from solver EOA `0x8636752e…`, gasPrice 7), latest
   2026-09-21 — none in the ~8 weeks before this check. The other executor
   address in the repo (`0x49BC86FC…`, "Prod RelayExecutor deployment" per
   `packages/multisig-tools/scripts/generate-configure-relay-executor.ts`)
   has **2 txs ever, 0 `execute()` calls**. The chain itself is live
   (`eth_blockNumber` 0x65a1ed ≈ 6,660,589; Hub had 100 recent txs), so the
   executor path specifically is barely used — the documented withdrawal
   flow in the docs goes through `RelayAllocatorSpender`, not
   `RelayExecutor.execute()`.
4. **Conclusion for severity:** mechanism = confirmed (S2 stands); likelihood
   L2 is **not** supported by the evidence — L1 (or lower, given ~zero live
   `execute()` traffic) is the honest rating unless Relay confirms solvers
   submit `execute()` via the public mempool. A report should disclose
   points 1–3 rather than asserting a public-mempool front-run.

## Layout

- `src/` — verbatim Relay contracts (see header note above) + vendored deps
  in `lib/` (`openzeppelin-contracts` 5.3.0, `forge-std` 1.9.0).
- `test/RelayExecutorFrontRun.t.sol` — the PoC (3 tests; resolvers and mock
  DEX defined in-file, mirroring the upstream
  `test/RelayExecutor/RelayExecutor.t.sol` harness).
- `foundry.toml`, `remappings.txt` — solc 0.8.28, optimizer on.

Nothing was submitted anywhere; no mainnet transactions, no real funds.
