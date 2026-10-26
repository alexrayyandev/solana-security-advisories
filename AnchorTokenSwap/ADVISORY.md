# Security Audit Advisory

**Program:** `swap_example` (AMM / Swap)
**Declared Program ID:** `UPxp2moQFWsGqfFd3ynqG2W9mj9CTjH68NN2bYUAqV1`
**Auditor:** Alex Rayyan (bansoslab2026@tutamail.com)
**Scope Provided:** `lib.rs` only (module root / entry point)

---

## ⚠️ Scope Limitation Notice

The submitted artifact contains **only** the program entry point (`lib.rs`). The actual instruction handlers, account validation structs (`Context<...>`), PDA derivation logic, state definitions (`state.rs`), constants, and error enums are **not included**. A full vulnerability assessment requires review of:

- `instructions/create_amm.rs`
- `instructions/create_pool.rs`
- `instructions/deposit_liquidity.rs`
- `instructions/withdraw_liquidity.rs`
- `instructions/swap_exact_tokens_for_tokens.rs`
- `state.rs`, `constants.rs`, `errors.rs`

**The findings below are derived from the AMM/swap architecture implied by the instruction signatures and from common Solana/Anchor vulnerability classes applicable to this program type. Each item maps to a concrete code location that must be verified against the (unprovided) implementation files.**

---

## Executive Summary & Severity Rating

| # | Vulnerability Class | Likely Severity | Location (inferred) |
|---|---------------------|-----------------|---------------------|
| 1 | Arbitrary CPI / Missing Program ID check on token program | CRITICAL | `deposit_liquidity`, `withdraw_liquidity`, `swap_exact_tokens_for_tokens` |
| 2 | Missing Signer check on authority / LP owner | CRITICAL | `create_amm`, `withdraw_liquidity` |
| 3 | Improper PDA derivation / bump not stored or validated | HIGH | Pool / vault PDA seeds |
| 4 | Integer overflow / precision truncation in AMM math (constant product) | HIGH | `swap_exact_tokens_for_tokens`, `withdraw_liquidity` |
| 5 | Account re-initialization / Type Cosplay via missing `init`/discriminator checks | HIGH | `create_amm`, `create_pool` |
| 6 | Closing account logic / residual lamport drain | MEDIUM | Any `close = ...` constraint or manual lamport zeroing |

**Overall Risk:** **CRITICAL** (pending full source review; AMM programs with token CPI are high-impact).

---

## Vulnerability Descriptions

### 1. Arbitrary CPI & Missing Program ID Checks (CRITICAL)

**Description:** Token transfer CPIs in `deposit_liquidity`, `withdraw_liquidity`, and `swap_exact_tokens_for_tokens` must validate that the passed `token_program` account equals `spl_token::ID` (or Token-2022 program ID). Without this, an attacker can substitute a malicious program that mimics the token interface and drains vaults.

**Exact lines/functions to inspect:**
- Any `ctx.accounts.token_program` usage.
- `CpiContext::new(ctx.accounts.token_program.to_account_info(), transfer { ... })`.

**Exploitation:** Attacker deploys a fake token program accepting the same instruction discriminators, passes it as `token_program`, and the AMM CPIs into it, transferring vault authority to the attacker.

**Recommended patch:**
```rust
// In each Accounts struct:
#[account(address = spl_token::ID @ ErrorCode::InvalidTokenProgram)]
pub token_program: AccountInfo<'info>,
```
Or use `Program<'info, Token>` which enforces the program ID automatically.

---

### 2. Missing Signer & Account Ownership Validation (CRITICAL)

**Description:** `withdraw_liquidity` and `create_amm` (if admin-gated) must enforce that the caller is a signer and is the legitimate owner of the LP position / AMM. Missing `Signer<'info>` or `has_one = authority` allows unauthorized withdrawals.

**Exact lines/functions to inspect:**
- `WithdrawLiquidity` accounts struct: `user` / `owner` field.
- `CreateAmm` accounts struct: `authority` field.

**Recommended patch:**
```rust
#[account(mut, has_one = authority @ ErrorCode::Unauthorized)]
pub pool: Account<'info, Pool>,
pub authority: Signer<'info>,
```

---

### 3. Improper PDA Derivation / Missing Bump Validation (HIGH)

**Description:** Vault accounts and pool PDAs must be derived with canonical seeds and the bump must be stored in state and re-validated on use. Using `find_program_address` at runtime without storing/checking the bump, or accepting a user-supplied bump, allows PDA collision / account substitution.

**Exact lines/functions to inspect:**
- `seeds = [b"vault", pool.key().as_ref(), mint.key().as_ref()]`, `bump` in vault init.
- Pool PDA seeds in `create_pool`.

**Recommended patch:**
```rust
#[account(
    seeds = [b"vault", pool.key().as_ref(), mint_a.key().as_ref()],
    bump = vault.bump,
)]
pub vault_a: Account<'info, TokenAccount>,
```
Store `bump: u8` in the `Pool`/`Vault` state at creation.

---

### 4. Integer Overflow / Precision Truncation (HIGH)

**Description:** Constant-product AMM math (`x * y = k`) using `u64` multiplication can overflow. Division truncation in output calculation can be exploited to drain pools via repeated small swaps (rounding attacks). `withdraw_liquidity` proportional share math must use checked arithmetic.

**Exact lines/functions to inspect:**
- `swap_exact_tokens_for_tokens`: `output = (input * reserve_out) / (reserve_in + input)` style formulas.
- `withdraw_liquidity`: `amount_a = (lp_burned * reserve_a) / total_lp`.

**Recommended patch:**
```rust
let numerator = (input_amount as u128)
    .checked_mul(reserve_out as u128)
    .ok_or(ErrorCode::Overflow)?;
let denominator = (reserve_in as u128)
    .checked_add(input_amount as u128)
    .ok_or(ErrorCode::Overflow)?;
let output = (numerator / denominator) as u64;
// Apply fee with checked math
```
Use `u128` intermediates and `checked_*` operations throughout. Consider rounding in favor of the pool (round down outputs, round up inputs).

---

### 5. Account Re-initialization / Type Cosplay (HIGH)

**Description:** `create_amm` and `create_pool` must use `init` (not `init_if_needed` without guards) and verify the account discriminator. Re-initialization allows overwriting an existing AMM/pool's authority/fee. Type cosplay: an attacker passes an account of a different type with the same layout; Anchor's discriminator check prevents this only if `Account<'info, T>` is used (not `AccountInfo`).

**Exact lines/functions to inspect:**
- `CreateAmm` / `CreatePool` accounts structs: `#[account(init, ...)]` vs `#[account(mut)]`.
- Any `AccountInfo<'info>` used where `Account<'info, T>` should be used.

**Recommended patch:**
```rust
#[account(
    init,
    payer = authority,
    space = 8 + Amm::INIT_SPACE,
    seeds = [b"amm", id.as_ref()],
    bump
)]
pub amm: Account<'info, Amm>,
```
Never use `init_if_needed` for one-time creation without an explicit "already initialized" guard.

---

### 6. Closing Account Logic & Residual Lamport Drains (MEDIUM)

**Description:** If `close = recipient` is used on pool/vault accounts, ensure no CPI or state read occurs after close in the same instruction (use-after-close). Also ensure vault token accounts are emptied before close, and that the close recipient is validated.

**Exact lines/functions to inspect:**
- Any `#[account(close = ...)]` constraints.
- Manual `**account.lamports.borrow_mut() = 0` patterns.

**Recommended patch:**
- Drain token balances to zero before close.
- Set `close = authority` (validated signer), never an arbitrary account.
- Avoid reading closed accounts later in the instruction.

---

## Exploitation Scenario (Composite)

1. Attacker calls `create_pool` with a **re-initialized** existing pool account (if `init_if_needed` misused), overwriting `authority` to themselves.
2. Attacker calls `withdraw_liquidity` passing a **fake `token_program`** (arbitrary CPI) and a non-signer `user` (missing signer check), draining vault A and vault B.
3. Residual lamports in closed pool accounts are swept by the attacker via the close recipient.

**Result:** Total loss of pool TVL.

---

## TypeScript / Anchor PoC (Sketch)

```typescript
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SwapExample } from "../target/types/swap_example";

// PoC: arbitrary token program substitution
const fakeTokenProgram = await deployFakeTokenProgram(provider);

await program.methods
  .swapExactTokensForTokens(true, new anchor.BN(1_000_000), new anchor.BN(0))
  .accounts({
    pool: poolPda,
    vaultA: vaultA,
    vaultB: vaultB,
    userTokenA: attackerTokenA,
    userTokenB: attackerTokenB,
    user: attacker.publicKey,
    tokenProgram: fakeTokenProgram.publicKey, // <-- arbitrary CPI
  })
  .signers([attacker])
  .rpc();
```

*(Full PoC requires the unprovided IDL; above demonstrates the attack vector.)*

---

## Recommended Remediation Summary

1. Use `Program<'info, Token>` (or explicit `address = spl_token::ID`) for all token program accounts.
2. Enforce `Signer<'info>` + `has_one` on every authority/owner.
3. Store and validate PDA bumps; use canonical seeds.
4. Replace all arithmetic with `u128` + `checked_*`; round in pool's favor.
5. Use `init` (not `init_if_needed`) for one-time accounts; rely on Anchor discriminators via `Account<'info, T>`.
6. Validate close recipients; drain balances before close.

---

## Author & Disclosure Details

- **Researcher:** Alex Rayyan (bansoslab2026@tutamail.com)
- **USDC (Solana):** `39YTqgacjKt1iz22SrvX4G3Ds8TUUjd9hWPPSJpdd2jZ`
- **USDC (Base/EVM):** `0xf71e0734cb53162e8c9baaf5f49841a51c945899`

**Disclosure:** Findings are provided for defensive remediation. Full confirmation requires review of the unprovided instruction/state modules. Please share `instructions/`, `state.rs`, `constants.rs`, and `errors.rs` for a complete, line-numbered audit.