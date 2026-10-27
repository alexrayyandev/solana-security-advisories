# Defensive Security Audit — raydium-cp-swap (lib.rs)

**Scope:** `lib.rs` entrypoint, module declarations, program ID / admin constants, `create_amm_config` entry wrapper.  
**Methodology:** Static review of supplied source only; instruction handlers in `instructions/` were not provided, so findings below are limited to visible surface plus architectural observations.

---

## Executive Summary

| Severity | Count |
|---|---|
| CRITICAL | 0 (not demonstrable from supplied file) |
| HIGH | 1 |
| MEDIUM | 2 |
| LOW | 3 |

The visible entrypoint is structurally conventional for Anchor. The primary concrete defect is the use of `assert!` inside `create_amm_config`, which aborts the transaction with a panic rather than a typed `ProgramError`, degrading composability and obscuring failure reasons. Secondary risks are configuration/feature-flag hygiene and missing per-field fee bounds.

---

## Technical Vulnerability Analysis

### 1. Panic-Based Validation in `create_amm_config` (HIGH)

**Affected function:** `raydium_cp_swap::create_amm_config`  
**Location:** `lib.rs`, inside `#[program] mod raydium_cp_swap`.

```rust
assert!(trade_fee_rate + creator_fee_rate < FEE_RATE_DENOMINATOR_VALUE);
assert!(protocol_fee_rate <= FEE_RATE_DENOMINATOR_VALUE);
assert!(fund_fee_rate <= FEE_RATE_DENOMINATOR_VALUE);
assert!(fund_fee_rate + protocol_fee_rate <= FEE_RATE_DENOMINATOR_VALUE);
```

**Issue:** `assert!` panics on failure. In Solana/Anchor programs this surfaces as an opaque abort, prevents clean error propagation to clients, and complicates CPI callers. Validation should use `require!` with a domain error enum.

**Remediation (exact replacement):**

```rust
use crate::error::ErrorCode; // adjust path to actual error module

pub fn create_amm_config(
    ctx: Context<CreateAmmConfig>,
    index: u16,
    trade_fee_rate: u64,
    protocol_fee_rate: u64,
    fund_fee_rate: u64,
    create_pool_fee: u64,
    creator_fee_rate: u64,
) -> Result<()> {
    require!(
        trade_fee_rate.checked_add(creator_fee_rate)
            .ok_or(ErrorCode::MathOverflow)? < FEE_RATE_DENOMINATOR_VALUE,
        ErrorCode::InvalidFeeRate
    );
    require!(protocol_fee_rate <= FEE_RATE_DENOMINATOR_VALUE, ErrorCode::InvalidFeeRate);
    require!(fund_fee_rate <= FEE_RATE_DENOMINATOR_VALUE, ErrorCode::InvalidFeeRate);
    require!(
        fund_fee_rate.checked_add(protocol_fee_rate)
            .ok_or(ErrorCode::MathOverflow)? <= FEE_RATE_DENOMINATOR_VALUE,
        ErrorCode::InvalidFeeRate
    );
    require!(creator_fee_rate <= FEE_RATE_DENOMINATOR_VALUE, ErrorCode::InvalidFeeRate);

    instructions::create_amm_config(
        ctx,
        index,
        trade_fee_rate,
        protocol_fee_rate,
        fund_fee_rate,
        create_pool_fee,
        creator_fee_rate,
    )
}
```

Notes:
- `checked_add` prevents u64 overflow on adversarial inputs.
- Added explicit `creator_fee_rate <= FEE_RATE_DENOMINATOR_VALUE` bound; the sum check alone does not bound the individual term against overflow-free but still semantically inconsistent inputs.

### 2. Feature-Gated Program / Admin Identity (MEDIUM)

**Affected symbols:** `declare_id!` (devnet vs mainnet), `admin::ID`, `create_pool_fee_reveiver::ID`, `collect_lamports::ID`, `fund_fee_owner::ID`, `protocol_fee_owner::ID`, `shared_creator_fee_owner::ID`.

**Issue:** Identity constants are selected by Cargo features. A build with the wrong feature set deploys or interacts against unintended authorities. This is an operational/deployment risk rather than a code defect, but it must be enforced in CI: release artifacts should be built with an explicit, audited feature matrix and the resulting program ID verified on-chain.

**Remediation:** Add build-time assertions in `build.rs` or CI that fail unless exactly one of `devnet`/`localnet` is selected for non-mainnet builds, and publish reproducible build hashes.

### 3. `create_pool_fee` Unvalidated (MEDIUM)

**Affected function:** `create_amm_config`.

**Issue:** `create_pool_fee: u64` is accepted without bounds. Downstream state may store an arbitrary fee. Recommend a documented upper bound and `require!` check, e.g.:

```rust
require!(create_pool_fee <= MAX_CREATE_POOL_FEE, ErrorCode::InvalidCreatePoolFee);
```

Define `MAX_CREATE_POOL_FEE` in `curve::fees` or `states`.

### 4. `AUTH_SEED` Exposure (LOW)

**Symbol:** `pub const AUTH_SEED: &str = "vault_and_lp_mint_auth_seed";`

**Issue:** Seed is public, which is expected for PDA derivation, but any code deriving the authority must combine this seed with the pool key and program ID and verify the bump. Audit the `instructions/` handlers to confirm `find_program_address` results are compared against passed accounts and that bumps are stored/reused consistently. Not verifiable from this file.

### 5. `assert!` Removal / Error Enum Completeness (LOW)

Ensure `ErrorCode` contains `InvalidFeeRate`, `MathOverflow`, `InvalidCreatePoolFee`. If absent, add them to `error.rs`.

### 6. Security.txt Present (LOW / Positive)

The `solana_security_txt!` block is present and populated. Retain and keep contact URLs current.

---

## Architectural Risk Analysis

- **CPI trust:** Not visible in supplied file. All CPI targets (token programs, associated token program, system program) must be constrained by `Program<'info, Token>` / `Program<'info, AssociatedToken>` / `Program<'info, System>` rather than `AccountInfo`, and any external program invoked for fees must be allow-listed.
- **PDA validation:** Authority PDA derived from `AUTH_SEED` must be re-derived in every handler that uses it; never trust a passed bump without recompute.
- **Re-initialization:** Pool/config accounts need discriminator + `is_initialized` or Anchor `init`/`init_if_needed` discipline. `init_if_needed` on config accounts is a known re-init vector; verify handlers.
- **Arithmetic:** All fee math in `curve/fees` should use checked operations; spot-check for `*`/`/` without overflow guards and for precision loss in LP mint calculations.
- **Closure safety:** `collect_excess_lamports`, `close_support_mint_associated`, permission PDA close paths must zero data, refund rent to a designated recipient, and prevent re-use of closed accounts (Anchor `close` constraint handles this; manual closes must replicate).
- **Signer checks:** Admin-only instructions (`update_amm_config`, `update_pool_status`, fee collection of protocol/fund) must enforce `Signer` on the authority and match against stored `owner`/`fund_owner`, not just a passed account.

---

## Verified Defensive Remediation Code

Replace the `create_amm_config` wrapper as shown in §1. Additionally, in `error.rs` (if missing):

```rust
#[error_code]
pub enum ErrorCode {
    #[msg("Invalid fee rate")]
    InvalidFeeRate,
    #[msg("Math overflow")]
    MathOverflow,
    #[msg("Invalid create pool fee")]
    InvalidCreatePoolFee,
}
```

---

## Author & Disclosure Details

Researcher: Alex Rayyan (bansoslab2026@tutamail.com)  
USDC (Solana): 39YTqgacjKt1iz22SrvX4G3Ds8TUUjd9hWPPSJpdd2jZ  
USDC (Base/EVM): 0xf71e0734cb53162e8c9baaf5f49841a51c945899

*Note: This advisory is based solely on the supplied `lib.rs`. A complete audit requires the `instructions/`, `states/`, `curve/`, and `utils/` modules.*