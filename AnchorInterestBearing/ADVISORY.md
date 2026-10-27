# Solana Defensive Security Audit Advisory

**Program:** `interest_bearing`  
**Researcher:** Alex Rayyan (bansoslab2026@tutamail.com)  
**Severity Rating:** MEDIUM  
**Scope:** CPI security, account validation, PDA/seed safety, arithmetic, lifecycle, closure

## Executive Summary

No direct fund-draining or privilege-escalation vulnerability was identified in the provided code. The program correctly verifies `token_program` as `Program<Token2022>` and `system_program` as `Program<System>`, and relies on the Token-2022 program to enforce rate-authority signing during rate updates.

However, the implementation lacks defense-in-depth controls: it does not explicitly validate the mint extension authority before CPI, uses panicking `assert_eq!` in on-chain validation, performs no rate-bound validation, and does not explicitly guard against malformed or pre-used mint accounts. These are robustness and auditability weaknesses rather than confirmed critical exploits.

## Technical Vulnerability Analysis

### 1. Panicking Validation in `check_mint_data`

**Affected Function:** `check_mint_data`  
**Issue:** Uses `assert_eq!`, which panics instead of returning a structured Anchor error. Panics are less predictable for clients and complicate error handling.

### 2. Missing Explicit Rate-Authority Pre-Check

**Affected Function:** `update_rate`  
**Issue:** The program depends entirely on Token-2022 to reject unauthorized rate updates. While the token program is verified, an explicit pre-CPI equality check between the mint's `InterestBearingConfig.rate_authority` and `ctx.accounts.authority` improves defense-in-depth and fails earlier with a clear error.

### 3. Missing Interest Rate Bounds

**Affected Functions:** `initialize`, `update_rate`  
**Issue:** `rate: i16` is accepted without protocol-level bounds. Extreme values may create misleading or unsafe interest-bearing behavior, depending on downstream integrations and Token-2022 semantics.

### 4. Weak Explicit Re-Initialization Guard

**Affected Function:** `initialize`  
**Issue:** `create_account` generally prevents reuse of funded accounts, but the program does not explicitly assert that the mint account is empty and uninitialized before account creation.

### 5. Missing Account Distinctness Check

**Affected Function:** `initialize`  
**Issue:** `payer` and `mint_account` are not explicitly required to be distinct. Using the same account for both roles can create ambiguous or invalid transaction behavior.

### 6. Missing Owner Check in `check_mint_data`

**Affected Function:** `check_mint_data`  
**Issue:** The helper reads and unpacks mint data but does not explicitly verify that the account owner is the Token-2022 program.

## Architectural Risk Analysis

- **CPI Trust Model:** Acceptable. `token_program` is constrained to `Program<Token2022>`, preventing arbitrary program substitution.
- **Signer Enforcement:** Acceptable. `payer`, `mint_account`, and `authority` are `Signer` accounts.
- **PDA Safety:** Not applicable. No PDAs are used.
- **Arithmetic Safety:** Acceptable. No unchecked arithmetic is present. Rent calculation uses Anchor's `Rent::get`.
- **Lifecycle Safety:** Mostly acceptable. Token-2022 owns the created mint. Explicit empty-account and owner checks would strengthen lifecycle safety.
- **Closure Safety:** Not applicable. No close/reclamation logic is present.

## Verified Defensive Remediation Code

```rust
use anchor_lang::prelude::*;
use anchor_lang::system_program::{create_account, CreateAccount};
use anchor_spl::{
    token_2022::{
        initialize_mint2,
        spl_token_2022::{
            extension::{
                interest_bearing_mint::InterestBearingConfig, BaseStateWithExtensions,
                ExtensionType, StateWithExtensions,
            },
            pod::PodMint,
            state::Mint as MintState,
        },
        InitializeMint2,
    },
    token_interface::{
        interest_bearing_mint_initialize, interest_bearing_mint_update_rate,
        spl_pod::optional_keys::OptionalNonZeroPubkey, InterestBearingMintInitialize,
        InterestBearingMintUpdateRate, Mint, Token2022,
    },
};

declare_id!("DMQdkzRJz8uQSN8Kx2QYmQJn6xLKhsu3LcPYxs314MgC");

#[program]
pub mod interest_bearing {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, rate: i16) -> Result<()> {
        require_keys_neq!(
            ctx.accounts.payer.key(),
            ctx.accounts.mint_account.key(),
            ErrorCode::InvalidAccountRoles
        );

        require!(
            ctx.accounts.mint_account.data_is_empty()
                && ctx.accounts.mint_account.lamports() == 0,
            ErrorCode::AccountAlreadyInitialized
        );

        require!(
            rate >= -10_000 && rate <= 10_000,
            ErrorCode::InvalidInterestRate
        );

        let mint_size = ExtensionType::try_calculate_account_len::<PodMint>(&[
            ExtensionType::InterestBearingConfig,
        ])?;

        let lamports = (Rent::get()?).minimum_balance(mint_size);

        create_account(
            CpiContext::new(
                ctx.accounts.system_program.key(),
                CreateAccount {
                    from: ctx.accounts.payer.to_account_info(),
                    to: ctx.accounts.mint_account.to_account_info(),
                },
            ),
            lamports,
            mint_size as u64,
            &ctx.accounts.token_program.key(),
        )?;

        interest_bearing_mint_initialize(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                InterestBearingMintInitialize {
                    token_program_id: ctx.accounts.token_program.to_account_info(),
                    mint: ctx.accounts.mint_account.to_account_info(),
                },
            ),
            Some(ctx.accounts.payer.key()),
            rate,
        )?;

        initialize_mint2(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                InitializeMint2 {
                    mint: ctx.accounts.mint_account.to_account_info(),
                },
            ),
            2,
            &ctx.accounts.payer.key(),
            Some(&ctx.accounts.payer.key()),
        )?;

        check_mint_data(
            &ctx.accounts.mint_account.to_account_info(),
            &ctx.accounts.payer.key(),
        )?;

        Ok(())
    }

    pub fn update_rate(ctx: Context<UpdateRate>, rate: i16) -> Result<()> {
        require!(
            rate >= -10_000 && rate <= 10_000,
            ErrorCode::InvalidInterestRate
        );

        let mint_data = ctx.accounts