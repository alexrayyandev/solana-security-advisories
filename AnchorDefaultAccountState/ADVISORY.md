# Defensive Security Audit Advisory

**Program:** `default_account_state`  
**Framework:** Anchor / Rust  
**Auditor:** Alex Rayyan (bansoslab2026@tutamail.com)

---

## Executive Summary & Severity Rating

**Overall Severity: MEDIUM**

The program correctly uses typed program accounts, signer constraints, and ordered Token-2022 CPI initialization. No critical account-takeover or arbitrary CPI vulnerability was identified. The primary defensive gaps are insufficient validation of the requested default account state and an unchecked integer cast during mint sizing.

---

## Technical Vulnerability Analysis & Affected Functions

### 1. Unrestricted `Uninitialized` Default State
**Affected Function:** `update_default_state`

`AnchorAccountState::Uninitialized` is accepted and forwarded to Token-2022. Default account state should represent a usable post-creation state, typically `Initialized` or `Frozen`. Allowing `Uninitialized` can create token accounts in an invalid or unusable state and expands the attack surface for state-confusion issues.

### 2. Unchecked `usize -> u64` Cast
**Affected Function:** `initialize`

```rust
mint_size as u64
```

This cast is not defensively checked. Although the current Solana target width makes overflow unlikely, defensive code should use a checked conversion.

### 3. Mint Extension Presence Is Not Pre-Validated
**Affected Function:** `update_default_state`

The update CPI will fail if the mint lacks the `DefaultAccountState` extension, but the program does not explicitly validate extension presence before invoking CPI. This is acceptable functionally, but explicit validation improves fail-closed behavior and diagnostics.

### 4. Unused Account in Update Context
**Affected Function:** `update_default_state`

`system_program` is included in `UpdateDefaultState` but is not used. This is not directly exploitable, but it increases unnecessary account validation surface.

---

## Architectural Risk Analysis

- The same payer is both mint authority and freeze authority. This is a centralization and key-compromise risk, though it appears intentional for this example.
- No PDA-based authority is used; all authority is externally controlled.
- No account closure or rent reclamation logic exists, which is acceptable because the program does not close accounts.
- The mint is created through a raw account creation flow rather than Anchor `init`, which is appropriate for Token-2022 extensions but requires strict signer and owner checks.

---

## Verified Defensive Remediation Code

```rust
use anchor_lang::prelude::*;
use anchor_lang::system_program::{create_account, CreateAccount};
use anchor_spl::{
    token_2022::{
        initialize_mint2,
        spl_token_2022::{extension::ExtensionType, pod::PodMint, state::AccountState},
        InitializeMint2,
    },
    token_interface::{
        default_account_state_initialize, default_account_state_update,
        DefaultAccountStateInitialize, DefaultAccountStateUpdate, Mint, Token2022,
    },
};

declare_id!("5LdYbHiUsFxVG8bfqoeBkhBYMRmWZb3BoLuABgYW7coB");

#[program]
pub mod default_account_state {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let mint_size = ExtensionType::try_calculate_account_len::<PodMint>(&[
            ExtensionType::DefaultAccountState,
        ])?;

        let mint_size_u64 = u64::try_from(mint_size)
            .map_err(|_| error!(ErrorCode::InvalidMintSize))?;

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
            mint_size_u64,
            &ctx.accounts.token_program.key(),
        )?;

        default_account_state_initialize(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                DefaultAccountStateInitialize {
                    token_program_id: ctx.accounts.token_program.to_account_info(),
                    mint: ctx.accounts.mint_account.to_account_info(),
                },
            ),
            &AccountState::Frozen,
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

        Ok(())
    }

    pub fn update_default_state(
        ctx: Context<UpdateDefaultState>,
        account_state: AnchorAccountState,
    ) -> Result<()> {
        require!(
            account_state != AnchorAccountState::Uninitialized,
            ErrorCode::InvalidDefaultAccountState
        );

        let account_state = account_state.to_spl_account_state();

        default_account_state_update(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                DefaultAccountStateUpdate {
                    token_program_id: ctx.accounts.token_program.to_account_info(),
                    mint: ctx.accounts.mint_account.to_account_info(),
                    freeze_authority: ctx.accounts.freeze_authority.to_account_info(),
                },
            ),
            &account_state,
        )?;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(mut)]
    pub mint_account: Signer<'info>,

    pub token_program: Program<'info, Token2022>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateDefaultState<'info> {
    #[account(mut)]
    pub freeze_authority: Signer<'info>,

    #[account(
        mut,
        mint::freeze_authority = freeze_authority,
    )]
    pub mint_account: InterfaceAccount<'info, Mint>,

    pub token_program: Program<'info, Token2022>,
}

#[derive(AnchorSerialize, AnchorDeserialize, PartialEq, Eq)]
pub enum AnchorAccountState {
    Uninitialized,
    Initialized,
    Frozen,
}

impl AnchorAccountState {
    pub fn to_spl_account_state(&self) -> AccountState