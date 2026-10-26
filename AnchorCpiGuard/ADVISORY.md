# Defensive Security Audit Advisory

**Program:** `cpi_guard`  
**Researcher:** Alex Rayyan (bansoslab2026@tutamail.com)  
**Overall Severity:** HIGH

## Executive Summary

The audited instruction performs a Token-2022 `transfer_checked` CPI, but it lacks ownership validation on the source token account, uses a globally shared PDA for the destination token account, and assigns the destination token account authority to itself. These flaws can result in account misuse, irreversible token lockup, and cross-user account collisions.

## Technical Vulnerability Analysis & Affected Functions

### 1. Missing Source Token Account Authority Check
**Severity:** HIGH  
**Affected:** `cpi_transfer`, `CpiTransfer.sender_token_account`

`sender_token_account` is only constrained by `token::mint = mint_account`. It is not constrained to be owned by `sender`. This allows arbitrary token accounts with the same mint to be supplied. Although the Token program enforces authority during transfer, the missing Anchor constraint weakens defensive validation and can enable confusion or misuse in extended flows.

### 2. Destination Token Account Authority Is Itself
**Severity:** HIGH  
**Affected:** `CpiTransfer.recipient_token_account`

`token::authority = recipient_token_account` sets the token account owner to its own address. Since no program instruction exists to sign as that PDA, deposited tokens become permanently locked and unrecoverable.

### 3. Global Fixed PDA Seed
**Severity:** MEDIUM  
**Affected:** `CpiTransfer.recipient_token_account`

Using only `seeds = [b"pda"]` creates one destination token account for all users and mints. This causes account collisions, initialization failures, and potential denial of service when different mints or users interact with the same PDA.

### 4. CPI Program Account Passed Incorrectly
**Severity:** LOW  
**Affected:** `cpi_transfer`

`CpiContext::new(ctx.accounts.token_program.key(), ...)` passes a `Pubkey` where an `AccountInfo` is expected. The correct value is `ctx.accounts.token_program.to_account_info()`.

### 5. `init_if_needed` on Shared Token Account
**Severity:** MEDIUM  
**Affected:** `CpiTransfer.recipient_token_account`

Using `init_if_needed` with a shared PDA and no per-user or per-mint isolation increases reinitialization and collision risk. The destination account should be uniquely derived per sender and mint.

## Architectural Risk Analysis

- No per-user account isolation.
- No recoverable authority model for destination funds.
- Weak source account ownership validation.
- Potential global state contention on a single PDA.
- Incorrect CPI program account construction.

## Verified Defensive Remediation Code

```rust
use anchor_lang::prelude::*;
use anchor_spl::{
    token_2022::{transfer_checked, TransferChecked},
    token_interface::{Mint, Token2022, TokenAccount},
};

declare_id!("6tU3MEowU6oxxeDZLSxEwzcEZsZrhBJsfUR6xECvShid");

#[program]
pub mod cpi_guard {
    use super::*;

    pub fn cpi_transfer(ctx: Context<CpiTransfer>) -> Result<()> {
        transfer_checked(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.sender_token_account.to_account_info(),
                    mint: ctx.accounts.mint_account.to_account_info(),
                    to: ctx.accounts.recipient_token_account.to_account_info(),
                    authority: ctx.accounts.sender.to_account_info(),
                },
            ),
            1,
            ctx.accounts.mint_account.decimals,
        )?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CpiTransfer<'info> {
    #[account(mut)]
    pub sender: Signer<'info>,

    #[account(
        mut,
        token::mint = mint_account,
        token::authority = sender
    )]
    pub sender_token_account: InterfaceAccount<'info, TokenAccount>,

    #[account(
        init_if_needed,
        payer = sender,
        seeds = [b"recipient", sender.key().as_ref(), mint_account.key().as_ref()],
        bump,
        token::mint = mint_account,
        token::authority = sender,
        token::token_program = token_program
    )]
    pub recipient_token_account: InterfaceAccount<'info, TokenAccount>,

    pub mint_account: InterfaceAccount<'info, Mint>,
    pub token_program: Program<'info, Token2022>,
    pub system_program: Program<'info, System>,
}
```

## Author & Disclosure Details

Researcher: Alex Rayyan (bansoslab2026@tutamail.com)  
USDC (Solana): 39YTqgacjKt1iz22SrvX4G3Ds8TUUjd9hWPPSJpdd2jZ  
USDC (Base/EVM): 0xf71e0734cb53162e8c9baaf5f49841a51c945899