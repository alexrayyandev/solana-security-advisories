# Defensive Security Audit Advisory

## Executive Summary

The reviewed program initializes a Token-2022 mint with the `NonTransferable` extension. The overall control flow is directionally correct: extension initialization occurs before mint initialization, required programs are typed through Anchor, and account creation is delegated to the System Program.

No critical exploitable vulnerability was identified in the provided code. However, the implementation contains a compile-time CPI construction defect, an unchecked size cast, and missing explicit defensive guards around account initialization state. These should be remediated before deployment.

**Severity Rating:** MEDIUM

---

## Technical Vulnerability Analysis

### 1. CPI Program Account Passed as Pubkey Instead of AccountInfo

**Affected Code:**
- `initialize`
- `create_account`
- `non_transferable_mint_initialize`
- `initialize_mint2`

**Issue:**  
`CpiContext::new` expects an `AccountInfo` for the target program. The code passes `ctx.accounts.system_program.key()` and `ctx.accounts.token_program.key()`, which are `Pubkey` values. This is not a valid CPI program account construction under standard Anchor APIs and will prevent compilation/deployment.

**Risk:** Deployment failure / non-functional program.

**Remediation:** Use `.to_account_info()` for both program accounts.

---

### 2. Unchecked `usize` to `u64` Cast for Mint Account Size

**Affected Code:**
```rust
mint_size as u64
```

**Issue:**  
The calculated account size is cast directly to `u64` without bounds checking. On the Solana target this is unlikely to overflow in practice, but defensive code should avoid unchecked numeric conversions.

**Risk:** Low. Potential truncation if an unexpectedly large size is calculated.

**Remediation:** Use `u64::try_from(mint_size)` and return an error on failure.

---

### 3. Missing Explicit Re-Initialization Guard

**Affected Code:**
- `Initialize` accounts
- `initialize` instruction

**Issue:**  
Although the System Program `create_account` CPI will fail if the target account already has lamports or data, the instruction does not explicitly assert that `mint_account` is uninitialized before proceeding. For defensive clarity and auditability, an explicit guard should be present.

**Risk:** Low. Reliance on downstream program behavior rather than explicit invariant checking.

**Remediation:** Add an explicit check that `mint_account` has zero lamports and empty data before account creation.

---

### 4. Authority Centralization

**Affected Code:**
```rust
&ctx.accounts.payer.key(),       // mint authority
Some(&ctx.accounts.payer.key()), // freeze authority
```

**Issue:**  
The payer becomes both mint authority and freeze authority. This is not inherently a vulnerability, but it concentrates privileged control in one key. For production systems, authority design should be explicitly documented and, where appropriate, separated or governed by a multisig.

**Risk:** Operational / governance risk.

---

## Architectural Risk Analysis

- **PDA Usage:** None. No PDA seed or bump validation is required for this instruction.
- **Signer Verification:** `payer` and `mint_account` are correctly marked as `Signer`.
- **Program Verification:** `token_program` is typed as `Program<Token2022>` and `system_program` is typed as `Program<System>`, providing Anchor-level program ID verification.
- **Account Closure:** No account closure logic is present. Not applicable to this initialization-only program.
- **Discriminator Validation:** Not applicable because the mint account is an SPL Token-2022 account, not an Anchor account.
- **Atomicity:** Initialization is performed within one transaction. A failure at any CPI aborts the entire transaction.

---

## Verified Defensive Remediation Code

```rust
use anchor_lang::prelude::*;
use anchor_lang::system_program::{create_account, CreateAccount};
use anchor_spl::{
    token_2022::{
        initialize_mint2,
        spl_token_2022::{extension::ExtensionType, pod::PodMint},
        InitializeMint2,
    },
    token_interface::{non_transferable_mint_initialize, NonTransferableMintInitialize, Token2022},
};

declare_id!("8Bz4wpHaUckiC169Rg5ZfaBHFemp5S8RwTSDTKzhJ9W");

#[program]
pub mod non_transferable {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        // Explicit defensive guard: mint account must not already exist.
        require!(
            ctx.accounts.mint_account.lamports() == 0
                && ctx.accounts.mint_account.data_is_empty(),
            ErrorCode::AccountAlreadyInitialized
        );

        let mint_size =
            ExtensionType::try_calculate_account_len::<PodMint>(&[ExtensionType::NonTransferable])?;

        let mint_size_u64 = u64::try_from(mint_size)
            .map_err(|_| ErrorCode::InvalidAccountSize)?;

        let lamports = Rent::get()?.minimum_balance(mint_size);

        create_account(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                CreateAccount {
                    from: ctx.accounts.payer.to_account_info(),
                    to: ctx.accounts.mint_account.to_account_info(),
                },
            ),
            lamports,
            mint_size_u64,
            &ctx.accounts.token_program.key(),
        )?;

        non_transferable_mint_initialize(CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            NonTransferableMintInitialize {
                token_program_id: ctx.accounts.token_program.to_account_info(),
                mint: ctx.accounts.mint_account.to_account_info(),
            },
        ))?;

        initialize_mint2(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
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

#[error_code]
pub enum ErrorCode {
    #[msg("Mint account is already initialized")]
    AccountAlreadyInitialized,

    #[msg("Calculated mint account size is invalid")]
    InvalidAccountSize,
}
```

---

## Author & Disclosure Details

Researcher: Alex Rayyan (bansoslab2026@tutamail.com)  
USDC (Solana): 39YTqgacjKt1iz22SrvX4G3Ds8TUUjd9hWPPSJpdd2jZ  
USDC (Base/EVM): 0xf71e0734cb53