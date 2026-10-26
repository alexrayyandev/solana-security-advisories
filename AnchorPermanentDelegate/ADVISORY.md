# Defensive Security Audit — `permanent_delegate` Program

**Researcher:** Alex Rayyan (bansoslab2026@tutamail.com)

## Executive Summary & Severity Rating

**Overall Risk: MEDIUM-HIGH** (no exploitable fund-drain via missing signer checks, but concentrated authority and improper error handling present).

| # | Finding | Severity |
|---|---------|----------|
| F-01 | `assert_eq!` panic instead of `require_eq!` in production path | MEDIUM |
| F-02 | Permanent delegate == payer == mint authority (single-key total control) | HIGH (architectural) |
| F-03 | No explicit owner check on mint account before unpacking extension data | LOW |
| F-04 | No re-initialization / authority-rotation guard beyond `init` | LOW |

## Technical Vulnerability Analysis & Affected Functions

### F-01 — Panic-based assertion in `check_mint_data`
**Affected function:** `Initialize::check_mint_data` (`programs/permanent_delegate/src/lib.rs`).

The function validates the on-chain permanent-delegate extension using `assert_eq!`. In a Solana program, `assert_eq!` compiles to a Rust panic, which aborts the transaction with an opaque runtime error rather than a structured Anchor error code. This defeats client-side error decoding, complicates monitoring, and can mask the real failure mode (e.g. a maliciously crafted mint account whose extension differs from expected).

**Remediation:** replace with `require_eq!` and a typed `#[error_code]`.

### F-02 — Concentrated authority (architectural)
**Affected:** `Initialize` account constraints.

`mint::authority = payer` and `extensions::permanent_delegate::delegate = payer`. The permanent delegate can transfer/burn tokens from **any** holder at any time. Combining mint authority, permanent delegate, and fee-payer into one EOA means a single key compromise drains the entire token supply and mints arbitrary supply. There is no multisig, timelock, or separation of duties.

**Remediation (architectural):** use a dedicated, ideally multisig-controlled, delegate pubkey distinct from the mint authority and payer; document the trust model.

### F-03 — Missing explicit owner validation before unpack
**Affected:** `check_mint_data`.

Although `init` ensures correct creation, defensive programs should assert `mint_info.owner == token_program` before `StateWithExtensions::unpack`, so a future refactor (e.g. passing an existing account) cannot cause a deserialization of attacker-controlled data.

### F-04 — No authority-rotation / freeze hooks
No freeze authority is set (`mint::freeze_authority` omitted defaults to `None`), and no upgrade/rotation path exists. Acceptable for v1 but should be documented.

## Architectural Risk Analysis

- **Trust model:** single EOA holds mint authority + permanent delegate. This is the dominant risk; recommend separation.
- **Token-2022 extensions:** permanent delegate is a powerful compliance primitive; ensure downstream integrations (DEXs, lending) are aware that balances are not final.
- **Error surfacing:** panic-based checks reduce observability.

## Verified Defensive Remediation Code

```rust
use anchor_lang::prelude::*;
use anchor_spl::{
    token_2022::spl_token_2022::extension::permanent_delegate::PermanentDelegate,
    token_interface::{
        spl_pod::optional_keys::OptionalNonZeroPubkey,
        spl_token_2022::{
            extension::{BaseStateWithExtensions, StateWithExtensions},
            state::Mint as MintState,
        },
        Mint, Token2022,
    },
};

declare_id!("A9rxKS84ZoJVyeTfQbCEfxME2vvAM4uwSMjkmhR5XWb1");

#[program]
pub mod permanent_delegate {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        ctx.accounts.check_mint_data()?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        init,
        payer = payer,
        mint::decimals = 2,
        mint::authority = payer,
        // NOTE: for production, set delegate to a dedicated/multisig authority,
        // not the payer EOA. See architectural risk F-02.
        extensions::permanent_delegate::delegate = payer,
    )]
    pub mint_account: InterfaceAccount<'info, Mint>,
    pub token_program: Program<'info, Token2022>,
    pub system_program: Program<'info, System>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Mint account is not owned by the token program")]
    InvalidMintOwner,
    #[msg("Permanent delegate does not match expected authority")]
    InvalidDelegate,
}

impl<'info> Initialize<'info> {
    pub fn check_mint_data(&self) -> Result<()> {
        let mint_info = &self.mint_account.to_account_info();

        // Defensive: verify owner before deserializing extension data.
        require!(
            *mint_info.owner == *self.token_program.key,
            ErrorCode::InvalidMintOwner
        );

        let mint_data = mint_info.data.borrow();
        let mint_with_extension = StateWithExtensions::<MintState>::unpack(&mint_data)?;
        let extension_data = mint_with_extension.get_extension::<PermanentDelegate>()?;

        require_eq!(
            extension_data.delegate,
            OptionalNonZeroPubkey::try_from(Some(self.payer.key()))?,
            ErrorCode::InvalidDelegate
        );

        msg!("{:?}", extension_data);
        Ok(())
    }
}
```

## Author & Disclosure Details

- **Researcher:** Alex Rayyan (bansoslab2026@tutamail.com)
- **USDC (Solana):** `39YTqgacjKt1iz22SrvX4G3Ds8TUUjd9hWPPSJpdd2jZ`
- **USDC (Base/EVM):** `0xf71e0734cb53162e8c9baaf5f49841a51c945899`