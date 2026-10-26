# Security Advisory: transfer_switch

**Researcher:** Alex Rayyan (bansoslab2026@tutamail.com)  
**Program ID:** `FjcHckEgXcBhFmSGai3FRpDLiT6hbpV893n8iTxVd81g`

## Executive Summary

The provided entrypoint module exposes a transfer-hook-gated switch. The visible code does not itself implement account validation, PDA derivation, CPI, or arithmetic, so the most concrete issue observable at this layer is an authorization gap in the `switch` instruction: it is forwarded directly to `ctx.accounts.switch(on)` without any visible admin/signer gate at the program entrypoint. If the underlying `Switch` account constraints do not independently enforce an admin signer, any caller can toggle the transfer hook switch.

**Severity Rating:** HIGH (potentially CRITICAL if `Switch` controls all token transfers and lacks independent admin enforcement)

## Vulnerability Description

### 1. Missing Visible Authorization on `switch`

**Location:** `switch` function

```rust
pub fn switch(ctx: Context<Switch>, on: bool) -> Result<()> {
    ctx.accounts.switch(on)
}
```

Unlike `configure_admin`, which calls `ctx.accounts.is_admin()?` before mutating state, `switch` performs no visible authorization check. The security of this instruction therefore depends entirely on account constraints in `instructions/switch.rs`, which were not provided for review.

If `Switch` does not enforce an admin signer, an attacker can enable or disable the transfer hook behavior at will.

### 2. Unverifiable Account Constraints From Provided Scope

The following cannot be confirmed from the supplied file alone:

- `ConfigureAdmin` account validation and signer enforcement
- `Switch` account validation and signer enforcement
- Extra account meta list initialization idempotency / re-initialization protection
- PDA derivation and bump validation
- Token account ownership and transfer-hook `is_transferring` validation
- Closing logic and lamport handling

These must be reviewed in `instructions/` and `state/` before deployment.

## Exploitation Scenario

If `Switch` lacks admin enforcement:

1. Attacker calls `switch(false)`.
2. The transfer hook's `assert_switch_is_on()` subsequently fails for all transfers using this hook.
3. Token transfers for the affected mint are effectively frozen, or, conversely, an attacker calls `switch(true)` to bypass an intended transfer restriction.

### TypeScript / Anchor PoC

```ts
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";

const program = anchor.workspace.TransferSwitch as Program;

// If Switch is not admin-gated, any wallet can toggle the switch.
await program.methods
  .switch(false)
  .accounts({
    // Fill with the accounts required by Switch
  })
  .signers([attacker])
  .rpc();
```

## Recommended Remediation Patch

At minimum, enforce the same admin gate used by `configure_admin` before toggling the switch:

```rust
pub fn switch(ctx: Context<Switch>, on: bool) -> Result<()> {
    ctx.accounts.is_admin()?;
    ctx.accounts.switch(on)
}
```

Additionally, audit and harden the full instruction account structs:

```rust
// Example expected constraints; adapt to actual state layout.
#[derive(Accounts)]
pub struct Switch<'info> {
    #[account(mut)]
    pub switch_state: Account<'info, SwitchState>,

    #[account(
        constraint = admin.key() == switch_state.admin @ ErrorCode::Unauthorized
    )]
    pub admin: Signer<'info>,
}
```

For `configure_admin`, ensure the target admin account is a `Signer` and that initialization cannot be repeated:

```rust
pub fn configure_admin(ctx: Context<ConfigureAdmin>) -> Result<()> {
    ctx.accounts.is_admin()?;
    ctx.accounts.configure_admin()
}
```

```rust
#[derive(Accounts)]
pub struct ConfigureAdmin<'info> {
    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + SwitchState::INIT_SPACE,
        seeds = [b"switch_state"],
        bump
    )]
    pub switch_state: Account<'info, SwitchState>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub admin: Signer<'info>,
}
```

For `initialize_extra_account_metas_list`, ensure it uses `init` rather than `init_if_needed` unless re-initialization is intentionally supported and guarded.

For `transfer_hook`, retain and verify:

```rust
ctx.accounts.assert_is_transferring()?;
ctx.accounts.assert_switch_is_on()?;
```

and ensure the hook's source/destination token accounts and mint are validated against the expected token program and mint.

## Author & Disclosure Details

**Researcher:** Alex Rayyan (bansoslab2026@tutamail.com)  
**USDC (Solana):** `39YTqgacjKt1iz22SrvX4G3Ds8TUUjd9hWPPSJpdd2jZ`  
**USDC (Base/EVM):** `0xf71e0734cb53162e8c9baaf5f49841a51c945899`