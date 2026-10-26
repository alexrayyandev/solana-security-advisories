# Security Advisory — `basic_2` Program

**Researcher:** Alex Rayyan (bansoslab2026@tutamail.com)
**USDC (Solana):** `39YTqgacjKt1iz22SrvX4G3Ds8TUUjd9hWPPSJpdd2jZ`
**USDC (Base/EVM):** `0xf71e0734cb53162e8c9baaf5f49841a51c945899`

---

## Executive Summary

| # | Finding | Severity |
|---|---------|----------|
| F-1 | Unchecked integer overflow in `increment` (`counter.count += 1`) | MEDIUM |
| F-2 | Unrestricted `authority` assignment in `create` (no signer/ownership validation) | MEDIUM |

No CRITICAL findings (no arbitrary CPI, no lamport drain, no re-init, no PDA misuse). Program is small; attack surface limited.

---

## F-1 — Unchecked Arithmetic Overflow

**Location:** `increment`, line `counter.count += 1;`

**Description:** `counter.count` is `u64`. The `+= 1` operation uses wrapping arithmetic in release builds (Rust default for `+=` on integers in release is wrapping, not panicking). An attacker who controls the authority can call `increment` `2^64` times to wrap `count` back to `0`. While practically expensive, any downstream logic that depends on monotonic counting (thresholds, epochs, reward accrual) can be corrupted, and Anchor programs integrating this counter may assume non-wrapping semantics.

**Exploitation Scenario:** If a consumer program gates an action on `counter.count >= N`, repeated increments beyond `u64::MAX` reset the value, bypassing the gate.

**PoC (TypeScript / Anchor):**
```ts
import * as anchor from "@coral-xyz/anchor";

const program = anchor.workspace.Basic2;
// Repeatedly invoke until wrap (conceptual; not run to completion)
for (let i = 0; i < Number.MAX_SAFE_INTEGER; i++) {
  await program.methods.increment().accounts({ counter, authority }).rpc();
}
// count wraps to 0
```

**Recommended Remediation:**
```rust
pub fn increment(ctx: Context<Increment>) -> Result<()> {
    let counter = &mut ctx.accounts.counter;
    counter.count = counter.count.checked_add(1).ok_or(ErrorCode::Overflow)?;
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("counter overflow")]
    Overflow,
}
```

---

## F-2 — Unrestricted Authority Assignment at Creation

**Location:** `create`, lines:
```rust
pub fn create(ctx: Context<Create>, authority: Pubkey) -> Result<()> {
    let counter = &mut ctx.accounts.counter;
    counter.authority = authority;
    ...
}
```

**Description:** `authority` is an arbitrary `Pubkey` argument. There is no constraint that `authority == user.key()` or that `authority` has signed/consented. Any payer can mint a `Counter` attributed to an arbitrary third party. Depending on integrations, this enables spam, attribution fraud, and (if downstream code trusts counter authority without additional checks) impersonation of a privileged role.

**Exploitation Scenario:** Attacker creates many counters with `authority = victim_pubkey`. If a downstream protocol iterates/enumerates counters by authority, victim's quota or reputation is polluted. If `authority` is later treated as an admin, attacker pre-assigns adminship to themselves on a counter they control the payer for (still requires signer later, so limited, but attribution is uncontrolled).

**PoC (TypeScript / Anchor):**
```ts
const victim = new anchor.web3.PublicKey("...");
await program.methods
  .create(victim)
  .accounts({ counter: counterKp.publicKey, user: attacker.publicKey, systemProgram: anchor.web3.SystemProgram.programId })
  .signers([attacker, counterKp])
  .rpc();
// counter.authority == victim, payer == attacker
```

**Recommended Remediation (Option A — authority must be payer):**
```rust
pub fn create(ctx: Context<Create>) -> Result<()> {
    let counter = &mut ctx.accounts.counter;
    counter.authority = ctx.accounts.user.key();
    counter.count = 0;
    Ok(())
}
```
And remove the `authority` argument from the IDL call.

**Option B — require authority signer at creation:**
```rust
#[derive(Accounts)]
pub struct Create<'info> {
    #[account(init, payer = user, space = 8 + 40)]
    pub counter: Account<'info, Counter>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

pub fn create(ctx: Context<Create>) -> Result<()> {
    let counter = &mut ctx.accounts.counter;
    counter.authority = ctx.accounts.authority.key();
    counter.count = 0;
    Ok(())
}
```

---

## Items Checked (No Finding)

- **Re-initialization:** `init` constraint prevents re-init of an existing account.
- **Type Cosplay:** `Account<'info, Counter>` enforces the 8-byte discriminator.
- **Ownership:** Anchor validates `counter` is owned by this program.
- **Signer checks:** `user: Signer` (create), `authority: Signer` (increment) enforced.
- **`has_one`:** `counter.authority == authority.key()` enforced in `Increment`.
- **CPI:** No cross-program invocations present.
- **Account closing / lamport drain:** No close logic present.
- **PDA:** No PDA seeds used; none to validate.

---

## Disclosure

Researcher: Alex Rayyan (bansoslab2026@tutamail.com)
USDC (Solana): 39YTqgacjKt1iz22SrvX4G3Ds8TUUjd9hWPPSJpdd2jZ
USDC (Base/EVM): 0xf71e0734cb53162e8c9baaf5f49841a51c945899