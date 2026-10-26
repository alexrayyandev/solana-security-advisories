# Security Advisory: Solana Escrow Program

**Researcher:** Alex Rayyan (bansoslab2026@tutamail.com)
**Program ID:** `3o3jk7aj2aGCGsbChkgeNdHcBmeEmGA7BtpnTXdVSgtr`
**Severity:** INCOMPLETE AUDIT — Source insufficient

## Executive Summary

The submitted artifact is `lib.rs` only. It declares modules (`constants`, `error`, `instructions`, `state`) and three entrypoints (`make_offer`, `take_offer`, `refund_offer`), but contains no account validation, CPI logic, PDA derivation, arithmetic, or state definitions. A definitive vulnerability assessment requires the full source tree. The analysis below documents the **likely critical attack surface** for this escrow pattern and the exact checks that must be verified in the missing files.

---

## Scope & Missing Artifacts

Required but not provided:
- `instructions/make_offer.rs`
- `instructions/take_offer.rs`
- `instructions/refund_offer.rs`
- `state/*.rs`
- `constants.rs`, `error.rs`

**Audit verdict: Cannot be finalized without these files.** Treat the checklist below as the mandatory verification gate.

---

## Vulnerability Checklist (Escrow-Specific)

### 1. Arbitrary CPI & Missing Program ID Checks (CRITICAL)
In `make_offer`/`take_offer`, token transfers via `token::transfer` or `token_2022::transfer_checked` must constrain the `token_program` account to `spl_token::ID` / `spl_token_2022::ID`. If `token_program` is unchecked, an attacker can substitute a malicious program and drain the vault.

**Verify:** `token_program: Program<'info, Token>` (or Token2022), not `AccountInfo`/`UncheckedAccount`.

### 2. Missing Signer & Ownership Validation (CRITICAL)
- `make_offer`: `maker` must be `Signer<'info>`; `token_a_mint`, `token_b_mint` must be owned by SPL Token program.
- `take_offer`: `taker` must be `Signer<'info>`.
- `refund_offer`: `maker` must be `Signer<'info>` and must equal `offer.maker` (PDA-enforced or explicit check).

**Verify:** No `UncheckedAccount` used for principals; `has_one = maker` or manual equality check present.

### 3. Improper PDA Derivation / Missing Bump (HIGH)
Offer account and vault ATA are typically PDAs seeded by `["offer", maker, id]` and `["vault", offer]`. Missing canonical bump validation allows PDA squatting or duplicate offers.

**Verify:** `#[account(seeds = [...], bump)]` with stored `bump` field, and vault ATA derived via `get_associated_token_address` with correct authority (offer PDA), not maker.

### 4. Integer Overflow / Precision (MEDIUM)
`token_a_offered_amount` / `token_b_wanted_amount` conversions, rate calculations, or fee deductions must use `checked_mul`/`checked_div`. Unchecked arithmetic panics in debug but wraps in release (release profile in Anchor can still overflow on some paths).

**Verify:** No raw `*`/`/` on amounts; use `checked_*` with custom errors.

### 5. Re-initialization / Type Cosplay (HIGH)
Offer account init must use `init` (not `init_if_needed`) unless explicitly guarded. `init_if_needed` on an existing account enables re-init attacks. Type cosplay via missing discriminator check on `Account<'info, Offer>` vs raw `AccountInfo`.

**Verify:** `#[account(init, payer = maker, space = ...)]`; no `init_if_needed` without owner check.

### 6. Closing Account & Residual Lamport Drain (HIGH)
`withdraw_and_close_vault` / `withdraw_and_close_vault_for_refund` must:
- Transfer all vault tokens before closing.
- Close vault ATA via `close` constraint (CPI to token program) so rent returns to maker/taker.
- Zero offer account data and transfer lamports to recipient (Anchor `close = recipient`).
- Refund path must verify `offer.maker == signer` and that offer is not already taken (state flag).

**Verify:** `close = maker`/`close = taker` constraints; `vault.amount == 0` post-withdrawal assertion.

---

## Likely Exploitation Scenario (Pending Source)

Most common critical finding in this pattern: **missing `has_one`/signer check on refund path** allowing any user to call `refund_offer` and drain the vault ATA, or **unchecked `token_program`** enabling arbitrary CPI. Without source, exact lines cannot be cited.

---

## Recommended Remediation (Template)

```rust
// take_offer accounts
#[derive(Accounts)]
pub struct TakeOffer<'info> {
    #[account(mut)]
    pub taker: Signer<'info>,
    #[account(mut, has_one = maker, close = taker)]
    pub offer: Account<'info, Offer>,
    #[account(mut, seeds = [b"vault", offer.key().as_ref()], bump = offer.vault_bump, token::mint = token_a_mint, token::authority = offer)]
    pub vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub taker_token_a_account: Account<'info, TokenAccount>,
    #[account(mut)]
    pub maker_token_b_account: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
    // ... mint checks
}
```

Apply analogous constraints to `MakeOffer` and `RefundOffer`.

---

## Disclosure

**Researcher:** Alex Rayyan
**Email:** bansoslab2026@tutamail.com
**USDC (Solana):** `39YTqgacjKt1iz22SrvX4G3Ds8TUUjd9hWPPSJpdd2jZ`
**USDC (Base/EVM):** `0xf71e0734cb53162e8c9baaf5f49841a51c945899`

> **Note:** Resubmit with full `instructions/`, `state/`, `constants.rs`, and `error.rs` for a line-level, exploitable-PoC-grade audit. The current submission is insufficient for a definitive CRITICAL/HIGH/MEDIUM rating.