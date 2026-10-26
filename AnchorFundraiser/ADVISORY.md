# Security Advisory

**Program:** `fundraiser`  
**Declared Program ID:** `Eoiuq1dXvHxh6dLx3wh9gj8kSAUpga11krTrbfF5XYsC`  
**Researcher:** Alex Rayyan (bansoslab2026@tutamail.com)  
**USDC (Solana):** `39YTqgacjKt1iz22SrvX4G3Ds8TUUjd9hWPPSJpdd2jZ`  
**USDC (Base/EVM):** `0xf71e0734cb53162e8c9baaf5f49841a51c945899`

## Executive Summary & Severity Rating

**Severity:** Not Assessable from Provided Snippet

The supplied code contains only the program entrypoint/router. All security-relevant logic is delegated to the following modules, which were not provided:

- `constants`
- `error`
- `instructions`
- `state`

No vulnerability can be confirmed, reproduced, or patched from the entrypoint alone. The router itself only forwards instruction contexts and does not perform account validation, arithmetic, CPI validation, PDA derivation, or account lifecycle handling.

## Scope Limitation

The following files are required for a complete audit:

1. `instructions/initialize.rs`
2. `instructions/contribute.rs`
3. `instructions/check_contributions.rs`
4. `instructions/refund.rs`
5. `state/*.rs`
6. `constants.rs`
7. `error.rs`
8. `Cargo.toml` / dependency versions, especially Anchor version

## Audit Focus Areas Once Full Source Is Provided

The full review must specifically verify:

1. **Arbitrary CPI / Program ID Checks**
   - Every CPI uses a validated program account.
   - Token program, System program, Associated Token Program, and any custom program IDs are constrained with `Program<'info, ...>` or explicit key checks.
   - No user-supplied program account is invoked unchecked.

2. **Missing Signer / Ownership Validation**
   - `authority`, `contributor`, and any admin accounts are constrained as `Signer<'info>`.
   - Token accounts are validated for correct mint, owner, and program ownership.
   - Fundraiser/vault state accounts are owned by the program.

3. **PDA Derivation / Bump Validation**
   - All PDAs use canonical seeds and stored or recomputed bumps.
   - `bump = ...` constraints are present and consistent.
   - No alternate bump can be supplied to derive a different but valid PDA.

4. **Integer Overflow / Precision / Balance Manipulation**
   - All contribution totals use checked arithmetic: `checked_add`, `checked_sub`, `checked_mul`.
   - Token transfer amounts are validated against user balances and fundraiser limits.
   - Refund amounts cannot exceed recorded contributions.

5. **Re-initialization / Type Cosplay**
   - Initialized accounts are protected with `init` or explicit `is_initialized` checks.
   - Account discriminators are enforced.
   - No account can be reinitialized or repurposed through type confusion.

6. **Closing Accounts / Residual Lamport Drains**
   - Closed accounts zero data and drain lamports to a validated recipient.
   - Contribution accounts cannot be closed twice.
   - Refund flows cannot leave stale state that permits repeated withdrawals.
   - Vault/token accounts are closed only after all obligations are satisfied.

## Required Submission for Full Advisory

Please provide the complete `instructions`, `state`, `constants`, and `error` modules. A full advisory with exact vulnerable lines, exploitation scenario, Anchor/TypeScript PoC, and replacement Rust patch cannot be issued from the router-only snippet.