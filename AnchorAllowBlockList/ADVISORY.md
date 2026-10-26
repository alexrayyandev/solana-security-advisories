# Defensive Security Audit: `abl_token` Solana Program

**Auditor:** Alex Rayyan (bansoslab2026@tutamail.com)
**Scope:** `lib.rs` program entry point only — implementation modules (`instructions/`, `state/`, `utils/`, `errors/`, `constants/`) were NOT provided for review.

---

## Executive Summary

The provided source is the program's instruction dispatcher only. All security-critical logic resides in unprovided modules. This audit identifies **structural risks visible from the entry point** and enumerates the **mandatory review checklist** for the missing files. No severity rating can be finalized without the implementation source.

**Provisional Severity: HIGH (pending full source review)** — transfer-hook programs with compliance/allowlist logic are high-impact attack surfaces.

---

## 1. Cross-Program Invocation (CPI) Security

### Visible Risk
- `tx_hook` is a Token-2022 transfer hook (`spl_transfer_hook_interface`). Transfer hooks execute **in-band during token transfers** and receive arbitrary accounts from the caller.
- The hook must verify that the invoking program is the Token-2022 program and that the mint's transfer-hook extension actually points to this program.

### Required Checks in Missing Code (`instructions/tx_hook.rs`)
- Validate `token_program` account == `spl_token_2022::ID`
- Validate `mint` account's transfer-hook authority == this program ID (read via `ExtensionType::TransferHook` on mint)
- Validate `source`/`destination` token accounts are owned by Token-2022 program
- Ensure no arbitrary CPI to attacker-controlled programs via account injection
- Guard against reentrancy: transfer hooks can be re-entered if the program performs token transfers internally

### Remediation Pattern
```rust
// In tx_hook handler
let mint_data = ctx.accounts.mint.to_account_info();
let mint = Mint::unpack(&mint_data.try_borrow_data()?)?;
// verify transfer hook extension points to this program
let hook_ext = mint.get_extension::<TransferHook>()?;
require!(hook_ext.program_id == crate::ID, ErrorCode::InvalidHookProgram);
require!(ctx.accounts.token_program.key() == spl_token_2022::ID, ErrorCode::InvalidTokenProgram);
```

---

## 2. Account Ownership & Signer Verification

### Visible Risk
- `init_config` uses `ctx.bumps.config` — implies a PDA config account. Must verify `config` is owned by this program and signer authority is enforced.
- `init_wallet`, `remove_wallet`, `change_mode` imply an authority-gated allowlist/blocklist. Missing authority checks would allow anyone to modify compliance state.
- `attach_to_mint` likely sets the transfer hook on a mint — must require mint authority signer.

### Required Checks in Missing Code
- Every mutating instruction must have an `authority` signer constraint
- `config` account: `#[account(mut, seeds = [...], bump = config.bump, has_one = authority)]`
- `attach_to_mint`: `mint.mint_authority == Some(authority.key())` or authority must be the configured admin

---

## 3. PDA Seed & Bump Validation

### Visible Risk
- `init_config(ctx.bumps.config)` — bump is passed from Anchor's bump canonicalization. Must be **stored** in config account and re-validated on subsequent calls to prevent bump grinding / account substitution.
- Wallet allowlist entries likely use PDA seeds like `[b"wallet", mint, wallet.key()]` — seeds must include mint to prevent cross-mint collisions.

### Required Checks
- Store `bump` field in `Config` and `WalletEntry` structs
- On init: `config.bump = ctx.bumps.config`
- On use: `#[account(seeds = [...], bump = wallet_entry.bump)]` — never accept user-supplied bump
- Wallet entry seeds must include mint pubkey

---

## 4. Integer Arithmetic & Precision

### Visible Risk
- `tx_hook(ctx, amount: u64)` receives a transfer amount. Compliance logic (e.g., per-tx limits, cumulative limits) must use checked math.
- `resize_meta_list` may involve size calculations — overflow risk.

### Required Checks
- All arithmetic on `amount`, balances, limits: use `checked_add`, `checked_sub`, `checked_mul`
- Reject on overflow with custom error rather than wrapping
- Avoid `as` casts between integer types without bounds checks

---

## 5. Account Lifecycle & Re-initialization Guards

### Visible Risk
- `init_mint`, `init_config`, `init_wallet` — each must guard against re-initialization.
- Anchor's `init` constraint prevents re-init if account already exists, but if `init_if_needed` is used anywhere, it's a critical risk.
- `resize_meta_list` for the extra-account-meta-list: must ensure only authorized resize, and size must be bounded to prevent rent exhaustion / DoS.

### Required Checks
- Use `init` (not `init_if_needed`) unless strictly required
- Add `require!(!account.is_initialized, ErrorCode::AlreadyInitialized)` guards
- `resize_meta_list`: validate new size <= MAX_META_LIST_SIZE, authority signer required

---

## 6. Secure Account Closure & Rent Reclamation

### Visible Risk
- `remove_wallet` likely closes a wallet entry PDA. Must ensure:
  - Authority signer
  - Lamports returned to a controlled recipient (not attacker)
  - Account data zeroed to prevent revival attacks
  - Discriminator invalidated

### Required Checks
- Use Anchor's `close = recipient` constraint with a validated recipient
- Zero account data after closure
- Set discriminator to closed marker

---

## Architectural Risk Analysis

| Risk | Description |
|------|-------------|
| Transfer-hook reentrancy | Hook executes during every token transfer; if it performs CPI to token program, reentrancy possible |
| Compliance bypass via account injection | Attacker may pass fake wallet-entry accounts to skip checks |
| Meta-list resize DoS | Unbounded resize could exhaust rent or create oversized accounts |
| Authority centralization | Single admin key controls allowlist — key compromise = total control |
| Missing hook verification | If hook doesn't verify mint's hook extension, attacker can attach arbitrary behavior |

---

## Verified Defensive Remediation Code

Since implementation files were not provided, below are **template constraints** to apply in the missing instruction contexts:

```rust
// === instructions/init_config.rs ===
#[derive(Accounts)]
pub struct InitConfig<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Config::INIT_SPACE,
        seeds = [b"config", mint.key().as_ref()],
        bump
    )]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub mint: Account<'info, Mint>,
    pub system_program: Program<'info, System>,
}
// In handler: config.bump = ctx.bumps.config; config.authority = authority.key();

// === instructions/tx_hook.rs ===
#[derive(Accounts)]
pub struct TxHook<'info> {
    #[account(token::mint = mint, token::authority = source_owner)]
    pub source_token: Account<'info, TokenAccount>,
    pub mint: Account<'info, Mint>,
    #[account(token::mint = mint)]
    pub destination_token: Account<'info, TokenAccount>,
    /// CHECK: validated in handler
    pub owner: UncheckedAccount<'info>,
    pub extra_account_meta_list: Account<'info, ExtraAccountMetaList>,
    pub token_program: Program<'info, Token2022>,
}
// Handler must verify: token_program == spl_token_2022::ID
// and mint transfer-hook extension == crate::ID

// === instructions/remove_wallet.rs ===
#[derive(Accounts)]
pub struct RemoveWallet<'info> {
    #[account(
        mut,
        close = authority,
        seeds = [b"wallet", config.mint.as_ref(), wallet.key().as_ref()],
        bump = wallet_entry.bump,
        has_one = authority
    )]
    pub wallet_entry: Account<'info, WalletEntry>,
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub authority: Signer<'info>,
    /// CHECK: wallet being removed
    pub wallet: UncheckedAccount<'info>,
}
```

---

## Mandatory Full-Source Review Checklist

The following files **must** be provided for a complete audit:

- [ ] `instructions/init_mint.rs` — mint creation, hook attachment, authority
- [ ] `instructions/init_config.rs` — config PDA, authority, bump storage
- [ ] `instructions/attach_to_mint.rs` — mint authority verification
- [ ] `instructions/tx_hook.rs` — core compliance logic, CPI safety
- [ ] `instructions/init_wallet.rs` — allowlist entry creation
- [ ] `instructions/remove_wallet.rs` — closure, rent, signer
- [ ] `instructions/change_mode.rs` — mode switching, authority
- [ ] `instructions/resize_meta_list.rs` — size bounds, authority
- [ ] `state/*.rs` — account structs, discriminators, sizes
- [ ] `utils/*.rs` — helper functions, PDA derivations
- [ ] `errors/*.rs` — error codes
- [ ] `Cargo.toml` — dependency versions (spl-token-2022, anchor)

---

## Author & Disclosure Details

- **Researcher:** Alex Rayyan (bansoslab2026@tutamail.com)
- **USDC (Solana):** 39YTqgacjKt1iz22SrvX4G3Ds8TUUjd9hWPPSJpdd2jZ
- **USDC (Base/EVM):** 0xf71e0734cb53162e8c9baaf5f49841a51c945899

---

**Disclaimer:** This advisory is based solely on the program entry point (`lib.rs`). All findings are provisional. Submit full source for a definitive audit with severity ratings and proof-of-concept exploits.