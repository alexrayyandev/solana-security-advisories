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