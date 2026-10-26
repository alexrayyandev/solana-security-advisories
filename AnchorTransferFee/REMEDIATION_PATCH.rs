#[derive(Accounts)]
pub struct Example<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        mut,
        has_one = authority,
        owner = crate::ID
    )]
    pub state: Account<'info, State>,

    pub token_program: Program<'info, Token>,
}