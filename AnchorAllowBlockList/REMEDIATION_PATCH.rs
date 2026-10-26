// In tx_hook handler
let mint_data = ctx.accounts.mint.to_account_info();
let mint = Mint::unpack(&mint_data.try_borrow_data()?)?;
// verify transfer hook extension points to this program
let hook_ext = mint.get_extension::<TransferHook>()?;
require!(hook_ext.program_id == crate::ID, ErrorCode::InvalidHookProgram);
require!(ctx.accounts.token_program.key() == spl_token_2022::ID, ErrorCode::InvalidTokenProgram);