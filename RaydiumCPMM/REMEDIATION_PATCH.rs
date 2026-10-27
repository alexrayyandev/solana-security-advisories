assert!(trade_fee_rate + creator_fee_rate < FEE_RATE_DENOMINATOR_VALUE);
assert!(protocol_fee_rate <= FEE_RATE_DENOMINATOR_VALUE);
assert!(fund_fee_rate <= FEE_RATE_DENOMINATOR_VALUE);
assert!(fund_fee_rate + protocol_fee_rate <= FEE_RATE_DENOMINATOR_VALUE);