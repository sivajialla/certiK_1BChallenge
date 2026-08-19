// Extracted from program/src/processor.rs (blockworks-foundation/mango-v3,
// commit 43963f0f8a, the pre-incident state - last commit to this file before
// the Oct 11 2022 exploit, never patched afterward).
//
// Only the withdraw/withdraw2 instruction handlers and the oracle price-reading
// path (read_oracle, cache_prices) are included - these are the exact functions
// through which the attacker's inflated unrealized-PnL health let them withdraw
// real assets. The full file is 8,737 lines covering ~100 unrelated instruction
// handlers (place_spot_order, liquidate variants, settle_funds, group/market
// initialization, etc.) trimmed for scan.

use crate::error::{check, throw_err, MangoErrorCode, MangoResult};

// --- cache_prices (processor.rs:1063-1103) ---
    fn cache_prices(program_id: &Pubkey, accounts: &[AccountInfo]) -> MangoResult<()> {
        const NUM_FIXED: usize = 2;
        let (fixed_ais, oracle_ais) = array_refs![accounts, NUM_FIXED; ..;];
        let [
            mango_group_ai,     // read
            mango_cache_ai,     // write
        ] = fixed_ais;
        let mango_group = MangoGroup::load_checked(mango_group_ai, program_id)?;
        let mut mango_cache =
            MangoCache::load_mut_checked(mango_cache_ai, program_id, &mango_group)?;
        let clock = Clock::get()?;
        let last_update = clock.unix_timestamp as u64;

        let mut oracle_indexes = Vec::new();
        let mut oracle_prices = Vec::new();
        for oracle_ai in oracle_ais.iter() {
            let oracle_index = mango_group.find_oracle_index(oracle_ai.key).ok_or(throw!())?;

            if let Ok(price) = read_oracle(
                &mango_group,
                oracle_index,
                oracle_ai,
                mango_cache.price_cache[oracle_index].price,
            ) {
                mango_cache.price_cache[oracle_index] = PriceCache { price, last_update };

                oracle_indexes.push(oracle_index as u64);
                oracle_prices.push(price.to_bits());
            } else {
                msg!("Failed CachePrice for oracle_index: {}", oracle_index);
            }
        }

        mango_emit_heap!(CachePricesLog {
            mango_group: *mango_group_ai.key,
            oracle_indexes,
            oracle_prices
        });

        Ok(())
    }


// --- withdraw (processor.rs:1192-1299) ---
    fn withdraw(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        quantity: u64,
        allow_borrow: bool,
    ) -> MangoResult<()> {
        const NUM_FIXED: usize = 10;
        let accounts = array_ref![accounts, 0, NUM_FIXED + MAX_PAIRS];
        let (fixed_ais, open_orders_ais) = array_refs![accounts, NUM_FIXED, MAX_PAIRS];
        let [
            mango_group_ai,     // read
            mango_account_ai,   // write
            owner_ai,           // read
            mango_cache_ai,     // read
            root_bank_ai,       // read
            node_bank_ai,       // write
            vault_ai,           // write
            token_account_ai,   // write
            signer_ai,          // read
            token_prog_ai,      // read
        ] = fixed_ais;
        check_eq!(&spl_token::ID, token_prog_ai.key, MangoErrorCode::InvalidProgramId)?;

        let mango_group = MangoGroup::load_checked(mango_group_ai, program_id)?;
        check!(signer_ai.key == &mango_group.signer_key, MangoErrorCode::InvalidSignerKey)?;

        let mut mango_account =
            MangoAccount::load_mut_checked(mango_account_ai, program_id, mango_group_ai.key)?;
        check!(&mango_account.owner == owner_ai.key, MangoErrorCode::InvalidOwner)?;
        check!(!mango_account.is_bankrupt, MangoErrorCode::Bankrupt)?;
        check!(owner_ai.is_signer, MangoErrorCode::SignerNecessary)?;
        mango_account.check_open_orders(&mango_group, open_orders_ais)?;

        let root_bank = RootBank::load_checked(root_bank_ai, program_id)?;
        let token_index = mango_group
            .find_root_bank_index(root_bank_ai.key)
            .ok_or(throw_err!(MangoErrorCode::InvalidToken))?;

        let mode = mango_group.tokens[token_index].spot_market_mode;
        check!(!(mode.is_reduce_only() && allow_borrow), MangoErrorCode::InvalidAllowBorrow)?;

        let mut node_bank = NodeBank::load_mut_checked(node_bank_ai, program_id)?;
        check!(root_bank.node_banks.contains(node_bank_ai.key), MangoErrorCode::InvalidNodeBank)?;
        let clock = Clock::get()?;
        let now_ts = clock.unix_timestamp as u64;

        // Safety checks
        check_eq!(&node_bank.vault, vault_ai.key, MangoErrorCode::InvalidVault)?;

        let active_assets = UserActiveAssets::new(
            &mango_group,
            &mango_account,
            vec![(AssetType::Token, token_index)],
        );
        let mango_cache = MangoCache::load_checked(mango_cache_ai, program_id, &mango_group)?;
        mango_cache.check_valid(&mango_group, &active_assets, now_ts)?;

        let root_bank_cache = &mango_cache.root_bank_cache[token_index];

        let native_deposit = mango_account.get_native_deposit(root_bank_cache, token_index)?;
        // if quantity is u64 max, interpret as a request to get all
        let (withdraw, quantity) = if quantity == u64::MAX && !allow_borrow {
            let floored = native_deposit.checked_floor().unwrap();
            (floored, floored.to_num::<u64>())
        } else {
            (I80F48::from_num(quantity), quantity)
        };

        // Borrow if withdrawing more than deposits
        check!(native_deposit >= withdraw || allow_borrow, MangoErrorCode::InsufficientFunds)?;
        checked_change_net(
            root_bank_cache,
            &mut node_bank,
            &mut mango_account,
            mango_account_ai.key,
            token_index,
            -withdraw,
        )?;

        let signers_seeds = gen_signer_seeds(&mango_group.signer_nonce, mango_group_ai.key);
        invoke_transfer(
            token_prog_ai,
            vault_ai,
            token_account_ai,
            signer_ai,
            &[&signers_seeds],
            quantity,
        )?;

        let mut health_cache = HealthCache::new(active_assets);
        health_cache.init_vals(&mango_group, &mango_cache, &mango_account, open_orders_ais)?;
        let health = health_cache.get_health(&mango_group, HealthType::Init);

        check!(health >= ZERO_I80F48, MangoErrorCode::InsufficientFunds)?;

        // If health is above Init then being liquidated should be false anyway
        mango_account.being_liquidated = false;

        mango_emit_heap!(WithdrawLog {
            mango_group: *mango_group_ai.key,
            mango_account: *mango_account_ai.key,
            owner: *owner_ai.key,
            token_index: token_index as u64,
            quantity,
        });

        Ok(())
    }


// --- withdraw2 (processor.rs:1303-1417) ---
    fn withdraw2(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        quantity: u64,
        allow_borrow: bool,
    ) -> MangoResult<()> {
        const NUM_FIXED: usize = 10;
        let (fixed_ais, packed_open_orders_ais) = array_refs![accounts, NUM_FIXED; ..;];
        let [
            mango_group_ai,     // read
            mango_account_ai,   // write
            owner_ai,           // read
            mango_cache_ai,     // read
            root_bank_ai,       // read
            node_bank_ai,       // write
            vault_ai,           // write
            token_account_ai,   // write
            signer_ai,          // read
            token_prog_ai,      // read
        ] = fixed_ais;
        check_eq!(&spl_token::ID, token_prog_ai.key, MangoErrorCode::InvalidProgramId)?;

        let mango_group = MangoGroup::load_checked(mango_group_ai, program_id)?;
        check!(signer_ai.key == &mango_group.signer_key, MangoErrorCode::InvalidSignerKey)?;

        let mut mango_account =
            MangoAccount::load_mut_checked(mango_account_ai, program_id, mango_group_ai.key)?;
        check!(&mango_account.owner == owner_ai.key, MangoErrorCode::InvalidOwner)?;
        check!(!mango_account.is_bankrupt, MangoErrorCode::Bankrupt)?;
        check!(owner_ai.is_signer, MangoErrorCode::SignerNecessary)?;

        let root_bank = RootBank::load_checked(root_bank_ai, program_id)?;
        let token_index = mango_group
            .find_root_bank_index(root_bank_ai.key)
            .ok_or(throw_err!(MangoErrorCode::InvalidToken))?;

        let mode = mango_group.tokens[token_index].spot_market_mode;
        check!(!(mode.is_reduce_only() && allow_borrow), MangoErrorCode::InvalidAllowBorrow)?;

        let mut node_bank = NodeBank::load_mut_checked(node_bank_ai, program_id)?;
        check!(root_bank.node_banks.contains(node_bank_ai.key), MangoErrorCode::InvalidNodeBank)?;
        let clock = Clock::get()?;
        let now_ts = clock.unix_timestamp as u64;

        // Safety checks
        check_eq!(&node_bank.vault, vault_ai.key, MangoErrorCode::InvalidVault)?;

        let open_orders_ais =
            mango_account.checked_unpack_open_orders(&mango_group, packed_open_orders_ais)?;
        let open_orders_accounts = load_open_orders_accounts(&open_orders_ais)?;

        let active_assets = UserActiveAssets::new(
            &mango_group,
            &mango_account,
            vec![(AssetType::Token, token_index)],
        );
        let mango_cache = MangoCache::load_checked(mango_cache_ai, program_id, &mango_group)?;
        mango_cache.check_valid(&mango_group, &active_assets, now_ts)?;

        let root_bank_cache = &mango_cache.root_bank_cache[token_index];

        let native_deposit = mango_account.get_native_deposit(root_bank_cache, token_index)?;
        // if quantity is u64 max, interpret as a request to get all
        let (withdraw, quantity) = if quantity == u64::MAX && !allow_borrow {
            let floored = native_deposit.checked_floor().unwrap();
            (floored, floored.to_num::<u64>())
        } else {
            (I80F48::from_num(quantity), quantity)
        };

        // Borrow if withdrawing more than deposits
        check!(native_deposit >= withdraw || allow_borrow, MangoErrorCode::InsufficientFunds)?;
        checked_change_net(
            root_bank_cache,
            &mut node_bank,
            &mut mango_account,
            mango_account_ai.key,
            token_index,
            -withdraw,
        )?;

        let signers_seeds = gen_signer_seeds(&mango_group.signer_nonce, mango_group_ai.key);
        invoke_transfer(
            token_prog_ai,
            vault_ai,
            token_account_ai,
            signer_ai,
            &[&signers_seeds],
            quantity,
        )?;

        let mut health_cache = HealthCache::new(active_assets);
        health_cache.init_vals_with_orders_vec(
            &mango_group,
            &mango_cache,
            &mango_account,
            &open_orders_accounts,
        )?;
        let health = health_cache.get_health(&mango_group, HealthType::Init);

        check!(health >= ZERO_I80F48, MangoErrorCode::InsufficientFunds)?;

        // If health is above Init then being liquidated should be false anyway
        mango_account.being_liquidated = false;

        mango_emit_heap!(WithdrawLog {
            mango_group: *mango_group_ai.key,
            mango_account: *mango_account_ai.key,
            owner: *owner_ai.key,
            token_index: token_index as u64,
            quantity,
        });

        Ok(())
    }


// --- read_oracle (processor.rs:8128-8202) ---
pub fn read_oracle(
    mango_group: &MangoGroup,
    token_index: usize,
    oracle_ai: &AccountInfo,
    last_known_price_in_cache: I80F48,
) -> MangoResult<I80F48> {
    let quote_decimals = mango_group.tokens[QUOTE_INDEX].decimals as i32;
    let base_decimals = mango_group.tokens[token_index].decimals as i32;

    let oracle_type = determine_oracle_type(oracle_ai);

    let price = match oracle_type {
        OracleType::Pyth => {
            let oracle_data = oracle_ai.try_borrow_data()?;
            let price_account = pyth_client::load_price(&oracle_data).unwrap();
            let value = I80F48::from_num(price_account.agg.price);

            // Filter out bad prices on mainnet
            #[cfg(not(feature = "devnet"))]
            let conf = I80F48::from_num(price_account.agg.conf).checked_div(value).unwrap();

            #[cfg(not(feature = "devnet"))]
            if conf > PYTH_CONF_FILTER {
                msg!(
                    "Pyth conf interval too high; oracle index: {} value: {} conf: {}",
                    token_index,
                    value.to_num::<f64>(),
                    conf.to_num::<f64>()
                );

                // For luna, to prevent market from getting stuck, just continue using last known price in cache
                if oracle_ai.key == &luna_pyth_oracle::ID {
                    return Ok(last_known_price_in_cache);
                }

                return Err(throw_err!(MangoErrorCode::InvalidOraclePrice));
            }

            let decimals = quote_decimals
                .checked_add(price_account.expo)
                .unwrap()
                .checked_sub(base_decimals)
                .unwrap();

            let decimal_adj = I80F48::from_num(10u64.pow(decimals.abs() as u32));
            if decimals < 0 {
                value.checked_div(decimal_adj).unwrap()
            } else {
                value.checked_mul(decimal_adj).unwrap()
            }
        }
        OracleType::Stub => {
            let oracle = StubOracle::load(oracle_ai)?;
            I80F48::from_num(oracle.price)
        }
        OracleType::Switchboard => {
            let result =
                FastRoundResultAccountData::deserialize(&oracle_ai.try_borrow_data()?).unwrap();
            let value = I80F48::from_num(result.result.result);

            let decimals = quote_decimals.checked_sub(base_decimals).unwrap();
            if decimals < 0 {
                let decimal_adj = I80F48::from_num(10u64.pow(decimals.abs() as u32));
                value.checked_div(decimal_adj).unwrap()
            } else if decimals > 0 {
                let decimal_adj = I80F48::from_num(10u64.pow(decimals.abs() as u32));
                value.checked_mul(decimal_adj).unwrap()
            } else {
                value
            }
        }
        OracleType::Unknown => return Err(throw_err!(MangoErrorCode::InvalidOracleType)),
    };
    Ok(price)
}


