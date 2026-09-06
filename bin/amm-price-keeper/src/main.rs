//! `amm-price-keeper`: holds the experimint AMM's BTC/USDt pool near an
//! external reference price.
//!
//! It is **not** an arbitrage bot. At the pool's depth there is no profitable
//! arbitrage to extract, so its mandate is price accuracy and its expected
//! P&L is negative: it pays the pool's fee, plus adverse selection, in
//! exchange for quoting a sane price to real users. `README.md` next to this
//! file is the operator-facing version;
//! `docs/superpowers/specs/2026-09-01-amm-price-keeper-design.md` is the
//! design this implements.
//!
//! The tick is: read the oracle, read the pool, read the balances, ask
//! [`policy::decide`], and — if it says so — place exactly one swap and wait
//! for it. Everything that decides anything is in [`policy`]; everything that
//! validates the feed is in [`oracle`]; this file is the client, the loop and
//! the flags.

mod exec;
mod oracle;
mod policy;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, bail, ensure};
use clap::Parser;
use fedimint_amm_client::AmmClientModule;
use fedimint_amm_common::config::AmmClientConfig;
use fedimint_amm_common::pool_id::PoolId;
use fedimint_bip39::{Bip39RootSecretStrategy, Mnemonic};
use fedimint_cli::envs::FM_CLIENT_DIR_ENV;
use fedimint_cli_experimint::experimint_modules;
use fedimint_client::module_init::ClientModuleInitRegistry;
use fedimint_client::secret::RootSecretStrategy as _;
use fedimint_client::{Client, ClientHandleArc, RootSecret};
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::Amount;
use fedimint_core::db::Database;
use fedimint_core::module::AmountUnit;
use fedimint_logging::TracingSetup;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info, warn};

use crate::oracle::DEFAULT_ORACLE_URL;
use crate::policy::{Balances, Decision, KeeperConfig, MinSwapIn, PoolState};

/// Holds the AMM's BTC/USDt pool near an external reference price.
///
/// Not an arbitrage bot: its expected P&L is negative, and its mandate is
/// price accuracy. Every flag also takes an environment variable, so it can
/// run from a systemd unit with nothing on the command line (design §8).
/// `README.md` is the operator guide.
#[derive(Debug, Parser)]
#[command(name = "amm-price-keeper", version)]
struct Opts {
    /// Client data dir: the rocksdb database and the seed of a wallet already
    /// joined to the federation and already funded in both units.
    ///
    /// The bot holds this open for its lifetime and is its sole writer — a
    /// concurrent `fedimint-cli-experimint` against the same directory will
    /// fail to open it.
    #[arg(long, env = FM_CLIENT_DIR_ENV)]
    data_dir: PathBuf,

    /// The price feed. Only its `BTC/USD` pair is read.
    #[arg(long, env = "AMM_KEEPER_ORACLE_URL", default_value = DEFAULT_ORACLE_URL)]
    oracle_url: String,

    /// Canonical `lo:hi` pool id. `lo` must be unit 0 (bitcoin, msats).
    #[arg(long, env = "AMM_KEEPER_POOL", default_value = "0:1", value_parser = parse_pool_id)]
    pool: PoolId,

    /// How often to look. The feed updates about once a minute.
    #[arg(long, env = "AMM_KEEPER_TICK_INTERVAL", default_value = "60s", value_parser = parse_duration)]
    tick_interval: Duration,

    /// Deadband half-width, in basis points. Must exceed the pool's fee: at
    /// `fee_per_mille = 3` a round trip burns ~60 bps, so a band under 30 bps
    /// pays fees to move the price nowhere (design §4.4).
    #[arg(long, env = "AMM_KEEPER_BAND_BPS", default_value_t = 50)]
    band_bps: u64,

    /// Per-tick size cap, in US dollars, converted to the input unit at the
    /// oracle price. Decimal, to six places: `12.50`.
    #[arg(long, env = "AMM_KEEPER_MAX_TRADE_USD", value_parser = parse_micro_usd)]
    max_trade_usd: u128,

    /// Never spend the bitcoin balance below this, in msats.
    #[arg(long, env = "AMM_KEEPER_BTC_FLOOR_MSAT", default_value_t = 0)]
    btc_floor_msat: u64,

    /// Never spend the USDt balance below this, in micros.
    #[arg(long, env = "AMM_KEEPER_USDT_FLOOR_MICROS", default_value_t = 0)]
    usdt_floor_micros: u64,

    /// Refuse to trade on a feed entry older than this.
    #[arg(long, env = "AMM_KEEPER_MAX_ORACLE_AGE", default_value = "300s", value_parser = parse_duration)]
    max_oracle_age: Duration,

    /// Refuse to trade on a rate that moved more than this, in percent,
    /// against the last accepted tick.
    #[arg(long, env = "AMM_KEEPER_MAX_RATE_JUMP_PCT", default_value_t = 10)]
    max_rate_jump_pct: u64,

    /// Passed to `amm.swap`, which re-quotes immediately before submitting and
    /// derives `min_out` itself. `0` would reject on any concurrent pool
    /// activity at all, including a guardian fee vote landing mid-rollout.
    #[arg(long, env = "AMM_KEEPER_MAX_SLIPPAGE_BPS", default_value_t = 50)]
    max_slippage_bps: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();

    TracingSetup::default()
        .with_base_level("info")
        .init()
        .context("tracing initializes")?;

    // Design §2: unit 0 is bitcoin in msats and unit 1 is USDt in micros, and
    // `policy`'s 10^11 decimal gap is only correct under that reading. The
    // pool id alone does not say so, so assert it rather than trust it.
    ensure!(
        opts.pool.lo() == AmountUnit::BITCOIN,
        "--pool must have unit 0 (bitcoin) as its low side, got {}:{}",
        opts.pool.lo().id(),
        opts.pool.hi().id()
    );

    let client = open_client(&opts.data_dir).await?;
    let amm_config = resolve_amm_config(&client, opts.pool).await?;
    let min_swap_in = MinSwapIn {
        lo: unit_params(&amm_config, opts.pool.lo())?,
        hi: unit_params(&amm_config, opts.pool.hi())?,
    };

    let amm = client.get_first_module::<AmmClientModule>()?;

    // Design §6: sweep anything a crash between Tx1 and Tx2 stranded, before
    // the first tick rather than after it.
    //
    // Retry on transient federation-connectivity errors. On a cold start the
    // iroh endpoint's DHT has not yet resolved the guardians' node ids to
    // addresses, so the very first federation RPC can fail with "Failed to
    // connect to peer" purely because the process is younger than the
    // connection setup. Aborting there (the `?` used to) made the unit
    // crash-loop under systemd, each restart cold again. Retry with backoff
    // until the endpoint is warm; give up only after a generous deadline so a
    // genuinely-unreachable federation still surfaces as a failure.
    let recovered = with_startup_retry("AMM startup recovery", || amm.recover()).await?;
    info!(
        balances_found = recovered.balances_found,
        balances_claimed = recovered.balances_claimed,
        positions_restored = recovered.positions_restored,
        claim_errors = recovered.claim_errors.len(),
        "startup recovery complete"
    );

    let mut keeper = Keeper {
        client: &client,
        amm: amm.inner(),
        http: reqwest::Client::new(),
        pool: opts.pool,
        min_swap_in,
        cfg: KeeperConfig {
            band_bps: opts.band_bps,
            max_trade_micro_usd: opts.max_trade_usd,
            btc_floor_msat: opts.btc_floor_msat,
            usdt_floor_micros: opts.usdt_floor_micros,
        },
        oracle_url: opts.oracle_url.clone(),
        max_oracle_age_secs: opts.max_oracle_age.as_secs(),
        max_rate_jump_pct: opts.max_rate_jump_pct,
        max_slippage_bps: opts.max_slippage_bps,
        last_rate_micro: None,
    };

    // Design §4.4: refuse to *start* with a band the fee swallows. Read from
    // the live pool, never from config. A pool that does not exist yet has no
    // fee to check against; every later tick re-checks through
    // `policy::decide`, which holds rather than trading if a fee vote ever
    // narrows the margin.
    match keeper.pool_fee().await {
        Ok(Some(fee_per_mille)) => policy::check_band_exceeds_fee(opts.band_bps, fee_per_mille)?,
        Ok(None) => warn!(
            pool = %format_pool(opts.pool),
            "pool does not exist yet; the band-versus-fee check will run on the first tick that finds it"
        ),
        Err(error) => bail!("could not read the pool at startup: {error}"),
    }

    info!(
        pool = %format_pool(opts.pool),
        band_bps = opts.band_bps,
        max_trade_usd = %format_micro_usd(opts.max_trade_usd),
        tick_interval_secs = opts.tick_interval.as_secs(),
        max_slippage_bps = opts.max_slippage_bps,
        oracle_url = %opts.oracle_url,
        "armed"
    );

    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    loop {
        // A tick is never interrupted: an in-flight swap's await runs to
        // completion, and only then is the shutdown signal observed (design
        // §6).
        keeper.tick().await;

        tokio::select! {
            _ = sigint.recv() => break,
            _ = sigterm.recv() => break,
            () = tokio::time::sleep(opts.tick_interval) => {}
        }
    }

    info!("shutting down");

    Ok(())
}

/// One tick's worth of state, plus everything it reads.
struct Keeper<'a> {
    client: &'a Client,
    amm: &'a AmmClientModule,
    http: reqwest::Client,
    pool: PoolId,
    min_swap_in: MinSwapIn,
    cfg: KeeperConfig,
    oracle_url: String,
    max_oracle_age_secs: u64,
    max_rate_jump_pct: u64,
    max_slippage_bps: u64,
    /// The last rate that passed every validation, for the jump check. The
    /// first tick has no predecessor and is accepted on staleness alone
    /// (design §6).
    last_rate_micro: Option<u128>,
}

impl Keeper<'_> {
    /// Reads, decides, and at most trades. Never returns an error: a tick that
    /// cannot read something holds, logs, and tries again next time (design
    /// §6, fail-closed).
    async fn tick(&mut self) {
        let Some(oracle_micro) = self.read_oracle().await else {
            return;
        };

        let pool_state = match self.read_pool().await {
            Ok(Some(pool_state)) => pool_state,
            Ok(None) => {
                warn!(pool = %format_pool(self.pool), "pool not found; holding");
                return;
            }
            Err(error) => {
                warn!(%error, "could not read the pool; holding");
                return;
            }
        };

        let balances = match self.read_balances().await {
            Ok(balances) => balances,
            Err(error) => {
                warn!(%error, "could not read balances; holding");
                return;
            }
        };

        let decision = policy::decide(
            &pool_state,
            self.min_swap_in,
            oracle_micro,
            balances,
            &self.cfg,
        );

        self.report(&pool_state, oracle_micro, balances, decision);

        let Decision::Trade {
            unit_in,
            unit_out,
            amount_in,
        } = decision
        else {
            return;
        };

        if let Err(error) = exec::execute_swap(
            self.amm,
            unit_in,
            unit_out,
            Amount::from_msats(amount_in),
            self.max_slippage_bps,
        )
        .await
        {
            // Tx1 rejected, or the transaction could not be built or
            // submitted. The next tick re-reads everything and decides again
            // from scratch; nothing here is carried forward.
            error!(%error, "swap failed");
        }
    }

    /// Fetches, parses and validates the reference price. `None` means this
    /// tick holds.
    async fn read_oracle(&mut self) -> Option<u128> {
        let body = match oracle::fetch(&self.http, &self.oracle_url).await {
            Ok(body) => body,
            Err(error) => {
                warn!(%error, "could not fetch the oracle; holding");
                return None;
            }
        };

        let price = match oracle::parse_feed(&body, unix_now(), self.max_oracle_age_secs) {
            Ok(price) => price,
            Err(error) => {
                warn!(%error, "oracle price refused; holding");
                return None;
            }
        };

        if let Some(previous) = self.last_rate_micro
            && let Err(error) =
                oracle::check_jump(previous, price.micro_usd_per_btc, self.max_rate_jump_pct)
        {
            warn!(%error, "oracle price refused; holding");
            return None;
        }

        self.last_rate_micro = Some(price.micro_usd_per_btc);

        Some(price.micro_usd_per_btc)
    }

    /// The pool's effective fee, or `None` if the pool does not exist yet.
    async fn pool_fee(&self) -> anyhow::Result<Option<u16>> {
        Ok(self.read_pool().await?.map(|pool| pool.fee_per_mille))
    }

    async fn read_pool(&self) -> anyhow::Result<Option<PoolState>> {
        Ok(self
            .amm
            .pools()
            .await?
            .into_iter()
            .find(|summary| summary.pool == self.pool)
            .map(|summary| PoolState {
                unit_lo: self.pool.lo(),
                unit_hi: self.pool.hi(),
                reserve_lo: summary.reserve_lo.msats,
                reserve_hi: summary.reserve_hi.msats,
                fee_per_mille: summary.fee_per_mille,
            }))
    }

    async fn read_balances(&self) -> anyhow::Result<Balances> {
        Ok(Balances {
            lo: self
                .client
                .get_balance_for_unit(self.pool.lo())
                .await?
                .msats,
            hi: self
                .client
                .get_balance_for_unit(self.pool.hi())
                .await?
                .msats,
        })
    }

    /// The tick's one log line. Prices are formatted by integer division —
    /// there is no float here either.
    fn report(
        &self,
        pool_state: &PoolState,
        oracle_micro: u128,
        balances: Balances,
        decision: Decision,
    ) {
        let pool_usd = policy::pool_price_micro_usd(pool_state.reserve_lo, pool_state.reserve_hi)
            .map_or_else(|| "-".to_owned(), format_micro_usd);
        let oracle_usd = format_micro_usd(oracle_micro);
        let dev_bps = policy::dev_bps(pool_state.reserve_lo, pool_state.reserve_hi, oracle_micro)
            .map_or_else(|| "-".to_owned(), |deviation| deviation.to_string());
        let fee_per_mille = u64::from(pool_state.fee_per_mille);

        // One arm per level, through a macro taking the level and the reason,
        // so the field list exists once. `reason` has to be a macro argument:
        // a name written in the body would resolve at the definition site,
        // where the match arm's binding does not exist.
        macro_rules! hold_line {
            ($level:ident, $reason:expr) => {
                tracing::$level!(
                    pool_usd = %pool_usd,
                    oracle_usd = %oracle_usd,
                    dev_bps = %dev_bps,
                    fee_per_mille,
                    reserve_lo = pool_state.reserve_lo,
                    reserve_hi = pool_state.reserve_hi,
                    balance_lo = balances.lo,
                    balance_hi = balances.hi,
                    reason = ?$reason,
                    "holding"
                )
            };
        }

        match decision {
            Decision::Trade {
                unit_in, amount_in, ..
            } => {
                let lands_at_usd = policy::apply_trade(pool_state, unit_in, amount_in)
                    .and_then(|(reserve_lo, reserve_hi)| {
                        policy::pool_price_micro_usd(reserve_lo, reserve_hi)
                    })
                    .map_or_else(|| "-".to_owned(), format_micro_usd);

                info!(
                    pool_usd = %pool_usd,
                    oracle_usd = %oracle_usd,
                    dev_bps = %dev_bps,
                    fee_per_mille,
                    unit_in = unit_in.id(),
                    amount_in,
                    lands_at_usd = %lands_at_usd,
                    "trading"
                );
            }
            Decision::Hold(reason) if reason.is_warning() => hold_line!(warn, reason),
            Decision::Hold(reason) => hold_line!(info, reason),
        }
    }
}

/// Opens the client the data dir has already joined to a federation.
///
/// The same sequence `bin/fedimint-cli-experimint`'s `info` uses — same
/// `client.db` filename, same `Bip39RootSecretStrategy`, same
/// [`experimint_modules`] registry — so a data dir is readable by either
/// binary and a module this bot cannot build is one the CLI could not build
/// either.
async fn open_client(data_dir: &Path) -> anyhow::Result<ClientHandleArc> {
    let db: Database = fedimint_rocksdb::RocksDb::build(data_dir.join("client.db"))
        .open()
        .await
        .context("could not open rocksdb database (is another client holding it open?)")?
        .into();

    let entropy = Client::load_decodable_client_secret_opt::<Vec<u8>>(&db)
        .await?
        .context("encoded client secret not present in DB; join a federation first")?;

    let root_secret = RootSecret::StandardDoubleDerive(
        Bip39RootSecretStrategy::<12>::to_root_secret(&Mnemonic::from_entropy(&entropy)?),
    );

    let mut builder = Client::builder().await?.with_iroh_enable_dht(true);
    builder.with_module_inits(experimint_modules(ClientModuleInitRegistry::new()));

    let connectors = ConnectorRegistry::build_from_client_defaults()
        .iroh_pkarr_dht(true)
        .bind()
        .await?;

    Ok(Arc::new(builder.open(connectors, db, root_secret).await?))
}

/// The AMM's client config, from the federation's *one* `amm` instance.
///
/// Resolved by kind, and **fails if the federation reports more than one**
/// rather than silently taking the lowest id the way `get_first_instance`
/// would (design §5). The topology this bot targets runs exactly one `amm`;
/// a second one would mean two markets and no way to tell from a flag which
/// was meant.
async fn resolve_amm_config(client: &Client, pool: PoolId) -> anyhow::Result<AmmClientConfig> {
    let config = client.config().await;

    let instances: Vec<_> = config
        .modules
        .iter()
        .filter(|(_, module)| module.kind == fedimint_amm_common::KIND)
        .map(|(id, _)| *id)
        .collect();

    let [instance] = instances[..] else {
        bail!(
            "expected exactly one `amm` instance, found {}: {instances:?}",
            instances.len()
        );
    };

    let amm_config = config.get_module::<AmmClientConfig>(instance)?.clone();

    for unit in [pool.lo(), pool.hi()] {
        ensure!(
            amm_config.units.contains_key(&unit),
            "unit {} is not in the AMM's allowlist",
            unit.id()
        );
    }

    info!(instance, pool = %format_pool(pool), "resolved the AMM instance");

    Ok(amm_config)
}

fn unit_params(config: &AmmClientConfig, unit: AmountUnit) -> anyhow::Result<u64> {
    Ok(config
        .units
        .get(&unit)
        .with_context(|| format!("unit {} is not in the AMM's allowlist", unit.id()))?
        .min_swap_in
        .msats)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        })
}

/// `"0:1"`, the form the CLI and the AMM's own config use.
fn format_pool(pool: PoolId) -> String {
    format!("{}:{}", pool.lo().id(), pool.hi().id())
}

/// Micro-USD as dollars and six decimals, by integer division — the log lines
/// are the other place design §3 permits a float, and they do not need one.
fn format_micro_usd(micro: u128) -> String {
    format!("{}.{:06}", micro / 1_000_000, micro % 1_000_000)
}

/// `"lo:hi"` with `lo < hi`, the canonical form (AMM spec §5.1).
fn parse_pool_id(value: &str) -> Result<PoolId, String> {
    let (lo, hi) = value
        .split_once(':')
        .ok_or_else(|| format!("expected `lo:hi`, got {value:?}"))?;

    let lo: u64 = lo.parse().map_err(|_| format!("{lo:?} is not a unit id"))?;
    let hi: u64 = hi.parse().map_err(|_| format!("{hi:?} is not a unit id"))?;

    PoolId::new(AmountUnit::new_custom(lo), AmountUnit::new_custom(hi))
        .filter(|_| lo < hi)
        .ok_or_else(|| format!("a pool id must be canonical (`lo:hi` with lo < hi), got {value:?}"))
}

/// `"90"`, `"90s"`, `"5m"` or `"2h"`. Bare digits are seconds.
fn parse_duration(value: &str) -> Result<Duration, String> {
    let (digits, multiplier) = match value.as_bytes().last() {
        Some(b's') => (&value[..value.len() - 1], 1),
        Some(b'm') => (&value[..value.len() - 1], 60),
        Some(b'h') => (&value[..value.len() - 1], 3_600),
        _ => (value, 1),
    };

    let amount: u64 = digits
        .parse()
        .map_err(|_| format!("expected a duration like `60s`, `5m` or `2h`, got {value:?}"))?;

    amount
        .checked_mul(multiplier)
        .map(Duration::from_secs)
        .ok_or_else(|| format!("{value:?} is too long"))
}

/// A decimal number of US dollars -> micro-USD. `"12.5"` is 12 500 000.
///
/// Parsed digit by digit rather than through `f64`: this figure is a clamp on
/// how much money the bot may move, and design §3 keeps floats off every path
/// that decides anything.
fn parse_micro_usd(value: &str) -> Result<u128, String> {
    let invalid = || format!("expected a dollar amount like `12.50`, got {value:?}");

    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));

    if whole.is_empty() && fraction.is_empty() {
        return Err(invalid());
    }
    if !whole.bytes().all(|b| b.is_ascii_digit()) || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    if fraction.len() > 6 {
        return Err(format!(
            "a dollar amount has at most six decimal places (micro-USD), got {value:?}"
        ));
    }

    let whole: u128 = if whole.is_empty() {
        0
    } else {
        whole.parse().map_err(|_| invalid())?
    };
    let fraction: u128 = if fraction.is_empty() {
        0
    } else {
        // `"5"` is five tenths, i.e. 500 000 micro-USD.
        fraction.parse::<u128>().map_err(|_| invalid())?
            * 10u128.pow(6 - u32::try_from(fraction.len()).map_err(|_| invalid())?)
    };

    whole
        .checked_mul(1_000_000)
        .and_then(|micro| micro.checked_add(fraction))
        .ok_or_else(|| format!("{value:?} is too large"))
}

/// Retry a connectivity-dependent startup step with exponential backoff until
/// it succeeds or a deadline passes. Exists because a freshly-started process
/// races its own iroh DHT bootstrap: the first federation RPC can fail with a
/// transient "Failed to connect to peer" that a retry a few seconds later
/// resolves. Without this a single such failure aborted `main`, and systemd's
/// restart turned it into a cold-start crash-loop.
async fn with_startup_retry<T, F, Fut>(what: &str, mut op: F) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    let deadline = std::time::Instant::now() + Duration::from_secs(300);
    let mut delay = Duration::from_secs(2);
    loop {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) if std::time::Instant::now() < deadline => {
                warn!(
                    step = what,
                    err = %err,
                    retry_in_secs = delay.as_secs(),
                    "startup step failed (federation likely not yet reachable); retrying"
                );
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(30));
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("{what} still failing after the startup retry deadline")
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pool_id_must_be_canonical() {
        let pool = parse_pool_id("0:1").expect("canonical");
        assert_eq!(pool.lo(), AmountUnit::BITCOIN);
        assert_eq!(pool.hi(), AmountUnit::new_custom(1));
        assert_eq!(format_pool(pool), "0:1");

        for value in ["1:0", "1:1", "0", "0:", ":1", "0:1:2", "a:b", "-1:1"] {
            assert!(parse_pool_id(value).is_err(), "{value:?} was accepted");
        }
    }

    #[test]
    fn durations_take_a_unit_suffix() {
        assert_eq!(parse_duration("60"), Ok(Duration::from_secs(60)));
        assert_eq!(parse_duration("60s"), Ok(Duration::from_secs(60)));
        assert_eq!(parse_duration("5m"), Ok(Duration::from_secs(300)));
        assert_eq!(parse_duration("2h"), Ok(Duration::from_secs(7_200)));
        assert_eq!(parse_duration("0s"), Ok(Duration::ZERO));

        for value in ["", "s", "-1s", "1.5m", "1d", "60 s"] {
            assert!(parse_duration(value).is_err(), "{value:?} was accepted");
        }
    }

    #[test]
    fn dollars_parse_to_micro_usd_without_a_float() {
        assert_eq!(parse_micro_usd("1"), Ok(1_000_000));
        assert_eq!(parse_micro_usd("12.50"), Ok(12_500_000));
        assert_eq!(parse_micro_usd("12.5"), Ok(12_500_000));
        assert_eq!(parse_micro_usd("0.000001"), Ok(1));
        assert_eq!(parse_micro_usd(".5"), Ok(500_000));
        assert_eq!(parse_micro_usd("0"), Ok(0));

        for value in ["", ".", "-1", "1.2345678", "1e6", "1,5", "abc"] {
            assert!(parse_micro_usd(value).is_err(), "{value:?} was accepted");
        }
    }

    #[test]
    fn micro_usd_formats_as_dollars() {
        assert_eq!(format_micro_usd(0), "0.000000");
        assert_eq!(format_micro_usd(12_500_000), "12.500000");
        assert_eq!(format_micro_usd(77_785_250_000), "77785.250000");
    }

    /// The defaults design §8's table names, pinned so that changing one is a
    /// deliberate act rather than a typo.
    #[test]
    fn the_documented_defaults_are_what_clap_produces() {
        let opts = Opts::try_parse_from([
            "amm-price-keeper",
            "--data-dir",
            "/tmp/keeper",
            "--max-trade-usd",
            "25",
        ])
        .expect("the two required flags are enough");

        assert_eq!(opts.oracle_url, DEFAULT_ORACLE_URL);
        assert_eq!(format_pool(opts.pool), "0:1");
        assert_eq!(opts.tick_interval, Duration::from_secs(60));
        assert_eq!(opts.band_bps, 50);
        assert_eq!(opts.max_trade_usd, 25_000_000);
        assert_eq!(opts.btc_floor_msat, 0);
        assert_eq!(opts.usdt_floor_micros, 0);
        assert_eq!(opts.max_oracle_age, Duration::from_secs(300));
        assert_eq!(opts.max_rate_jump_pct, 10);
        assert_eq!(opts.max_slippage_bps, 50);
    }

    /// `--max-trade-usd` has no default on purpose: a size cap chosen on the
    /// operator's behalf is a decision about how much money the bot may move.
    #[test]
    fn the_size_cap_is_required() {
        Opts::try_parse_from(["amm-price-keeper", "--data-dir", "/tmp/keeper"])
            .expect_err("--max-trade-usd has no default");
    }
}
