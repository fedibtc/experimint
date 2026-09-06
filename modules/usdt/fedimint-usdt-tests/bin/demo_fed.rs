//! Long-running local regtest demo federation carrying the full experimint
//! module set, for testing clients against.
//!
//! Modeled on `usdt_e2e.rs` (same `devimint` + `anvil` harness, same
//! Part A/Part B ERC-4337 bootstrap), but instead of running a scripted
//! deposit->claim flow it stands the federation up, prints the invite code
//! and the chain fixtures, and then parks until Ctrl-C, leaving four
//! guardians serving their APIs for any client to join and poke at.
//!
//! # Topology
//!
//! The full intended experimint topology, **eight instances** across the
//! seven kinds: `walletv2`, **two `mintv2` instances** (BTC unit 0 and USDT
//! unit 1 — so both peg-in ecash and claimed USDT ecash work), `lnv2`,
//! `usdt` (against a real local `anvil` with a freshly deployed test
//! ERC-20 + ERC-4337 EntryPoint), `amm`, `meta`, and
//! `multi_sig_stability_pool` under its **test params** (mock BTC/USD
//! oracle, 15s cycles — no outbound HTTP, fast feedback for
//! multispend-style clients).
//!
//! devimint's own config-gen helper cannot express a second instance of one
//! kind, so this binary spawns the guardians with `pre_dkg` and drives
//! config-gen itself: the same DKG sequence as `run_cli_dkg_v2`, but the
//! leader's `set-local-params` carries the fork's repeatable `--module`
//! instance list (see `run_dkg_with_module_list`).
//!
//! One deviation from a production deployment remains: **no Lightning
//! gateway** — `lnv2` boots and appears in the config, but nothing routes.
//!
//! # Iroh
//!
//! The federation runs the iroh networking stack by default (set
//! `FM_ENABLE_IROH=0` for a websocket fed). devimint pre-generates every
//! guardian's iroh node keys and exports `FM_IROH_CONNECT_OVERRIDES_PLAIN`
//! mapping each node id to `127.0.0.1:<port>`, so neither guardians nor
//! clients need a relay or external DNS — but that mapping lives in env, so
//! client processes must `source <test-dir>/env` (or export the override var
//! printed at startup) before joining.
//!
//! # Running
//!
//! Needs `bitcoind`/`bitcoin-cli` and `anvil` on PATH, plus the two
//! experimint binaries via env (devimint would otherwise look for stock
//! `fedimintd`/`fedimint-cli` names):
//!
//! ```text
//! cargo build -p fedimintd-experimint -p fedimint-cli-experimint \
//!     -p fedimint-usdt-tests
//! FM_FEDIMINTD_BASE_EXECUTABLE=target/debug/fedimintd-experimint \
//! FM_FEDIMINT_CLI_BASE_EXECUTABLE=target/debug/fedimint-cli-experimint \
//!     cargo run -p fedimint-usdt-tests --bin demo-fed
//! ```

use std::collections::BTreeMap;
use std::ffi;
use std::ops::ControlFlow;
use std::time::Duration;

use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use anyhow::Context;
use clap::Parser;
use devimint::cli::{self, cleanup_on_exit};
use devimint::cmd;
use devimint::envs::FM_DEVIMINT_CONFIG_GEN_TIMEOUT_SECS_ENV;
use devimint::external::{Anvil, Bitcoind};
use devimint::federation::Federation;
use devimint::util::{FedimintCli, poll, poll_with_timeout};
use fedimint_core::PeerId;
use fedimint_core::envs::{
    FM_USDT_BROADCASTER_PRIVATE_KEY_ENV, FM_USDT_CONTRACT_ENV, FM_USDT_ENTRY_POINT_ENV,
    FM_USDT_ETH_USD_PRICE_FEED_ENV,
};
use fedimint_core::module::ApiAuth;
use fedimint_server_core::ServerModuleInit;
use fedimint_usdt_common::{EvmAddress, UsdtAmount};
use tracing::info;

/// The spv2 test-params env var name, spelled as a string literal because its
/// constant lives in `stability_pool_server::envs` (a git dep of the
/// *binaries*, not of this test crate) and one string does not justify
/// pulling the whole server module into the test crate's dependency graph.
const FM_SPV2_TEST_PARAMS: &str = "FM_SPV2_TEST_PARAMS";

/// `fedimintd`'s iroh switch (`fedimintd_envs::FM_ENABLE_IROH_ENV`), spelled
/// as a literal for the same reason as the spv2 vars above.
const FM_ENABLE_IROH: &str = "FM_ENABLE_IROH";

#[derive(Parser)]
#[command(name = "demo-fed")]
#[command(
    about = "Long-running local regtest federation with the full experimint module set (incl. spv2)",
    long_about = None
)]
struct Cli {}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _cli = Cli::parse();

    let args = cli::CommonArgs::parse_from::<_, ffi::OsString>(vec![]);
    let (process_mgr, task_group) = cli::setup(args).await?;

    let main = async {

        info!("Starting bitcoind + anvil...");
        let bitcoind = Bitcoind::new(&process_mgr, false).await?;
        let anvil = Anvil::new(&process_mgr).await?;

        info!("Deploying the test ERC-20 and minting a supply to account 1...");
        let holder = account_1_address()?;
        let token = deploy_test_erc20(&anvil, holder, UsdtAmount(10_000_000_000)).await?;

        // Part A: deploy ONLY the EntryPoint (canonical; the module
        // self-deploys its factory + impl from it at startup). See
        // `usdt_e2e.rs` for the full reasoning.
        info!("Deploying the ERC-4337 EntryPoint...");
        let entry_point = deploy_entry_point(&anvil).await?;

        // SAFETY: single-threaded at this point, and set before any
        // `fedimintd` subprocess is spawned below -- env vars are captured at
        // process-spawn time, so every guardian inherits these.
        unsafe {
            // The usdt module's threshold-ECDSA DKG exceeds devimint's
            // default 60s config-gen timeout.
            std::env::set_var(FM_DEVIMINT_CONFIG_GEN_TIMEOUT_SECS_ENV, "300");

            // The module instance list is passed explicitly to the config-gen
            // leader below (`--module ...`), so no FM_ENABLE_MODULE_* vars are
            // needed — those only shape the *default* list.

            // spv2 under test params: mock oracle (no outbound HTTP from the
            // guardians) and 15s cycles, so multispend-style clients get fast
            // feedback. Read by fedimintd-experimint when constructing
            // `StabilityPoolInit`.
            std::env::set_var(FM_SPV2_TEST_PARAMS, "1");

            // Iroh federation by default: config-gen mints iroh node keys
            // instead of ws p2p/api endpoints (fedimint-server setup honors
            // the per-peer FM_IROH_*_SECRET_KEY_OVERRIDE vars devimint always
            // exports, and FM_IROH_CONNECT_OVERRIDES_PLAIN maps every node id
            // to 127.0.0.1 so nothing needs a relay or external DNS). Respect
            // an explicit FM_ENABLE_IROH=0/false from the caller to fall back
            // to a websocket fed.
            if std::env::var(FM_ENABLE_IROH).is_err() {
                std::env::set_var(FM_ENABLE_IROH, "1");
            }

            // The usdt module's chain fixtures, mirroring `usdt_e2e.rs`:
            // freshly deployed token + EntryPoint, anvil account 0 as the
            // gas-fronting broadcaster, all-zero price feed to select the
            // static ETH/USD fallback (no Chainlink on anvil).
            std::env::set_var(FM_USDT_CONTRACT_ENV, token.to_string());
            std::env::set_var(FM_USDT_ENTRY_POINT_ENV, entry_point.to_string());
            std::env::set_var(
                FM_USDT_BROADCASTER_PRIVATE_KEY_ENV,
                ANVIL_ACCOUNT_0_PRIVATE_KEY,
            );
            std::env::set_var(
                FM_USDT_ETH_USD_PRICE_FEED_ENV,
                EvmAddress([0u8; 20]).to_string(),
            );
        }

        // devimint's DKG phase deliberately unsets
        // FM_FEDIMINT_CLI_BASE_EXECUTABLE (`use_matching_fedimint_cli_for_dkg`
        // sees fedimintd's version equal its own package version and assumes
        // fedimint's dev shell, where a matching `fedimint-cli` is on PATH).
        // On this machine PATH resolution would then find an unrelated
        // system-wide stock `fedimint-cli`, whose pre-0.11 setup calls the
        // fork's config-gen API rejects ("The leader must set the federation
        // size"). Pin PATH resolution to the experimint CLI by symlinking it
        // as `fedimint-cli` into a private dir prepended to PATH.
        let cli_exe = std::env::var("FM_FEDIMINT_CLI_BASE_EXECUTABLE").context(
            "FM_FEDIMINT_CLI_BASE_EXECUTABLE must point at fedimint-cli-experimint (see module docs)",
        )?;
        let cli_exe = std::fs::canonicalize(&cli_exe)
            .with_context(|| format!("cannot resolve FM_FEDIMINT_CLI_BASE_EXECUTABLE: {cli_exe}"))?;
        let shim_dir = process_mgr.globals.FM_TEST_DIR.join("bin");
        std::fs::create_dir_all(&shim_dir).context("creating PATH shim dir")?;
        let shim = shim_dir.join("fedimint-cli");
        let _ = std::fs::remove_file(&shim);
        std::os::unix::fs::symlink(&cli_exe, &shim).context("symlinking fedimint-cli shim")?;
        // SAFETY: same single-threaded window as the set_var block above.
        unsafe {
            std::env::set_var(
                "PATH",
                format!(
                    "{}:{}",
                    shim_dir.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            );
        }

        // The usdt config-gen params, derived exactly the way the env-driven
        // default path would (env overrides applied, factory/impl derived
        // from the EntryPoint). Serialized into the leader's `--module` spec
        // below so the explicit instance list carries identical params.
        let usdt_params =
            ServerModuleInit::default_config_gen_params(&fedimint_usdt_server::UsdtInit::default());
        let usdt_json = serde_json::to_string(&usdt_params)
            .context("serializing usdt config-gen params")?;

        // The intended experimint topology (README's `set-local-params`
        // example plus spv2): notably TWO `mintv2` instances, one per unit.
        // devimint's own config-gen path cannot express a second instance of
        // a kind, which is why this binary drives DKG itself via the fork's
        // repeatable `--module` flag.
        let module_specs: Vec<String> = vec![
            "walletv2".into(),
            r#"mintv2={"amount_unit":0}"#.into(),
            r#"mintv2={"amount_unit":1}"#.into(),
            "lnv2".into(),
            format!("usdt={usdt_json}"),
            "amm".into(),
            "meta".into(),
            "multi_sig_stability_pool".into(),
        ];

        info!("Starting the federation (real cggmp21 DKG, allow a few minutes)...");
        let fed = Federation::new(
            &process_mgr,
            bitcoind.clone(),
            false,
            true, // pre_dkg: guardians spawn, we drive config-gen ourselves
            false,
            0,
            "default".to_string(),
        )
        .await?;

        let endpoints: BTreeMap<PeerId, String> = fed
            .vars
            .iter()
            .map(|(id, v)| {
                (
                    PeerId::from(u16::try_from(*id).expect("peer ids are small")),
                    v.FM_API_URL.clone(),
                )
            })
            .collect();

        run_dkg_with_module_list(&endpoints, &module_specs).await?;

        // Post-DKG bookkeeping `Federation::new` would have done on its
        // non-pre_dkg path: wait for every guardian to write its invite code
        // (the marker that config-gen finished), then copy peer 0's into the
        // client dir, which is where `Federation::invite_code` reads it from.
        let config_gen_timeout = Duration::from_secs(300);
        for peer_vars in fed.vars.values() {
            let path = peer_vars.FM_DATA_DIR.join("invite-code");
            poll_with_timeout("awaiting-invite-code", config_gen_timeout, || async {
                tokio::fs::read_to_string(&path)
                    .await
                    .with_context(|| format!("awaiting invite code file: {}", path.display()))
                    .map_err(ControlFlow::Continue)
            })
            .await?;
        }
        let client_dir = std::env::var(devimint::envs::FM_CLIENT_DIR_ENV)
            .context("FM_CLIENT_DIR must be set by devimint setup")?;
        tokio::fs::copy(
            fed.vars[&0].FM_DATA_DIR.join("invite-code"),
            format!("{client_dir}/invite-code"),
        )
        .await
        .context("copying invite-code to the client dir")?;

        let invite_code = fed.invite_code()?;

        // Deliberately eprintln!, not tracing: this block is the whole point
        // of the binary and must not depend on log levels or formatting.
        eprintln!("\n========================================================");
        eprintln!("demo federation is up (4 guardians, regtest)");
        eprintln!("========================================================");
        eprintln!("invite code:\n{invite_code}\n");
        eprintln!("join it:");
        eprintln!("  fedimint-cli-experimint --data-dir <dir> join-federation --invite-code {invite_code}");
        eprintln!("  fedimint-cli-experimint --data-dir <dir> info\n");
        if std::env::var(FM_ENABLE_IROH).is_ok_and(|v| v != "0" && v != "false") {
            eprintln!("iroh fed: clients must resolve the guardians' node ids locally —");
            eprintln!("either `source {}/env` before running the CLI, or:", process_mgr.globals.FM_TEST_DIR.display());
            eprintln!(
                "  export FM_IROH_CONNECT_OVERRIDES_PLAIN='{}'\n",
                std::env::var("FM_IROH_CONNECT_OVERRIDES_PLAIN").unwrap_or_default()
            );
        }
        eprintln!("anvil RPC:        {}", anvil.rpc_url());
        eprintln!("test USDT token:  {token}");
        eprintln!("4337 EntryPoint:  {entry_point}");
        eprintln!("USDT holder key (anvil account 1, 10_000 USDT): {ANVIL_ACCOUNT_1_PRIVATE_KEY}");
        eprintln!("topology: 8 instances — walletv2, mintv2(BTC), mintv2(USDT), lnv2, usdt, amm, meta, spv2");
        eprintln!("spv2: mock oracle, 15s cycles (test params)");
        eprintln!("\nCtrl-C shuts everything down.");
        eprintln!("========================================================\n");

        // Park forever; `cleanup_on_exit` turns Ctrl-C into an orderly
        // task-group shutdown that reaps every spawned daemon.
        std::future::pending::<()>().await;
        #[allow(unreachable_code)] // pins the async block's Ok type
        anyhow::Ok(())
    };

    cleanup_on_exit(main, task_group).await?;
    Ok(())
}

/// `run_cli_dkg_v2` with an explicit module instance list: same
/// status-poll → set-local-params → add-peer → start-dkg sequence, but the
/// leader's `set-local-params` carries the repeatable `--module` flags that
/// devimint's own helper cannot express (needed for the second `mintv2`).
async fn run_dkg_with_module_list(
    endpoints: &BTreeMap<PeerId, String>,
    module_specs: &[String],
) -> anyhow::Result<()> {
    let auth = ApiAuth::new("pass".to_string());

    // Wait for every guardian's setup API to come up.
    for endpoint in endpoints.values() {
        poll("awaiting-setup-status", || async {
            FedimintCli
                .setup_status(&auth, endpoint)
                .await
                .map_err(ControlFlow::Continue)
        })
        .await?;
    }

    info!("Setting local parameters (leader carries the module instance list)...");
    let mut setup_codes = BTreeMap::new();
    for (peer, endpoint) in endpoints {
        let code = if peer.to_usize() == 0 {
            let mut command = cmd!(
                FedimintCli,
                "--password",
                auth.as_str(),
                "admin",
                "setup",
                endpoint,
                "set-local-params",
                format!("Devimint Guardian {peer}"),
                "--federation-name",
                "Experimint Demo",
                "--federation-size",
                endpoints.len().to_string()
            );
            for spec in module_specs {
                command = command.arg(&"--module").arg(spec);
            }
            serde_json::from_value::<String>(command.out_json().await?)
                .context("parsing leader setup code")?
        } else {
            FedimintCli
                .set_local_params_follower(peer, &auth, endpoint)
                .await?
        };
        setup_codes.insert(*peer, code);
    }

    info!("Exchanging peer setup codes...");
    for (peer, code) in &setup_codes {
        for (other, endpoint) in endpoints {
            if other != peer {
                FedimintCli.add_peer(code, &auth, endpoint).await?;
            }
        }
    }

    info!("Starting DKG...");
    for endpoint in endpoints.values() {
        FedimintCli.start_dkg(&auth, endpoint).await?;
    }

    Ok(())
}

/// Private key of `anvil`'s first deterministic default account (derived
/// from its well-known dev mnemonic); deploys the fixtures and fronts
/// broadcaster gas.
const ANVIL_ACCOUNT_0_PRIVATE_KEY: &str =
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Private key of `anvil`'s second deterministic default account, seeded
/// with the test ERC-20 supply so a human can send deposits from it.
const ANVIL_ACCOUNT_1_PRIVATE_KEY: &str =
    "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

sol! {
    #[sol(rpc)]
    interface ITestUsdt {
        function mint(address to, uint256 amount) external;
    }
}

fn account_1_address() -> anyhow::Result<EvmAddress> {
    let signer: PrivateKeySigner = ANVIL_ACCOUNT_1_PRIVATE_KEY
        .parse()
        .context("malformed ANVIL_ACCOUNT_1_PRIVATE_KEY")?;
    Ok(EvmAddress(signer.address().into_array()))
}

fn wallet_provider(anvil: &Anvil, private_key: &str) -> anyhow::Result<impl Provider + Clone> {
    let signer: PrivateKeySigner = private_key
        .parse()
        .context("malformed anvil dev-account private key")?;
    let url = anvil
        .rpc_url()
        .parse()
        .with_context(|| format!("invalid anvil url: {}", anvil.rpc_url()))?;

    Ok(ProviderBuilder::new().wallet(signer).connect_http(url))
}

/// The vendored `TestUsdt` fixture's creation bytecode + ABI (compiled
/// offline; this harness never invokes `solc`/`forge`). `bin/` targets
/// cannot import the `tests/` `common` module, so this is duplicated from
/// `usdt_e2e.rs`, which duplicates it from `tests/common/anvil.rs`.
const TEST_USDT_FIXTURE_JSON: &str = include_str!("../tests/fixtures/test_usdt.json");

fn test_usdt_creation_bytecode() -> anyhow::Result<Vec<u8>> {
    let fixture: serde_json::Value = serde_json::from_str(TEST_USDT_FIXTURE_JSON)
        .context("failed to parse tests/fixtures/test_usdt.json")?;
    let bytecode_hex = fixture["bytecode"]
        .as_str()
        .context("fixture is missing a `bytecode` string field")?;
    let bytecode_hex = bytecode_hex.strip_prefix("0x").unwrap_or(bytecode_hex);

    hex::decode(bytecode_hex).context("fixture `bytecode` is not valid hex")
}

/// Deploys the vendored `TestUsdt` ERC-20 fixture to `anvil` (as account 0)
/// and mints `amount` to `holder`. Returns the deployed contract's address.
async fn deploy_test_erc20(
    anvil: &Anvil,
    holder: EvmAddress,
    amount: UsdtAmount,
) -> anyhow::Result<EvmAddress> {
    let provider = wallet_provider(anvil, ANVIL_ACCOUNT_0_PRIVATE_KEY)?;

    let bytecode = test_usdt_creation_bytecode()?;
    let deploy_tx = TransactionRequest::default().with_deploy_code(bytecode);
    let receipt = provider
        .send_transaction(deploy_tx)
        .await
        .context("failed to send TestUsdt creation transaction")?
        .get_receipt()
        .await
        .context("failed to confirm TestUsdt creation transaction")?;
    let token_address = receipt
        .contract_address
        .context("TestUsdt creation receipt is missing a contract_address")?;

    let contract = ITestUsdt::new(token_address, &provider);
    contract
        .mint(Address::from(holder.0), U256::from(amount.0))
        .send()
        .await
        .context("failed to send mint() transaction")?
        .get_receipt()
        .await
        .context("failed to confirm mint() transaction")?;

    Ok(EvmAddress(token_address.into_array()))
}

/// The vendored ERC-4337 v0.7 `EntryPoint` creation artifact (compiled
/// offline), duplicated from `usdt_e2e.rs` for the same `bin/`-vs-`tests/`
/// reason as the ERC-20 fixture above.
const ENTRY_POINT_ARTIFACT_JSON: &str = include_str!("../tests/fixtures/erc4337/EntryPoint.json");

fn artifact_hex_field(artifact_json: &str, field: &str) -> anyhow::Result<Vec<u8>> {
    let artifact: serde_json::Value = serde_json::from_str(artifact_json)
        .with_context(|| format!("failed to parse erc4337 artifact JSON (`{field}` lookup)"))?;
    let hex_str = artifact[field]
        .as_str()
        .with_context(|| format!("artifact is missing a `{field}` string field"))?;
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

    hex::decode(hex_str).with_context(|| format!("artifact `{field}` is not valid hex"))
}

/// Real-constructor-deploys ONLY the ERC-4337 v0.7 `EntryPoint` (no ctor
/// args) as account 0, returning its address; the module self-deploys the
/// factory + impl derived from it (Part A, see `usdt_e2e.rs`).
async fn deploy_entry_point(anvil: &Anvil) -> anyhow::Result<EvmAddress> {
    let provider = wallet_provider(anvil, ANVIL_ACCOUNT_0_PRIVATE_KEY)?;

    let entry_point_creation_bytecode = artifact_hex_field(ENTRY_POINT_ARTIFACT_JSON, "bytecode")
        .context("failed to extract EntryPoint bytecode")?;
    let entry_point_receipt = provider
        .send_transaction(
            TransactionRequest::default().with_deploy_code(entry_point_creation_bytecode),
        )
        .await
        .context("failed to send EntryPoint creation transaction")?
        .get_receipt()
        .await
        .context("failed to confirm EntryPoint creation transaction")?;
    let entry_point = entry_point_receipt
        .contract_address
        .context("EntryPoint creation receipt is missing a contract_address")?;

    Ok(EvmAddress(entry_point.into_array()))
}
