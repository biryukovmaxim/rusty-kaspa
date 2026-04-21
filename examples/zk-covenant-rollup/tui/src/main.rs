use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use kaspa_addresses::Prefix;
use kaspa_wrpc_client::prelude::NetworkId;

use zk_covenant_rollup_tui::app::App;
use zk_covenant_rollup_tui::db::RollupDb;
use zk_covenant_rollup_tui::node::KaspaNode;

#[derive(Parser, Debug)]
#[command(name = "zk-covenant-rollup-tui")]
#[command(about = "Interactive TUI for the ZK Covenant Rollup")]
struct Args {
    /// Kaspa network id: "mainnet", "testnet-N", "devnet", or "simnet".
    /// Determines address prefix and default wRPC port.
    #[arg(long, default_value = "testnet-12")]
    network: String,

    /// wRPC endpoint URL. If omitted, defaults to ws://127.0.0.1:<port>
    /// where <port> is the network's default borsh wRPC port
    /// (mainnet=17110, testnet=17210, simnet=17510, devnet=17610).
    #[arg(long)]
    wrpc_url: Option<String>,

    /// Path to the RocksDB database directory
    #[arg(long, default_value = "./rollup-db")]
    db_path: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let network_id: NetworkId = args.network.parse().with_context(|| format!("invalid --network: {}", args.network))?;
    let prefix: Prefix = network_id.network_type().into();
    let wrpc_url = args.wrpc_url.unwrap_or_else(|| format!("ws://127.0.0.1:{}", network_id.network_type().default_borsh_rpc_port()));

    // Open database
    let db = Arc::new(RollupDb::open(&args.db_path)?);

    // Connect to Kaspa node (pre-TUI, blocking)
    eprintln!("Connecting to {wrpc_url} (network: {network_id}) ...");
    let node = KaspaNode::try_new(&wrpc_url, network_id)?;
    node.connect().await?;

    // Get initial chain info
    let dag_info = node.get_block_dag_info().await?;

    // Build app state
    let log_path = args.db_path.join("tui.log");
    let mut app = App::with_log_path(db, node.clone(), prefix, Some(log_path));
    app.daa_score = dag_info.virtual_daa_score;
    app.pruning_point = dag_info.pruning_point_hash;
    app.connected = true;
    app.log(format!("Connected to {wrpc_url} (DAA: {})", dag_info.virtual_daa_score));

    // Auto-select first covenant if available
    app.auto_select_first_covenant();

    // Run TUI
    let mut terminal = ratatui::init();
    let result = app.run(&mut terminal).await;
    ratatui::restore();

    // Shutdown node
    node.stop().await?;

    result
}
