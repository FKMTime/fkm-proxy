use anyhow::Result;
use clap::{Parser, command};
use fkm_proxy::utils::{
    client::{Consts, Options, connector},
    parse_socketaddr,
};
use std::net::SocketAddr;

const MAX_REQUEST_TIME: u128 = 1000;
const ERROR_HTML: &str = include_str!("./resources/error.html");
const LIST_HTML: &str = include_str!("./resources/list.html");

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, value_parser = parse_socketaddr, default_value = "vps.filipton.space:6969", env = "PROXY")]
    proxy_addr: SocketAddr,

    #[arg(short, long, value_parser = parse_socketaddr, default_value = "127.0.0.1:80", env = "ADDR")]
    addr: SocketAddr,

    #[arg(long, value_parser = parse_socketaddr, env = "SSL_ADDR")]
    ssl_addr: Option<SocketAddr>,

    #[arg(short, long, env = "TOKEN")]
    token: u128,

    #[arg(short, long, action, env = "REDIRECT_SSL")]
    redirect_ssl: bool,

    #[arg(long, action, short = 'f')]
    serve_files: bool,

    #[arg(long, action, short = 'i')]
    files_index: bool,

    #[arg(long, action, env = "USE_QUIC")]
    use_quic: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    _ = dotenvy::dotenv();
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    if args.files_index && !args.serve_files {
        tracing::error!(
            "You cannot use files indexing (-i, --files-index) without enabling files serving (-f, --serve-files)!"
        );
        return Ok(());
    }

    let options = Options {
        proxy: args.proxy_addr,
        local: args.addr,
        local_ssl: args.ssl_addr,
        token: args.token,
        redirect_ssl: args.redirect_ssl,
        files_index: args.files_index,
        serve_files: args.serve_files,
        quic: args.use_quic,
        consts: Consts {
            max_req_time: MAX_REQUEST_TIME,
            error_html: ERROR_HTML,
            list_html: LIST_HTML,
        },
    };

    loop {
        if let Err(e) = connector(&options).await {
            tracing::error!("Connector error: {e}");
        }

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    // Ok(())
}
