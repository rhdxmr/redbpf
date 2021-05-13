use redbpf::{HashMap, Map};
use std::process;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, Level};
use tracing_subscriber::FmtSubscriber;

const MAP_PIN_PATH: &str = "/sys/fs/bpf/tc/globals/blocked_packets";

async fn monitor() {
    let map = Map::from_pin_path(MAP_PIN_PATH).expect("error on creating map from pin path");
    let persist_map = HashMap::<u64, u64>::new(&map).expect("error on creating Array");

    loop {
        if let Some(cnt) = persist_map.get(0) {
            println!("blocked packet number: {}", cnt);
        }

        sleep(Duration::from_secs(1)).await
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    if unsafe { libc::getuid() != 0 } {
        error!("You must be root to use eBPF!");
        process::exit(1);
    }
    monitor().await;
}
