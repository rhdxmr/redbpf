use redbpf::load::Loader;
use redbpf::Array;
use std::process;
use std::time::Duration;
use tokio::signal::ctrl_c;
use tokio::time::sleep;
use tracing::{debug, error, Level};
use tracing_subscriber::FmtSubscriber;

const PIN_FILE: &str = "/sys/fs/bpf/sharedmap";
const MAP_NAME: &str = "sharedmap";

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

    let mut loaded = Loader::load(probe_code()).unwrap();
    loaded
        .map_mut(MAP_NAME)
        .expect("map not found")
        .pin(PIN_FILE)
        .expect("error on pinning");
    for kp in loaded.kprobes_mut() {
        debug!("attach_kprobe on {}", kp.name());
        kp.attach_kprobe(&kp.name(), 0)
            .expect("error on attach_kprobe");
    }
    let sarray = Array::<u64>::new(loaded.map_mut(MAP_NAME).unwrap()).expect("error on Array::new");
    loop {
        println!("shared counter: {}", sarray.get(0).unwrap());
        tokio::select! {
            _ = sleep(Duration::from_secs(1)) => {}
            _ = ctrl_c() => {
                break;
            }
        }
    }

    loaded
        .map_mut(MAP_NAME)
        .unwrap()
        .unpin()
        .expect("error on unpin");
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/sharemap1/sharemap1.elf"
    ))
}
