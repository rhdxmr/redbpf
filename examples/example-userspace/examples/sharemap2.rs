use redbpf::{Array, Map, Module};
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

    let mut module = Module::parse_with_maps(
        probe_code(),
        vec![Map::from_pin_file(PIN_FILE).expect("error on Map::from_pin_file")],
    )
    .unwrap();
    for prog in module.programs.iter_mut() {
        debug!("load program: {}", prog.name());
        prog.load(module.version, module.license.clone())
            .expect("error on load program");
    }
    for kp in module.kprobes_mut() {
        debug!("attach kprobe: {}", kp.name());
        kp.attach_kprobe(&kp.name(), 0)
            .expect("error on attach_kprobe");
    }
    let sarray = Array::<u64>::new(module.map(MAP_NAME).expect("map not found"))
        .expect("error on Array::new");
    loop {
        println!("shared counter: {}", sarray.get(0).unwrap());
        tokio::select! {
            _ = sleep(Duration::from_secs(1)) => {}
            _ = ctrl_c() => {
                break;
            }
        }
    }
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/sharemap2/sharemap2.elf"
    ))
}
