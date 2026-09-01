use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use aya::maps::HashMap;
use aya::{include_bytes_aligned, Bpf};
use clap::Parser;
use log::{info, warn};
use tokio::signal;

#[derive(Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let opt = Opt::parse();

    info!("Starting EdgeShield-DNS Community Edition on interface {}", opt.iface);

    // Load compiled eBPF bytecode
    // Note: In a real environment, you'd use `aya-bpf` to compile this or load the .o file.
    // Assuming `dns_drop.o` is built.
    #[cfg(target_arch = "x86_64")]
    let mut bpf = Bpf::load_file("ebpf/dns_drop.o").context("Failed to load eBPF object")?;

    let program: &mut Xdp = bpf
        .program_mut("xdp_dns_drop")
        .unwrap()
        .try_into()?;
        
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("Failed to attach XDP program")?;

    info!("XDP program successfully attached to {}.", opt.iface);

    // Populate blocklist map
    let mut blocklist: HashMap<_, u32, u8> = HashMap::try_from(bpf.map_mut("blocklist").unwrap())?;
    
    // Example: Blocking a specific hash (e.g., hash of "ads.example.com")
    let dummy_hash: u32 = 123456789;
    blocklist.insert(dummy_hash, 1, 0)?;
    info!("Loaded static blocklist domains.");

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
