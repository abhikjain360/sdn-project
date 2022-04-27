#![allow(unused_imports)]
use std::process::exit;

use clap::Parser;
use pcap::{Capture, Device};

#[derive(Parser)]
struct Opts {
    #[clap(long)]
    psh: u64,
    #[clap(long, short = 'f')]
    flow_duration: u64,
    #[clap(long)]
    syn: u64,
    #[clap(long)]
    ack: u64,
    #[clap(long, short = 't')]
    total_packets: u64,
    #[clap(long = "tlfp", short = 'f')]
    total_length_of_forwarded_packets: u64,
    #[clap(long = "iwbf", short = 'w')]
    init_win_bytes_forward: u64,
    #[clap(long, short = 'a')]
    active_min: u64,
    #[clap(long = "fim", short = 'i')]
    flow_iat_min: u64,
}

fn main() {
    let mut opts = Opts::parse();

    if opts.syn > 1
        || opts.psh > 1
        || opts.syn > 1
        || opts.init_win_bytes_forward > 65536
        || opts.total_packets > 600000
        || opts.total_packets < 2
    {
        println!("ERROR: contraints not valid");
        exit(1);
    }
}
