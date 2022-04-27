#![allow(unused_variables, dead_code, unused_imports)]
use std::{
    cell::RefCell,
    env, fs,
    io::{self, Write},
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    rc::Rc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ahash::RandomState;
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use indexmap::IndexMap;
use pcap::{Capture, Packet};
use pcap_file::PcapWriter;

type FlowMap = IndexMap<Flow, Stats, RandomState>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Flow {
    source: Ipv4Addr,
    destination: Ipv4Addr,
}

impl Flow {
    fn rev(&self) -> Self {
        Self {
            source: self.destination,
            destination: self.source,
        }
    }
}

struct Stats {
    writer: PcapWriter<io::BufWriter<fs::File>>,
    total_count: usize,
    last_packet_timestamp: SystemTime,
}

impl Stats {
    #[inline]
    fn new(packet: &Packet, src: [u8; 4], dst: [u8; 4], dir: &str) -> anyhow::Result<Self> {
        let ts = packet.header.ts;
        let init_timestamp = UNIX_EPOCH
            + Duration::from_secs(ts.tv_sec as u64)
            + Duration::from_micros(ts.tv_usec as u64);
        let filepath = format!(
            "{dir}/flow-{}.{}.{}.{}-{}.{}.{}.{}.pcap",
            src[0], src[1], src[2], src[3], dst[0], dst[1], dst[2], dst[3],
        );
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(&filepath)?;
        let mut writer = PcapWriter::new(io::BufWriter::new(file))?;
        writer.write(
            ts.tv_sec as u32,
            (ts.tv_usec as u32) * 1000,
            &packet,
            packet.len() as u32,
        )?;

        Ok(Self {
            writer,
            total_count: 0,
            last_packet_timestamp: init_timestamp,
        })
    }

    #[inline]
    fn add_packet(&mut self, packet: &Packet, timestamp: SystemTime) -> anyhow::Result<()> {
        let ts = packet.header.ts;
        self.writer.write(
            ts.tv_sec as u32,
            (ts.tv_usec as u32) * 1000,
            &packet,
            packet.len() as u32,
        )?;

        self.last_packet_timestamp = timestamp;

        self.total_count += 1;
        Ok(())
    }

    #[allow(dead_code)]
    #[inline]
    fn len(&self) -> usize {
        self.total_count
    }
}

impl Drop for Stats {
    fn drop(&mut self) {
        self.writer.get_mut().flush().unwrap();
    }
}

fn main() -> anyhow::Result<()> {
    let mut args = env::args();
    args.next().unwrap();
    let filepath = args.next().expect("enter filepath to split to flows");
    let output_dir = args.next().expect("enter output dir as 2nd argument");
    let timeout: u64 = args
        .next()
        .expect("enter timeout (in ms) as 3rd argument")
        .parse()?;

    if !Path::new(&output_dir).is_dir() {
        println!("given output_dir should be a directory");
    }

    let mut capture = Capture::from_file(filepath)?;
    let mut flowmap = FlowMap::with_hasher(RandomState::new());
    let mut i = 0;
    let timeout = Duration::from_millis(timeout);

    while let Ok(packet) = capture.next() {
        let ether_packet = SlicedPacket::from_ethernet(&packet)?;

        let (src_ip, dst_ip) =
            if let Some(InternetSlice::Ipv4(header, _externsions)) = ether_packet.ip {
                (
                    Ipv4Addr::from(header.source()),
                    Ipv4Addr::from(header.destination()),
                )
            } else {
                continue;
            };

        let tcp_hdr_slice = if let Some(TransportSlice::Tcp(tcp_hdr_slice)) = ether_packet.transport
        {
            tcp_hdr_slice
        } else {
            continue;
        };

        // let (src_port, dst_port) = (
        //     tcp_hdr_slice.source_port(),
        //     tcp_hdr_slice.destination_port(),
        // );

        let flow_hdr = Flow {
            source: src_ip,
            destination: dst_ip,
        };

        let ts = packet.header.ts;
        let timestamp = UNIX_EPOCH
            + Duration::from_secs(ts.tv_sec as u64)
            + Duration::from_micros(ts.tv_usec as u64);

        match flowmap.get_mut(&flow_hdr) {
            Some(stats) => {
                /*
                // flow stopped due to timeout
                if timestamp.duration_since(stats.last_packet_timestamp)? >= timeout {
                    let new_stats = Stats::new(&packet, i, &output_dir)?;
                    i += 1;
                    let _ = std::mem::replace(stats, new_stats);
                }

                // flow stopped due to fin flag
                if tcp_hdr_slice.fin() {
                    let mut stats = flowmap.remove(&flow_hdr).unwrap();
                    stats.add_packet(&packet, timestamp)?;
                    continue;
                }

                // flow stopped due to rst flag
                if tcp_hdr_slice.rst() {
                    let mut stats = flowmap.remove(&flow_hdr).unwrap();
                    stats.add_packet(&packet, timestamp)?;
                    continue;
                }
                */

                stats.add_packet(&packet, timestamp)?;
            }
            None => {
                // match flowmap.get_mut(&flow_hdr.rev()) {
                //     Some(stats) => {
                //         stats.add_packet(&packet, timestamp)?;
                //     }
                //     None => {
                //         let stats =
                //             Stats::new(&packet, src_ip.octets(), dst_ip.octets(), &output_dir)?;
                //         i += 1;
                //         flowmap.insert(flow_hdr, stats);
                //     }
                // }

                let stats = Stats::new(&packet, src_ip.octets(), dst_ip.octets(), &output_dir)?;
                i += 1;
                flowmap.insert(flow_hdr, stats);
            }
        }
    }

    Ok(())
}
