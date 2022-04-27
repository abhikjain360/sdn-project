use std::{
    env, fs,
    io::{self, BufRead},
    net::{IpAddr, SocketAddr},
    time::{Duration, SystemTime},
};

use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use pcap::Capture;

const UTC_11AM_7_3_2017: u64 = 1499079600;

struct Flow {
    source: SocketAddr,
    destination: SocketAddr,
    protocol: u8,
    // Duration since morning 11AM UTC
    start_timestamp: Duration,
}

fn main() -> anyhow::Result<()> {
    let mut args = env::args();
    args.next().unwrap();
    let csv_filepath = args.next().unwrap();
    let pcap_filepath = args.next().unwrap();
    let attack_type = args.next().unwrap();
    let day: u8 = args.next().unwrap().parse()?;
    let output_type = args.next().unwrap();

    let mut csv = io::BufReader::new(fs::OpenOptions::new().read(true).open(csv_filepath)?);
    let mut line = Vec::new();
    csv.read_until(b'\n', &mut line)?;
    line.clear();

    while csv.read_until(b'\n', &mut line)? != 0 {
        lin
    }

    let mut pcap = Capture::from_file(pcap_filepath)?;

    let start_time = SystemTime::UNIX_EPOCH
        + Duration::from_secs(UTC_11AM_7_3_2017)
        + match day {
            0 => Duration::from_secs(0),
            1 => Duration::from_secs(24 * 60 * 60),
            2 => Duration::from_secs(2 * 24 * 60 * 60),
            3 => Duration::from_secs(3 * 24 * 60 * 60),
            4 => Duration::from_secs(4 * 24 * 60 * 60),
            _ => unreachable!(),
        };

    while let Ok(packet) = pcap.next() {
        let ts = packet.header.ts;
        let packet_time = SystemTime::UNIX_EPOCH
            + Duration::from_secs(ts.tv_sec as u64)
            + Duration::from_micros(ts.tv_usec as u64);

        let packet_parsed = SlicedPacket::from_ethernet(&packet)?;

        let (protocol, src_ip, dst_ip) = match packet_parsed.ip {
            Some(InternetSlice::Ipv4(hdr, _)) => (
                hdr.protocol(),
                IpAddr::from(hdr.source()),
                IpAddr::from(hdr.destination()),
            ),
            Some(InternetSlice::Ipv6(hdr, _)) => (
                hdr.next_header(),
                IpAddr::from(hdr.source()),
                IpAddr::from(hdr.destination()),
            ),
            None => continue,
        };

        let (src_port, dst_port) = match packet_parsed.transport {
            Some(TransportSlice::Tcp(hdr)) => (hdr.source_port(), hdr.destination_port()),
            Some(TransportSlice::Udp(hdr)) => (hdr.source_port(), hdr.destination_port()),
            _ => continue,
        };

        let flow = Flow {
            source: SocketAddr::from((src_ip, src_port)),
            destination: SocketAddr::from((dst_ip, dst_port)),
            protocol,
            start_timestamp: packet_time.duration_since(start_time)?,
        };
    }

    Ok(())
}
