use std::{
    fs,
    io::{self, Write},
};

use etherparse::{InternetSlice, SlicedPacket};
use pcap::Capture;
use pcap_file::PcapWriter;

fn run() -> anyhow::Result<()> {
    let filepath = "../cicids2017/pcaps/Tuesday-WorkingHours.pcap";
    let victim_ip_local = [192, 168, 10, 50];
    let victim_ip = [205, 174, 165, 68];

    let mut read_pcap = Capture::from_file(filepath)?;

    let result_file = "../perflow_attack/tue_ftp_patator.pcap";
    let mut write_pcap = PcapWriter::new(io::BufWriter::new(
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(result_file)?,
    ))?;

    let origin_sec = read_pcap.next()?.header.ts.tv_sec;

    while let Ok(packet) = read_pcap.next() {
        let sec = packet.header.ts.tv_sec - origin_sec;
        if sec < 1100 {
            continue;
        }
        if sec > 4900 {
            break;
        }

        let sliced_packet = SlicedPacket::from_ethernet(&packet.data)?;
        if let Some(InternetSlice::Ipv4(header, _extension)) = sliced_packet.ip {
            if header.destination() == victim_ip || header.destination() == victim_ip_local {
                println!(
                    "writing ts {} {}",
                    packet.header.ts.tv_sec, packet.header.ts.tv_usec
                );
                write_pcap.write(
                    packet.header.ts.tv_sec as u32,
                    packet.header.ts.tv_usec as u32 * 1000,
                    &packet,
                    packet.data.len() as u32,
                )?;
            }
        }
    }

    write_pcap.get_mut().flush()?;

    Ok(())
}

fn main() {
    run().unwrap();
}
