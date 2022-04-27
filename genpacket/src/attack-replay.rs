use std::{
    thread::sleep,
    time::{Duration, SystemTime},
};

use pcap::{Capture, Device};

fn main() -> anyhow::Result<()> {
    let filepath = "../cicids2017/pcaps/Tuesday-WorkingHours.pcap";
    let start_time_delay_secs = 20 * 60 * 60; // 9:20
    let end_time_delay_secs = 20 * 60 * 60 + 60 * 60 * 60; // 10:20
    let mut pcap = Capture::from_file(filepath)?;

    let mut req_device = None;
    for device in Device::list()? {
        if device.name.as_str() == "eth00" {
            req_device = Some(device);
            break;
        }
    }

    let mut capture = req_device.expect("eth00 not found").open()?;
    let start_ts = pcap.next().unwrap().header.ts.tv_sec;

    while let Ok(packet) = pcap.next() {
        if start_ts + start_time_delay_secs >= packet.header.ts.tv_sec {
            capture.sendpacket(packet.data)?;
            break;
        }
    }

    println!("done phase 1 - skipping");

    let mut timeout = SystemTime::now() + Duration::from_secs(5);
    let packet1 = pcap.next().unwrap();
    let mut prev = packet1.header.ts;
    capture.sendpacket(packet1.data).unwrap();
    let mut last_sent = SystemTime::now();

    let mut i: u128 = 0;

    while let Ok(packet) = pcap.next() {
        if start_ts + end_time_delay_secs <= packet.header.ts.tv_sec {
            break;
        }

        let curts = packet.header.ts;
        let mut sd = curts.tv_sec - prev.tv_sec;
        let ud = if sd == 0 {
            curts.tv_usec - prev.tv_usec
        } else if curts.tv_usec > prev.tv_usec {
            curts.tv_usec - prev.tv_usec
        } else {
            sd -= 1;
            prev.tv_usec - curts.tv_usec
        };

        if sd > 0 || (sd == 0 && ud > 0) {
            let dur = Duration::from_secs(sd as u64) + Duration::from_micros(ud as u64);
            // print!("sd {sd:10} ud {ud:10} {dur:10?}");
            let new_time = last_sent + dur;
            let now = SystemTime::now();
            if new_time > now {
                let d = new_time.duration_since(now).unwrap();
                // println!("{:15} sleeping for {:?}",i, d);
                sleep(d);
            }
        }

        capture.sendpacket(packet.data).unwrap();
        last_sent = SystemTime::now();
        prev = curts;
        println!("sent {}", i);
        i = i.wrapping_add(1);

        let now = SystemTime::now();
        if timeout <= now {
            println!("{:#?}", capture.stats().unwrap());
            timeout = now + Duration::from_secs(5);
        }
    }

    Ok(())
}
