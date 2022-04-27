use std::{
    env::args,
    thread::sleep,
    time::{Duration, SystemTime},
};

use pcap::{Capture, Device, Linktype};

fn main() {
    let mut args = args();
    args.next().unwrap();
    let device_name = args.next().expect("pass a device name as argument");
    let file_name = args
        .next()
        .expect("2nd argument should be a valid pcap file path");

    let mut device_opt = None;
    for device in Device::list().unwrap() {
        if device.name == device_name {
            device_opt = Some(device);
        }
    }

    let device = device_opt.expect("no matching device found");

    let capture = Capture::from_device(device).unwrap();

    let mut capture = capture.open().unwrap();
    capture.set_datalink(Linktype::ETHERNET).unwrap();

    let mut pcap_file = Capture::from_file(file_name).unwrap();

    let mut timeout = SystemTime::now() + Duration::from_secs(5);
    let packet1 = pcap_file.next().unwrap();
    let mut prev = packet1.header.ts;
    capture.sendpacket(packet1.data).unwrap();
    let mut last_sent = SystemTime::now();

    let mut i: u128 = 0;


    while let Ok(packet) = pcap_file.next() {
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
}
