use std::{env::args, process::exit, sync::mpsc, time::Duration};

use pcap::{Capture, Device};

fn main() {
    let mut args = args();
    args.next().unwrap();
    let device_name = args
        .next()
        .expect("please pass in the device name to capture");
    let file_name = args.next().expect("2nd arg should be file to store pcap");
    let mut device_opt = None;
    for device in Device::list().unwrap() {
        if device.name == device_name {
            device_opt = Some(device);
        }
    }
    let (tx, rx) = mpsc::sync_channel(1);
    let mut device = Capture::from_device(device_opt.expect("no matching device found"))
        .unwrap()
        .timeout(10000)
        .open()
        .unwrap()
        .setnonblock()
        .unwrap();
    let mut savefile = device
        .savefile(file_name)
        .expect("unable to write pcap file");

    ctrlc::set_handler(move || {
        tx.send(())
            .expect("could not send stop signal to main thread")
    })
    .expect("not able to set ctrl-c handler");

    let mut i: u128 = 0;
    let exit_code = loop {
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(_) => {
                println!("\nflushing..");
                while let Ok(p) = device.next() {
                    savefile.write(&p);
                    print!("\rwrote {i} packets");
                    i = i.wrapping_add(1);
                }
                savefile.flush().unwrap();
                println!("flushed {i}");
                println!("{:#?}", device.stats().unwrap());
                break 0;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                println!("unexpected channel exit");
                break 1;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                while let Ok(p) = device.next() {
                    savefile.write(&p);
                    i = i.wrapping_add(1);
                    println!("wrote {i} packets");
                }
                savefile.flush().unwrap();
                println!("recved {}", device.stats().unwrap().received);
            }
        }
    };
    exit(exit_code);
}
