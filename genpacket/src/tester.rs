use pcap::*;
use etherparse::SlicedPacket;

fn main() {
    let mut args = std::env::args();
    args.next().unwrap();
    let file_name = args.next().expect("provide a file");
    let mut capture = Capture::from_file(file_name).unwrap();
    // let mut i: u128 = 0;
    // for _i in 0..10 {
    //     let raw_p = capture.next().unwrap();
    //     let p = SlicedPacket::from_ethernet(&raw_p).unwrap();
    //     println!("link        : {:?}", p.link.unwrap().to_header());
    //     println!("vlan        : {:?}", p.vlan.map(|p| p.to_header()));
    //     println!("ip          : {:?}", p.ip);
    //     match p.ip {
    //         Some(etherparse::InternetSlice::Ipv4(header, _extension)) => println!("ip          : {:?}", header.to_header()),
    //         p => println!("transport   : {:?}", p),
    //     }
    //     match p.transport {
    //         Some(etherparse::TransportSlice::Tcp(slice)) => println!("transport   : {:?}", slice.to_header()),
    //         p => println!("transport   : {:?}", p),
    //     }
    //     println!("payload_len : {}\n\n"  , p.payload.len());
    // }

    // while let Ok(_p) = capture.next() {
        // println!("{:?}", p.header.ts);
        // i += 1;
    // }
    // println!("{i}");

    // let mut m = 0;
    // while let Ok(p) = capture.next() {
    //     m = p.data.len().max(m);
    // }
    // println!("{m}");

    println!("{:?}", capture.next().unwrap().header.ts);
}
