use clap::Parser;
use pcap_file::pcap::PcapReader;
use std::io::{self, Write};
use std::path::PathBuf;
use std::{fs::File, net::Ipv4Addr};

use hashbrown::HashMap;
use std::hash::{BuildHasherDefault, Hasher};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    input_file: PathBuf,

    #[arg(short, long, default_value_t = false)]
    all_ips: bool,

    #[arg(short, long)]
    out_file: Option<PathBuf>,
}

#[derive(Default)]
struct IpHasher {
    hash: u64,
}

impl Hasher for IpHasher {
    fn finish(&self) -> u64 {
        self.hash
    }

    // todo: ipv6
    fn write(&mut self, bytes: &[u8]) {
        self.hash = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64;
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let file_in = File::open(args.input_file).expect("Error opening file");
    let mut pcap_reader = PcapReader::new(file_in)?;

    let mut num_packets = 0;
    let s: BuildHasherDefault<IpHasher> = BuildHasherDefault::default();
    let mut dest_ips = HashMap::with_hasher(s);

    let mut protocols = [0; 3];
    let mut total_volume = 0;

    while let Some(pkt) = pcap_reader.next_raw_packet() {
        let pkt = pkt?;

        num_packets += 1;

        let pdata = parse_packet(&pkt.data);

        dest_ips
            .entry(pdata.dest_ip)
            .and_modify(|c| *c += 1)
            .or_insert(1);

        match pdata.protocol {
            17 => protocols[0] += 1,
            6 => protocols[1] += 1,
            _ => protocols[2] += 1,
        }
        total_volume += pkt.orig_len;
    }

    let mut dest_ips_vec: Vec<_> = dest_ips.iter().collect();
    dest_ips_vec.sort_unstable_by_key(|(_, count)| -*count);
    let limit = if args.all_ips { dest_ips_vec.len() } else { 5 };

    if let Some(file_name) = args.out_file {
        let file_out = File::create(file_name)?;
        let mut handle = io::BufWriter::new(file_out);
        output_stats(
            &mut handle,
            total_volume,
            num_packets,
            &dest_ips_vec,
            protocols,
            limit,
        )
    } else {
        let stdout = io::stdout();
        let mut handle = io::BufWriter::new(stdout.lock());

        output_stats(
            &mut handle,
            total_volume,
            num_packets,
            &dest_ips_vec,
            protocols,
            limit,
        )
    }
}

fn output_stats<W: Write>(
    handle: &mut W,
    total_volume: u32,
    num_packets: u32,
    dest_ips_vec: &[(&Ipv4Addr, &i32)],
    protocols: [i32; 3],
    limit: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut handle = io::BufWriter::new(handle);
    writeln!(
        handle,
        "Average packet size: {:.2} bytes",
        f64::from(total_volume) / f64::from(num_packets)
    )?;
    writeln!(handle, "Total volume: {total_volume} bytes")?;
    writeln!(handle, "\nPrimary targets:")?;

    for (ip, count) in dest_ips_vec.iter().take(limit) {
        writeln!(handle, "\t{ip:15} ({count} packets recieved)")?;
    }
    writeln!(handle, "\nProtocols:")?;

    for (count, protocol) in protocols.iter().zip(&["UDP", "TCP", "Other"]) {
        writeln!(handle, "\t{protocol:6}: {count}")?;
    }

    handle.flush()?;

    Ok(())
}

struct PacketData {
    dest_ip: Ipv4Addr,
    protocol: u8,
}

#[inline]
fn parse_packet(data: &[u8]) -> PacketData {
    let packet_size = data.len();
    assert!(packet_size >= 14, "malformed packet");
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    match ethertype {
        0x0800 /* IPv4 */ => {
            assert!(packet_size >= 34, "malformed packet");

            let dest_ip = Ipv4Addr::new(
                data[30],
                data[31],
                data[32],
                data[33]
            );
            let protocol = data[23];

            PacketData {
                dest_ip,
                protocol
            }
        },
        0x86DD /* IPv6 */ => {
            unimplemented!("ipv6 addresses are not supported");
        }
        n => unreachable!("ethertype {n} was neither ipv4 or ipv6")
    }
}
