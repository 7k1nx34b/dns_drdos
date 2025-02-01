
pub mod resolv {

    use std::fs::File;
    use std::io;
    use std::io::BufRead;
    use std::net::{IpAddr, Ipv4Addr};
    use pnet::datalink;
    use pnet::datalink::{Channel, NetworkInterface};
    use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
    use pnet::packet::Packet;
    use pnet::util::MacAddr;
    use crate::ETHERNET_HEADER_LEN;

    const ARP_HEADER_LEN: usize = 28;

    pub fn get_default_gateway_ip_address_for_interface(interface_name: &str) -> Option<Ipv4Addr> {
        let fd = File::open("/proc/net/route").expect("this system does not run on the Linux kernel!");
        let buf = io::BufReader::new(fd);

        for line in buf.lines().skip(1) {
            let line = line.unwrap();
            let fields: Vec<&str> = line.split_whitespace().collect();

            if 3 > fields.len() {
                continue;
            }

            let _interface_name = fields[0];
            let cidr_block = fields[1];
            let gateway_ip_address = u32::from_str_radix(fields[2], 16).unwrap();
            if cidr_block == "00000000" && _interface_name == interface_name {
                return Some(
                    Ipv4Addr::new(
                        (gateway_ip_address & 0xFF) as u8,
                        ((gateway_ip_address >> 8) & 0xFF) as u8,
                        ((gateway_ip_address >> 16) & 0xFF) as u8,
                        ((gateway_ip_address >> 24) & 0xFF) as u8,
                    )
                )
            }
        }
        None
    }
    pub fn get_default_gateway_mac_address(
        interface: &NetworkInterface,
        gateway_ip_address: Ipv4Addr,
    ) -> Option<MacAddr> {

        let mut packet = [0u8; ETHERNET_HEADER_LEN+ARP_HEADER_LEN];
        {
            let mut eth_header = MutableEthernetPacket::new(
                &mut packet [..ETHERNET_HEADER_LEN]
            ).unwrap();
            eth_header.set_source(interface.mac.unwrap());
            eth_header.set_destination(MacAddr::broadcast());
        }

        let sender_proto_addr  = match interface.ips.iter()
            .find(|a| a.is_ipv4())
            .expect("No IPv4 address for interface")
            .ip() {
            IpAddr::V4(ip) => ip,
            _ => panic!()
        };

        {
            let mut arp_header = MutableArpPacket::new(
                &mut packet [ETHERNET_HEADER_LEN..]
            ).unwrap();
            arp_header.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp_header.set_protocol_type(EtherTypes::Ipv4);
            arp_header.set_hw_addr_len(6);
            arp_header.set_proto_addr_len(4);
            arp_header.set_operation(ArpOperations::Request);

            arp_header.set_sender_hw_addr(interface.mac?);
            arp_header.set_sender_proto_addr(sender_proto_addr);

            arp_header.set_target_hw_addr(MacAddr::broadcast());
            arp_header.set_target_proto_addr(gateway_ip_address);

        }

        let (mut tx, mut rx) = match datalink::channel(interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unknown channel type"),
            Err(e) => panic!("Error happened {}", e),
        };
        tx.send_to(&packet, None);
        loop {
            match rx.next() {
                Ok(frame) => {
                    let packet = EthernetPacket::new(frame).unwrap();
                    if packet.get_ethertype() == EtherTypes::Arp {
                        if let Some(reply) = ArpPacket::new(packet.payload()) {
                            if reply.get_sender_proto_addr() == gateway_ip_address {
                                return Some(reply.get_sender_hw_addr());
                            }
                        }
                    }
                }
                Err(_) => {}
            }
        }

    }
}