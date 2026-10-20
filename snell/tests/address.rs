//! Address compatibility at the public request/packet codec boundary.
use snell::{
    Buffer, Socksaddr, read_connect_address, read_udp_request_address, write_connect_address, write_udp_request_address,
};

#[test]
fn non_utf8_connect_host_round_trips_without_replacement() {
    for host in [vec![0xff], vec![0xff; 255], b"example.com".to_vec()] {
        let mut wire = vec![host.len() as u8];
        wire.extend_from_slice(&host);
        wire.extend_from_slice(&443u16.to_be_bytes());
        let address = read_connect_address(&mut Buffer::from_vec(wire.clone())).unwrap();
        let mut encoded = Buffer::with_capacity(512);
        write_connect_address(&mut encoded, &address).unwrap();
        assert_eq!(wire, encoded.bytes(), "CONNECT must preserve host bytes");
        let request = snell::Request { command: snell::COMMAND_CONNECT, destination: address, ..Default::default() };
        assert_eq!(3 + wire.len(), request.len());
        assert_eq!(&request.encode().unwrap()[3..], wire);
    }
}

#[test]
fn non_utf8_udp_host_round_trips_without_replacement() {
    let wire = vec![2, 0xff, 0xfe, 0x01, 0xbb];
    let address = read_udp_request_address(&mut Buffer::from_vec(wire.clone())).unwrap();
    let mut encoded = Buffer::with_capacity(512);
    write_udp_request_address(&mut encoded, &address).unwrap();
    assert_eq!(wire, encoded.bytes(), "UDP must preserve host bytes");
}

#[test]
fn scoped_ipv6_connect_keeps_address_type_and_zone() {
    for host in ["fe80::1%lo0", "fe80::1%7"] {
        let mut wire = vec![host.len() as u8];
        wire.extend_from_slice(host.as_bytes());
        wire.extend_from_slice(&443u16.to_be_bytes());
        let address = read_connect_address(&mut Buffer::from_vec(wire.clone())).unwrap();
        assert!(address.is_ipv6(), "scoped literal must stay an IP: {host}");
        assert!(!address.is_domain());
        assert_eq!(host, address.addr_string());
        assert_eq!(host, address.host().unwrap());
        let mut encoded = Buffer::with_capacity(512);
        write_connect_address(&mut encoded, &address).unwrap();
        assert_eq!(wire, encoded.bytes());
    }
    let address = Socksaddr::parse("[fe80::1%7]:443");
    assert_eq!("[fe80::1%7]:443".parse::<std::net::SocketAddr>().unwrap(), address.socket_addr().unwrap());
}

#[test]
fn socket_address_scope_survives_conversion() {
    let socket = "[fe80::1%7]:443".parse::<std::net::SocketAddr>().unwrap();
    let address = Socksaddr::from(socket);
    assert_eq!(Some(socket), address.socket_addr());
    assert_eq!("fe80::1%7", address.addr_string());
}

#[tokio::test]
async fn system_dialer_rejects_non_utf8_host_before_resolution() {
    use snell::{Context, Dialer, SystemDialer};
    let address = Socksaddr::from_host_bytes(&[0xff], 443);
    assert_eq!(std::io::ErrorKind::InvalidInput, address.host().unwrap_err().kind());
    let result = SystemDialer.dial_tcp(&Context::default(), &address).await;
    let error = match result {
        Ok(_) => panic!("invalid host must fail"),
        Err(error) => error,
    };
    assert_eq!(std::io::ErrorKind::InvalidInput, error.kind());
}
