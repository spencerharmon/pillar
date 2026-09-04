//! Trivial UDP echo binary — the acceptance test's "image" for
//! `workload-oci-runtime-real`. Not a placeholder: a real standalone
//! executable, spawned as a real child process and bound to a real
//! listening UDP socket by the OCI runtime layer under test
//! (`pillar_controller::runtime::SupervisedWorkload`). Binds to the port
//! given as its first CLI argument and echoes every datagram it receives
//! back to its sender until the process is killed.
use std::net::UdpSocket;

fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .expect("udp_echo requires a port argument")
        .parse()
        .expect("port argument must be a valid u16");

    let socket = UdpSocket::bind(("127.0.0.1", port)).expect("bind udp echo socket");

    let mut buf = [0u8; 1024];
    while let Ok((n, from)) = socket.recv_from(&mut buf) {
        let _ = socket.send_to(&buf[..n], from);
    }
}
