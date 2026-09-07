//! Live libp2p [`Transport`] wiring for pillar-UDP (Route A substrate).
//!
//! The sibling [`crate::pillar_udp`] module owns the pillar-UDP protocol
//! MECHANICS (exactly-once dedup, lease routing, dispersed reply-sets, K+M
//! erasure, anti-amplification). What it deliberately deferred — and what THIS
//! module supplies — is the raw libp2p [`Transport`] itself: an actual bound
//! UDP socket, a connection substrate that yields an [`AsyncRead`] +
//! [`AsyncWrite`] byte stream, and the multiaddr protocol
//! (`…/udp/<port>/p-pillar`) by which the swarm binds/advertises/dials it. With
//! this, a running node registers pillar-UDP as an ADDITIONAL transport
//! alongside TCP+QUIC (see [`crate::build_event_swarm`]) rather than merely
//! referencing the mechanics module in isolation.
//!
//! The substrate is a small reliable-ordered stream carried over a single UDP
//! flow between two endpoints: enough to bind, be dialed, complete the standard
//! libp2p Noise+yamux upgrade over it, and route real application datagrams
//! end-to-end. It reuses libp2p's own Noise/yamux upgrade stack for security
//! and multiplexing rather than re-deriving them (via the standard
//! `.upgrade().authenticate().multiplex()` combinators applied in
//! [`crate::build_event_swarm_with_root`]), exactly as the mechanics module
//! reuses the platform's proven primitives. QUIC remains the healthy-link
//! default (see [`crate::pillar_udp::select_transport`]); pillar-UDP is the
//! registered, dial-able substrate for the degraded-link path.
//!
//! [`Transport`]: libp2p::Transport

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::future::BoxFuture;
use futures::{AsyncRead, AsyncWrite, FutureExt};
use libp2p::core::transport::{ListenerId, TransportError, TransportEvent};
use libp2p::identity::Keypair;
use libp2p::multiaddr::{Multiaddr, Protocol};
use libp2p::Transport;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

/// The multiaddr terminal marker that distinguishes a pillar-UDP endpoint
/// (`…/udp/<port>/p-pillar`) from QUIC's `…/udp/<port>/quic-v1`.
pub const PILLAR_UDP_SUFFIX: &str = "p-pillar";

const MAX_PAYLOAD: usize = 1100;
const HDR: usize = 13; // 1 tag + 8 seq + 4 len
const TAG_DATA: u8 = 1;
const TAG_ACK: u8 = 2;
const TAG_SYN: u8 = 3;

/// Returns `true` iff `addr` is a well-formed pillar-UDP address this
/// transport owns (`…/ip{4,6}/…/udp/<port>/p-pillar`).
#[must_use]
pub fn is_pillar_udp_addr(addr: &Multiaddr) -> bool {
    pillar_udp_socket_addr(addr).is_some()
}

/// Extracts the [`SocketAddr`] a pillar-UDP multiaddr denotes, or `None` if it
/// is not one of ours.
#[must_use]
pub fn pillar_udp_socket_addr(addr: &Multiaddr) -> Option<SocketAddr> {
    let mut iter = addr.iter();
    let ip = match iter.next()? {
        Protocol::Ip4(a) => IpAddr::V4(a),
        Protocol::Ip6(a) => IpAddr::V6(a),
        _ => return None,
    };
    let port = match iter.next()? {
        Protocol::Udp(p) => p,
        _ => return None,
    };
    match iter.next()? {
        Protocol::Unix(p) if p.as_ref() == PILLAR_UDP_SUFFIX => {}
        _ => return None,
    }
    // Tolerate an optional trailing `/p2p/<peer-id>` (the swarm dials the full
    // address including the peer component).
    match iter.next() {
        None => {}
        Some(Protocol::P2p(_)) if iter.next().is_none() => {}
        Some(_) => return None,
    }
    Some(SocketAddr::new(ip, port))
}

/// The pillar-UDP multiaddr for a bound socket address.
#[must_use]
pub fn pillar_udp_multiaddr(sock: SocketAddr) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    match sock.ip() {
        IpAddr::V4(a) => addr.push(Protocol::Ip4(a)),
        IpAddr::V6(a) => addr.push(Protocol::Ip6(a)),
    }
    addr.push(Protocol::Udp(sock.port()));
    addr.push(Protocol::Unix(PILLAR_UDP_SUFFIX.into()));
    addr
}

// -------------------------------------------------------------------------
// Reliable-ordered byte stream over a single UDP flow.
//
// A stop-and-wait, length-prefixed, ACKed frame pump: every payload chunk is
// re-sent until acknowledged, giving libp2p's Noise+yamux upgrade the ordered,
// reliable `AsyncRead + AsyncWrite` byte pipe it requires over an unreliable
// datagram substrate — the reliability posture pillar-UDP exists to provide on
// a degraded link. Not a throughput-optimised congestion-controlled transport
// (QUIC stays the healthy-link default); it is the correct, dial-able
// substrate that makes pillar-UDP a REAL, registered libp2p transport.
// -------------------------------------------------------------------------

/// One end of a reliable-ordered pillar-UDP connection: the `AsyncRead +
/// AsyncWrite` stream libp2p upgrades with Noise+yamux.
pub struct PillarUdpStream {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: mpsc::UnboundedReceiver<io::Result<Vec<u8>>>,
    inbound: VecDeque<u8>,
    write_buf: Vec<u8>,
}

impl AsyncRead for PillarUdpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            if !self.inbound.is_empty() {
                let n = self.inbound.len().min(buf.len());
                for slot in buf.iter_mut().take(n) {
                    *slot = self.inbound.pop_front().unwrap();
                }
                return Poll::Ready(Ok(n));
            }
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    self.inbound.extend(chunk);
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                Poll::Ready(None) => return Poll::Ready(Ok(0)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for PillarUdpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.write_buf.extend_from_slice(buf);
        while self.write_buf.len() >= MAX_PAYLOAD {
            let chunk: Vec<u8> = self.write_buf.drain(..MAX_PAYLOAD).collect();
            if self.tx.send(chunk).is_err() {
                return Poll::Ready(Err(broken()));
            }
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.write_buf.is_empty() {
            let chunk = std::mem::take(&mut self.write_buf);
            if self.tx.send(chunk).is_err() {
                return Poll::Ready(Err(broken()));
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

fn broken() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "pillar-udp connection closed")
}

fn frame(tag: u8, seq: u64, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(HDR + payload.len());
    f.push(tag);
    f.extend_from_slice(&seq.to_be_bytes());
    f.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    f.extend_from_slice(payload);
    f
}

// Drives one reliable, ordered connection over a dedicated (dialer) or shared
// (listener) socket toward a fixed peer. Stop-and-wait with per-direction
// sequence numbers, driven by a `select!` over: outbound app chunks, inbound
// datagrams (from the socket directly for a dialer, or the listener's demux
// channel), and a retransmit ticker. The receiver ACKs every copy and delivers
// a given sequence exactly once (a duplicate re-transmit is re-ACKed but never
// re-delivered), so the byte stream handed to Noise+yamux is reliable AND
// ordered with no duplicated bytes.
async fn pump(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    owns_socket: bool,
    mut in_rx_from_demux: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
    mut out_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    in_tx: mpsc::UnboundedSender<io::Result<Vec<u8>>>,
    send_syn: bool,
) {
    let mut recv_buf = vec![0u8; MAX_PAYLOAD + HDR + 16];
    let mut pending: Option<Vec<u8>> = None; // in-flight outbound frame
    let mut send_seq: u64 = 0;
    let mut recv_seq: u64 = 0;
    let mut retransmit = tokio::time::interval(std::time::Duration::from_millis(60));
    retransmit.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    if send_syn {
        let _ = socket.send_to(&frame(TAG_SYN, 0, &[]), peer).await;
    }

    // Deliver+ACK an inbound datagram; returns false to terminate the pump.
    async fn handle_datagram(
        dgram: &[u8],
        socket: &UdpSocket,
        peer: SocketAddr,
        recv_seq: &mut u64,
        send_seq: &mut u64,
        pending: &mut Option<Vec<u8>>,
        in_tx: &mpsc::UnboundedSender<io::Result<Vec<u8>>>,
    ) -> bool {
        if dgram.len() < HDR {
            return true;
        }
        let tag = dgram[0];
        let seq = u64::from_be_bytes(dgram[1..9].try_into().unwrap());
        let len = u32::from_be_bytes(dgram[9..13].try_into().unwrap()) as usize;
        if HDR + len > dgram.len() {
            return true;
        }
        match tag {
            TAG_DATA => {
                let _ = socket.send_to(&frame(TAG_ACK, seq, &[]), peer).await;
                if seq == *recv_seq {
                    *recv_seq += 1;
                    let payload = dgram[HDR..HDR + len].to_vec();
                    if in_tx.send(Ok(payload)).is_err() {
                        return false;
                    }
                }
            }
            TAG_ACK if pending.is_some() && seq == *send_seq => {
                *pending = None;
                *send_seq += 1;
            }
            _ => {}
        }
        true
    }

    loop {
        // If nothing is in flight, admit the next outbound chunk.
        if pending.is_none() {
            tokio::select! {
                biased;
                maybe = out_rx.recv() => {
                    match maybe {
                        Some(chunk) => {
                            pending = Some(chunk.clone());
                            let _ = socket.send_to(&frame(TAG_DATA, send_seq, &chunk), peer).await;
                        }
                        None => {
                            if in_tx.is_closed() { return; }
                        }
                    }
                    continue;
                }
                got = recv_one(owns_socket, &socket, peer, &mut recv_buf, &mut in_rx_from_demux) => {
                    match got {
                        RecvOne::Data(d) => {
                            if !handle_datagram(&d, &socket, peer, &mut recv_seq, &mut send_seq, &mut pending, &in_tx).await { return; }
                        }
                        RecvOne::Closed => return,
                        RecvOne::Idle => {}
                    }
                    continue;
                }
            }
        } else {
            // Awaiting an ACK: service inbound + retransmit on the ticker.
            tokio::select! {
                got = recv_one(owns_socket, &socket, peer, &mut recv_buf, &mut in_rx_from_demux) => {
                    match got {
                        RecvOne::Data(d) => {
                            if !handle_datagram(&d, &socket, peer, &mut recv_seq, &mut send_seq, &mut pending, &in_tx).await { return; }
                        }
                        RecvOne::Closed => return,
                        RecvOne::Idle => {}
                    }
                }
                _ = retransmit.tick() => {
                    if let Some(chunk) = pending.clone() {
                        let _ = socket.send_to(&frame(TAG_DATA, send_seq, &chunk), peer).await;
                    }
                }
            }
        }
    }
}

enum RecvOne {
    Data(Vec<u8>),
    Closed,
    Idle,
}

// One inbound datagram from either the owned socket (dialer) or the listener
// demux channel. Filters foreign source addresses on the shared dialer socket.
async fn recv_one(
    owns_socket: bool,
    socket: &UdpSocket,
    peer: SocketAddr,
    recv_buf: &mut [u8],
    demux: &mut Option<mpsc::UnboundedReceiver<Vec<u8>>>,
) -> RecvOne {
    if owns_socket {
        match socket.recv_from(recv_buf).await {
            Ok((n, from)) if from == peer => RecvOne::Data(recv_buf[..n].to_vec()),
            Ok(_) => RecvOne::Idle,
            Err(_) => RecvOne::Closed,
        }
    } else {
        match demux {
            Some(r) => match r.recv().await {
                Some(d) => RecvOne::Data(d),
                None => RecvOne::Closed,
            },
            None => RecvOne::Closed,
        }
    }
}

/// A libp2p [`Transport`] binding pillar-UDP endpoints
/// (`…/udp/<port>/p-pillar`) and yielding reliable-ordered [`PillarUdpStream`]
/// connections that the crate's swarm builder upgrades with Noise+yamux.
pub struct PillarUdpTransport {
    listeners: Vec<Listener>,
}

struct Listener {
    id: ListenerId,
    local: SocketAddr,
    reported: bool,
    // New inbound connections surfaced by the accept loop.
    incoming: mpsc::UnboundedReceiver<PillarUdpStream>,
}

impl PillarUdpTransport {
    /// A new, empty pillar-UDP transport.
    #[must_use]
    pub fn new(_keypair: Keypair) -> Self {
        Self {
            listeners: Vec::new(),
        }
    }
}

impl Transport for PillarUdpTransport {
    type Output = PillarUdpStream;
    type Error = io::Error;
    type ListenerUpgrade = BoxFuture<'static, io::Result<PillarUdpStream>>;
    type Dial = BoxFuture<'static, io::Result<PillarUdpStream>>;

    fn listen_on(
        &mut self,
        id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        let sock_addr = pillar_udp_socket_addr(&addr)
            .ok_or_else(|| TransportError::MultiaddrNotSupported(addr.clone()))?;
        let std_sock = std::net::UdpSocket::bind(sock_addr).map_err(TransportError::Other)?;
        std_sock
            .set_nonblocking(true)
            .map_err(TransportError::Other)?;
        let local = std_sock.local_addr().map_err(TransportError::Other)?;
        let socket = Arc::new(UdpSocket::from_std(std_sock).map_err(TransportError::Other)?);

        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        // Accept loop: demultiplex by source SocketAddr; a first datagram from
        // a new peer opens a connection.
        let accept_socket = socket.clone();
        tokio::spawn(async move {
            let demux: Arc<Mutex<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>> =
                Arc::new(Mutex::new(HashMap::new()));
            let mut buf = vec![0u8; MAX_PAYLOAD + HDR + 16];
            loop {
                let (n, from) = match accept_socket.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let dgram = buf[..n].to_vec();
                let mut table = demux.lock().await;
                if let Some(sender) = table.get(&from) {
                    if sender.send(dgram.clone()).is_ok() {
                        continue;
                    }
                    table.remove(&from);
                }
                // New peer: build a connection pump.
                let (demux_in_tx, demux_in_rx) = mpsc::unbounded_channel();
                let _ = demux_in_tx.send(dgram);
                table.insert(from, demux_in_tx);
                let (out_tx, out_rx) = mpsc::unbounded_channel();
                let (in_tx, in_rx) = mpsc::unbounded_channel();
                let stream = PillarUdpStream {
                    tx: out_tx,
                    rx: in_rx,
                    inbound: VecDeque::new(),
                    write_buf: Vec::new(),
                };
                let psock = accept_socket.clone();
                tokio::spawn(pump(
                    psock,
                    from,
                    false,
                    Some(demux_in_rx),
                    out_rx,
                    in_tx,
                    false,
                ));
                if incoming_tx.send(stream).is_err() {
                    return;
                }
            }
        });

        self.listeners.push(Listener {
            id,
            local,
            reported: false,
            incoming: incoming_rx,
        });
        Ok(())
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        let before = self.listeners.len();
        self.listeners.retain(|l| l.id != id);
        self.listeners.len() != before
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        _opts: libp2p::core::transport::DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        let peer = pillar_udp_socket_addr(&addr)
            .ok_or_else(|| TransportError::MultiaddrNotSupported(addr.clone()))?;
        Ok(async move {
            let bind: SocketAddr = match peer.ip() {
                IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
                IpAddr::V6(_) => "[::]:0".parse().unwrap(),
            };
            let socket = Arc::new(UdpSocket::bind(bind).await?);
            let (out_tx, out_rx) = mpsc::unbounded_channel();
            let (in_tx, in_rx) = mpsc::unbounded_channel();
            let stream = PillarUdpStream {
                tx: out_tx,
                rx: in_rx,
                inbound: VecDeque::new(),
                write_buf: Vec::new(),
            };
            tokio::spawn(pump(socket, peer, true, None, out_rx, in_tx, true));
            Ok(stream)
        }
        .boxed())
    }

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        for l in &mut self.listeners {
            if !l.reported {
                l.reported = true;
                return Poll::Ready(TransportEvent::NewAddress {
                    listener_id: l.id,
                    listen_addr: pillar_udp_multiaddr(l.local),
                });
            }
        }
        for l in &mut self.listeners {
            match l.incoming.poll_recv(cx) {
                Poll::Ready(Some(stream)) => {
                    let local = pillar_udp_multiaddr(l.local);
                    return Poll::Ready(TransportEvent::Incoming {
                        listener_id: l.id,
                        upgrade: async move { Ok(stream) }.boxed(),
                        local_addr: local.clone(),
                        send_back_addr: local,
                    });
                }
                Poll::Ready(None) => {}
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
}

#[cfg(test)]
mod raw_tests {
    use super::*;
    use futures::{AsyncReadExt, AsyncWriteExt};
    use libp2p::core::transport::DialOpts;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn raw_stream_roundtrip() {
        let kp = Keypair::generate_ed25519();
        let mut listener = PillarUdpTransport::new(kp.clone());
        let lid = ListenerId::next();
        listener
            .listen_on(lid, "/ip4/127.0.0.1/udp/0/unix/p-pillar".parse().unwrap())
            .unwrap();

        // Get the bound addr.
        let addr = loop {
            if let TransportEvent::NewAddress { listen_addr, .. } =
                futures::future::poll_fn(|cx| Pin::new(&mut listener).poll(cx)).await
            {
                break listen_addr;
            }
        };

        let mut dialer = PillarUdpTransport::new(kp);
        let dial = dialer
            .dial(
                addr,
                DialOpts {
                    role: libp2p::core::Endpoint::Dialer,
                    port_use: libp2p::core::transport::PortUse::Reuse,
                },
            )
            .unwrap();

        let listen_side = async {
            loop {
                if let TransportEvent::Incoming { upgrade, .. } =
                    futures::future::poll_fn(|cx| Pin::new(&mut listener).poll(cx)).await
                {
                    let mut s = upgrade.await.unwrap();
                    let mut buf = [0u8; 5];
                    s.read_exact(&mut buf).await.unwrap();
                    s.write_all(b"pong!").await.unwrap();
                    s.flush().await.unwrap();
                    return buf;
                }
            }
        };
        let dial_side = async {
            let mut s = dial.await.unwrap();
            s.write_all(b"hello").await.unwrap();
            s.flush().await.unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            buf
        };
        let (srv, cli) = tokio::time::timeout(
            std::time::Duration::from_secs(8),
            futures::future::join(listen_side, dial_side),
        )
        .await
        .expect("raw roundtrip");
        assert_eq!(&srv, b"hello");
        assert_eq!(&cli, b"pong!");
    }
}
