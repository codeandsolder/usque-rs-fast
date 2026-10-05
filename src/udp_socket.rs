use std::io;
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};

use socket2::SockRef;
use tokio::net::UdpSocket;

const UDP_SOCKET_BUFFER_BYTES: usize = 4 * 1024 * 1024;

pub fn bind_udp_socket(bind_addr: SocketAddr, label: &'static str) -> io::Result<UdpSocket> {
    let socket = StdUdpSocket::bind(bind_addr)?;
    let sock_ref = SockRef::from(&socket);
    sock_ref.set_recv_buffer_size(UDP_SOCKET_BUFFER_BYTES)?;
    sock_ref.set_send_buffer_size(UDP_SOCKET_BUFFER_BYTES)?;

    let recv_buffer_bytes = sock_ref.recv_buffer_size()?;
    let send_buffer_bytes = sock_ref.send_buffer_size()?;
    socket.set_nonblocking(true)?;

    log::info!(
        "configured UDP socket buffers for {label} on {bind_addr}: recv={recv_buffer_bytes} send={send_buffer_bytes}"
    );

    if recv_buffer_bytes < UDP_SOCKET_BUFFER_BYTES {
        log::warn!(
            "actual UDP receive buffer for {label} on {bind_addr} is below requested size: actual={recv_buffer_bytes} requested={UDP_SOCKET_BUFFER_BYTES}"
        );
    }

    if send_buffer_bytes < UDP_SOCKET_BUFFER_BYTES {
        log::warn!(
            "actual UDP send buffer for {label} on {bind_addr} is below requested size: actual={send_buffer_bytes} requested={UDP_SOCKET_BUFFER_BYTES}"
        );
    }

    UdpSocket::from_std(socket)
}

#[cfg(all(feature = "tun", target_os = "linux"))]
pub fn detect_udp_gso(socket: &UdpSocket, segment_size: usize) -> bool {
    use nix::sys::socket::{setsockopt, sockopt::UdpGsoSegment};

    let Ok(segment_size) = i32::try_from(segment_size) else {
        return false;
    };

    setsockopt(socket, UdpGsoSegment, &segment_size).is_ok()
}

#[cfg(all(feature = "tun", not(target_os = "linux")))]
pub fn detect_udp_gso(_socket: &UdpSocket, _segment_size: usize) -> bool {
    false
}

#[cfg(all(feature = "tun", target_os = "linux"))]
pub async fn send_udp_gso(
    socket: &UdpSocket,
    buf: &[u8],
    segment_size: usize,
    to: SocketAddr,
) -> io::Result<usize> {
    use nix::sys::socket::{ControlMessage, MsgFlags, SockaddrStorage, sendmsg};
    use std::io::IoSlice;
    use std::os::fd::AsRawFd;
    use tokio::io::Interest;

    let segment_size = u16::try_from(segment_size)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "UDP GSO segment too large"))?;
    let dst = SockaddrStorage::from(to);
    let iov = [IoSlice::new(buf)];

    loop {
        socket.writable().await?;

        let result = socket.try_io(Interest::WRITABLE, || {
            let cmsg = [ControlMessage::UdpGsoSegments(&segment_size)];
            sendmsg(
                socket.as_raw_fd(),
                &iov,
                &cmsg,
                MsgFlags::empty(),
                Some(&dst),
            )
            .map_err(io::Error::from)
        });

        match result {
            Ok(written) => return Ok(written),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
    }
}

#[cfg(all(feature = "tun", not(target_os = "linux")))]
pub async fn send_udp_gso(
    _socket: &UdpSocket,
    _buf: &[u8],
    _segment_size: usize,
    _to: SocketAddr,
) -> io::Result<usize> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "UDP GSO is only available on Linux",
    ))
}
