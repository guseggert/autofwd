use std::io;

use crate::ListeningSocket;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use nix::sys::socket::{
        sendto, socket, AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType,
    };
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::os::unix::io::RawFd;

    const SOCK_DIAG_BY_FAMILY: u16 = 20;

    const NLM_F_REQUEST: u16 = 0x01;
    const NLM_F_DUMP: u16 = 0x300;

    const NLMSG_DONE: u16 = 0x03;
    const NLMSG_ERROR: u16 = 0x02;

    const TCP_LISTEN: u8 = 10;
    const TCPF_LISTEN: u32 = 1 << (TCP_LISTEN as u32);

    const INET_DIAG_NOCOOKIE: u32 = 0xFFFF_FFFF;

    const NLMSG_HDR_LEN: usize = 16;
    const INET_DIAG_REQ_V2_LEN: usize = 60;
    const INET_DIAG_MSG_MIN_LEN: usize = 72;

    fn io_err(msg: &'static str) -> io::Error {
        io::Error::other(msg)
    }

    fn open_sock() -> io::Result<OwnedFd> {
        // Safe wrapper. The underlying crate uses unsafe internally.
        socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::empty(),
            SockProtocol::NetlinkSockDiag,
        )
        .map_err(io::Error::other)
    }

    fn write_u16_ne(dst: &mut [u8], off: usize, v: u16) -> bool {
        let Some(slot) = dst.get_mut(off..off + 2) else {
            return false;
        };
        slot.copy_from_slice(&v.to_ne_bytes());
        true
    }

    fn write_u32_ne(dst: &mut [u8], off: usize, v: u32) -> bool {
        let Some(slot) = dst.get_mut(off..off + 4) else {
            return false;
        };
        slot.copy_from_slice(&v.to_ne_bytes());
        true
    }

    fn read_u16_ne(src: &[u8], off: usize) -> Option<u16> {
        Some(u16::from_ne_bytes(src.get(off..off + 2)?.try_into().ok()?))
    }

    fn read_u32_ne(src: &[u8], off: usize) -> Option<u32> {
        Some(u32::from_ne_bytes(src.get(off..off + 4)?.try_into().ok()?))
    }

    fn read_i32_ne(src: &[u8], off: usize) -> Option<i32> {
        Some(i32::from_ne_bytes(src.get(off..off + 4)?.try_into().ok()?))
    }

    fn send_req(fd: RawFd, family: u8, seq: u32) -> io::Result<()> {
        let mut buf = vec![0u8; NLMSG_HDR_LEN + INET_DIAG_REQ_V2_LEN];

        // nlmsghdr (native endian)
        let nlmsg_len = buf.len() as u32;
        if !write_u32_ne(&mut buf, 0, nlmsg_len)
            || !write_u16_ne(&mut buf, 4, SOCK_DIAG_BY_FAMILY)
            || !write_u16_ne(&mut buf, 6, NLM_F_REQUEST | NLM_F_DUMP)
            || !write_u32_ne(&mut buf, 8, seq)
            || !write_u32_ne(&mut buf, 12, 0)
        {
            return Err(io_err("netlink: failed to encode header"));
        }

        // inet_diag_req_v2
        let req_off = NLMSG_HDR_LEN;
        buf[req_off] = family;
        buf[req_off + 1] = 6; // IPPROTO_TCP
        buf[req_off + 2] = 0; // idiag_ext
        buf[req_off + 3] = 0; // pad
        if !write_u32_ne(&mut buf, req_off + 4, TCPF_LISTEN) {
            return Err(io_err("netlink: failed to encode req"));
        }

        // inet_diag_sockid starts at req_off+8, fill cookie with NOCOOKIE; everything else 0
        let sockid_off = req_off + 8;
        // cookie is last 8 bytes of sockid (offset 44, len 8)
        let cookie_off = sockid_off + 44;
        if !write_u32_ne(&mut buf, cookie_off, INET_DIAG_NOCOOKIE)
            || !write_u32_ne(&mut buf, cookie_off + 4, INET_DIAG_NOCOOKIE)
        {
            return Err(io_err("netlink: failed to encode cookie"));
        }

        let addr = NetlinkAddr::new(0, 0);
        sendto(fd, &buf, &addr, MsgFlags::empty())
            .map(|_| ())
            .map_err(io::Error::other)
    }

    fn recv_msgs(fd: RawFd, seq: u32, out: &mut Vec<ListeningSocket>) -> io::Result<()> {
        let mut buf = vec![0u8; 64 * 1024];

        loop {
            let rc = nix::sys::socket::recv(fd, &mut buf, MsgFlags::empty())
                .map_err(io::Error::other)?;
            if rc == 0 {
                return Err(io_err("netlink: EOF"));
            }

            let mut offset = 0usize;
            let n = rc as usize;
            while offset + NLMSG_HDR_LEN <= n {
                let nlmsg_len =
                    read_u32_ne(&buf, offset).ok_or_else(|| io_err("netlink: bad len"))?;
                let nlmsg_type =
                    read_u16_ne(&buf, offset + 4).ok_or_else(|| io_err("netlink: bad type"))?;
                let _nlmsg_flags =
                    read_u16_ne(&buf, offset + 6).ok_or_else(|| io_err("netlink: bad flags"))?;
                let nlmsg_seq =
                    read_u32_ne(&buf, offset + 8).ok_or_else(|| io_err("netlink: bad seq"))?;

                if nlmsg_len < NLMSG_HDR_LEN as u32 {
                    return Err(io_err("netlink: short nlmsg"));
                }
                let msg_len = nlmsg_len as usize;
                if offset + msg_len > n {
                    break;
                }

                if nlmsg_seq != seq {
                    offset += nlmsg_align(msg_len);
                    continue;
                }

                match nlmsg_type {
                    NLMSG_DONE => return Ok(()),
                    NLMSG_ERROR => {
                        // nlmsgerr payload starts with i32 error (native endian)
                        let err = read_i32_ne(&buf, offset + NLMSG_HDR_LEN)
                            .ok_or_else(|| io_err("netlink: bad nlmsgerr"))?;
                        if err == 0 {
                            return Ok(());
                        }
                        return Err(io::Error::from_raw_os_error(-err));
                    }
                    _ => {
                        let payload_off = offset + NLMSG_HDR_LEN;
                        let payload_len = msg_len - NLMSG_HDR_LEN;
                        if payload_len >= INET_DIAG_MSG_MIN_LEN {
                            let family = buf[payload_off];
                            let state = buf[payload_off + 1];
                            if state != TCP_LISTEN {
                                // Should already be filtered, but keep it strict.
                                offset += nlmsg_align(msg_len);
                                continue;
                            }

                            // sport is at offset 4 in inet_diag_msg, stored in network byte order.
                            let sport_off = payload_off + 4;
                            let Some(port) = buf
                                .get(sport_off..sport_off + 2)
                                .map(|b| u16::from_be_bytes([b[0], b[1]]))
                            else {
                                offset += nlmsg_align(msg_len);
                                continue;
                            };

                            // inode is the final u32 field at offset 68 (native endian)
                            let inode_off = payload_off + 68;
                            let Some(inode) = read_u32_ne(&buf, inode_off) else {
                                offset += nlmsg_align(msg_len);
                                continue;
                            };

                            if port != 0 && inode != 0 {
                                out.push(ListeningSocket {
                                    port,
                                    inode: inode as u64,
                                    is_v6: family == 10, // AF_INET6
                                });
                            }
                        }
                    }
                }

                offset += nlmsg_align(msg_len);
            }
        }
    }

    #[inline]
    fn nlmsg_align(len: usize) -> usize {
        const NLMSG_ALIGNTO: usize = 4;
        (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
    }

    pub(super) fn list_listening_sockets() -> io::Result<Vec<ListeningSocket>> {
        let fd = open_sock()?;
        let mut out = Vec::new();
        let mut seq = 1u32;

        let res = (|| -> io::Result<()> {
            // Query IPv4 + IPv6.
            send_req(fd.as_raw_fd(), 2, seq)?; // AF_INET
            recv_msgs(fd.as_raw_fd(), seq, &mut out)?;
            seq = seq.wrapping_add(1);

            send_req(fd.as_raw_fd(), 10, seq)?; // AF_INET6
            recv_msgs(fd.as_raw_fd(), seq, &mut out)?;

            Ok(())
        })();

        res?;
        Ok(out)
    }
}

#[cfg(target_os = "linux")]
pub fn list_listening_sockets() -> io::Result<Vec<ListeningSocket>> {
    linux::list_listening_sockets()
}

#[cfg(not(target_os = "linux"))]
pub fn list_listening_sockets() -> io::Result<Vec<ListeningSocket>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "netlink sock_diag is only available on Linux",
    ))
}
