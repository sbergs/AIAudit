//! DCE/RPC framing over SMB2 named pipes.

#![cfg(feature = "remote")]

use super::smb::{FileHandle, SmbSession, TreeId};

pub const PKT_REQUEST:  u8 = 0;
pub const PKT_RESPONSE: u8 = 2;
pub const PKT_FAULT:    u8 = 3;
pub const PKT_BIND:     u8 = 11;

/// A DCE/RPC session bound to a single named pipe handle.
///
/// Obtain via [`DceRpc::bind`]. Each [`DceRpc::call`] increments `call_id` and
/// performs one REQUEST → RESPONSE round-trip over the named pipe.
/// Not thread-safe; each host scan owns its own instance.
pub struct DceRpc {
    pub call_id: u32,
    pub pipe_handle: FileHandle,
    pub pipe_tree: TreeId,
}

impl DceRpc {
    pub fn bind(
        session: &SmbSession,
        pipe_tree: TreeId,
        pipe_handle: FileHandle,
        iface_uuid: &[u8; 16],
        iface_ver_major: u16,
        iface_ver_minor: u16,
    ) -> anyhow::Result<Self> {
        let call_id = 1u32;
        let pkt = build_bind(call_id, iface_uuid, iface_ver_major, iface_ver_minor);
        let resp = session.transact_pipe_on_tree(pipe_tree, pipe_handle, &pkt)?;
        parse_bind_ack(&resp)?;
        Ok(DceRpc { call_id, pipe_handle, pipe_tree })
    }

    pub fn call(
        &mut self,
        session: &SmbSession,
        opnum: u16,
        stub: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        self.call_id += 1;
        let pkt = build_request(self.call_id, opnum, stub);
        let resp = session.transact_pipe_on_tree(self.pipe_tree, self.pipe_handle, &pkt)?;
        parse_response(&resp)
    }
}

fn rpc_header(pkt_type: u8, call_id: u32, frag_len: u16) -> [u8; 16] {
    let mut h = [0u8; 16];
    h[0] = 5; h[1] = 0; h[2] = pkt_type; h[3] = 0x03;
    h[4..8].copy_from_slice(&0x0000_0010u32.to_le_bytes()); // NDR little-endian
    h[8..10].copy_from_slice(&frag_len.to_le_bytes());
    h[10..12].copy_from_slice(&0u16.to_le_bytes());
    h[12..16].copy_from_slice(&call_id.to_le_bytes());
    h
}

const NDR32_UUID: [u8; 16] = [
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
    0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
];

fn build_bind(call_id: u32, iface: &[u8; 16], ver_major: u16, ver_minor: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&4280u16.to_le_bytes());
    body.extend_from_slice(&4280u16.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.push(1u8);
    body.extend_from_slice(&[0u8; 3]);
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(iface);
    body.extend_from_slice(&ver_major.to_le_bytes());
    body.extend_from_slice(&ver_minor.to_le_bytes());
    body.extend_from_slice(&NDR32_UUID);
    body.extend_from_slice(&2u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());

    let total = 16 + body.len();
    let hdr = rpc_header(PKT_BIND, call_id, total as u16);
    let mut pkt = hdr.to_vec();
    pkt.extend_from_slice(&body);
    pkt
}

fn parse_bind_ack(buf: &[u8]) -> anyhow::Result<()> {
    if buf.len() < 16 {
        anyhow::bail!("DCE/RPC BIND_ACK too short");
    }
    match buf[2] {
        PKT_FAULT => {
            // Fault body: alloc_hint(4)+p_cont_id(2)+cancel(1)+reserved(1)+status(4) → status at 24
            let status = if buf.len() >= 28 {
                u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]])
            } else { 0 };
            anyhow::bail!("DCE/RPC BIND returned FAULT: 0x{:08X}", status);
        }
        12 => {
            // BIND_ACK body (after 16-byte header):
            //   max_xmit(2) + max_recv(2) + assoc_group(4) + sec_addr_len(2) + sec_addr(var) + pad + results
            if buf.len() < 26 {
                return Ok(()); // too short to parse further, hope for the best
            }
            let sec_len = u16::from_le_bytes([buf[24], buf[25]]) as usize;
            let after_sec = 26 + sec_len;
            // Align to 4 bytes
            let pad = (4 - (after_sec % 4)) % 4;
            let results_offset = after_sec + pad;
            if buf.len() >= results_offset + 4 {
                // num_results (2) + first result (2)
                let result = u16::from_le_bytes([
                    buf[results_offset + 2], buf[results_offset + 3],
                ]);
                if result != 0 {
                    let reason = if buf.len() >= results_offset + 6 {
                        u16::from_le_bytes([buf[results_offset + 4], buf[results_offset + 5]])
                    } else { 0 };
                    anyhow::bail!(
                        "DCE/RPC BIND_ACK: context rejected (result={}, reason={})", result, reason
                    );
                }
            }
            Ok(())
        }
        other => anyhow::bail!("DCE/RPC expected BIND_ACK (12), got {}", other),
    }
}

fn build_request(call_id: u32, opnum: u16, stub: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(stub.len() as u32).to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&opnum.to_le_bytes());
    body.extend_from_slice(stub);
    let total = 16 + body.len();
    let hdr = rpc_header(PKT_REQUEST, call_id, total as u16);
    let mut pkt = hdr.to_vec();
    pkt.extend_from_slice(&body);
    pkt
}

fn parse_response(buf: &[u8]) -> anyhow::Result<Vec<u8>> {
    if buf.len() < 16 { anyhow::bail!("DCE/RPC RESPONSE too short"); }
    match buf[2] {
        PKT_FAULT => {
            // Fault body layout (after 16-byte header):
            //   alloc_hint(4) + p_cont_id(2) + cancel_count(1) + reserved(1) + status(4)
            // → status is at offset 16+8 = 24
            let s = if buf.len() >= 28 {
                u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]])
            } else { 0 };
            anyhow::bail!("DCE/RPC REQUEST returned FAULT: 0x{:08X}", s);
        }
        PKT_RESPONSE => {
            // Response body: alloc_hint(4) + p_context_id(2) + cancel_count(1) + reserved(1)
            // → stub data starts at offset 16+8 = 24
            if buf.len() < 24 { return Ok(Vec::new()); }
            Ok(buf[24..].to_vec())
        }
        other => anyhow::bail!("DCE/RPC expected RESPONSE (2), got {}", other),
    }
}

/// Encode UUID string to 16 LE bytes (data1/2/3 byte-swapped for LE).
pub fn uuid_from_str(s: &str) -> anyhow::Result<[u8; 16]> {
    let s = s.replace('-', "");
    if s.len() != 32 { anyhow::bail!("Invalid UUID string: {}", s); }
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        bytes[i] = u8::from_str_radix(&s[i*2..i*2+2], 16)
            .map_err(|e| anyhow::anyhow!("UUID parse error: {}", e))?;
    }
    bytes[0..4].reverse();
    bytes[4..6].reverse();
    bytes[6..8].reverse();
    Ok(bytes)
}
