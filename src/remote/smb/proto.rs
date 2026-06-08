//! SMB2 wire-format helpers: header, request builders, response parsers.
//!
//! All integers are little-endian unless noted. Every SMB2 TCP message is
//! prefixed with a 4-byte NetBIOS session header (big-endian length, first
//! byte always 0x00).

#![cfg(feature = "remote")]

use std::io::{Read, Write};

// ─── SMB2 Command codes ───────────────────────────────────────────────────────
pub const CMD_NEGOTIATE:       u16 = 0x0000;
pub const CMD_SESSION_SETUP:   u16 = 0x0001;
pub const CMD_TREE_CONNECT:    u16 = 0x0003;
#[allow(dead_code)]
pub const CMD_TREE_DISCONNECT: u16 = 0x0004;
pub const CMD_CREATE:          u16 = 0x0005;
pub const CMD_CLOSE:           u16 = 0x0006;
pub const CMD_READ:            u16 = 0x0008;
pub const CMD_WRITE:           u16 = 0x0009;
pub const CMD_IOCTL:           u16 = 0x000b;

// ─── NTSTATUS codes used for flow control ────────────────────────────────────
pub const STATUS_OK:                    u32 = 0x0000_0000;
pub const STATUS_MORE_PROCESSING:       u32 = 0xC000_0016;
pub const STATUS_END_OF_FILE:           u32 = 0xC000_0011;
#[allow(dead_code)]
pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;

// ─── SMB2 Header (64 bytes) ───────────────────────────────────────────────────

/// Build a 64-byte SMB2 header.
pub fn smb2_header(
    command: u16,
    message_id: u64,
    tree_id: u32,
    session_id: u64,
    credit_charge: u16,
) -> [u8; 64] {
    let mut h = [0u8; 64];
    h[0..4].copy_from_slice(&[0xFE, 0x53, 0x4D, 0x42]); // protocol_id
    h[4..6].copy_from_slice(&64u16.to_le_bytes());       // structure_size
    h[6..8].copy_from_slice(&credit_charge.to_le_bytes());
    // status (offset 8) = 0 for requests
    h[12..14].copy_from_slice(&command.to_le_bytes());
    h[14..16].copy_from_slice(&1u16.to_le_bytes());     // credits_requested = 1
    // flags offset 16 = 0
    // next_command offset 20 = 0
    h[24..32].copy_from_slice(&message_id.to_le_bytes());
    h[32..36].copy_from_slice(&0xFEFFu32.to_le_bytes()); // process_id
    h[36..40].copy_from_slice(&tree_id.to_le_bytes());
    h[40..48].copy_from_slice(&session_id.to_le_bytes());
    // signature bytes 48..64 = 0 (no signing)
    h
}

/// Parse the status and session_id from an SMB2 response header.
pub fn parse_header(buf: &[u8]) -> anyhow::Result<(u32, u64, u32)> {
    if buf.len() < 64 {
        anyhow::bail!("SMB2 response too short for header ({})", buf.len());
    }
    if &buf[0..4] != &[0xFE, 0x53, 0x4D, 0x42] {
        anyhow::bail!("Not an SMB2 response (bad protocol_id)");
    }
    let status     = u32::from_le_bytes([buf[8],  buf[9],  buf[10], buf[11]]);
    let tree_id    = u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]);
    let session_id = u64::from_le_bytes([
        buf[40], buf[41], buf[42], buf[43],
        buf[44], buf[45], buf[46], buf[47],
    ]);
    Ok((status, session_id, tree_id))
}

// ─── NetBIOS framing ──────────────────────────────────────────────────────────

/// Write one SMB2 message (NetBIOS-framed) to `stream`.
pub fn send_message(stream: &mut impl Write, payload: &[u8]) -> anyhow::Result<()> {
    let len = payload.len();
    let prefix = [
        0x00,
        ((len >> 16) & 0xff) as u8,
        ((len >> 8)  & 0xff) as u8,
        (len         & 0xff) as u8,
    ];
    stream.write_all(&prefix)?;
    stream.write_all(payload)?;
    Ok(())
}

/// Read one SMB2 message from `stream` (strips the 4-byte NetBIOS prefix).
pub fn recv_message(stream: &mut impl Read) -> anyhow::Result<Vec<u8>> {
    let mut prefix = [0u8; 4];
    stream.read_exact(&mut prefix)
        .map_err(|e| anyhow::anyhow!("SMB2 read length prefix: {}", e))?;
    let len = ((prefix[1] as usize) << 16)
            | ((prefix[2] as usize) << 8)
            |  (prefix[3] as usize);
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)
        .map_err(|e| anyhow::anyhow!("SMB2 read payload ({} bytes): {}", len, e))?;
    Ok(buf)
}

// ─── Request builders ────────────────────────────────────────────────────────

/// Build an SMB2 Negotiate request.
pub fn negotiate_request(message_id: u64) -> Vec<u8> {
    let hdr = smb2_header(CMD_NEGOTIATE, message_id, 0, 0, 0);
    let mut body = Vec::new();
    body.extend_from_slice(&36u16.to_le_bytes()); // structure_size
    body.extend_from_slice(&2u16.to_le_bytes());  // dialect_count
    body.extend_from_slice(&3u16.to_le_bytes());  // security_mode: SIGNING_CAPABLE | SIGNING_REQUIRED
    body.extend_from_slice(&0u16.to_le_bytes());  // reserved
    body.extend_from_slice(&0x7fu32.to_le_bytes()); // capabilities
    body.extend_from_slice(&[0u8; 16]);           // client_guid
    body.extend_from_slice(&0u32.to_le_bytes());  // negotiate_context_offset
    body.extend_from_slice(&0u16.to_le_bytes());  // negotiate_context_count
    body.extend_from_slice(&0u16.to_le_bytes());  // reserved2
    // Offer only dialects that use HMAC-SHA256 signing (2.0.2, 2.1).
    // SMB 3.x requires AES-CMAC with a separate KDF; servers downgrade gracefully to 2.1.
    body.extend_from_slice(&0x0202u16.to_le_bytes()); // SMB 2.0.2
    body.extend_from_slice(&0x0210u16.to_le_bytes()); // SMB 2.1
    let mut pkt = hdr.to_vec();
    pkt.extend_from_slice(&body);
    pkt
}

/// Parse an SMB2 Negotiate response; returns (dialect, security_blob).
pub fn parse_negotiate(buf: &[u8]) -> anyhow::Result<(u16, Vec<u8>)> {
    let (status, _, _) = parse_header(buf)?;
    if status != STATUS_OK {
        anyhow::bail!("SMB2 Negotiate failed: status 0x{:08X}", status);
    }
    // Body starts at offset 64.
    // structure_size (2), padding (2), dialect_revision at +4 (relative to body start)
    if buf.len() < 64 + 6 {
        anyhow::bail!("SMB2 Negotiate response too short");
    }
    let dialect = u16::from_le_bytes([buf[64 + 4], buf[64 + 5]]);
    // security_buffer_offset at body+56, security_buffer_length at body+58
    if buf.len() < 64 + 60 {
        return Ok((dialect, Vec::new()));
    }
    let sec_off = u16::from_le_bytes([buf[64 + 56], buf[64 + 57]]) as usize;
    let sec_len = u16::from_le_bytes([buf[64 + 58], buf[64 + 59]]) as usize;
    let blob = if sec_len > 0 && sec_off + sec_len <= buf.len() {
        buf[sec_off..sec_off + sec_len].to_vec()
    } else {
        Vec::new()
    };
    Ok((dialect, blob))
}

/// Build an SMB2 SessionSetup request (round 1 or 3).
pub fn session_setup_request(
    message_id: u64,
    session_id: u64,
    security_blob: &[u8],
) -> Vec<u8> {
    let hdr = smb2_header(CMD_SESSION_SETUP, message_id, 0, session_id, 0);
    // Fixed fields: structure_size(2)+flags(1)+security_mode(1)+capabilities(4)+
    //               channel(4)+sec_buf_offset(2)+sec_buf_len(2)+prev_session_id(8) = 24 bytes
    let sec_buf_offset: u16 = 64 + 24; // header + fixed fields
    let mut body = Vec::new();
    body.extend_from_slice(&25u16.to_le_bytes()); // structure_size
    body.push(0u8);                               // flags
    body.push(3u8);                               // security_mode: SIGNING_CAPABLE | SIGNING_REQUIRED
    body.extend_from_slice(&0x7fu32.to_le_bytes()); // capabilities
    body.extend_from_slice(&0u32.to_le_bytes());  // channel
    body.extend_from_slice(&sec_buf_offset.to_le_bytes());
    body.extend_from_slice(&(security_blob.len() as u16).to_le_bytes());
    body.extend_from_slice(&0u64.to_le_bytes());  // previous_session_id
    body.extend_from_slice(security_blob);
    let mut pkt = hdr.to_vec();
    pkt.extend_from_slice(&body);
    pkt
}

/// Parse SessionSetup response; returns (status, session_id, security_blob).
pub fn parse_session_setup(buf: &[u8]) -> anyhow::Result<(u32, u64, Vec<u8>)> {
    let (status, session_id, _) = parse_header(buf)?;
    // Body at 64: structure_size(2)+session_flags(2)+sec_off(2)+sec_len(2)
    if buf.len() < 64 + 8 {
        return Ok((status, session_id, Vec::new()));
    }
    let sec_off = u16::from_le_bytes([buf[64 + 4], buf[64 + 5]]) as usize;
    let sec_len = u16::from_le_bytes([buf[64 + 6], buf[64 + 7]]) as usize;
    let blob = if sec_len > 0 && sec_off + sec_len <= buf.len() {
        buf[sec_off..sec_off + sec_len].to_vec()
    } else {
        Vec::new()
    };
    Ok((status, session_id, blob))
}

/// Build an SMB2 TreeConnect request.
pub fn tree_connect_request(
    message_id: u64,
    session_id: u64,
    unc_path: &str,
) -> Vec<u8> {
    let hdr = smb2_header(CMD_TREE_CONNECT, message_id, 0, session_id, 0);
    let path_utf16: Vec<u8> = unc_path.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let path_offset: u16 = 64 + 8; // header + structure_size(2)+flags(2)+offset(2)+len(2)
    let mut body = Vec::new();
    body.extend_from_slice(&9u16.to_le_bytes()); // structure_size
    body.extend_from_slice(&0u16.to_le_bytes()); // flags
    body.extend_from_slice(&path_offset.to_le_bytes());
    body.extend_from_slice(&(path_utf16.len() as u16).to_le_bytes());
    body.extend_from_slice(&path_utf16);
    let mut pkt = hdr.to_vec();
    pkt.extend_from_slice(&body);
    pkt
}

/// Parse TreeConnect response — returns tree_id from the header.
pub fn parse_tree_connect(buf: &[u8]) -> anyhow::Result<u32> {
    let (status, _, tree_id) = parse_header(buf)?;
    if status != STATUS_OK {
        anyhow::bail!("SMB2 TreeConnect failed: status 0x{:08X}", status);
    }
    Ok(tree_id)
}

/// Build an SMB2 Create request for a file or named pipe.
pub fn create_request(
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    name: &str,
    desired_access: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
) -> Vec<u8> {
    let hdr = smb2_header(CMD_CREATE, message_id, tree_id, session_id, 1);
    let name_utf16: Vec<u8> = name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    // name_offset = 64 (header) + 56 (fixed Create body fields) = 120
    let name_offset: u16 = 120;
    let mut body = Vec::new();
    body.extend_from_slice(&57u16.to_le_bytes()); // structure_size
    body.push(0u8); // security_flags
    body.push(0u8); // requested_oplock_level (NONE)
    body.extend_from_slice(&2u32.to_le_bytes()); // impersonation_level
    body.extend_from_slice(&0u64.to_le_bytes()); // smb_create_flags
    body.extend_from_slice(&0u64.to_le_bytes()); // reserved
    body.extend_from_slice(&desired_access.to_le_bytes());
    body.extend_from_slice(&0x20u32.to_le_bytes()); // file_attributes = NORMAL
    body.extend_from_slice(&share_access.to_le_bytes());
    body.extend_from_slice(&create_disposition.to_le_bytes());
    body.extend_from_slice(&create_options.to_le_bytes());
    body.extend_from_slice(&name_offset.to_le_bytes());
    body.extend_from_slice(&(name_utf16.len() as u16).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes()); // create_contexts_offset
    body.extend_from_slice(&0u32.to_le_bytes()); // create_contexts_length
    body.extend_from_slice(&name_utf16);
    let mut pkt = hdr.to_vec();
    pkt.extend_from_slice(&body);
    pkt
}

/// Parse a Create response — returns the 16-byte FileId.
pub fn parse_create(buf: &[u8]) -> anyhow::Result<[u8; 16]> {
    let (status, _, _) = parse_header(buf)?;
    if status != STATUS_OK {
        anyhow::bail!("SMB2 Create failed: status 0x{:08X}", status);
    }
    // structure_size(2)+oplock(1)+flags(1) = 4 bytes, then FileId at offset 64+4 = 68
    if buf.len() < 68 + 16 {
        anyhow::bail!("SMB2 Create response too short for FileId");
    }
    let mut fid = [0u8; 16];
    fid.copy_from_slice(&buf[68..84]);
    Ok(fid)
}

/// Build an SMB2 Write request.
pub fn write_request(
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: &[u8; 16],
    offset: u64,
    data: &[u8],
) -> Vec<u8> {
    let hdr = smb2_header(CMD_WRITE, message_id, tree_id, session_id, 1);
    // data_offset = 64 + 48 = 112
    let data_offset: u16 = 112;
    let mut body = Vec::new();
    body.extend_from_slice(&49u16.to_le_bytes()); // structure_size
    body.extend_from_slice(&data_offset.to_le_bytes());
    body.extend_from_slice(&(data.len() as u32).to_le_bytes());
    body.extend_from_slice(&offset.to_le_bytes());
    body.extend_from_slice(file_id);
    body.extend_from_slice(&0u32.to_le_bytes()); // channel
    body.extend_from_slice(&0u32.to_le_bytes()); // remaining_bytes
    body.extend_from_slice(&0u16.to_le_bytes()); // write_channel_info_offset
    body.extend_from_slice(&0u16.to_le_bytes()); // write_channel_info_length
    body.extend_from_slice(&0u32.to_le_bytes()); // flags
    body.extend_from_slice(data);
    let mut pkt = hdr.to_vec();
    pkt.extend_from_slice(&body);
    pkt
}

/// Parse a Write response — returns bytes_written.
pub fn parse_write(buf: &[u8]) -> anyhow::Result<u32> {
    let (status, _, _) = parse_header(buf)?;
    if status != STATUS_OK {
        anyhow::bail!("SMB2 Write failed: status 0x{:08X}", status);
    }
    if buf.len() < 64 + 8 {
        return Ok(0);
    }
    // structure_size(2)+reserved(2)+count(4)
    let count = u32::from_le_bytes([buf[64+4], buf[64+5], buf[64+6], buf[64+7]]);
    Ok(count)
}

/// Build an SMB2 Read request.
pub fn read_request(
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: &[u8; 16],
    offset: u64,
    length: u32,
) -> Vec<u8> {
    let hdr = smb2_header(CMD_READ, message_id, tree_id, session_id, 1);
    let mut body = Vec::new();
    body.extend_from_slice(&49u16.to_le_bytes()); // structure_size
    body.push(0x50u8); // padding
    body.push(0u8);    // flags
    body.extend_from_slice(&length.to_le_bytes());
    body.extend_from_slice(&offset.to_le_bytes());
    body.extend_from_slice(file_id);
    body.extend_from_slice(&0u32.to_le_bytes()); // minimum_count
    body.extend_from_slice(&0u32.to_le_bytes()); // channel
    body.extend_from_slice(&0u32.to_le_bytes()); // remaining_bytes
    body.extend_from_slice(&0u16.to_le_bytes()); // read_channel_info_offset
    body.extend_from_slice(&0u16.to_le_bytes()); // read_channel_info_length
    body.push(0u8); // padding byte required by some implementations
    let mut pkt = hdr.to_vec();
    pkt.extend_from_slice(&body);
    pkt
}

/// Parse a Read response — returns (status, data_bytes).
pub fn parse_read(buf: &[u8]) -> anyhow::Result<(u32, Vec<u8>)> {
    let (status, _, _) = parse_header(buf)?;
    if status != STATUS_OK && status != STATUS_END_OF_FILE {
        anyhow::bail!("SMB2 Read failed: status 0x{:08X}", status);
    }
    if status == STATUS_END_OF_FILE || buf.len() < 64 + 8 {
        return Ok((status, Vec::new()));
    }
    // structure_size(2)+data_offset(1)+reserved(1)+data_length(4) = at body offsets
    let data_off = buf[64 + 2] as usize;
    let data_len = u32::from_le_bytes([buf[64+4], buf[64+5], buf[64+6], buf[64+7]]) as usize;
    if data_off + data_len > buf.len() {
        anyhow::bail!("SMB2 Read response data out of bounds");
    }
    Ok((status, buf[data_off..data_off + data_len].to_vec()))
}

/// Build an SMB2 Close request.
pub fn close_request(
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: &[u8; 16],
) -> Vec<u8> {
    let hdr = smb2_header(CMD_CLOSE, message_id, tree_id, session_id, 1);
    let mut body = Vec::new();
    body.extend_from_slice(&24u16.to_le_bytes()); // structure_size
    body.extend_from_slice(&0u16.to_le_bytes()); // flags
    body.extend_from_slice(&0u32.to_le_bytes()); // reserved
    body.extend_from_slice(file_id);
    let mut pkt = hdr.to_vec();
    pkt.extend_from_slice(&body);
    pkt
}

/// Build an SMB2 IOCTL request for FSCTL_PIPE_TRANSCEIVE.
pub fn ioctl_pipe_transceive_request(
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: &[u8; 16],
    data: &[u8],
) -> Vec<u8> {
    let hdr = smb2_header(CMD_IOCTL, message_id, tree_id, session_id, 1);
    // input_offset = 64 + 56 = 120
    let input_offset: u32 = 120;
    let mut body = Vec::new();
    body.extend_from_slice(&57u16.to_le_bytes()); // structure_size
    body.extend_from_slice(&0u16.to_le_bytes()); // reserved
    body.extend_from_slice(&0x0011_C017u32.to_le_bytes()); // FSCTL_PIPE_TRANSCEIVE
    body.extend_from_slice(file_id);
    body.extend_from_slice(&input_offset.to_le_bytes());
    body.extend_from_slice(&(data.len() as u32).to_le_bytes()); // input_count
    body.extend_from_slice(&0u32.to_le_bytes()); // max_input_response
    body.extend_from_slice(&input_offset.to_le_bytes()); // output_offset
    body.extend_from_slice(&0u32.to_le_bytes()); // output_count
    body.extend_from_slice(&4096u32.to_le_bytes()); // max_output_response
    body.extend_from_slice(&1u32.to_le_bytes()); // flags = IOCTL_IS_FSCTL
    body.extend_from_slice(&0u32.to_le_bytes()); // reserved2
    body.extend_from_slice(data);
    let mut pkt = hdr.to_vec();
    pkt.extend_from_slice(&body);
    pkt
}

/// Parse an IOCTL response; returns output data.
pub fn parse_ioctl(buf: &[u8]) -> anyhow::Result<Vec<u8>> {
    let (status, _, _) = parse_header(buf)?;
    if status != STATUS_OK {
        anyhow::bail!("SMB2 IOCTL failed: status 0x{:08X}", status);
    }
    if buf.len() < 64 + 48 {
        return Ok(Vec::new());
    }
    // output_offset at body+32, output_count at body+36
    let out_off = u32::from_le_bytes([buf[64+32], buf[64+33], buf[64+34], buf[64+35]]) as usize;
    let out_cnt = u32::from_le_bytes([buf[64+36], buf[64+37], buf[64+38], buf[64+39]]) as usize;
    if out_cnt > 0 && out_off + out_cnt <= buf.len() {
        Ok(buf[out_off..out_off + out_cnt].to_vec())
    } else {
        Ok(Vec::new())
    }
}

/// Sign an SMB2 message with HMAC-SHA256 (dialects 2.0.2 and 2.1).
///
/// Sets `SMB2_FLAGS_SIGNED` in the header flags, zeros the 16-byte signature
/// field, computes HMAC-SHA256(key, message), and writes the first 16 bytes of
/// the result back into the signature field (bytes 48–63).
pub fn sign_smb2_message(payload: &[u8], key: &[u8; 16]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let mut msg = payload.to_vec();
    if msg.len() < 64 {
        return msg;
    }
    // Set SMB2_FLAGS_SIGNED (0x00000008) in the header flags field (bytes 16–19).
    let flags = u32::from_le_bytes([msg[16], msg[17], msg[18], msg[19]]) | 0x0000_0008;
    msg[16..20].copy_from_slice(&flags.to_le_bytes());
    // The signature field (bytes 48–63) must be zeroed before computing the HMAC.
    msg[48..64].fill(0);
    // HMAC-SHA256 over the complete message; truncate to 16 bytes.
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&msg);
    msg[48..64].copy_from_slice(&mac.finalize().into_bytes()[..16]);
    msg
}

/// Build an SMB2 TreeDisconnect request.
#[allow(dead_code)]
pub fn tree_disconnect_request(
    message_id: u64,
    session_id: u64,
    tree_id: u32,
) -> Vec<u8> {
    let hdr = smb2_header(CMD_TREE_DISCONNECT, message_id, tree_id, session_id, 0);
    let mut body = Vec::new();
    body.extend_from_slice(&4u16.to_le_bytes()); // structure_size
    body.extend_from_slice(&0u16.to_le_bytes()); // reserved
    let mut pkt = hdr.to_vec();
    pkt.extend_from_slice(&body);
    pkt
}
