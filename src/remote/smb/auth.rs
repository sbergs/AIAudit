//! NTLMv2 authentication and SPNEGO wrapping — pure Rust, no external crates.

#![cfg(feature = "remote")]

// ─── MD4 (RFC 1320) ──────────────────────────────────────────────────────────

pub fn md4(data: &[u8]) -> [u8; 16] {
    let mut a: u32 = 0x6745_2301;
    let mut b: u32 = 0xefcd_ab89;
    let mut c: u32 = 0x98ba_dcfe;
    let mut d: u32 = 0x1032_5476;

    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let f = |x: u32, y: u32, z: u32| -> u32 { (x & y) | (!x & z) };
    let g = |x: u32, y: u32, z: u32| -> u32 { (x & y) | (x & z) | (y & z) };
    let h = |x: u32, y: u32, z: u32| -> u32 { x ^ y ^ z };

    for chunk in msg.chunks(64) {
        let mut x = [0u32; 16];
        for (i, w) in x.iter_mut().enumerate() {
            *w = u32::from_le_bytes([
                chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3],
            ]);
        }
        let (aa, bb, cc, dd) = (a, b, c, d);

        // Round 1
        for &base in &[0usize, 4, 8, 12] {
            a = a.wrapping_add(f(b, c, d)).wrapping_add(x[base]).rotate_left(3);
            d = d.wrapping_add(f(a, b, c)).wrapping_add(x[base + 1]).rotate_left(7);
            c = c.wrapping_add(f(d, a, b)).wrapping_add(x[base + 2]).rotate_left(11);
            b = b.wrapping_add(f(c, d, a)).wrapping_add(x[base + 3]).rotate_left(19);
        }

        // Round 2: groups [0,4,8,12], [1,5,9,13], [2,6,10,14], [3,7,11,15]
        for &i0 in &[0usize, 1, 2, 3] {
            let idxs = [i0, i0 + 4, i0 + 8, i0 + 12];
            a = a.wrapping_add(g(b, c, d)).wrapping_add(x[idxs[0]]).wrapping_add(0x5a82_7999).rotate_left(3);
            d = d.wrapping_add(g(a, b, c)).wrapping_add(x[idxs[1]]).wrapping_add(0x5a82_7999).rotate_left(5);
            c = c.wrapping_add(g(d, a, b)).wrapping_add(x[idxs[2]]).wrapping_add(0x5a82_7999).rotate_left(9);
            b = b.wrapping_add(g(c, d, a)).wrapping_add(x[idxs[3]]).wrapping_add(0x5a82_7999).rotate_left(13);
        }

        // Round 3: groups [0,8,4,12], [2,10,6,14], [1,9,5,13], [3,11,7,15]
        let r3: [[usize; 4]; 4] = [[0,8,4,12],[2,10,6,14],[1,9,5,13],[3,11,7,15]];
        for group in &r3 {
            a = a.wrapping_add(h(b, c, d)).wrapping_add(x[group[0]]).wrapping_add(0x6ed9_eba1).rotate_left(3);
            d = d.wrapping_add(h(a, b, c)).wrapping_add(x[group[1]]).wrapping_add(0x6ed9_eba1).rotate_left(9);
            c = c.wrapping_add(h(d, a, b)).wrapping_add(x[group[2]]).wrapping_add(0x6ed9_eba1).rotate_left(11);
            b = b.wrapping_add(h(c, d, a)).wrapping_add(x[group[3]]).wrapping_add(0x6ed9_eba1).rotate_left(15);
        }

        a = a.wrapping_add(aa);
        b = b.wrapping_add(bb);
        c = c.wrapping_add(cc);
        d = d.wrapping_add(dd);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a.to_le_bytes());
    out[4..8].copy_from_slice(&b.to_le_bytes());
    out[8..12].copy_from_slice(&c.to_le_bytes());
    out[12..16].copy_from_slice(&d.to_le_bytes());
    out
}

// ─── MD5 (RFC 1321) ──────────────────────────────────────────────────────────

#[rustfmt::skip]
const MD5_T: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

#[rustfmt::skip]
const MD5_S: [u32; 64] = [
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
];

pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xefcd_ab89;
    let mut c0: u32 = 0x98ba_dcfe;
    let mut d0: u32 = 0x1032_5476;

    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for (i, w) in m.iter_mut().enumerate() {
            *w = u32::from_le_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64u32 {
            let (f, g): (u32, usize) = match i {
                0..=15  => ((b & c) | (!b & d), i as usize),
                16..=31 => ((d & b) | (!d & c), (5 * i as usize + 1) % 16),
                32..=47 => (b ^ c ^ d,           (3 * i as usize + 5) % 16),
                _       => (c ^ (b | !d),         (7 * i as usize)     % 16),
            };
            let temp = d;
            d = c; c = b;
            b = b.wrapping_add(
                a.wrapping_add(f)
                 .wrapping_add(MD5_T[i as usize])
                 .wrapping_add(m[g])
                 .rotate_left(MD5_S[i as usize]),
            );
            a = temp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

// ─── HMAC-MD5 ────────────────────────────────────────────────────────────────

pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let key_hash;
    let k: &[u8] = if key.len() > 64 {
        key_hash = md5(key);
        &key_hash
    } else {
        key
    };
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..k.len() { ipad[i] ^= k[i]; opad[i] ^= k[i]; }
    let mut inner = ipad.to_vec();
    inner.extend_from_slice(data);
    let inner_hash = md5(&inner);
    let mut outer = opad.to_vec();
    outer.extend_from_slice(&inner_hash);
    md5(&outer)
}

// ─── RC4 (used for KEY_EXCH session-key encryption) ─────────────────────────

pub fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: Vec<u8> = (0u8..=255).collect();
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }
    let (mut i, mut j) = (0usize, 0usize);
    data.iter().map(|&b| {
        i = (i + 1) % 256;
        j = (j + s[i] as usize) % 256;
        s.swap(i, j);
        b ^ s[(s[i] as usize + s[j] as usize) % 256]
    }).collect()
}

// ─── NT hash ─────────────────────────────────────────────────────────────────

pub fn nt_hash(password: &str) -> [u8; 16] {
    let utf16: Vec<u8> = password.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    md4(&utf16)
}

pub fn client_challenge() -> [u8; 8] {
    use rand::{RngCore, rngs::OsRng};
    let mut cc = [0u8; 8];
    OsRng.fill_bytes(&mut cc);
    cc
}

pub fn filetime_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    (secs + 11_644_473_600) * 10_000_000
}

// ─── NTLM message builders ────────────────────────────────────────────────────

pub fn build_type1() -> Vec<u8> {
    const SIG: &[u8; 8] = b"NTLMSSP\0";
    const FLAGS: u32 = 0x0000_0001 // NEGOTIATE_UNICODE
                     | 0x0000_0002 // NEGOTIATE_OEM
                     | 0x0000_0004 // REQUEST_TARGET
                     | 0x0000_0200 // NEGOTIATE_NTLM
                     | 0x0000_8000 // NEGOTIATE_ALWAYS_SIGN
                     | 0x0008_0000 // NEGOTIATE_EXTENDED_SESSIONSECURITY
                     | 0x2000_0000 // NEGOTIATE_128
                     | 0x8000_0000; // NEGOTIATE_56
    let mut msg = Vec::with_capacity(32);
    msg.extend_from_slice(SIG);
    msg.extend_from_slice(&1u32.to_le_bytes());
    msg.extend_from_slice(&FLAGS.to_le_bytes());
    msg.extend_from_slice(&[0u8; 8]); // domain sec-buf (empty)
    msg.extend_from_slice(&[0u8; 8]); // workstation sec-buf (empty)
    msg
}

/// Returns (server_challenge, target_info, negotiate_flags).
pub fn parse_type2(msg: &[u8]) -> anyhow::Result<([u8; 8], Vec<u8>, u32)> {
    if msg.len() < 56 {
        anyhow::bail!("NTLM Type2 message too short ({})", msg.len());
    }
    if &msg[0..8] != b"NTLMSSP\0" {
        anyhow::bail!("NTLM challenge not found in Type2 message");
    }
    if u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]) != 2 {
        anyhow::bail!("Expected NTLM Type2, got different message type");
    }
    let mut challenge = [0u8; 8];
    challenge.copy_from_slice(&msg[24..32]);

    let flags = u32::from_le_bytes([msg[20], msg[21], msg[22], msg[23]]);

    let target_info = if msg.len() >= 48 {
        let ti_len = u16::from_le_bytes([msg[40], msg[41]]) as usize;
        let ti_off = u32::from_le_bytes([msg[44], msg[45], msg[46], msg[47]]) as usize;
        if ti_len > 0 && ti_off + ti_len <= msg.len() {
            msg[ti_off..ti_off + ti_len].to_vec()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    Ok((challenge, target_info, flags))
}

pub fn build_type3(
    server_challenge: &[u8; 8],
    target_info: &[u8],
    user: &str,
    domain: &str,
    password: &str,
    server_flags: u32,
) -> (Vec<u8>, [u8; 16]) {
    const SIG: &[u8; 8] = b"NTLMSSP\0";
    const NTLMSSP_NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
    let key_exch = (server_flags & NTLMSSP_NEGOTIATE_KEY_EXCH) != 0;

    // Echo back flags the server granted, forcing UNICODE and key-exch state to match.
    let flags = server_flags
        & !(0x0000_0002) // clear OEM: we use UNICODE
        | 0x0000_0001;  // ensure UNICODE is set

    let nt = nt_hash(password);
    let mut identity = user.to_uppercase();
    identity.push_str(domain);
    let id_utf16: Vec<u8> = identity.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let response_key_nt = hmac_md5(&nt, &id_utf16);

    let cc = client_challenge();
    let ts = filetime_now();

    let mut blob = Vec::new();
    // NTLMv2ClientChallenge header: RespType=1, HiRespType=1, Reserved1=0, Reserved2=0
    blob.extend_from_slice(&0x0000_0101u32.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&ts.to_le_bytes());
    blob.extend_from_slice(&cc);
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(target_info);
    blob.extend_from_slice(&0u32.to_le_bytes());

    let mut ntprf_in = server_challenge.to_vec();
    ntprf_in.extend_from_slice(&blob);
    let nt_proof = hmac_md5(&response_key_nt, &ntprf_in);
    // SessionBaseKey = HMAC-MD5(ResponseKeyNT, NTProofStr). Without NTLMSSP_NEGOTIATE_KEY_EXCH,
    // this IS the ExportedSessionKey used directly as the SMB2 signing key (dialects 2.x).
    let session_base_key = hmac_md5(&response_key_nt, &nt_proof);

    let mut nt_resp = nt_proof.to_vec();
    nt_resp.extend_from_slice(&blob);

    let mut lm_in = server_challenge.to_vec();
    lm_in.extend_from_slice(&cc);
    let lm_hash = hmac_md5(&response_key_nt, &lm_in);
    let mut lm_resp = lm_hash.to_vec();
    lm_resp.extend_from_slice(&cc);

    let domain_utf16: Vec<u8> = domain.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let user_utf16: Vec<u8>   = user.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

    // Header: SIG(8)+type(4)+6*secbuf(8 each)+flags(4)+version(8) = 72 bytes
    let hdr: u32 = 72;
    let lm_off     = hdr;
    let nt_off     = lm_off + lm_resp.len() as u32;
    let domain_off = nt_off + nt_resp.len() as u32;
    let user_off   = domain_off + domain_utf16.len() as u32;
    let ws_off     = user_off + user_utf16.len() as u32;

    let mut msg = Vec::new();
    msg.extend_from_slice(SIG);
    msg.extend_from_slice(&3u32.to_le_bytes());
    push_sec_buf(&mut msg, lm_resp.len() as u16,      lm_off);
    push_sec_buf(&mut msg, nt_resp.len() as u16,      nt_off);
    push_sec_buf(&mut msg, domain_utf16.len() as u16, domain_off);
    push_sec_buf(&mut msg, user_utf16.len() as u16,   user_off);
    // KEY_EXCH: generate a random ExportedSessionKey, RC4-encrypt it under the
    // SessionBaseKey, and include the encrypted form in the Type3 session key field.
    // Without KEY_EXCH the ExportedSessionKey == SessionBaseKey directly.
    let (exported_session_key, encrypted_session_key): ([u8; 16], Vec<u8>) = if key_exch {
        use rand::{RngCore, rngs::OsRng};
        let mut esk = [0u8; 16];
        OsRng.fill_bytes(&mut esk);
        let encrypted = rc4(&session_base_key, &esk);
        (esk, encrypted)
    } else {
        (session_base_key, Vec::new())
    };

    let sk_off = ws_off; // session key data starts after the workstation (which is empty)
    let sk_len = encrypted_session_key.len() as u16;

    push_sec_buf(&mut msg, 0, ws_off); // workstation (empty)
    push_sec_buf(&mut msg, sk_len, sk_off); // session key
    msg.extend_from_slice(&flags.to_le_bytes());
    msg.extend_from_slice(&[0u8; 8]); // version (zeroed; NTLMSSP_NEGOTIATE_VERSION not set)

    msg.extend_from_slice(&lm_resp);
    msg.extend_from_slice(&nt_resp);
    msg.extend_from_slice(&domain_utf16);
    msg.extend_from_slice(&user_utf16);
    if !encrypted_session_key.is_empty() {
        msg.extend_from_slice(&encrypted_session_key);
    }
    (msg, exported_session_key)
}

fn push_sec_buf(buf: &mut Vec<u8>, len: u16, offset: u32) {
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&len.to_le_bytes()); // maxlen
    buf.extend_from_slice(&offset.to_le_bytes());
}

// ─── SPNEGO / ASN.1 BER ──────────────────────────────────────────────────────

const NTLM_OID: &[u8] = &[0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a];

pub fn encode_ber_len(n: usize) -> Vec<u8> {
    if n < 128 {
        vec![n as u8]
    } else if n <= 0xffff {
        vec![0x82, (n >> 8) as u8, (n & 0xff) as u8]
    } else {
        vec![0x83, (n >> 16) as u8, ((n >> 8) & 0xff) as u8, (n & 0xff) as u8]
    }
}

fn ber_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&encode_ber_len(content.len()));
    out.extend_from_slice(content);
    out
}

pub fn spnego_wrap_type1(ntlm: &[u8]) -> Vec<u8> {
    // RFC 4178 §4.2.1: NegotiationToken CHOICE [0] NegTokenInit
    // Structure: [60] { SPNEGO_OID [a0] { [30] { [a0] mechTypes [a2] mechToken } } }
    let mech_types_seq = ber_tlv(0x30, NTLM_OID);
    let mech_types = ber_tlv(0xa0, &mech_types_seq);  // [0] mechTypes
    let mech_token = ber_tlv(0xa2, &ber_tlv(0x04, ntlm)); // [2] mechToken
    let mut neg_init_body = Vec::new();
    neg_init_body.extend_from_slice(&mech_types);
    neg_init_body.extend_from_slice(&mech_token);
    let neg_token_init = ber_tlv(0xa0, &ber_tlv(0x30, &neg_init_body)); // [0] { SEQUENCE }
    let spnego_oid: &[u8] = &[0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02];
    let mut app = Vec::new();
    app.extend_from_slice(spnego_oid);
    app.extend_from_slice(&neg_token_init);
    ber_tlv(0x60, &app)
}

pub fn spnego_wrap_type3(ntlm: &[u8]) -> Vec<u8> {
    // RFC 4178 negTokenResp: [1] { [30] { [a2] responseToken } }
    // Clients omit negState from their Authenticate response.
    let resp_token = ber_tlv(0xa2, &ber_tlv(0x04, ntlm));
    let seq = ber_tlv(0x30, &resp_token);
    ber_tlv(0xa1, &seq)
}

pub fn spnego_extract_ntlm(blob: &[u8]) -> Option<Vec<u8>> {
    if blob.starts_with(b"NTLMSSP\0") {
        return Some(blob.to_vec());
    }
    find_ntlm_in_ber(blob)
}

fn find_ntlm_in_ber(data: &[u8]) -> Option<Vec<u8>> {
    let mut i = 0;
    while i < data.len() {
        let tag = data[i];
        i += 1;
        let (len, consumed) = ber_decode_len(&data[i..])?;
        i += consumed;
        if i + len > data.len() { break; }
        let content = &data[i..i + len];
        if tag == 0x04 && content.starts_with(b"NTLMSSP\0") {
            return Some(content.to_vec());
        }
        if (tag & 0x20) != 0 || matches!(tag, 0xa0|0xa1|0xa2|0xa3|0x60|0x61) {
            if let Some(found) = find_ntlm_in_ber(content) {
                return Some(found);
            }
        }
        i += len;
    }
    None
}

fn ber_decode_len(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() { return None; }
    if data[0] < 0x80 { return Some((data[0] as usize, 1)); }
    let n = (data[0] & 0x7f) as usize;
    if data.len() < 1 + n { return None; }
    let mut len = 0usize;
    for &b in &data[1..1+n] { len = (len << 8) | (b as usize); }
    Some((len, 1 + n))
}

// ─── Kerberos / GSSAPI ───────────────────────────────────────────────────────

#[cfg(feature = "kerberos")]
pub mod kerberos {
    use libgssapi::{
        context::{ClientCtx, CtxFlags},
        credential::{Cred, CredUsage},
        name::Name,
        oid::{OidSet, GSS_MECH_KRB5, GSS_NT_HOSTBASED_SERVICE, GSS_NT_USER_NAME},
    };

    /// Live GSSAPI client context used to complete mutual authentication.
    pub struct KerberosCtx(ClientCtx);

    /// Acquire a KRB5 service ticket for `cifs@host` and return the SPNEGO-wrapped
    /// AP-REQ ready for SMB2 SESSION_SETUP.
    ///
    /// - `principal` + `password` both `Some`: GSSAPI performs the full AS-REQ/AS-REP
    ///   exchange internally — no `kinit` required.
    /// - Both `None`: uses the existing TGT in the system ticket cache (`kinit` first).
    pub fn initiate(
        host: &str,
        principal: Option<&str>,
        password: Option<&str>,
    ) -> anyhow::Result<(KerberosCtx, Vec<u8>)> {
        let svc = format!("cifs@{}", host);
        // Oid<'static> is Copy — pass by value, not reference.
        let svc_name = Name::new(svc.as_bytes(), Some(GSS_NT_HOSTBASED_SERVICE))
            .map_err(|e| anyhow::anyhow!("GSSAPI service name '{}': {}", svc, e))?;
        let svc_name = svc_name
            .canonicalize(Some(GSS_MECH_KRB5))
            .map_err(|e| anyhow::anyhow!("GSSAPI canonicalize: {}", e))?;

        let mut oids = OidSet::new();
        oids.add(GSS_MECH_KRB5)
            .map_err(|e| anyhow::anyhow!("GSSAPI OidSet add: {}", e))?;

        let cred = match (principal, password) {
            (Some(p), Some(pw)) => {
                // Build the client principal name (user@DOMAIN.COM).
                let user_name = Name::new(p.as_bytes(), Some(GSS_NT_USER_NAME))
                    .map_err(|e| anyhow::anyhow!("GSSAPI principal name '{}': {}", p, e))?;
                // gss_acquire_cred_with_password — GSSAPI does the full AS-REQ/AS-REP.
                Cred::acquire_with_password(
                    Some(&user_name),
                    pw,
                    None,
                    CredUsage::Initiate,
                    Some(&oids),
                )
                .map_err(|e| anyhow::anyhow!("Kerberos AS-REQ failed for '{}': {}", p, e))?
            }
            _ => {
                // Fall back to the system ticket cache (requires prior kinit).
                Cred::acquire(None, None, CredUsage::Initiate, Some(&oids)).map_err(|e| {
                    let user = std::env::var("USER").unwrap_or_else(|_| "user".into());
                    anyhow::anyhow!(
                        "No Kerberos credentials in cache ({}). \
                         Pass --user user@DOMAIN --password or run: kinit {}@YOUR.DOMAIN",
                        e,
                        user
                    )
                })?
            }
        };

        let mut ctx = ClientCtx::new(
            Some(cred),
            svc_name,
            CtxFlags::GSS_C_MUTUAL_FLAG | CtxFlags::GSS_C_SEQUENCE_FLAG,
            Some(GSS_MECH_KRB5),
        );

        let krb5_tok = ctx
            .step(None, None)
            .map_err(|e| anyhow::anyhow!("GSSAPI TGS-REQ failed: {}", e))?
            .ok_or_else(|| anyhow::anyhow!("GSSAPI produced no initial token"))?;

        let spnego = spnego_wrap_krb5(&krb5_tok);
        Ok((KerberosCtx(ctx), spnego))
    }

    impl KerberosCtx {
        /// Feed the server's AP-REP back into GSSAPI to complete mutual auth.
        /// `server_token` is the responseToken extracted from the SPNEGO negTokenResp;
        /// it may be absent if the server does not send mutual auth confirmation.
        pub fn finish(&mut self, server_token: Option<&[u8]>) -> anyhow::Result<()> {
            if let Some(tok) = server_token {
                self.0
                    .step(Some(tok), None)
                    .map_err(|e| anyhow::anyhow!("Kerberos mutual auth failed: {}", e))?;
            }
            Ok(())
        }
    }

    /// Wrap a raw KRB5 GSSAPI token in a SPNEGO negTokenInit for SMB2.
    pub fn spnego_wrap_krb5(krb5_token: &[u8]) -> Vec<u8> {
        // KRB5:    1.2.840.113554.1.2.2
        const KRB5_OID: &[u8] =
            &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];
        // MS-KRB5: 1.2.840.48018.1.2.2
        const MS_KRB5_OID: &[u8] =
            &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02];
        // SPNEGO:  1.3.6.1.5.5.2
        const SPNEGO_OID: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

        let mut oids = Vec::new();
        oids.extend_from_slice(KRB5_OID);
        oids.extend_from_slice(MS_KRB5_OID);

        let mech_types = tlv(0xa0, &tlv(0x30, &oids));
        let mech_token = tlv(0xa2, &tlv(0x04, krb5_token));

        let mut neg_body = Vec::new();
        neg_body.extend_from_slice(&mech_types);
        neg_body.extend_from_slice(&mech_token);

        let neg_token_init = tlv(0xa0, &tlv(0x30, &neg_body));

        let mut app = Vec::new();
        app.extend_from_slice(SPNEGO_OID);
        app.extend_from_slice(&neg_token_init);
        tlv(0x60, &app)
    }

    /// Extract the responseToken ([2]) from a SPNEGO negTokenResp, if present.
    /// Returns the raw bytes of the server's AP-REP token.
    pub fn spnego_extract_response_token(data: &[u8]) -> Option<Vec<u8>> {
        let neg_resp_body = find_tagged(data, 0xa1)?; // [1] negTokenResp
        let a2_body = find_tagged(&neg_resp_body, 0xa2)?; // [2] responseToken
        // a2_body content: OCTET STRING wrapping the AP-REP
        if a2_body.len() >= 2 && a2_body[0] == 0x04 {
            let (len, consumed) = super::ber_decode_len(&a2_body[1..])?;
            let start = 1 + consumed;
            if start + len <= a2_body.len() {
                return Some(a2_body[start..start + len].to_vec());
            }
        }
        Some(a2_body)
    }

    fn find_tagged(data: &[u8], target: u8) -> Option<Vec<u8>> {
        let mut i = 0;
        while i < data.len() {
            let tag = data[i];
            i += 1;
            let (len, consumed) = super::ber_decode_len(&data[i..])?;
            i += consumed;
            if i + len > data.len() {
                break;
            }
            let content = &data[i..i + len];
            if tag == target {
                return Some(content.to_vec());
            }
            if matches!(tag, 0x30 | 0x60 | 0xa0 | 0xa1 | 0xa2 | 0xa3) {
                if let Some(found) = find_tagged(content, target) {
                    return Some(found);
                }
            }
            i += len;
        }
        None
    }

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend_from_slice(&super::encode_ber_len(content.len()));
        out.extend_from_slice(content);
        out
    }
}
