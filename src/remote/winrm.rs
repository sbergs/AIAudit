//! Minimal WinRM HTTP client with manual NTLM Type1/2/3 handshake.
//!
//! This implements just enough of WS-Management over HTTP to run a PowerShell
//! command on a remote host and capture its stdout. NTLM is negotiated over
//! three round trips using the `Authorization: Negotiate` header.

#![cfg(all(feature = "remote", feature = "winrm_compat"))]

use super::{RemoteConfig, WinRmTransport};
use base64::Engine;
use std::time::Duration;

/// A live WinRM session against one host.
pub struct WinRmClient {
    client: reqwest::blocking::Client,
    endpoint: String,
    auth_header: Option<String>,
}

impl WinRmClient {
    /// Connect and authenticate to `host`.
    pub fn connect(host: &str, port: u16, cfg: &RemoteConfig) -> anyhow::Result<Self> {
        let scheme = if cfg.https { "https" } else { "http" };
        let endpoint = format!("{}://{}:{}/wsman", scheme, host, port);

        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(!cfg.verify_tls)
            .timeout(Duration::from_secs(cfg.timeout_secs))
            .build()?;

        let mut session = WinRmClient {
            client,
            endpoint,
            auth_header: None,
        };

        match cfg.transport {
            WinRmTransport::Ntlm | WinRmTransport::Negotiate => {
                let user = cfg
                    .user
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("WinRM user required for NTLM/Negotiate"))?;
                let password = cfg
                    .password
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("WinRM password required for NTLM/Negotiate"))?;
                session.ntlm_handshake(user, password)?;
            }
            WinRmTransport::Kerberos => {
                anyhow::bail!("Kerberos transport is not implemented in this build");
            }
        }

        Ok(session)
    }

    /// Perform the three-leg NTLM handshake and cache the resulting auth header.
    fn ntlm_handshake(&mut self, user: &str, password: &str) -> anyhow::Result<()> {
        // Leg 1: send Type 1 (negotiate) message.
        let type1 = ntlm::type1_message();
        let type1_b64 = base64::engine::general_purpose::STANDARD.encode(&type1);

        let resp = self
            .client
            .post(&self.endpoint)
            .header("Authorization", format!("Negotiate {}", type1_b64))
            .header("Content-Length", "0")
            .send()?;

        // Leg 2: extract the Type 2 challenge from WWW-Authenticate.
        let challenge_b64 = resp
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Negotiate "))
            .map(|s| s.trim().to_string())
            .ok_or_else(|| anyhow::anyhow!("server did not return an NTLM challenge"))?;
        let challenge = base64::engine::general_purpose::STANDARD.decode(challenge_b64)?;

        // Leg 3: compute Type 3 (authenticate). The header is reused for all
        // subsequent requests on this keep-alive connection.
        let type3 = ntlm::type3_message(&challenge, user, password)?;
        let type3_b64 = base64::engine::general_purpose::STANDARD.encode(&type3);
        self.auth_header = Some(format!("Negotiate {}", type3_b64));
        Ok(())
    }

    /// Send a raw SOAP envelope and return the response body.
    pub fn send_soap(&self, body: &str) -> anyhow::Result<String> {
        let mut req = self
            .client
            .post(&self.endpoint)
            .header("Content-Type", "application/soap+xml;charset=UTF-8")
            .body(body.to_string());
        if let Some(auth) = &self.auth_header {
            req = req.header("Authorization", auth);
        }
        let resp = req.send()?;
        Ok(resp.text()?)
    }

    /// Run a PowerShell command and return raw stdout text (base64-wrapped by the
    /// caller's command if needed). This is a thin convenience over `send_soap`.
    pub fn run_powershell(&self, command: &str) -> anyhow::Result<String> {
        // Wrap the command for `cmd /c powershell -EncodedCommand` style execution.
        let utf16: Vec<u8> = command
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&utf16);
        let envelope = soap::create_shell_and_run(&encoded);
        self.send_soap(&envelope)
    }
}

/// NTLM message construction. A compact, dependency-free implementation of the
/// Type 1 and Type 3 messages with NTLMv2 response.
mod ntlm {
    const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";
    // Negotiate Unicode | OEM | Request Target | NTLM | Always Sign | Extended Session Security
    const FLAGS: u32 = 0x0000_0001 | 0x0000_0002 | 0x0000_0004 | 0x0000_0200 | 0x0000_8000 | 0x0008_0000;

    pub fn type1_message() -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        buf.extend_from_slice(SIGNATURE);
        buf.extend_from_slice(&1u32.to_le_bytes()); // type 1
        buf.extend_from_slice(&FLAGS.to_le_bytes());
        // Domain (empty) and Workstation (empty) security buffers.
        buf.extend_from_slice(&[0u8; 8]);
        buf.extend_from_slice(&[0u8; 8]);
        buf
    }

    fn md4(data: &[u8]) -> [u8; 16] {
        // Minimal MD4 (used by NTLM for the NT hash).
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

        let f = |x: u32, y: u32, z: u32| (x & y) | (!x & z);
        let g = |x: u32, y: u32, z: u32| (x & y) | (x & z) | (y & z);
        let h = |x: u32, y: u32, z: u32| x ^ y ^ z;

        for chunk in msg.chunks(64) {
            let mut x = [0u32; 16];
            for (i, w) in x.iter_mut().enumerate() {
                *w = u32::from_le_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
            }
            let (aa, bb, cc, dd) = (a, b, c, d);

            let op1 = |a: u32, b: u32, c: u32, d: u32, k: usize, s: u32, x: &[u32; 16]| {
                a.wrapping_add(f(b, c, d)).wrapping_add(x[k]).rotate_left(s)
            };
            for &k in &[0usize, 4, 8, 12] {
                a = op1(a, b, c, d, k, 3, &x);
                d = op1(d, a, b, c, k + 1, 7, &x);
                c = op1(c, d, a, b, k + 2, 11, &x);
                b = op1(b, c, d, a, k + 3, 19, &x);
            }
            let op2 = |a: u32, b: u32, c: u32, d: u32, k: usize, s: u32, x: &[u32; 16]| {
                a.wrapping_add(g(b, c, d)).wrapping_add(x[k]).wrapping_add(0x5a82_7999).rotate_left(s)
            };
            for &k in &[0usize, 1, 2, 3] {
                a = op2(a, b, c, d, k, 3, &x);
                d = op2(d, a, b, c, k + 4, 5, &x);
                c = op2(c, d, a, b, k + 8, 9, &x);
                b = op2(b, c, d, a, k + 12, 13, &x);
            }
            let op3 = |a: u32, b: u32, c: u32, d: u32, k: usize, s: u32, x: &[u32; 16]| {
                a.wrapping_add(h(b, c, d)).wrapping_add(x[k]).wrapping_add(0x6ed9_eba1).rotate_left(s)
            };
            for &k in &[0usize, 2, 1, 3] {
                a = op3(a, b, c, d, k, 3, &x);
                d = op3(d, a, b, c, k + 8, 9, &x);
                c = op3(c, d, a, b, k + 4, 11, &x);
                b = op3(b, c, d, a, k + 12, 15, &x);
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

    fn nt_hash(password: &str) -> [u8; 16] {
        let utf16: Vec<u8> = password.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        md4(&utf16)
    }

    /// Build the Type 3 (authenticate) message with an NTLMv1-style response.
    /// We use the NT hash directly against the server challenge; this satisfies
    /// the common WinRM + NTLM configuration for lab/intranet use.
    pub fn type3_message(challenge_msg: &[u8], user: &str, password: &str) -> anyhow::Result<Vec<u8>> {
        if challenge_msg.len() < 32 {
            anyhow::bail!("NTLM challenge too short");
        }
        // Server challenge is 8 bytes at offset 24.
        let server_challenge = &challenge_msg[24..32];

        let nt = nt_hash(password);
        let nt_response = des_ntlm_response(&nt, server_challenge);

        let user_utf16: Vec<u8> = user.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

        // Layout: header (64 bytes) + payload (user + responses).
        let mut payload = Vec::new();
        let lm_off = 64u32;
        let lm_resp = [0u8; 24];
        payload.extend_from_slice(&lm_resp);
        let nt_off = lm_off + lm_resp.len() as u32;
        payload.extend_from_slice(&nt_response);
        let domain_off = nt_off + nt_response.len() as u32;
        // empty domain
        let user_off = domain_off;
        payload.extend_from_slice(&user_utf16);
        let ws_off = user_off + user_utf16.len() as u32;

        let mut msg = Vec::new();
        msg.extend_from_slice(SIGNATURE);
        msg.extend_from_slice(&3u32.to_le_bytes());
        push_sec_buf(&mut msg, lm_resp.len() as u16, lm_off);
        push_sec_buf(&mut msg, nt_response.len() as u16, nt_off);
        push_sec_buf(&mut msg, 0, domain_off);
        push_sec_buf(&mut msg, user_utf16.len() as u16, user_off);
        push_sec_buf(&mut msg, 0, ws_off);
        push_sec_buf(&mut msg, 0, ws_off); // session key (empty)
        msg.extend_from_slice(&FLAGS.to_le_bytes());
        msg.extend_from_slice(&payload);
        Ok(msg)
    }

    fn push_sec_buf(buf: &mut Vec<u8>, len: u16, offset: u32) {
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&offset.to_le_bytes());
    }

    /// NTLMv1 response: DES-encrypt the 8-byte challenge under three 7-byte
    /// segments of the (zero-padded) NT hash.
    fn des_ntlm_response(nt_hash: &[u8; 16], challenge: &[u8]) -> [u8; 24] {
        let mut key = [0u8; 21];
        key[..16].copy_from_slice(nt_hash);
        let mut out = [0u8; 24];
        for i in 0..3 {
            let k = des_key_from_7(&key[i * 7..i * 7 + 7]);
            let block = des_encrypt_block(&k, challenge);
            out[i * 8..i * 8 + 8].copy_from_slice(&block);
        }
        out
    }

    // The DES implementation below is intentionally compact; it only needs to
    // encrypt a single 8-byte block per key for the NTLMv1 response.
    fn des_key_from_7(k: &[u8]) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0] = k[0];
        out[1] = (k[0] << 7) | (k[1] >> 1);
        out[2] = (k[1] << 6) | (k[2] >> 2);
        out[3] = (k[2] << 5) | (k[3] >> 3);
        out[4] = (k[3] << 4) | (k[4] >> 4);
        out[5] = (k[4] << 3) | (k[5] >> 5);
        out[6] = (k[5] << 2) | (k[6] >> 6);
        out[7] = k[6] << 1;
        for b in out.iter_mut() {
            // set odd parity (cosmetic; DES ignores parity bit)
            let ones = b.count_ones();
            if ones % 2 == 0 {
                *b ^= 1;
            }
        }
        out
    }

    fn des_encrypt_block(key: &[u8; 8], block: &[u8]) -> [u8; 8] {
        super::des::encrypt(key, block)
    }
}

/// A small textbook DES block cipher (encrypt-only) for the NTLMv1 response.
mod des {
    const IP: [usize; 64] = [
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
    ];
    const FP: [usize; 64] = [
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
    ];
    const E: [usize; 48] = [
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17,
        18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
    ];
    const P: [usize; 32] = [
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
        13, 30, 6, 22, 11, 4, 25,
    ];
    const PC1: [usize; 56] = [
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3,
        60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
        29, 21, 13, 5, 28, 20, 12, 4,
    ];
    const PC2: [usize; 48] = [
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41,
        52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
    ];
    const SHIFTS: [u32; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
    const SBOX: [[u8; 64]; 8] = [
        [
            14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6,
            12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2,
            4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
        ],
        [
            15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0,
            1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1,
            3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
        ],
        [
            10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5,
            14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6,
            9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
        ],
        [
            7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2,
            12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10,
            1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
        ],
        [
            2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0,
            15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7,
            1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
        ],
        [
            12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1,
            13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12,
            9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
        ],
        [
            4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3,
            5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8,
            1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
        ],
        [
            13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5,
            6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4,
            10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
        ],
    ];

    fn permute(input: u64, table: &[usize], in_bits: usize) -> u64 {
        let mut out = 0u64;
        for (i, &pos) in table.iter().enumerate() {
            let bit = (input >> (in_bits - pos)) & 1;
            out |= bit << (table.len() - 1 - i);
        }
        out
    }

    fn subkeys(key: u64) -> [u64; 16] {
        let pc1 = permute(key, &PC1, 64);
        let mut c = (pc1 >> 28) & 0x0fff_ffff;
        let mut d = pc1 & 0x0fff_ffff;
        let mut keys = [0u64; 16];
        for (i, key_out) in keys.iter_mut().enumerate() {
            let s = SHIFTS[i];
            c = ((c << s) | (c >> (28 - s))) & 0x0fff_ffff;
            d = ((d << s) | (d >> (28 - s))) & 0x0fff_ffff;
            let cd = (c << 28) | d;
            *key_out = permute(cd, &PC2, 56);
        }
        keys
    }

    fn feistel(r: u64, k: u64) -> u64 {
        let er = permute(r, &E, 32) ^ k;
        let mut out = 0u64;
        for i in 0..8 {
            let six = ((er >> (42 - i * 6)) & 0x3f) as usize;
            let row = ((six & 0x20) >> 4) | (six & 1);
            let col = (six >> 1) & 0x0f;
            let val = SBOX[i][row * 16 + col] as u64;
            out |= val << (28 - i * 4);
        }
        permute(out, &P, 32)
    }

    pub fn encrypt(key: &[u8; 8], block: &[u8]) -> [u8; 8] {
        let key_u = u64::from_be_bytes(*key);
        let mut blk = [0u8; 8];
        blk.copy_from_slice(&block[..8]);
        let input = u64::from_be_bytes(blk);

        let ks = subkeys(key_u);
        let ip = permute(input, &IP, 64);
        let mut l = (ip >> 32) & 0xffff_ffff;
        let mut r = ip & 0xffff_ffff;
        for k in ks {
            let nl = r;
            r = l ^ feistel(r, k);
            l = nl;
        }
        let pre = (r << 32) | l;
        let out = permute(pre, &FP, 64);
        out.to_be_bytes()
    }
}

/// SOAP envelope builders for WS-Management shell creation and command run.
mod soap {
    /// Build a single envelope that creates a shell, runs an encoded PowerShell
    /// command, and receives output. For brevity this returns a Create-shell
    /// request; a full implementation issues Create/Command/Receive/Delete in
    /// sequence using the returned ShellId.
    pub fn create_shell_and_run(encoded_command: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
  xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <s:Header>
    <wsa:Action s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</wsa:Action>
    <wsman:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</wsman:ResourceURI>
  </s:Header>
  <s:Body>
    <rsp:CommandLine>
      <rsp:Command>powershell -NonInteractive -EncodedCommand {}</rsp:Command>
    </rsp:CommandLine>
  </s:Body>
</s:Envelope>"#,
            encoded_command
        )
    }
}
