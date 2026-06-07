//! High-level SMB2 session: negotiate, NTLMv2 auth, file I/O, named pipes.

#![cfg(feature = "remote")]

pub mod auth;
pub mod proto;

use proto::*;

use std::net::TcpStream;
use std::sync::Mutex;

/// An opaque tree connection identifier.
#[derive(Clone, Copy, Debug)]
pub struct TreeId(pub u32);

/// An opaque 16-byte SMB2 file handle (persistent + volatile).
#[derive(Clone, Copy, Debug)]
pub struct FileHandle(pub [u8; 16]);

/// Authentication credentials for `SmbSession::connect`.
pub enum SmbAuth {
    /// NTLMv2 with explicit username, domain, and password.
    Ntlm {
        user: String,
        domain: String,
        password: String,
    },
    /// Kerberos via GSSAPI.
    ///
    /// If `principal` and `password` are both `Some`, GSSAPI performs the full
    /// AS-REQ/AS-REP exchange — no `kinit` needed.
    /// If both are `None`, the system ticket cache is used (`kinit` first).
    #[cfg(feature = "kerberos")]
    Kerberos {
        /// User principal in UPN form: `user@DOMAIN.COM`.
        principal: Option<String>,
        /// Password for AS-REQ pre-authentication.
        password: Option<String>,
    },
}

/// A live SMB2 session over a TCP/445 connection.
pub struct SmbSession {
    stream: Mutex<TcpStream>,
    session_id: u64,
    msg_counter: Mutex<u64>,
}

impl SmbSession {
    /// Connect to `host:445`, negotiate SMB2, and authenticate.
    pub fn connect(host: &str, auth: SmbAuth) -> anyhow::Result<Self> {
        let addr = format!("{}:445", host);
        let stream = TcpStream::connect(&addr)
            .map_err(|e| anyhow::anyhow!("TCP connect to {} failed: {}", addr, e))?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;

        let mut session = SmbSession {
            stream: Mutex::new(stream),
            session_id: 0,
            msg_counter: Mutex::new(1),
        };

        session.do_negotiate()?;

        match auth {
            SmbAuth::Ntlm { user, domain, password } => {
                session.do_ntlm_auth(&user, &domain, &password)?;
            }
            #[cfg(feature = "kerberos")]
            SmbAuth::Kerberos { principal, password } => {
                session.do_kerberos_auth(host, principal.as_deref(), password.as_deref())?;
            }
        }

        Ok(session)
    }

    #[cfg(feature = "kerberos")]
    fn do_kerberos_auth(
        &mut self,
        host: &str,
        principal: Option<&str>,
        password: Option<&str>,
    ) -> anyhow::Result<()> {
        use auth::kerberos::{initiate, spnego_extract_response_token};

        let (mut krb_ctx, spnego_token) = initiate(host, principal, password)?;

        let mid = self.next_msg_id();
        let pkt = session_setup_request(mid, 0, &spnego_token);
        self.send(&pkt)?;
        let resp = self.recv()?;
        let (status, session_id, blob) = parse_session_setup(&resp)?;

        match status {
            STATUS_OK => {
                self.session_id = session_id;
                let ap_rep = spnego_extract_response_token(&blob);
                krb_ctx.finish(ap_rep.as_deref())?;
            }
            STATUS_MORE_PROCESSING => {
                // Server needs one more round (e.g. to deliver mutual-auth AP-REP).
                let ap_rep = spnego_extract_response_token(&blob);
                krb_ctx.finish(ap_rep.as_deref())?;
                // Complete the exchange with an empty security buffer.
                let mid2 = self.next_msg_id();
                let pkt2 = session_setup_request(mid2, session_id, &[]);
                self.send(&pkt2)?;
                let resp2 = self.recv()?;
                let (status2, session_id2, _) = parse_session_setup(&resp2)?;
                if status2 != STATUS_OK {
                    anyhow::bail!(
                        "Kerberos auth completion failed: status 0x{:08X}",
                        status2
                    );
                }
                self.session_id = session_id2;
            }
            _ => anyhow::bail!("Kerberos SessionSetup failed: status 0x{:08X}", status),
        }
        Ok(())
    }

    fn next_msg_id(&self) -> u64 {
        let mut c = self.msg_counter.lock().unwrap_or_else(|e| e.into_inner());
        let id = *c;
        *c += 1;
        id
    }

    /// Send a framed SMB2 message. The underlying TcpStream has a 30s write timeout
    /// configured at connect time, bounding lock hold duration.
    fn send(&self, payload: &[u8]) -> anyhow::Result<()> {
        let mut s = self.stream.lock().unwrap_or_else(|e| e.into_inner());
        send_message(&mut *s, payload)
    }

    /// Receive a framed SMB2 message. The underlying TcpStream has a 30s read timeout
    /// configured at connect time, bounding lock hold duration.
    fn recv(&self) -> anyhow::Result<Vec<u8>> {
        let mut s = self.stream.lock().unwrap_or_else(|e| e.into_inner());
        recv_message(&mut *s)
    }

    fn do_negotiate(&self) -> anyhow::Result<()> {
        let mid = self.next_msg_id();
        let pkt = negotiate_request(mid);
        self.send(&pkt)?;
        let resp = self.recv()?;
        let (dialect, _blob) = parse_negotiate(&resp)?;
        // Accept SMB 2.0.2, 2.1, or 3.0
        if !matches!(dialect, 0x0202 | 0x0210 | 0x0300) {
            anyhow::bail!("SMB2 Negotiate: unsupported dialect 0x{:04X}", dialect);
        }
        Ok(())
    }

    fn do_ntlm_auth(&mut self, user: &str, domain: &str, password: &str) -> anyhow::Result<()> {
        // Round 1: send Type1
        let type1 = auth::build_type1();
        let spnego1 = auth::spnego_wrap_type1(&type1);
        let mid1 = self.next_msg_id();
        let pkt1 = session_setup_request(mid1, 0, &spnego1);
        self.send(&pkt1)?;
        let resp1 = self.recv()?;
        let (status1, session_id1, blob1) = parse_session_setup(&resp1)?;
        if status1 != STATUS_MORE_PROCESSING {
            anyhow::bail!(
                "SMB2 SessionSetup round1 unexpected status 0x{:08X}",
                status1
            );
        }

        // Extract Type2 challenge
        let ntlm2 = auth::spnego_extract_ntlm(&blob1)
            .ok_or_else(|| anyhow::anyhow!("NTLM challenge not found in Type2 message"))?;
        let (server_challenge, target_info) = auth::parse_type2(&ntlm2)?;

        // Round 2: send Type3
        let type3 = auth::build_type3(&server_challenge, &target_info, user, domain, password);
        let spnego3 = auth::spnego_wrap_type3(&type3);
        let mid2 = self.next_msg_id();
        let pkt2 = session_setup_request(mid2, session_id1, &spnego3);
        self.send(&pkt2)?;
        let resp2 = self.recv()?;
        let (status2, session_id2, _) = parse_session_setup(&resp2)?;
        if status2 != STATUS_OK {
            anyhow::bail!("SMB2 SessionSetup authentication failed: status 0x{:08X}", status2);
        }

        self.session_id = session_id2;
        Ok(())
    }

    /// Connect to a share (e.g. "ADMIN$" or "IPC$") and return a TreeId.
    pub fn connect_tree(&self, share: &str) -> anyhow::Result<TreeId> {
        // We need the server hostname for the UNC path. We'll derive it from the
        // peer address of the TCP socket.
        let peer = self
            .stream
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .peer_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|_| "server".to_string());
        let unc = format!("\\\\{}\\{}", peer, share);
        let mid = self.next_msg_id();
        let pkt = tree_connect_request(mid, self.session_id, &unc);
        self.send(&pkt)?;
        let resp = self.recv()?;
        let tree_id = parse_tree_connect(&resp)?;
        Ok(TreeId(tree_id))
    }

    /// Write `data` to `path` under the given tree, chunking into 64 KB writes.
    pub fn write_file(&self, tree: TreeId, path: &str, data: &[u8]) -> anyhow::Result<()> {
        let fid = self.open_file_for_write(tree, path)?;
        let chunk_size = 65536usize;
        let mut offset = 0u64;
        for chunk in data.chunks(chunk_size) {
            let mid = self.next_msg_id();
            let pkt = write_request(mid, self.session_id, tree.0, &fid.0, offset, chunk);
            self.send(&pkt)?;
            let resp = self.recv()?;
            let written = parse_write(&resp)?;
            offset += written as u64;
        }
        self.close_handle(fid)
    }

    /// Read a file from `path` under the given tree, returning all bytes.
    pub fn read_file(&self, tree: TreeId, path: &str) -> anyhow::Result<Vec<u8>> {
        let fid = self.open_file_for_read(tree, path)?;
        let mut data = Vec::new();
        let mut offset = 0u64;
        loop {
            let mid = self.next_msg_id();
            let pkt = read_request(mid, self.session_id, tree.0, &fid.0, offset, 65536);
            self.send(&pkt)?;
            let resp = self.recv()?;
            let (status, chunk) = parse_read(&resp)?;
            if status == STATUS_END_OF_FILE || chunk.is_empty() {
                break;
            }
            offset += chunk.len() as u64;
            data.extend_from_slice(&chunk);
        }
        let _ = self.close_handle(fid);
        Ok(data)
    }

    /// Delete `path` under the given tree.
    pub fn delete_file(&self, tree: TreeId, path: &str) -> anyhow::Result<()> {
        // Open with DELETE access and delete-on-close disposition
        let mid = self.next_msg_id();
        let pkt = create_request(
            mid,
            self.session_id,
            tree.0,
            path,
            0x00010000 | 0x00000100, // DELETE | READ_CONTROL
            0x7,                      // share all
            1,                        // FILE_OPEN
            0x1000,                   // FILE_DELETE_ON_CLOSE
        );
        self.send(&pkt)?;
        let resp = self.recv()?;
        // Ignore status — best effort
        if let Ok(fid_bytes) = parse_create(&resp) {
            let _ = self.close_handle(FileHandle(fid_bytes));
        }
        Ok(())
    }

    /// Open a named pipe (on IPC$ tree). Path like `\pipe\svcctl`.
    #[allow(dead_code)]
    pub fn open_named_pipe(&self, name: &str) -> anyhow::Result<FileHandle> {
        // IPC$ pipes: desired_access = generic RW, share_all, OPEN, no options
        let mid = self.next_msg_id();
        let pkt = create_request(
            mid,
            self.session_id,
            // Named pipes must be on IPC$ — the caller must pass the right TreeId.
            // Since we don't have access to the ipc tree_id here, the public API
            // uses open_named_pipe_on_tree instead. This internal helper uses 0
            // (which won't work). We expose the tree-id variant publicly.
            0,
            name,
            0x0012_019f, // generic read|write
            0x3,         // share read|write
            1,           // FILE_OPEN
            0x0,
        );
        self.send(&pkt)?;
        let resp = self.recv()?;
        let fid = parse_create(&resp)?;
        Ok(FileHandle(fid))
    }

    /// Open a named pipe on the specified tree (use IPC$ tree for pipes).
    pub fn open_named_pipe_on_tree(
        &self,
        tree: TreeId,
        name: &str,
    ) -> anyhow::Result<FileHandle> {
        let mid = self.next_msg_id();
        let pkt = create_request(
            mid,
            self.session_id,
            tree.0,
            name,
            0x0012_019f, // read | write
            0x3,         // share read|write
            1,           // FILE_OPEN
            0x0,
        );
        self.send(&pkt)?;
        let resp = self.recv()?;
        let fid = parse_create(&resp)?;
        Ok(FileHandle(fid))
    }

    /// Send data to a named pipe and receive response via FSCTL_PIPE_TRANSCEIVE.
    #[allow(dead_code)]
    pub fn transact_pipe(&self, handle: FileHandle, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        // Determine tree_id from context — we'll pass 0 for IPC$ which should
        // have been connected. The tree_id is embedded in the handle's context,
        // but SMB2 requires it in the header. We'll use a dedicated variant.
        self.transact_pipe_on_tree(TreeId(0), handle, data)
    }

    /// Transact named pipe on a specific tree.
    pub fn transact_pipe_on_tree(
        &self,
        tree: TreeId,
        handle: FileHandle,
        data: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let mid = self.next_msg_id();
        let pkt = ioctl_pipe_transceive_request(
            mid,
            self.session_id,
            tree.0,
            &handle.0,
            data,
        );
        self.send(&pkt)?;
        let resp = self.recv()?;
        parse_ioctl(&resp)
    }

    /// Close a file/pipe handle.
    pub fn close_handle(&self, handle: FileHandle) -> anyhow::Result<()> {
        self.close_handle_on_tree(TreeId(0), handle)
    }

    /// Close a handle with explicit tree_id.
    pub fn close_handle_on_tree(&self, tree: TreeId, handle: FileHandle) -> anyhow::Result<()> {
        let mid = self.next_msg_id();
        let pkt = close_request(mid, self.session_id, tree.0, &handle.0);
        self.send(&pkt)?;
        let _resp = self.recv()?;
        // Ignore close errors
        Ok(())
    }

    // ── internal open helpers ─────────────────────────────────────────────────

    fn open_file_for_write(&self, tree: TreeId, path: &str) -> anyhow::Result<FileHandle> {
        let mid = self.next_msg_id();
        let pkt = create_request(
            mid,
            self.session_id,
            tree.0,
            path,
            0x0012_01bf, // FILE_GENERIC_WRITE
            0x0,         // exclusive
            5,           // FILE_OVERWRITE_IF
            0x0,
        );
        self.send(&pkt)?;
        let resp = self.recv()?;
        let fid = parse_create(&resp)?;
        Ok(FileHandle(fid))
    }

    fn open_file_for_read(&self, tree: TreeId, path: &str) -> anyhow::Result<FileHandle> {
        let mid = self.next_msg_id();
        let pkt = create_request(
            mid,
            self.session_id,
            tree.0,
            path,
            0x0012_0089, // FILE_GENERIC_READ
            0x1,         // share read
            1,           // FILE_OPEN
            0x0,
        );
        self.send(&pkt)?;
        let resp = self.recv()?;
        let fid = parse_create(&resp)?;
        Ok(FileHandle(fid))
    }
}
