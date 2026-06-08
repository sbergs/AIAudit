//! Service Control Manager (SCM) operations via DCE/RPC over \pipe\svcctl.
//!
//! Provides a high-level `Scm` struct that can create, start, poll, and
//! delete a transient Windows service to run an arbitrary command.

#![cfg(feature = "remote")]

use super::dcerpc::{uuid_from_str, DceRpc};
use super::smb::{SmbSession, TreeId};

// SCM interface UUID: 367abb81-9844-35f1-ad32-98f038001003 v2.0
const SCM_UUID_STR: &str = "367abb81-9844-35f1-ad32-98f038001003";

// SCM opnums
const OPNUM_CLOSE:            u16 = 0;
const OPNUM_DELETE_SERVICE:   u16 = 2;
const OPNUM_QUERY_STATUS:     u16 = 6;
const OPNUM_CREATE_SERVICE:   u16 = 12;
const OPNUM_OPEN_SCM:         u16 = 15;
const OPNUM_START_SERVICE:    u16 = 19;

// Service states
const SERVICE_STOPPED: u32 = 1;

/// An open Service Control Manager session over DCE/RPC (`\pipe\svcctl`).
///
/// Obtain via [`Scm::open`]. Use [`Scm::run_command`] to create a transient
/// `SERVICE_WIN32_OWN_PROCESS | DEMAND_START` service, run it to completion,
/// then delete it. The caller uploads the binary and reads output separately.
pub struct Scm {
    rpc: DceRpc,
    sc_handle: [u8; 20],
    ipc_tree: TreeId,
}

impl Scm {
    /// Open a connection to the SCM on the remote host via \pipe\svcctl.
    pub fn open(session: &SmbSession, ipc_tree: TreeId) -> anyhow::Result<Self> {
        let pipe_handle = session.open_named_pipe_on_tree(ipc_tree, "svcctl")?;

        let scm_uuid = uuid_from_str(SCM_UUID_STR)?;
        let rpc = DceRpc::bind(session, ipc_tree, pipe_handle, &scm_uuid, 2, 0)?;

        // OpenSCManagerW (opnum 15)
        let stub = open_scm_stub();
        let mut rpc_cell = rpc;
        let resp = rpc_cell.call(session, OPNUM_OPEN_SCM, &stub)?;
        let sc_handle = parse_sc_handle(&resp, "OpenSCManager")?;

        Ok(Scm { rpc: rpc_cell, sc_handle, ipc_tree })
    }

    /// Create a service, start it, poll until stopped (or timeout), then delete it.
    pub fn run_command(
        &mut self,
        session: &SmbSession,
        service_name: &str,
        binary_path: &str,
    ) -> anyhow::Result<()> {
        // CreateServiceW
        let create_stub = create_service_stub(&self.sc_handle, service_name, binary_path);
        let create_resp = self.rpc.call(session, OPNUM_CREATE_SERVICE, &create_stub)?;
        let svc_handle = parse_create_service_resp(&create_resp)?;

        // StartServiceW. 1053 = ERROR_SERVICE_REQUEST_TIMEOUT is expected when the
        // binary doesn't call StartServiceCtrlDispatcher; any other non-zero code is
        // a real failure (e.g., binary not found = 2, access denied = 5).
        let start_stub = start_service_stub(&svc_handle);
        let start_resp = self.rpc.call(session, OPNUM_START_SERVICE, &start_stub)?;
        let start_rc = u32_from_tail(&start_resp);
        if start_rc != 0 && start_rc != 1053 {
            let _ = self.delete_service(session, &svc_handle);
            anyhow::bail!("StartServiceW failed: Win32 error 0x{:08X}", start_rc);
        }

        // Poll QueryServiceStatus until STOPPED (state == 1), timeout 5 minutes
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let q_stub = query_status_stub(&svc_handle);
            let q_resp = self.rpc.call(session, OPNUM_QUERY_STATUS, &q_stub)?;
            let state = parse_query_status(&q_resp)?;
            if state == SERVICE_STOPPED {
                break;
            }
            if std::time::Instant::now() >= deadline {
                // Best-effort cleanup then bail
                let _ = self.delete_service(session, &svc_handle);
                anyhow::bail!("Service '{}' did not stop within 5 minutes", service_name);
            }
        }

        self.delete_service(session, &svc_handle)?;
        Ok(())
    }

    fn delete_service(&mut self, session: &SmbSession, svc_handle: &[u8; 20]) -> anyhow::Result<()> {
        let stub = handle_stub(svc_handle);
        self.rpc.call(session, OPNUM_DELETE_SERVICE, &stub)?;
        let close_stub = handle_stub(svc_handle);
        let _ = self.rpc.call(session, OPNUM_CLOSE, &close_stub);
        Ok(())
    }
}

// ─── NDR encoding helpers ────────────────────────────────────────────────────

/// Read the last 4 bytes of a stub as a little-endian u32 (Win32 return code).
fn u32_from_tail(buf: &[u8]) -> u32 {
    if buf.len() < 4 { return 0; }
    u32::from_le_bytes([buf[buf.len()-4], buf[buf.len()-3], buf[buf.len()-2], buf[buf.len()-1]])
}

fn ndr_u32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

/// Null unique pointer (4 zero bytes = NULL referent).
fn ndr_null_ptr() -> [u8; 4] {
    [0u8; 4]
}

/// NDR conformant varying string body — embedded inline in the NDR stream.
/// Encodes: MaxCount(4) + Offset(4) + ActualCount(4) + UTF-16LE chars (with null) + alignment.
fn ndr_wstring_body(text: &str) -> Vec<u8> {
    let mut utf16: Vec<u16> = text.encode_utf16().collect();
    utf16.push(0); // null terminator
    let char_count = utf16.len() as u32;
    let byte_len = (char_count * 2) as usize;
    let mut out = Vec::new();
    out.extend_from_slice(&char_count.to_le_bytes()); // MaxCount
    out.extend_from_slice(&0u32.to_le_bytes());        // Offset
    out.extend_from_slice(&char_count.to_le_bytes()); // ActualCount
    for c in &utf16 {
        out.extend_from_slice(&c.to_le_bytes());
    }
    // Pad body to 4-byte alignment
    let pad = (4 - (byte_len % 4)) % 4;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

// ─── Stub builders ───────────────────────────────────────────────────────────

fn open_scm_stub() -> Vec<u8> {
    // ROpenSCManagerW(MachineName=NULL, DatabaseName=NULL, SC_MANAGER_ALL_ACCESS)
    // NULL DatabaseName → server defaults to ServicesActive.
    let mut s = Vec::new();
    s.extend_from_slice(&ndr_null_ptr()); // lpMachineName = NULL
    s.extend_from_slice(&ndr_null_ptr()); // lpDatabaseName = NULL
    s.extend_from_slice(&ndr_u32(0x000F_003F)); // dwDesiredAccess = SC_MANAGER_ALL_ACCESS
    s
}

fn create_service_stub(sc_handle: &[u8; 20], svc_name: &str, bin_path: &str) -> Vec<u8> {
    // RCreateServiceW NDR encoding per Samba/Wine IDL (wire-tested against Windows):
    //
    //   [in,string,charset(UTF16)] uint16 *ServiceName   → embedded conformant string
    //   [in,unique,string,charset(UTF16)] uint16 *DisplayName → unique ptr (we pass NULL)
    //   [in,string,charset(UTF16)] uint16 *binary_path   → embedded conformant string
    //
    // Layout:
    //   hSCManager(20) + ServiceName_embedded(var) + DisplayName_ref(4=NULL) +
    //   4×DWORD(16) + BinaryPath_embedded(var) + NullGroup_ref(4) +
    //   TagId_ref(4) + Dependencies_ref(4) + DependSize(4) +
    //   ServiceStartName_ref(4) + Password_ref(4) + PwSize(4)
    // No deferred section (DisplayName is NULL so nothing to defer).

    let mut s = Vec::new();
    s.extend_from_slice(sc_handle);                          // hSCManager (20)
    s.extend_from_slice(&ndr_wstring_body(svc_name));        // ServiceName embedded
    s.extend_from_slice(&ndr_null_ptr());                    // DisplayName = NULL
    s.extend_from_slice(&ndr_u32(0x000F_01FF));              // dwDesiredAccess
    s.extend_from_slice(&ndr_u32(0x10));                     // SERVICE_WIN32_OWN_PROCESS
    s.extend_from_slice(&ndr_u32(3));                        // SERVICE_DEMAND_START
    s.extend_from_slice(&ndr_u32(0));                        // SERVICE_ERROR_IGNORE
    s.extend_from_slice(&ndr_wstring_body(bin_path));        // BinaryPathName embedded
    s.extend_from_slice(&ndr_null_ptr());                    // lpLoadOrderGroup = NULL
    s.extend_from_slice(&ndr_null_ptr());                    // lpdwTagId = NULL
    s.extend_from_slice(&ndr_null_ptr());                    // lpDependencies = NULL
    s.extend_from_slice(&ndr_u32(0));                        // dwDependSize = 0
    s.extend_from_slice(&ndr_null_ptr());                    // lpServiceStartName = NULL
    s.extend_from_slice(&ndr_null_ptr());                    // lpPassword = NULL
    s.extend_from_slice(&ndr_u32(0));                        // dwPwSize = 0
    s
}

fn start_service_stub(svc_handle: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(svc_handle);
    s.extend_from_slice(&ndr_u32(0)); // dwNumServiceArgs
    s.extend_from_slice(&ndr_u32(0)); // null pointer for args
    s
}

fn query_status_stub(svc_handle: &[u8; 20]) -> Vec<u8> {
    svc_handle.to_vec()
}

fn handle_stub(handle: &[u8; 20]) -> Vec<u8> {
    handle.to_vec()
}

// ─── Response parsers ────────────────────────────────────────────────────────

fn parse_sc_handle(resp: &[u8], op: &str) -> anyhow::Result<[u8; 20]> {
    // Response: 20-byte SC_HANDLE + u32 return code
    if resp.len() < 24 {
        anyhow::bail!("SCM {} response too short ({})", op, resp.len());
    }
    let retcode = u32::from_le_bytes([
        resp[resp.len()-4], resp[resp.len()-3],
        resp[resp.len()-2], resp[resp.len()-1],
    ]);
    if retcode != 0 {
        anyhow::bail!("SCM {} failed: Win32 error 0x{:08X}", op, retcode);
    }
    let mut h = [0u8; 20];
    h.copy_from_slice(&resp[resp.len()-24..resp.len()-4]);
    Ok(h)
}

fn parse_create_service_resp(resp: &[u8]) -> anyhow::Result<[u8; 20]> {
    // Response: 4-byte tag + 20-byte service handle + u32 return code = 28 bytes min
    if resp.len() < 28 {
        anyhow::bail!("SCM CreateService response too short ({})", resp.len());
    }
    let retcode = u32::from_le_bytes([
        resp[resp.len()-4], resp[resp.len()-3],
        resp[resp.len()-2], resp[resp.len()-1],
    ]);
    if retcode != 0 {
        anyhow::bail!("SCM CreateService failed: Win32 error 0x{:08X}", retcode);
    }
    let mut h = [0u8; 20];
    // tag(4) + handle(20) + retcode(4) at end
    let handle_start = resp.len() - 24;
    h.copy_from_slice(&resp[handle_start..handle_start + 20]);
    Ok(h)
}

fn parse_query_status(resp: &[u8]) -> anyhow::Result<u32> {
    // SERVICE_STATUS (7 * u32 = 28 bytes) + u32 retcode = 32 bytes
    if resp.len() < 32 {
        anyhow::bail!("SCM QueryServiceStatus response too short ({})", resp.len());
    }
    let retcode = u32::from_le_bytes([
        resp[resp.len()-4], resp[resp.len()-3],
        resp[resp.len()-2], resp[resp.len()-1],
    ]);
    if retcode != 0 {
        anyhow::bail!("SCM QueryServiceStatus failed: Win32 error 0x{:08X}", retcode);
    }
    // dwCurrentState is the 2nd field of SERVICE_STATUS (offset 4 from start of SERVICE_STATUS)
    let ss_start = resp.len() - 32;
    let state = u32::from_le_bytes([
        resp[ss_start + 4], resp[ss_start + 5],
        resp[ss_start + 6], resp[ss_start + 7],
    ]);
    Ok(state)
}
