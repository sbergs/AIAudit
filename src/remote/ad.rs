//! Active Directory host discovery via LDAP.

#![cfg(feature = "remote")]

use super::inventory::Host;
use ldap3::{LdapConn, Scope, SearchEntry};

/// Discover Windows computer accounts from AD. Binds anonymously unless a user is
/// provided; returns hosts built from `dNSHostName`.
pub fn discover_hosts(
    server: &str,
    base_dn: &str,
    bind_user: Option<&str>,
    bind_password: Option<&str>,
) -> anyhow::Result<Vec<Host>> {
    let url = if server.starts_with("ldap://") || server.starts_with("ldaps://") {
        server.to_string()
    } else {
        format!("ldap://{}", server)
    };

    let mut conn = LdapConn::new(&url)?;
    match (bind_user, bind_password) {
        (Some(u), Some(p)) => {
            conn.simple_bind(u, p)?.success()?;
        }
        _ => {
            conn.simple_bind("", "")?.success()?;
        }
    }

    let filter = "(&(objectClass=computer)(operatingSystem=*Windows*))";
    let (entries, _res) = conn
        .search(base_dn, Scope::Subtree, filter, vec!["dNSHostName", "name"])?
        .success()?;

    let mut hosts = Vec::new();
    for entry in entries {
        let entry = SearchEntry::construct(entry);
        let hostname = entry
            .attrs
            .get("dNSHostName")
            .and_then(|v| v.first())
            .cloned()
            .or_else(|| entry.attrs.get("name").and_then(|v| v.first()).cloned());
        if let Some(h) = hostname {
            hosts.push(Host::new(h));
        }
    }
    let _ = conn.unbind();
    Ok(hosts)
}
