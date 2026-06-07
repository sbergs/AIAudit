//! Platform detection and path resolution.

use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Windows,
    MacOs,
    Linux,
    Wsl,
}

impl Platform {
    pub fn as_str(&self) -> &'static str {
        match self {
            Platform::Windows => "windows",
            Platform::MacOs => "macos",
            Platform::Linux => "linux",
            Platform::Wsl => "wsl",
        }
    }
}

/// Detect the current platform, distinguishing WSL from native Linux.
pub fn detect() -> Platform {
    #[cfg(target_os = "windows")]
    {
        return Platform::Windows;
    }
    #[cfg(target_os = "macos")]
    {
        return Platform::MacOs;
    }
    #[cfg(target_os = "linux")]
    {
        if std::fs::read_to_string("/proc/version")
            .map(|v| v.to_ascii_lowercase().contains("microsoft"))
            .unwrap_or(false)
        {
            return Platform::Wsl;
        }
        return Platform::Linux;
    }
    #[allow(unreachable_code)]
    Platform::Linux
}

pub fn home_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"))
}

/// XDG config dir (~/.config on Linux). Honors XDG_CONFIG_HOME.
pub fn xdg_config_dir() -> PathBuf {
    std::env::var("XDG_CONFIG_HOME")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join(".config"))
}

#[allow(dead_code)]
pub fn data_local_dir() -> PathBuf {
    dirs::data_local_dir().unwrap_or_else(home_dir)
}

/// On WSL, locate the Windows user's home under /mnt/c/Users/.
pub fn wsl_windows_home() -> Option<PathBuf> {
    if detect() != Platform::Wsl {
        return None;
    }
    let mnt = PathBuf::from("/mnt/c/Users");
    if !mnt.exists() {
        return None;
    }

    // Prefer the WINDOWS_USERNAME / USER env hints.
    if let Some(user) = std::env::var("WINDOWS_USERNAME")
        .ok()
        .or_else(|| std::env::var("USER").ok())
    {
        let candidate = mnt.join(&user);
        if candidate.join("AppData").exists() {
            return Some(candidate);
        }
    }

    // Otherwise iterate, skipping built-in profiles.
    let skip = ["Public", "Default", "Default User", "All Users"];
    let entries = std::fs::read_dir(&mnt).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if skip.contains(&name.as_ref()) {
            continue;
        }
        let path = entry.path();
        if path.join("AppData").exists() {
            return Some(path);
        }
    }
    None
}

/// Windows %APPDATA% (Roaming) from a native Windows host or WSL.
pub fn appdata() -> Option<PathBuf> {
    if let Ok(v) = std::env::var("APPDATA") {
        return Some(PathBuf::from(v));
    }
    if detect() == Platform::Wsl {
        return wsl_windows_home().map(|h| h.join("AppData").join("Roaming"));
    }
    None
}

/// Windows %LOCALAPPDATA% from a native Windows host or WSL.
pub fn localappdata() -> Option<PathBuf> {
    if let Ok(v) = std::env::var("LOCALAPPDATA") {
        return Some(PathBuf::from(v));
    }
    if detect() == Platform::Wsl {
        return wsl_windows_home().map(|h| h.join("AppData").join("Local"));
    }
    None
}
