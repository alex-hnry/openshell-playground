//! Sandbox policy configuration.

use miette::{IntoDiagnostic, Result};
use navigator_core::proto::{
    self, FilesystemPolicy as ProtoFilesystemPolicy, LandlockCompatibility as ProtoLandlockCompat,
    LandlockPolicy as ProtoLandlockPolicy, NetworkMode as ProtoNetworkMode,
    NetworkPolicy as ProtoNetworkPolicy, ProcessPolicy as ProtoProcessPolicy,
    SandboxPolicy as ProtoSandboxPolicy,
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxPolicy {
    #[serde(default = "default_policy_version")]
    pub version: u32,

    #[serde(default)]
    pub filesystem: FilesystemPolicy,

    #[serde(default)]
    pub network: NetworkPolicy,

    #[serde(default)]
    pub landlock: LandlockPolicy,

    #[serde(default)]
    pub process: ProcessPolicy,
}

impl SandboxPolicy {
    /// Load a sandbox policy from a YAML file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn from_path(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path).into_diagnostic()?;
        let policy: Self = serde_yaml::from_str(&contents).into_diagnostic()?;
        Ok(policy)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FilesystemPolicy {
    /// Read-only directory allow list.
    pub read_only: Vec<PathBuf>,

    /// Read-write directory allow list.
    pub read_write: Vec<PathBuf>,

    /// Automatically include the workdir as read-write.
    pub include_workdir: bool,
}

impl Default for FilesystemPolicy {
    fn default() -> Self {
        Self {
            read_only: Vec::new(),
            read_write: Vec::new(),
            include_workdir: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkPolicy {
    pub mode: NetworkMode,
    pub proxy: Option<ProxyPolicy>,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            mode: NetworkMode::Block,
            proxy: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    #[default]
    Block,
    Proxy,
    Allow,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyPolicy {
    /// Unix socket path for a local proxy (preferred for strict seccomp rules).
    pub unix_socket: Option<PathBuf>,

    /// TCP address for a local HTTP proxy (loopback-only).
    pub http_addr: Option<SocketAddr>,

    /// Allowed hostnames for proxy traffic. Empty means allow all.
    #[serde(default)]
    pub allow_hosts: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct LandlockPolicy {
    pub compatibility: LandlockCompatibility,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ProcessPolicy {
    /// User name to run the sandboxed process as.
    pub run_as_user: Option<String>,

    /// Group name to run the sandboxed process as.
    pub run_as_group: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LandlockCompatibility {
    #[default]
    BestEffort,
    HardRequirement,
}

const fn default_policy_version() -> u32 {
    1
}

// ============================================================================
// Proto to Rust type conversions
// ============================================================================

impl TryFrom<ProtoSandboxPolicy> for SandboxPolicy {
    type Error = miette::Report;

    fn try_from(proto: ProtoSandboxPolicy) -> Result<Self, Self::Error> {
        Ok(Self {
            version: proto.version,
            filesystem: proto
                .filesystem
                .map(FilesystemPolicy::from)
                .unwrap_or_default(),
            network: proto
                .network
                .map(NetworkPolicy::try_from)
                .transpose()?
                .unwrap_or_default(),
            landlock: proto.landlock.map(LandlockPolicy::from).unwrap_or_default(),
            process: proto.process.map(ProcessPolicy::from).unwrap_or_default(),
        })
    }
}

impl From<ProtoFilesystemPolicy> for FilesystemPolicy {
    fn from(proto: ProtoFilesystemPolicy) -> Self {
        Self {
            read_only: proto.read_only.into_iter().map(PathBuf::from).collect(),
            read_write: proto.read_write.into_iter().map(PathBuf::from).collect(),
            include_workdir: proto.include_workdir,
        }
    }
}

impl TryFrom<ProtoNetworkPolicy> for NetworkPolicy {
    type Error = miette::Report;

    fn try_from(proto: ProtoNetworkPolicy) -> Result<Self, Self::Error> {
        let mode = match proto::NetworkMode::try_from(proto.mode) {
            Ok(ProtoNetworkMode::Proxy) => NetworkMode::Proxy,
            Ok(ProtoNetworkMode::Allow) => NetworkMode::Allow,
            Ok(ProtoNetworkMode::Block | ProtoNetworkMode::Unspecified) | Err(_) => {
                NetworkMode::Block
            }
        };

        let proxy = proto.proxy.map(|p| ProxyPolicy {
            unix_socket: if p.unix_socket.is_empty() {
                None
            } else {
                Some(PathBuf::from(p.unix_socket))
            },
            http_addr: if p.http_addr.is_empty() {
                None
            } else {
                p.http_addr.parse().ok()
            },
            allow_hosts: p.allow_hosts,
        });

        Ok(Self { mode, proxy })
    }
}

impl From<ProtoLandlockPolicy> for LandlockPolicy {
    fn from(proto: ProtoLandlockPolicy) -> Self {
        let compatibility = match proto::LandlockCompatibility::try_from(proto.compatibility) {
            Ok(ProtoLandlockCompat::HardRequirement) => LandlockCompatibility::HardRequirement,
            _ => LandlockCompatibility::BestEffort,
        };
        Self { compatibility }
    }
}

impl From<ProtoProcessPolicy> for ProcessPolicy {
    fn from(proto: ProtoProcessPolicy) -> Self {
        Self {
            run_as_user: if proto.run_as_user.is_empty() {
                None
            } else {
                Some(proto.run_as_user)
            },
            run_as_group: if proto.run_as_group.is_empty() {
                None
            } else {
                Some(proto.run_as_group)
            },
        }
    }
}
