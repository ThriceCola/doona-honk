//! Shadowsocks SIP003 plugin contracts.
//!
//! honk implements simple-obfs and no other plugin. Every import entry — flat
//! structured fields, Clash `plugin`/`plugin-opts`, SIP008 and sing-box
//! strings, Surge-family records and `ss://` links — normalizes into
//! [`ShadowsocksPlugin`], so one entry behaves the same whichever dialect
//! carried it.
//!
//! A name honk does not implement stays in the model as
//! [`ShadowsocksPlugin::Unsupported`] and intrinsic validation rejects it. That
//! is deliberate: an entry whose plugin is dropped dials plain Shadowsocks at
//! an obfuscated server, which fails later as an unexplained cipher error.
//!
//! Wire reference: `github.com/olicesx/outbound`'s `transport/simpleobfs`
//! (the revision dae pins), which follows shadowsocks/simple-obfs.

use super::identity_field;

/// The name honk writes back into flat configurations.
const SIMPLE_OBFS_WIRE_NAME: &str = "obfs-local";

/// Names that select simple-obfs. Clash writes `obfs`, SIP003 clients and dae
/// write `obfs-local` (dae also accepts `simpleobfs`).
const SIMPLE_OBFS_NAMES: &[&str] = &["obfs", "obfs-local", "simple-obfs", "simpleobfs"];

const UNSUPPORTED_PLUGIN: &str = "unsupported Shadowsocks plugin; honk implements simple-obfs";

/// The SIP003 plugin an `ss` entry declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShadowsocksPlugin {
    /// simple-obfs, the plugin honk carries.
    Obfs(ShadowsocksObfs),
    /// A plugin name honk does not implement, retained so admission reports
    /// the entry instead of dialing it as plain Shadowsocks.
    Unsupported(String),
}

/// simple-obfs wire shape: HTTP-upgrade requests, or TLS records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowsocksObfs {
    pub mode: ShadowsocksObfsMode,
    /// `Host` header (http) or SNI (tls). `None` uses the server host.
    pub host: Option<String>,
    /// Request path for `http`; `None` uses `/`. Rejected with `tls`.
    pub path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowsocksObfsMode {
    Http,
    Tls,
}

impl ShadowsocksObfsMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Tls => "tls",
        }
    }
}

/// Canonical simple-obfs options before they are checked as a whole.
#[derive(Default)]
struct ObfsOptions {
    mode: Option<String>,
    host: Option<String>,
    path: Option<String>,
}

impl ObfsOptions {
    /// Fold one option claim: a repeated equal value is harmless, a second
    /// value for the same option is a conflict.
    fn claim(&mut self, key: &str, value: &str) -> Result<(), &'static str> {
        let value = value.trim();
        let slot = match key.trim().to_ascii_lowercase().as_str() {
            "obfs" | "mode" => &mut self.mode,
            "obfs-host" | "host" => &mut self.host,
            "obfs-path" | "obfs-uri" | "path" => &mut self.path,
            _ => return Err("unsupported simple-obfs option"),
        };
        match slot {
            Some(existing) if existing == value => Ok(()),
            Some(_) => Err("conflicting simple-obfs options"),
            None => {
                *slot = Some(value.to_string());
                Ok(())
            }
        }
    }

    /// Fold the SIP003 `key=value;key=value` option string.
    fn merge_sip003(&mut self, options: &str) -> Result<(), &'static str> {
        for field in options.split(';') {
            let field = field.trim();
            if field.is_empty() {
                continue;
            }
            let (key, value) = field
                .split_once('=')
                .ok_or("simple-obfs option must be key=value")?;
            self.claim(key, value)?;
        }
        Ok(())
    }

    /// Canonicalize into a dialable shape. The mode decides everything else,
    /// so an unusable combination is rejected here rather than at dial time.
    fn into_shape(self) -> Result<ShadowsocksObfs, &'static str> {
        let mode = match self.mode.as_deref() {
            Some(mode) if mode.eq_ignore_ascii_case("http") => ShadowsocksObfsMode::Http,
            Some(mode) if mode.eq_ignore_ascii_case("tls") => ShadowsocksObfsMode::Tls,
            _ => return Err("simple-obfs mode must be http or tls"),
        };
        let host = self
            .host
            .filter(|host| !host.trim().is_empty())
            .map(|host| host.trim().to_string());
        let path = self
            .path
            .filter(|path| !path.trim().is_empty())
            .map(|path| {
                let path = path.trim();
                if path.starts_with('/') {
                    path.to_string()
                } else {
                    format!("/{path}")
                }
            });
        if path.is_some() && mode == ShadowsocksObfsMode::Tls {
            return Err("simple-obfs path requires http mode");
        }
        Ok(ShadowsocksObfs { mode, host, path })
    }
}

impl ShadowsocksPlugin {
    /// Parse the `plugin` + `plugin_opts` pair every adapter carries, so
    /// "options without a plugin" is rejected in exactly one place. A blank
    /// name or option string is absent, not a value.
    pub fn from_flat(
        name: Option<&str>,
        options: Option<&str>,
    ) -> Result<Option<Self>, (&'static str, &'static str)> {
        let options = options.map(str::trim).filter(|options| !options.is_empty());
        match name.map(str::trim).filter(|name| !name.is_empty()) {
            Some(name) => Self::parse(name, options)
                .map(Some)
                .map_err(|reason| ("plugin", reason)),
            None if options.is_some() => {
                Err(("plugin_opts", "Shadowsocks plugin options require a plugin"))
            }
            None => Ok(None),
        }
    }

    /// Parse a plugin name with its options, as a share link, flat
    /// configuration or record carries them. Options may arrive inside the
    /// name (`obfs-local;obfs=http`) or beside it (`plugin_opts`).
    pub fn parse(name: &str, options: Option<&str>) -> Result<Self, &'static str> {
        let (name, inline) = match name.split_once(';') {
            Some((name, rest)) => (name, Some(rest)),
            None => (name, None),
        };
        let name = name.trim();
        if name.is_empty() {
            return Err("Shadowsocks plugin name must not be blank");
        }
        if !SIMPLE_OBFS_NAMES
            .iter()
            .any(|alias| alias.eq_ignore_ascii_case(name))
        {
            return Ok(Self::Unsupported(name.to_string()));
        }
        let mut parsed = ObfsOptions::default();
        for options in [inline, options].into_iter().flatten() {
            parsed.merge_sip003(options)?;
        }
        Ok(Self::Obfs(parsed.into_shape()?))
    }

    /// Reject a claim honk cannot dial. Every construction entry reaches this
    /// through intrinsic validation, so an unknown plugin never becomes a node.
    pub fn validate(&self) -> Result<(), (&'static str, &'static str)> {
        let obfs = match self {
            Self::Unsupported(_) => return Err(("plugin", UNSUPPORTED_PLUGIN)),
            Self::Obfs(obfs) => obfs,
        };
        if obfs
            .host
            .as_deref()
            .is_some_and(|host| host.trim().is_empty())
        {
            return Err(("plugin_opts", "simple-obfs host must not be blank"));
        }
        let Some(path) = obfs.path.as_deref() else {
            return Ok(());
        };
        if !path.starts_with('/') {
            return Err(("plugin_opts", "simple-obfs path must start with /"));
        }
        if obfs.mode == ShadowsocksObfsMode::Tls {
            return Err(("plugin_opts", "simple-obfs path requires http mode"));
        }
        Ok(())
    }

    /// Dial-shape identity material. Two entries that differ only by their
    /// plugin are different dials, so they must not share one node UUID.
    pub(crate) fn identity_fingerprint(&self) -> String {
        match self {
            Self::Obfs(obfs) => format!(
                "obfs|{}|{}|{}",
                obfs.mode.as_str(),
                identity_field(obfs.host.as_deref().unwrap_or("")),
                identity_field(obfs.path.as_deref().unwrap_or("")),
            ),
            Self::Unsupported(name) => format!("unsupported|{}", identity_field(name)),
        }
    }

    /// Flat wire form: the plugin name and its SIP003 option string.
    pub fn flat_wire(&self) -> (&str, Option<String>) {
        match self {
            Self::Obfs(obfs) => {
                let mut options = vec![format!("obfs={}", obfs.mode.as_str())];
                if let Some(host) = obfs.host.as_deref() {
                    options.push(format!("obfs-host={host}"));
                }
                if let Some(path) = obfs.path.as_deref() {
                    options.push(format!("obfs-uri={path}"));
                }
                (SIMPLE_OBFS_WIRE_NAME, Some(options.join(";")))
            }
            Self::Unsupported(name) => (name, None),
        }
    }
}
