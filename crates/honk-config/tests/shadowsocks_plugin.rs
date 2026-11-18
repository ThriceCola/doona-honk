//! Shadowsocks SIP003 plugin contract: one typed shape at every entry, one
//! rejection for a name honk does not implement, and dial-shape identity.

use honk_config::Config;
use honk_config::node::{Node, ShadowsocksObfs, ShadowsocksObfsMode, ShadowsocksPlugin};

/// One flat structured node, as the TOML/YAML/JSON loaders and `node {}` blocks
/// see it.
fn flat_config(plugin: &str, options: &str) -> String {
    format!(
        r#"{{"nodes":[{{"name":"ss-obfs","protocol":"ss","address":"1.2.3.4:8388",
           "host":"1.2.3.4","port":8388,"password":"pass",
           "encryption":"aes-256-gcm","plugin":"{plugin}","plugin_opts":"{options}"}}]}}"#
    )
}

fn obfs(
    mode: ShadowsocksObfsMode,
    host: Option<&str>,
    path: Option<&str>,
) -> Option<ShadowsocksPlugin> {
    Some(ShadowsocksPlugin::Obfs(ShadowsocksObfs {
        mode,
        host: host.map(str::to_string),
        path: path.map(str::to_string),
    }))
}

#[test]
fn flat_structured_plugin_is_typed_and_round_trips() {
    let config = Config::from_json_str(&flat_config(
        "obfs-local",
        "obfs=http;obfs-host=mask.example;obfs-uri=/asset",
    ))
    .unwrap();
    assert_eq!(
        config.nodes[0].shadowsocks().unwrap().plugin,
        obfs(
            ShadowsocksObfsMode::Http,
            Some("mask.example"),
            Some("/asset")
        )
    );
    let json = config.to_json_string().unwrap();
    let reparsed = Config::from_json_str(&json).unwrap();
    assert_eq!(reparsed.nodes[0], config.nodes[0]);
    assert_eq!(reparsed.to_json_string().unwrap(), json);
}

/// Every Clash/provider spelling reaches the same shape.
#[test]
fn plugin_name_and_option_aliases_agree() {
    for (plugin, options) in [
        ("obfs", "mode=tls;host=cdn.example"),
        ("obfs-local", "obfs=tls;obfs-host=cdn.example"),
        ("simple-obfs", "obfs=tls;obfs-host=cdn.example"),
    ] {
        let config = Config::from_json_str(&flat_config(plugin, options)).unwrap();
        assert_eq!(
            config.nodes[0].shadowsocks().unwrap().plugin,
            obfs(ShadowsocksObfsMode::Tls, Some("cdn.example"), None),
            "plugin {plugin} with {options}"
        );
    }
}

#[test]
fn plugin_options_without_a_plugin_are_rejected() {
    let error = Config::from_json_str(&flat_config("", "obfs=http")).unwrap_err();
    assert!(
        error.to_string().contains("require a plugin"),
        "unexpected error: {error}"
    );
}

/// A name honk cannot dial is kept in the model until admission rejects it: the
/// structured loader reports it against the entry, and a hand-built node fails
/// the same intrinsic check.
#[test]
fn unknown_plugin_name_is_rejected() {
    let error = Config::from_json_str(&flat_config("v2ray-plugin", "mode=websocket")).unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("unsupported Shadowsocks plugin"),
        "unexpected error: {message}"
    );
    assert!(message.contains("plugin"), "unexpected error: {message}");

    let mut node = Node::from_share_link("ss://aes-256-gcm:pass@1.2.3.4:8388#ss").unwrap();
    node.shadowsocks_mut().unwrap().plugin =
        Some(ShadowsocksPlugin::Unsupported("v2ray-plugin".into()));
    let error = node.validate().unwrap_err();
    assert!(
        error.to_string().contains("unsupported Shadowsocks plugin"),
        "unexpected error: {error}"
    );
}

#[test]
fn plugin_mode_and_path_must_agree() {
    for options in ["obfs=quic", "obfs=tls;obfs-uri=/asset", "mode=http;bogus=1"] {
        let error = Config::from_json_str(&flat_config("obfs-local", options)).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("simple-obfs"),
            "options {options} reported {message}"
        );
    }
}

/// A plugin shape that reaches a hand-built node still has to be dialable.
#[test]
fn intrinsic_validation_rejects_an_unusable_obfs_shape() {
    let mut node = Node::from_share_link("ss://aes-256-gcm:pass@1.2.3.4:8388#ss").unwrap();
    node.shadowsocks_mut().unwrap().plugin = obfs(ShadowsocksObfsMode::Tls, None, Some("/asset"));
    let error = node.validate().unwrap_err();
    assert!(
        error.to_string().contains("path requires http mode"),
        "unexpected error: {error}"
    );
    node.shadowsocks_mut().unwrap().plugin = obfs(ShadowsocksObfsMode::Http, Some("  "), None);
    let error = node.validate().unwrap_err();
    assert!(
        error.to_string().contains("host must not be blank"),
        "unexpected error: {error}"
    );
}

/// The plugin joins the dial shape. Both UUIDs are hard-coded goldens, not
/// recomputed here: the plain one repeats
/// `node::tests::test_protocol_identity_goldens` on purpose, so an identity
/// change to nodes without a plugin fails in this suite too, and the obfs one
/// was computed from the documented material when the plugin was added.
#[test]
fn simple_obfs_shape_joins_node_identity() {
    let plain = Node::from_share_link("ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#plain").unwrap();
    assert_eq!(plain.id.to_string(), "e4a92538-53a2-5f83-85cd-b5d11f90361b");

    let masked = Node::from_share_link(
        "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dmask.example#masked",
    )
    .unwrap();
    assert_eq!(
        masked.id.to_string(),
        "0999b0f6-b1c4-5053-a8ff-633401820028"
    );
    assert_ne!(masked.id, plain.id);

    let other_host = Node::from_share_link(
        "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dother.example#other",
    )
    .unwrap();
    assert_ne!(other_host.id, masked.id);
}
