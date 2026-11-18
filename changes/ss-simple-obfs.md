Added

- Shadowsocks nodes support the simple-obfs SIP003 plugin in `http` and `tls` mode through every import entry: Clash `plugin`/`plugin-opts`, sing-box and SIP008 `plugin`/`plugin_opts`, Surge-family `obfs`/`obfs-host` records, flat structured input and `ss://` share links. The plugin sits below the cipher and carries the first Shadowsocks ciphertext in its own handshake packet.
- simple-obfs carries TCP only, so Shadowsocks UDP still goes out as plain Shadowsocks to the node's host and port, matching dae and Mihomo.
- The plugin shape joins the node's derived ID, so entries that differ only by obfs are separate nodes; nodes without a plugin keep their previous ID.
- A plugin name honk does not implement now rejects its entry instead of being kept as inert metadata; a share link that used to parse with `plugin=v2ray-plugin` fails instead of dialing plain Shadowsocks.
