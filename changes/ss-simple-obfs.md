Added

- Shadowsocks nodes support the simple-obfs SIP003 plugin in `http` and `tls` mode through every import entry: Clash `plugin`/`plugin-opts`, sing-box and SIP008 `plugin`/`plugin_opts`, Surge-family `obfs`/`obfs-host` records, flat structured input and `ss://` share links. The plugin sits below the cipher and carries the first Shadowsocks ciphertext in its own handshake packet.
- simple-obfs carries TCP only, so Shadowsocks UDP still goes out as plain Shadowsocks to the node's host and port, matching dae and Mihomo.
