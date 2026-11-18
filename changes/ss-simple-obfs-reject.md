Changed

- A Shadowsocks plugin honk does not implement now rejects its entry instead of being kept as inert metadata: a static configuration fails to load, subscription entries are skipped one by one, and a share link that used to parse with `plugin=v2ray-plugin` fails instead of dialing plain Shadowsocks. Nodes that declare simple-obfs now really obfuscate, so their derived ID changes; nodes without a plugin keep theirs.
