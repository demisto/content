Formats destination ports from connection data passed in `value`, including nested objects, lists, and JSON strings. Each connection must contain `port` and can include `ipProto`.

For example, `[{"port": 443, "ipProto": "TCP"}, {"port": 53, "ipProto": "UDP"}]` returns `443 (tcp), 53 (udp)`. Duplicate formatted entries are removed; data without a port returns an empty string.

Use this transformer in the incoming mapper to populate the **Destination Port** incident field. The script returns a string and has no context outputs.
