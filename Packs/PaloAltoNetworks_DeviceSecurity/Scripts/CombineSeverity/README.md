Combines the `severity` and `display_severity` properties of the object passed in `value` into plain text, for example `info / low`. Missing or empty properties appear as `N/A`.

Use this transformer in the incoming mapper to populate the **Severity (raw / display)** incident field. The `value` argument must be an object. The script returns a string and has no context outputs.
