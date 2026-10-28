XSUP-79350 platform repro. DO NOT MERGE.

After you save the instance, the first run freezes itself once (after 180 seconds by default), so the server kills it for a missed heartbeat. Every later run only logs `XSUP79350-LR-REPRO run <id> alive uptime=<n>s`.

- **Bug reproduced:** each restart is killed at about 300 seconds.
- **No bug:** a restart stays up well past 300 seconds.

Run `!lr-repro-status` to see each run and how long it stayed up. Run `!lr-repro-reset`, then re-save the instance, to repeat the test.
