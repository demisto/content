## tLab Anti-APT Sandbox

### Server URL

The base URL of the tLab Anti-APT sandbox API (tlab-server). Through the tLab
web server it is `https://<tlab-host>/api`; for a direct connection it is
`http://<tlab-host>:8080`.

### Authentication

**tLab account (tlab-auth)** — the default and recommended mode. The
integration logs in to tlab-auth with a tLab account, exactly like the
omni-center portal, and sends the token as `Authorization: Bearer`. The session
is cached per instance and refreshed before it expires; a failed refresh falls
back to a new login, and a 401 from the sandbox triggers one refresh and one
retry.

- **Auth server URL** — where tlab-auth is reached. Leave it empty to use
  `https://<Server URL host>:8002/api`: the omni-center portal, which forwards
  `/api` to tlab-auth over TLS. If the portal certificate is self-signed,
  enable **Trust any certificate**. Do not use `https://<host>/api`: on a
  sandbox host that path is tlab-server, and the login is rejected with
  "No authorizationHeader data". A direct `http://<host>:8033/api` also works
  but sends the password unencrypted.
- **Credentials** — the login and password of an account with the `admin` or
  `developer` role. Turn off password expiry and forced password change for it:
  tlab-auth rejects an expired password with 403, and every command starts
  failing.

**Source key (Bearer)** — a key from the omni-center source-key registry,
type `CORTEX_XSOAR`. It needs the source-key gateway (balancer) and covers
submissions only, so report and artifact commands do not work with it.

**Username and password** — the legacy tlab-server sign-in (`/auth/sign_in`
on the sandbox itself). Use it only with servers that still provide it.

**Internal token (localhost only)** — works **only** when Cortex XSOAR runs on the
tlab-server host. The server checks the caller's address against
`tokenAuth.allowedRemoteAddresses`, which defaults to `127.0.0.1`, so a remote
Cortex XSOAR always receives 401 in this mode.

### Role requirements

Submitting samples works with any authenticated role, and polling a submission
needs no credentials at all. Retrieving artifacts — PCAP, memory dumps, dropped
files, extra logs — requires the `admin` or `developer` role in tLab. Press Test
after configuring: the result names the role that was detected and warns when
artifacts will not be reachable.
