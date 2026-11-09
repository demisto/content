## tLab Anti-APT Lookup

This integration only reads. It never submits a sample, so it can be given a
restricted tLab account — the `user` role is enough. Detonation, which needs a
more privileged account for artifacts, lives in the separate **tLab Anti-APT
Sandbox** integration.

### Hash handling

Only full MD5, SHA1 and SHA256 hashes are looked up. The server matches hash
filters by prefix, so a partial hash would match unrelated samples and return a
confident verdict about the wrong file. Every result is additionally verified
against the requested hash before it is used.

MD5 lookups are resolved through the hash search endpoint rather than the report
filter. The `fileHashMd5` report filter exists, but the server does not include
it in the field list allowed for the `company_admin` and `user` roles, and
discards it silently instead of rejecting it — which would turn a narrow query
into "return everything".

### Unknown files

A hash tLab Anti-APT has never analyzed returns DBot score 0 (Unknown), not 1
(Good). "We have no record of this file" is a different statement from "this
file is benign", and a Good score would suppress other vendors' findings on the
same indicator. Set **Treat an unknown verdict as benign** only if your playbooks
depend on the opposite behaviour.

### Search filters and roles

`tlab-search-reports` accepts filters that the server applies only for accounts
with the `admin` or `developer` role: verdict, score level, source, root-only,
minimum report ID, minimum score and file name. With a lower role these are
discarded without an error, so a narrow query silently returns everything. The
command adds a warning to its output whenever one of them is used.
