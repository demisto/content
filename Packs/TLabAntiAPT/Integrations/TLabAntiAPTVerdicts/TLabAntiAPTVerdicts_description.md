Creates XSOAR incidents from finished tLab Anti-APT sandbox analyses.

## Only enable one delivery mode

This integration is the **PULL** half of a two-sided product. The tLab XSOAR connector, a service that runs inside the tLab installation, is the **PUSH** half and creates the same incidents from the other direction.

**Enabling both against the same tenant produces two incidents for every analysis.** Pick one:

- **PULL** (this integration): XSOAR reaches into tLab on a schedule. Choose it when XSOAR must initiate every connection, when tLab cannot reach XSOAR through the network, or when you want the fetch schedule under XSOAR's control.
- **PUSH** (the connector): tLab posts incidents as analyses finish. Choose it for lower latency and when tLab already has outbound access to XSOAR.

If both halves do run against the same tenant during a migration, three settings **must** be identical or the duplicates will not be recognisable as duplicates: **Installation ID** (`INSTALLATION_UUID`), **Incident name template** (`INCIDENT_NAME_TEMPLATE`) and **Severity map** (`SEVERITY_MAP`). The `tLab Delivery Mode` field on each incident records which half created it.

## Select the mapper

The fields on the incident are populated by the **tLab Anti-APT - Incoming Mapper** shipped with this pack, which is selected by default. If you replace it with a custom mapper, map from the `tlab_*` keys in the raw JSON; the contract is documented in `docs/verdict-incident-schema.json` in the connector repository.

## Required permissions

Read-only. Use the default **tLab account (tlab-auth)** mode with an `admin` or `developer` account. A source key does not work here — it covers submissions only.

**Known constraint:** on current tlab-server builds `GET /sample_reports` does not serve the `external_service` role, so an Internal token alone is not sufficient for fetching; and for the `company_admin` and `user` roles the server **silently drops** the `fileVerdict`, `scoreLevel`, `sourceId`, `rootOnly` and `minReportId` filters instead of rejecting them. An instance running under such a role will appear to work while reading far more reports than configured, and the cursor will not behave as documented. Use an `admin` or `developer` account until this is resolved, and verify after the first fetch that the number of incidents matches the configured verdict filter.

## Choosing a starting point

The first fetch starts at **First sample report id**. On an installation with a long analysis history, leaving it empty backfills everything. Run `!tlab-get-verdicts` first to see what the current cursor would produce.

## Late completions

The sandbox finishes analyses out of id order, so a report can complete after a higher-numbered one already has. A cursor alone would step past it permanently, so each run also re-scans reports updated within **Late completion lookback**. Reports already turned into incidents are remembered between runs and are not sent twice.
