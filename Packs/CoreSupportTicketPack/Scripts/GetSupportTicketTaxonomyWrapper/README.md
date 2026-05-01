## GetSupportTicketTaxonomyWrapper

Wrapper for `GetSupportTicketTaxonomy`. Calls the inner script via `executeCommand` so it is dispatched through the XSOAR server where the exclusion list is honored.

### Outputs

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Core.SupportTicketTaxonomy | A mapping of support issue categories to their specific problem concentrations. | String |
