Integration with LogRhythm with REST api. You can execute queries on logs, get hosts information, add new hosts and update host status.

## Configuration Parameters

**Hostname**  
This is the network address of the LogRhythm server host.

**API Token**  
The credentials entered here should be those created in the LogRhythm console for REST api.

**Search API cluster ID**  
Enter `http://localhost:8500/ui/#/dc1/services/lr-legacy-search-api` in LogRhythm host, the cluster ID is under `TAGS` header

**Entity ID**
The Entity ID is used for multi-tenancy environment where case data or search query need to set for single entity only
---

LogRhythm7.x with case fetch and raw log search. This integrations support MSSP with multiple entities.

---
[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/log-rhythm-rest)
