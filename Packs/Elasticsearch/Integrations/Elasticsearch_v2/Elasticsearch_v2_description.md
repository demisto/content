The Elasticsearch v2 integration supports Elasticsearch 6.0.0 and later.
This integration was integrated and tested with versions 6.6.2, 7.3, 8.4.1 of Elasticsearch.

## Authentication

There are 3 different authentication [methods](https://www.elastic.co/docs/api/doc/elasticsearch#doc-authentication)

### Basic Auth (http)

To use **Basic Authentication**:

* Choose the **Basic Auth** type from the *Authorization type* dropdown list.
* Enter your **Username** into the *Username* field.
* Enter your **Password** into the *Password* field.

### API Key Auth (http_api_key)

To use **API Key Authentication**:

* Choose the **API Key Auth** type from the *Authorization type* dropdown list.
* Enter your **API key ID** into the *API key ID* field.
* Enter your **API key** into the *API key* field.

For more info about API Key management see [here](https://www.elastic.co/guide/en/elasticsearch/reference/7.6/security-api-create-api-key.html)

**Note:** Optionally, you can choose **Basic Auth** type and use the *Username* and *Password* fields to enter the API key ID and API key.
Example:
for *API Key ID* kQme5aOx enter: _api_key_id:kQme5aOx
for *API Key* ui2lp2axT enter: ui2lp2axT

### Bearer Auth (http)

To use **Bearer Authentication**:

* Choose the **Bearer Auth** type from the *Authorization type* dropdown list.
* Enter your **Username** into the *Username* field.
* Enter your **Password** into the *Password* field.

For more info see [here](https://www.elastic.co/guide/en/elasticsearch/reference/7.6/security-api-get-token.html#security-api-get-token-prereqs)

## Kibana Integration

This integration includes a set of **`es-kibana-*` commands** that let you interact with Kibana directly from Cortex XSOAR — no separate Kibana integration required.

### What you can do with Kibana commands

- **Case Management** — Create, update, delete, and list Kibana cases; add comments, attach files, and link alerts to cases.
- **Alerting & Rules** — List rule types, retrieve rules, enable/disable rules, mute/unmute alerts.
- **Detection Alerts** — Bulk-update the status of security detection alerts (open, acknowledged, closed).
- **Exception Lists & Items** — Manage Kibana exception lists and their items, including Elastic Endpoint exceptions.
- **Value Lists** — Create, update, delete, and import/export value lists used in detection rules.

### Kibana URL

- **On-premises (self-managed) deployments:** Set the **Kibana Server URL** parameter to the address of your Kibana server, including the port if it is not the default (e.g. `https://kibana.example.com:5601`). Kibana is usually hosted separately from Elasticsearch, so this URL cannot be derived from the Elasticsearch **Server URL**.
- **Elastic Cloud deployments:** You can leave **Kibana Server URL** empty. The URL is then derived automatically from the **Server URL**, by replacing the `.es.` segment of the hostname with `.kb.` (for example, `https://my-deployment.es.us-central1.gcp.cloud.es.io` becomes `https://my-deployment.kb.us-central1.gcp.cloud.es.io`).

> **Note:** When **Kibana Server URL** is set, it always takes precedence over the derivation from the **Server URL**.

### Required Kibana Privileges

Kibana API endpoints are gated by **feature privileges**. The level required depends on the operation:

| Privilege level | Operations covered |
|---|---|
| **Read** | GET / list / view (`es-kibana-*-list`, `es-kibana-*-get`, `es-kibana-alerting-health-get`) |
| **All** | POST / PUT / PATCH / DELETE — create, update, delete, and change-state commands |

For **Cases** and **Rules**, the required privilege is also scoped to the feature that owns the object:

- Objects owned by **Security** (e.g. SIEM detection rules, Security cases) require the **Security** feature privilege.
- Objects owned by **Observability** require the **Observability** feature privilege.
- Objects owned by **Stack / Management** (e.g. Stack Rules) require the **Stack Rules** / **Management** feature privilege.


### Kibana Spaces (optional)

If you use [Kibana Spaces](https://www.elastic.co/docs/deploy-manage/manage-spaces) to separate your data, set the **Space ID** parameter in the instance configuration. All `es-kibana-*` commands will then operate within that space by default. You can also override the space per-command using the `space_id` argument.

## Notes

* Not all fields can be used for sorting in Elasticsearch. Sorting is only supported for fields of the following types: **boolean**, **numeric**, **date**, and **keyword**.
* The "Test" button does not fully validate the fetch incidents functionality. To ensure the instance is correctly fetching incidents, run the *!es-integration-health-check* command

## Additional Configuration Parameters Details

Use the **Fetch incident types** parameter to select what to fetch from Elasticsearch: the default **Elasticsearch Entity**, **Elasticsearch Security Alert**, or **Elasticsearch Case**.

Mirroring is only available for Elasticsearch Security Alerts and Cases.

Fetching security alerts requires:
    - Index
    - Index time field
    - Query String or Raw Query

For further information about type mapping, see [here](https://www.elastic.co/guide/en/elasticsearch/reference/7.x/mapping.html#mapping-type).

**Query String**
Query String is queried using the Lucene syntax. For more information about the Lucene syntax see [here](https://www.elastic.co/guide/en/elasticsearch/reference/7.3/query-dsl-query-string-query.html#query-string-syntax).

**Raw Query**
Allows raw DSL queries. For more information about Query DSL see [here](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html).

### Fetch Security Alerts

To fetch security alerts, use the **Raw Query** field (DSL query). The index must follow one of these patterns: `.internal.alerts-security.alerts-*` or `.siem-signals-*`.

### Fetch Cases

Use the **Fetch cases by Severity** parameter to filter cases by the required severity and the **Fetch cases by Status** parameter to filter cases by the required status.

**Time field type**
3 formats supported:

* Simple-Date - A plain date string. You must specify the format in which the date is stored. For more information about time formatting, see [here](http://strftime.org/).
* Timestamp-Second - A numeric value representing the number of seconds since the Unix epoch (00:00:00 UTC on 1 January 1970). Example: '1572164838'
* Timestamp-Milliseconds - A numeric value representing the number of milliseconds since the Unix epoch. Example: '1572164838123'
