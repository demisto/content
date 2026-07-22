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

The Kibana URL is derived automatically from the **Server URL** you already configured for Elasticsearch. No additional URL field is needed.

> **Requirement:** Your Elasticsearch Server URL must be an Elastic Cloud URL containing `.es.` in the hostname (e.g. `https://my-deployment.es.us-central1.gcp.cloud.es.io`). The integration replaces `.es.` with `.kb.` to reach Kibana. Self-managed deployments with a custom Kibana URL are not supported by the automatic derivation.

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

Fetch incidents requires:
    - Index
    - Index time field
    - Query String or Raw Query

For further information about type mapping, see [here](https://www.elastic.co/guide/en/elasticsearch/reference/7.x/mapping.html#mapping-type).

**Query String**
Query String is queried using the Lucene syntax. For more information about the Lucene syntax see [here](https://www.elastic.co/guide/en/elasticsearch/reference/7.3/query-dsl-query-string-query.html#query-string-syntax).

**Raw Query**
Allows raw DSL queries. For more information about Query DSL see [here](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html).

**Time field type**
3 formats supported:

* Simple-Date - A plain date string. You must specify the format in which the date is stored. For more information about time formatting, see [here](http://strftime.org/).
* Timestamp-Second - A numeric value representing the number of seconds since the Unix epoch (00:00:00 UTC on 1 January 1970). Example: '1572164838'
* Timestamp-Milliseconds - A numeric value representing the number of milliseconds since the Unix epoch. Example: '1572164838123'
