## OpsGenie v3 (Standard Connector)

This integration is configured automatically as part of the Atlassian Standard Connector. Do not
configure it directly; set it up from the connector page.

### Authentication

The connector authenticates to OpsGenie with an **API key** connection profile. The key is sent
as `Authorization: GenieKey <key>` on every request.

Create the key in OpsGenie under **Settings > Integrations > API** (or a team's **Integrations >
API** integration). The key needs **Read** and **Create and Update** access (and **Delete** for
the delete commands); the integration must be **enabled**. Fetching alerts and incidents only
needs **Read** access.

Note: if **Query** is used for fetching, the **Status**, **Priority** and **Tags** filters are
ignored.

The *responders* argument of `opsgenie-create-alert`, `opsgenie-add-responder-alert`,
`opsgenie-create-incident` and `opsgenie-add-responder-incident` is a list of triples
*responder_type,value_type,value*, for example: `user,id,123,team,name,test_team`.
