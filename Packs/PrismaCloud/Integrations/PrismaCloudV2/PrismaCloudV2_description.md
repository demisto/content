## Prisma Cloud
Use the Prisma Cloud integration to manage alerts from Microsoft Azure, Google Cloud Platform, and AWS.

API reference: [Prisma Cloud API reference](https://api.docs.prismacloud.io/reference#try-the-apis)

### Fetch Incidents Filtering
The list of available names and possible values for fetch incidents filters can be retrieved by running ***prisma-cloud-alert-filter-list*** command.
The possible values for rule names can be found under "alertRule.name" entry, for policy names under "policy.name" entry and for severities under "policy.severity" entry.
Providing additional filters should be done in the following format: _filtername1=filtervalue1,filtername2=filtervalue2,etc_. For example: _cloud.type=gcp,policy.remediable=true,alert.status=snoozed_.

By default, the integration fetches incidents in an open state.