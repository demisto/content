## Prisma Cloud
Use the Prisma Cloud integration to manage alerts from Microsoft Azure, Google Cloud Platform, and AWS.

API reference: [Prisma Cloud API reference](https://api.docs.prismacloud.io/reference#try-the-apis)

### Fetch Incidents Filtering
The list of available names and possible values for fetch incidents filters can be retrieved by running the ***prisma-cloud-alert-filter-list*** command.
The possible values for severities can be found under "policy.severity" entry. In order to add a severity, use the filter name "policy.severity"
In order to add a rule name, use the filter name "alertRule.name". In order to add a policy name, use the filter name "policy.name".

In order to use multiple values for the same filter and get alerts that have one of the values, state them several time, for example: _policy.severity=high,policy.severity=medium_.
The filtering works the same way as in the Prisma Cloud UI. When providing several values for the same filter it gets only alerts that have one of these values, and when providing different values, it gets only alerts that have all the stated field values.

Providing additional filters should be done in the following format: _filtername1=filtervalue1,filtername2=filtervalue2,etc_. For example: _alert.status=open,policy.severity=high,policy.severity=medium,cloud.type=gcp,policy.remediable=true_.


By default, the integration fetches incidents in an open state.
