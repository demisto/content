Azure Resource Graph is an Azure service designed to extend Azure Resource Management by providing efficient and performant resource exploration with the ability to query at scale across a given set of resources. This pack is primarily used to allow for executing Azure Resource Graph queries.

## What does this pack do?

You can use Azure Resource Graph queries to:

- Query resources with complex filtering, grouping, and sorting by resource properties.
- Explore resources iteratively based on governance requirements.
- Assess the effect of applying policies in a vast cloud environment.
- Query changes made to resource properties.

## References

- [Link to starter Azure Resource Graph Queries](https://learn.microsoft.com/en-us/azure/governance/resource-graph/samples/starter?tabs=azure-cli)
- [Link to advanced Azure Resource Graph Queries](https://learn.microsoft.com/en-us/azure/governance/resource-graph/samples/advanced?tabs=azure-cli)

## Note from Microsoft

> Throttling
>
> As a free service, queries to Resource Graph are throttled to provide the best experience and response time for all customers. If your organization wants to use the Resource Graph API for large-scale and frequent queries, use portal Feedback from the [Resource Graph portal page](https://portal.azure.com/#blade/HubsExtension/ArgQueryBlade).
>
> For more information, see [Guidance for throttled requests](https://learn.microsoft.com/en-us/azure/governance/resource-graph/concepts/guidance-for-throttled-requests).