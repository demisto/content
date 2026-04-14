> **Important Notice – Microsoft Sentinel Migration to Microsoft Defender Portal**
>
> Microsoft is migrating Microsoft Sentinel from the Azure portal to the Microsoft Defender portal:
>
> - **From July 2025** – New customers have automatically been onboarded and redirected to the Defender portal.
> - **Starting March 2027** – All customers using Microsoft Sentinel in the Azure portal will be redirected to the Defender portal.
>
> This integration is **not being deprecated** at this time, as not all commands are supported in the Graph API. However, if you currently use Microsoft Sentinel in the Azure portal, Microsoft recommends planning your transition to the Defender portal now.
>
> We strongly recommend transitioning to the following integrations for managing incidents and indicators:
>
> - [Microsoft Graph Security](https://xsoar.pan.dev/docs/reference/integrations/microsoft-graph)
> - [Microsoft Defender Threat Intelligence](https://xsoar.pan.dev/docs/reference/integrations/microsoft-defender-threat-intelligence)

Use the Azure Sentinel integration to get and manage incidents and get related entity information for incidents.
​

## What does this pack do?

- Gets a single incident or a list of incidents from Azure Sentinel.
- Gets a list of watchlists from Azure Sentinel.
- Creates, updates, or deletes a watchlist in Azure Sentinel.
- Creates, updates or deletes a single incident in Azure Sentinel.
- Gets, adds, or deletes the comments of an incident from Azure Sentinel.
- Gets a list of an incident's related entities from Azure Sentinel.
- Gets a list of an incident's entities from Azure Sentinel.
- Gets a list of an incident's alerts from Azure Sentinel.
- Get a single watchlist item or list of watchlist items.
- Creates, updates, deletes a watchlist item.
- Returns a list of threat indicators.
- Returns a list of threat indicators with specific entities.
- Creates, updates, or deletes a threat indicator.
- Appends new tags to an existing indicator.
- Replaces the tags of a given indicator.
