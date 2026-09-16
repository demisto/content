## EWS O365

### Microsoft EWS Retirement and EwsAllowedAppIds

Microsoft has announced the final phase of Exchange Web Services (EWS) retirement in Exchange Online, with phased disablement beginning in October 2026.

As part of this transition, Microsoft is moving away from unrestricted EWS access and has introduced a new tenant-level allow list called `EwsAllowedAppIds`. Starting in October 2026, Microsoft will block all EWS traffic by default. Applications will only be able to access EWS if their specific Application (Client) ID is explicitly added to this allow list by the tenant administrator.

We highly recommend using the [Microsoft Graph Mail](https://xsoar.pan.dev/docs/reference/integrations/microsoft-graph-mail) integration for mailbox operations such as reading, searching, and managing emails and attachments, as Microsoft itself recommends transitioning from EWS to Graph-based APIs.

#### Action Required

##### For customers using a Self-Deployed Application

You are responsible for updating your tenant configuration before the October 2026 enforcement takes effect. To ensure this integration continues to function without disruption, you must add the Entra Application (Client) ID used by this integration to your Exchange Online tenant's allow list.

1. Connect to Exchange Online PowerShell and add the Application ID.

    If this is the only application you are allowing, run the following command (replace `<Your-App-ID>` with your actual Application Client ID):

    ```powershell
    Set-OrganizationConfig -EwsAllowedAppIDs "<Your-App-ID>"
    ```

    **Warning:** This command replaces the entire allow list. If you already have other approved EWS applications, first read the current list and append the new ID so that you don't overwrite existing entries.

2. Ensure EWS is enabled for your tenant.

    ```powershell
    Set-OrganizationConfig -EwsEnabled $true
    ```

    (For full details, complete timelines, and PowerShell scripts for safely appending to an existing allow list, refer to the official Microsoft documentation: [Introducing EWSAllowedAppIDs: Preparing for the Final Phase of EWS Retirement](https://techcommunity.microsoft.com/blog/exchange/introducing-ewsallowedappids-preparing-for-the-final-phase-of-ews-retirement/4529471))

##### For customers using the Cortex Application authentication method

Palo Alto Networks is making the necessary updates to align our shared Application ID with Microsoft's new requirements, so you do not need to run the steps above. However, because this change is enforced and controlled entirely by Microsoft, we cannot validate the changes in advance or guarantee uninterrupted functionality. Palo Alto Networks is not responsible for any disruptions resulting from this rollout. We recommend verifying that your integration continues to function as expected once the October 2026 enforcement takes effect.

## Important note: Retirement of RBAC Application Impersonation

As of February 2025, the Impersonation access type of the integration is deprecated by Microsoft, read about it [here](https://techcommunity.microsoft.com/blog/exchange/critical-update-applicationimpersonation-rbac-role-deprecation-in-exchange-onlin/4295762).
To avoid disruptions, it is imperative that administrators begin transitioning their applications immediately.
To identify accounts using the ApplicationImpersonation role use the Exchange Online PowerShell command:
`Get-ManagementRoleAssignment -Role ApplicationImpersonation -GetEffectiveUsers -Delegating:$false`

## Set up the Third Party System

There are two application authentication methods available.
Follow your preferred method's guide on how to use the admin consent flow in order to receive your authentication information:

* [Cortex XSOAR Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#cortex-xsoar-application)
    To allow access to EWS O365, an administrator has to approve the Demisto app using an admin consent flow, by clicking on the following [link](https://oproxy.demisto.ninja/ms-ews-o365).
    After authorizing the Demisto app, you will get an ID, Token, and Key, which needs to be added to the integration instance configuration's corresponding fields.

* [Self-Deployed Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application) - Client Credential Flow.

## Permissions Needed

In order to function as expected, set the following permissions:

**Impersonation rights** to the service account - Deprecated.
**eDiscovery** permissions to the Exchange Server.
**full_access_as_app** to the _application used for authentication_.

Fore more information check the [documentation](https://xsoar.pan.dev/docs/reference/integrations/ewso365)