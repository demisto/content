![lumu_logo](../../doc_files/Lumu_image.png)

## Cortex - XSOAR and LUMU SECOPS Integration

Lumu SecOps operations, reflect and manage the Lumu Incidents either from XSOAR Cortex or viceversa using the mirroring integration flow, https://lumu.io/

#### Diagram

![diagram](../../doc_files/Cortex_Lumu_draw.png)

#### Lumu API Specifications

here the short list of the http endpoint used in the Cortex-Lumu Integration

* [Get all incidents  [Available for Insights]](https://docs.lumu.io/portal/en/kb/articles/core-concepts-api#heading-ee15950c-6781-bc30)
* [Get open incidents [Available for Insights]](https://docs.lumu.io/portal/en/kb/articles/core-concepts-api#heading-e122950f-869e-86e5)
* [Get muted incidents [Available for Insights]](https://docs.lumu.io/portal/en/kb/articles/core-concepts-api#Get_muted_incidents_Available_for_Insights)
* [Get closed incidents [Available for Insights]](https://docs.lumu.io/portal/en/kb/articles/core-concepts-api#Get_closed_incidents_Available_for_Insights)
* [Get incident events groupings [Available for Insights]](https://docs.lumu.io/portal/en/kb/articles/core-concepts-api#Get_incident_events_groupings_Available_for_Insights)
* [Get incident details [Available for Insights]](https://docs.lumu.io/portal/en/kb/articles/core-concepts-api#Get_incident_details_Available_for_Insights)
* [Mark incident as read [Available for Insights]](https://docs.lumu.io/portal/en/kb/articles/core-concepts-api#Mark_incident_as_read_Available_for_Insights)
* [Begin incident work [Available for Insights]](https://docs.lumu.io/portal/en/kb/articles/core-concepts-api#Begin_incident_work_Available_for_Insights)
* [Comment incident [Available for Insights]](https://docs.lumu.io/portal/en/kb/articles/core-concepts-api#heading-51187ea8-bf25-4327)
* [Mute incident [Available for Insights]](https://docs.lumu.io/portal/en/kb/articles/core-concepts-api#heading-2bdab078-aa36-ebe2)
* [Unmute incident [Available for Insights]](https://docs.lumu.io/portal/en/kb/articles/core-concepts-api#Unmute_incident_Available_for_Insights)
* [Close incident [Available for Insights]](https://docs.lumu.io/portal/en/kb/articles/core-concepts-api#Close_incident_Available_for_Insights)
* [Consult incidents updates [Available for Insights]](https://docs.lumu.io/portal/en/kb/articles/core-concepts-api#Consult_incidents_updates_Available_for_Insights)
* [Get security event details [Available for Insights]](https://docs.lumu.io/portal/en/kb/articles/core-concepts-api#Get_security_event_details_Available_for_Insights)
* [Get incident security events details [Available for Insights]](https://docs.lumu.io/portal/en/kb/articles/core-concepts-api#Get_incident_security_events_details_Available_for_Insights)

#### Operation

##### Marketplace

![marketplace](../../doc_files/lumusecops_LumuLocalMarketPlace.png)


##### Configure: Set Off the integration

- Prerequisites
  - Lumu Defender Api key (company-key) `[required]`
  - Lumu access to request the Lumu API Endpoints, [Lumu API Specifications](https://docs.lumu.io/portal/en/kb/articles/core-concepts-api), [**Lumu Insights**](https://lumu.io/pricing/)
  - the Offset number to consult the latest updates as of the offset, [check API endpoint](https://docs.lumu.io/portal/en/kb/articles/core-concepts-api#Consult_incidents_updates_through_REST) `[required]`

Once the Lumu package was downloaded from the Cortex Marketplace, then next the Lumu integration initialization

- from the left panel select the `gear` settings, go to `Integrations` Tab and `Instances`, Sub-tab, search for **Lumu** and add a new instance.
    ![](../../doc_files/lumusecops_integrationConfig1.png)
    <br>

- Instance Settings
  - Parameters
    - _Name_ `[required]`
    - _Fetches incidents_ checked `[required]`
    - _Lumu_ Classifier `[required]`
    - _Lumu_ Incident type `[required]`
    - _LumuInMap_ Mapper (incoming) `[required]`
    -  `Mapper (outgoing)` ignore.
    -  `Maximum number of incidents to fetch every time` ignore
    -  `First fetch time interval` ignore
    -  _Server URL_ `[required]`
    -  `Proxy settings` optional
    -  `Trust any certificate` optional
    -  _API Key_ `[required]`
    -  _Incident Offset_ `[required]`
    -  _Incident Mirror Direction_ - select `Incoming and Outgoing` `[required]`
    -  `Mirror Tags`, do not change
    -  `Do not use by default` ignore
    -  _Log Level_ - select `debug or None` as it needs `[required]`
 -  Submit
    -  Click `Test` button and expect the green successful output.
    -  Submit the setup, click `Save and Exit`
    ![](../../doc_files/lumusecops_integrationConfig2.png)
    ![](../../doc_files/lumusecops_integrationConfig3.png)


##### Dashboard: Incident list

- These two are the main windows to list, select and check the Lumu incidents which have been mirrored for the Lumu integration in Cortex
    > Note: Lumu Portal to the left screen and Cortex to the right screen.

    ![](../../doc_files/incidentsDashboardBoth.png)
    <br>



##### Creation & Update Incident

- Mirroring process run in background and trigger each x time interval the commands which are required to successful sync both security platforms

    - Creation
    > Note: Cortex to the left screen and Lumu Portal to the right screen.

    ![](../../doc_files/lumusecops_incidentCreation.png)
    <br>

    - Updates
    > Note: Cortex to the left screen and Lumu Portal to the right screen.

    ![](../../doc_files/lumusecops_incidentEventUpdate.png)
    <br>

##### Mute/Unmute Incident

- Mute/Unmute an incident from Cortex XSOAR
    > Note: Cortex to the left screen and Lumu Portal to the right screen.

    - hover and click in the `comment` field to edit, overwrite the new comment and click on the `ok` icon.
    - hover and click in the `lumu_status` field to edit, overwrite the field typing `mute` or `muted` magic words and click on the `ok` icon.
    `wait 1 minute tops until the changes are mirrored`
        ![](../../doc_files/lumusecops_incidentMuteFromCortexToLumu.png)
        <br>

-  Mute/Unmute an incident from Lumu Portal
    > Note: Cortex to the left screen and Lumu Portal to the right screen.

    - click in **Take Actions** button, go to `Mute`, fill in the text box field  and submit the form.
    `wait 1 minute tops until the changes are mirrored`
        ![](../../doc_files/lumusecops_incidentMuteFromLumuToCortex.png)
        <br>

##### Close Incident

- Closing an incident from Cortex XSOAR
    > Note: Cortex to the left screen and Lumu Portal to the right screen.

    - click in **Actions** button, fill in the `Close Reason` and yhe `Close Notes` fields and submit the form.

        
    
    - Incident closed in both sides triggered by Cortex side.
        `wait 1 minute tops until the changes are mirrored`
        ![](../../doc_files/lumusecops_incidentCloseFromCortexToLumu.png)
        <br>

-  Closing an incident from Lumu Portal
    > Note: Lumu Portal to the left screen and Cortex to the right screen.

    - click in **Take Actions** button, go to `Close Incident`, fill in the text box field  and submit the form.

    - Incident closed in both sides triggered by Cortex side.
        `wait 1 minute tops until the changes are mirrored`
        ![](../../doc_files/lumusecops_incidentCloseFromLumuToCortex.png)
        <br>


##### Logs

- War Room
    it is a kind a CLI where you can crank manual command and check the entries of the integration.
    ![](../../doc_files/lumusecops_warRoomCLIHistory.png)
    <br>

- Check the fetch history
    it is a table which print every `fetch-incidents` command execution and show the output data result.
    ![fetch_history](../../doc_files/lumusecops_fetchHistoryRecords.png)
    <br>

- Integration instance logs (Cortex Xsoar Web Console)
    ![](../../doc_files/lumusecops_integration-instance-log.png)

- integration-instance.log (ssh)

```bash
[root@cortex ~]# tail -f /var/log/demisto/integration-instance.log
2023-01-26 22:12:03.6217 debug (Lumu_instance_15_Lumu_fetch-incidents) Ignoring Message (IncidentMuted - 17af99e0-9b70-11ed-980e-915fb2011ca7) from Cortex to not create a loop between both parties (source: /builds/GOPATH/src/gitlab.xdr.pan.local/xdr/xsoar/server/services/automation/dockercoderunner.go:992)
2023-01-26 22:12:03.6219 debug (Lumu_instance_15_Lumu_fetch-incidents) Ignoring Message (IncidentUnmuted - 17af99e0-9b70-11ed-980e-915fb2011ca7) from Cortex to not create a loop between both parties (source: /builds/GOPATH/src/gitlab.xdr.pan.local/xdr/xsoar/server/services/automation/dockercoderunner.go:992)
2023-01-26 22:12:03.6224 debug (Lumu_instance_15_Lumu_fetch-incidents) Ignoring Message (IncidentMuted - f563af00-9bda-11ed-a0c7-dd6f8e69d343) from Cortex to not create a loop between both parties (source: /builds/GOPATH/src/gitlab.xdr.pan.local/xdr/xsoar/server/services/automation/dockercoderunner.go:992)
2023-01-26 22:12:03.6226 debug (Lumu_instance_15_Lumu_fetch-incidents) Ignoring Message (IncidentUnmuted - f563af00-9bda-11ed-a0c7-dd6f8e69d343) from Cortex to not create a loop between both parties (source: /builds/GOPATH/src/gitlab.xdr.pan.local/xdr/xsoar/server/services/automation/dockercoderunner.go:992)
2023-01-26 22:12:03.6229 debug (Lumu_instance_15_Lumu_fetch-incidents) Ignoring Message (IncidentMuted - f563af00-9bda-11ed-a0c7-dd6f8e69d343) from Cortex to not create a loop between both parties (source: /builds/GOPATH/src/gitlab.xdr.pan.local/xdr/xsoar/server/services/automation/dockercoderunner.go:992)
2023-01-26 22:12:03.6232 debug (Lumu_instance_15_Lumu_fetch-incidents) Ignoring Message (IncidentUnmuted - f563af00-9bda-11ed-a0c7-dd6f8e69d343) from Cortex to not create a loop between both parties (source: /builds/GOPATH/src/gitlab.xdr.pan.local/xdr/xsoar/server/services/automation/dockercoderunner.go:992)
2023-01-26 22:12:03.6239 debug (Lumu_instance_15_Lumu_fetch-incidents) There are 1 events queued ready to process their updates (source: /builds/GOPATH/src/gitlab.xdr.pan.local/xdr/xsoar/server/services/automation/dockercoderunner.go:992)
2023-01-26 22:12:03.6242 debug (Lumu_instance_15_Lumu_fetch-incidents) Setting integration context (source: /builds/GOPATH/src/gitlab.xdr.pan.local/xdr/xsoar/server/services/automation/dockercoderunner.go:992)
2023-01-26 22:12:03.6244 debug (Lumu_instance_15_Lumu_fetch-incidents) Updating integration context with version -1. Sync: True (source: /builds/GOPATH/src/gitlab.xdr.pan.local/xdr/xsoar/server/services/automation/dockercoderunner.go:992)
2023-01-26 22:12:03.6312 debug (Lumu_instance_15_Lumu_fetch-incidents) total inc found: 3, count=Counter({'17af99e0-9b70-11ed-980e-915fb2011ca7': 1, '2bc88020-9b2c-11ed-980e-915fb2011ca7': 1, 'f563af00-9bda-11ed-a0c7-dd6f8e69d343': 1}) last_run={} next_run={'last_fetch': '1091141'} (source: /builds/GOPATH/src/gitlab.xdr.pan.local/xdr/xsoar/server/services/automation/dockercoderunner.go:992)

```




---
[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/lumu)