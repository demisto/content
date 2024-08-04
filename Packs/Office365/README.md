# Office 365
This pack includes Cortex XSIAM content.
</~XSIAM>

### Native O365 Collector

To create or configure the Office 365 collector, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Ingest-Logs-from-Microsoft-Office-365).

To access the Office 365 Native Collector on your XSIAM tenant:
1.  On the left panel, click **Settings** &rarr; **Data Sources**
2.  At the top-right corner, click **Add Data Source**
3.  Search for **Office 365** and click **Connect**.

<img src="https://raw.githubusercontent.com/demisto/content/33839fe3e0437efec10295ec69e81d8a761bce4f/Packs/Office365/doc_files/Office_365_Collector_Settings.png" width="100" height="100">

**Pay Attention:**
Timestamp ingestion for Office 365 logs is currently available for the following datasets:
* General &rarr; `msft_o365_general_raw`
* Exchange Online &rarr; `msft_o365_exchange_online_raw`
* SharePoint Online &rarr; `msft_o365_sharepoint_online_raw`
* DLP &rarr; `msft_o365_dlp_raw`
</~XSIAM>
