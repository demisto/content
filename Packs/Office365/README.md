# Office 365
This pack includes Cortex XSIAM content.
</~XSIAM>

### XDRC (XDR Collector)
In order to use the collector, use the XDRC (XDR Collector).

To create or configure the Office 365 collector, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Ingest-Logs-from-Microsoft-Office-365).

To access the Office 365 XDRC on your XSIAM tenant:
1.  On the left panel, click **Settings** &rarr; **Data Sources**
2.  At the top-right corner, click **Add Data Source**
3.  Search for **Office 365** and click **Connect**.

**Pay Attention:**
Timestamp ingestion for Office 365 logs is currently available for the following datasets:
* General &rarr; `msft_o365_general_raw`
* Exchange Online &rarr; `msft_o365_exchange_online_raw`
* SharePoint Online &rarr; `msft_o365_sharepoint_online_raw`
* DLP &rarr; `msft_o365_dlp_raw`
</~XSIAM>
