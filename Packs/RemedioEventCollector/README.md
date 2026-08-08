<~XSIAM>

## Overview

Remedio (Gytpol) is a device misconfiguration remediation platform. This pack fetches active misconfigurations from the Remedio Customer API and ingests them into the Cortex XSIAM data lake.

### This pack includes

- Collection of active, remediable misconfiguration events from Remedio.

## Supported Event Types

- Active misconfigurations from the `POST /misconfigurations` Customer API endpoint, stored in the `remedio_misconfigurations_raw` dataset.

## Enabling Remedio Event Collector

To configure the Remedio Event Collector to receive misconfiguration events:

1. Make sure you have the Remedio Event Collector pack installed on your Cortex XSIAM tenant.
2. Go to **Settings** &rarr; **Configurations** &rarr; **Automation & Feed Integrations**.
3. In the search bar, type **Remedio** and click **+ Add instance**.
4. Set the **Server URL** to your Remedio tenant (for example, `https://acme.gytpol.com`).
5. Set the **API Key** generated from the Remedio portal (**Settings** &rarr; **API Keys**) with read access to the Customer API.
6. Optionally set **Maximum misconfigurations per fetch**; leave empty to fetch all.
7. Click **Test** to validate the connection, then **Done**.

</~XSIAM>
