This playbook automates the collection and forensic analysis of RDP sessions cache data by collecting the cache files and convert it to an image, extract readable text from the image and build IOC's from text and finally enrich any extracted indicators for further hunting

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Retrieve File from Endpoint - Generic V3
* Set list of indicator types
* Threat Hunting - Generic
* Set RDP Bitmap Cache Overall Score

### Integrations

* Rasterize

### Scripts

* ConvertFile
* SetGridField
* BMCTool
* StringSimilarity
* PreProcessImage
* Set

### Commands

* setIncident
* rasterize-image
* rasterize-pdf
* extractIndicators
* xdr-file-retrieve
* splunk-search
* image-ocr-extract-text

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ShouldCollectRDPCache | When set to True, will use XDR to get RDP cache files from the endpoints, but set to False will try and use existing cache file from context | false | Required |
| EndpointIDs | A comma seperated list of endpoint ID's to retrieve cache files from |  | Optional |
| FilePath | The path of the file to retrieve.<br/>For example:<br/>C:\\users\\folder\\file.txt | C:\Users\administrator\AppData\Local\Microsoft\Terminal Server Client\Cache\ | Optional |
| Hostname | Hostname of the machine on which the file is located for PS remote it can also be an IP address. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![RDP Bitmap Cache - Detect and Hunt](../doc_files/RDP_Bitmap_Cache_-_Detect_and_Hunt.png)
