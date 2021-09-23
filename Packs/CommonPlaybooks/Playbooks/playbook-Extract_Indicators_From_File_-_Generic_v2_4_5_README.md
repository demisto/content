Extracts indicators from a file.
Supported file types:
- CSV
- PDF
- TXT
- HTM, HTML
- DOC, DOCX
- PPT
- PPTX
- RTF
- XLS
- XLSX
- XML

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* Set
* ExtractIndicatorsFromTextFile
* ConvertFile
* ReadPDFFileV2
* ExtractIndicatorsFromWordFile

### Commands
* image-ocr-extract-text
* rasterize-pdf

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| File | The file from which to extract indicators. | File.None | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Domain.Name | Extracted domains. | unknown |
| Account.Email.Address | Extracted emails addresses. | unknown |
| File.MD5 | Extracted MD5 hash. | unknown |
| File.SHA1 | Extracted SHA1 hash. | unknown |
| File.SHA256 | Extracted SHA256 hash. | unknown |
| IP.Address | Extracted IP addresses. | unknown |
| File.Text | The text or images extracted from the PDF file. | unknown |
| File.Producer | The PDF file producer. | unknown |
| File.Title | The title of the PDF file. | unknown |
| File.xap | The xap of the PDF file. | unknown |
| File.Author | The author of the file. | unknown |
| File.dc | The dc of the file. | unknown |
| File.xapmm | The xapmm of the file. | unknown |
| File.ModDate | The ModDate of the file. | unknown |
| File.CreationDate | The CreationDate of the file. | unknown |
| File.Pages | Number of pages in file. | unknown |
| URL.Data | List of URLs that were extracted from the file. | unknown |

## Playbook Image
---
![Extract Indicators From File - Generic v2](https://raw.githubusercontent.com/demisto/content/Enrichment_for_extract_indicators_playbook_v2/Packs/CommonPlaybooks/doc_files/Extract_Indicators_From_File_-_Generic_v2.png)
