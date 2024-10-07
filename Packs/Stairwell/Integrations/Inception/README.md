Use the Stairwell Inception integration to enrich data in XSOAR using Stairwell's knowledge and perform automated variant discovery.

Not a customer and interested in signing up? You can request access [here](https://stairwell.com/contact/).

## Generate required API key

Follow these steps for a self-deployed configuration.

1. Access the Inception web UI and generate a API/CLI token [here](https://app.stairwell.com/dashboard?open-modal=auth-token).
2. Copy your API token for the integration configuration usage.

## Configure Stairwell Inception in Cortex


| **Parameter** | **Required** |
| --- | --- |
| API Key | True |
| Use system proxy settings | False |
| Trust any certificate (not secure) | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### inception-file-enrichment
***
Enrich files using file hash (MD5, SHA1, SHA256) with Stairwell's knowledge.


#### Base Command

`inception-file-enrichment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fileHash | File hash (MD5, SHA1, SHA256) to lookup. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Inception.File_Details | Dict | Raw JSON output from API | 


#### Command Example
```!inception-file-enrichment fileHash=9fe1ac46f0cdebf03156a6232d771c14559f8daf```

#### Context Example
```json
{
	"inception": {
		"file_details": {
			"type": "file",
			"id": "e7762f90024c5366807c7c145d3456f0ac3be086c0ec3557427d3c2c10a2052d",
			"links": {
				"self": "/api/v3/files/e7762f90024c5366807c7c145d3456f0ac3be086c0ec3557427d3c2c10a2052d"
			},
			"data": {
				"attributes": {
					"md5": "00ddbafe247c891eed36bd74f66f936b",
					"sha1": "9fe1ac46f0cdebf03156a6232d771c14559f8daf",
					"sha256": "e7762f90024c5366807c7c145d3456f0ac3be086c0ec3557427d3c2c10a2052d",
					"size": 118024,
					"creation_date": 1653722032,
					"last_analysis_results": {
						"ClamAV": {
							"category": "undetected",
							"engine_name": "ClamAV",
							"result": "undetected"
						},
						"Engine2": {
							"category": "malicious",
							"engine_name": "Engine2",
							"result": "Trojan/Win.Hermeticwiper"
						}
					},
					"last_analysis_stats": {
						"harmless": 1,
						"malicious": 1
					},
					"names": [
						"C:\\GimmeCreds.dll"
					],
					"meaningful_name": "C:\\GimmeCreds.dll",
					"type_description": "EXE",
					"crowdsourced_yara_results": [{
							"rule_name": "wiper_HermeticWiper"
						},
						{
							"rule_name": "MAL_HERMETIC_WIPER"
						}
					],
					"inception": {
						"environments": [{
							"environment_id": {
								"id": "AAAAAA-BBBBBB-CCCCCC-DDDDDDD"
							}
						}],
						"assets": [{
							"asset_id": {
								"id": "DDDDDD-CCCCCC-BBBBBB-AAAAAAA"
							},
							"name": "WORKGROUP\\IDABEAR"
						}]
					},
					"magic": "EXE",
					"imphash": "fe4a2284122da348258c83ef437fbd7b",
					"ssdeep": "1536:WBOoa7Nn54urilmw9BgjKu1sPPxaS4NOyqC:WBOoa7P4xlPwV16PkS4NVqC"
				}
			}
		}
	}
}
```

#### Human Readable Output

># Stairwell Inception
>MD5: 00ddbafe247c891eed36bd74f66f936b
>SHA256: e7762f90024c5366807c7c145d3456f0ac3be086c0ec3557427d3c2c10a2052d
>Seen Assets: 1
>Matching YARA Intel: wiper_HermeticWiper,MAL_HERMETIC_WIPER
>### AV Scanning Results
>Engine Name|Result
>---|---
>ClamAV|undetected
>Engine2|Trojan/Win.Hermeticwiper

### inception-variant-discovery
***
Hunt for variants using a SHA256 across all files you have access to, including your environments and Stairwell's malware feeds.


#### Base Command

`inception-variant-discovery`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha256 | SHA256 of file to hunt for variants on. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Inception.Variants | Dict | Raw JSON output from API | 


#### Command Example
```!inception-variant-discovery sha256=30e27357b7b773b226d4ee638e17b19b954226d197b0781822859269a5c22b4d```

#### Context Example
```json
{
	"inception": {
		"variants": {
			"name": "variants/30e27357b7b773b226d4ee638e17b19b954226d197b0781822859269a5c22b4d",
			"variants": [{
					"similarity": 1,
					"sha256": "e1a00d8923bac6f863c262236f15eb60d80571f8b31e7220c4b2912fae7e9a14"
				},
				{
					"similarity": 0.9875,
					"sha256": "d2a00d8923bac6f863c262236f15eb60d80571f8b31e7220c4b2912fae7e9a12"
				}
			],
			"variant_count": 2,
			"original_object": "30e27357b7b773b226d4ee638e17b19b954226d197b0781822859269a5c22b4d"
		}
	}
}
```

#### Human Readable Output

>### File Variants Discovered
>|sha256|similarity|
>|---|---|
>| e1a00d8923bac6f863c262236f15eb60d80571f8b31e7220c4b2912fae7e9a14 | 1 |
>| d2a00d8923bac6f863c262236f15eb60d80571f8b31e7220c4b2912fae7e9a12 | 0.9875 |