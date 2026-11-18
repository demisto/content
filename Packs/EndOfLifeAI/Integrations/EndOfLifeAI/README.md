Look up end-of-life and end-of-support dates, EOL risk scores and CISA KEV exposure for software and hardware products. endoflife.ai is an independent service, and each date is labelled with its source.

## Configure endoflife.ai in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The base URL of the endoflife.ai API. | True |
| API Key | The endoflife.ai API key. It is sent in the X-API-Key header of every request. A free API key is available at https://endoflife.ai/api#free-key. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### endoflife-ai-product-get

***
Returns the lifecycle of a product: each tracked version with its end-of-life date, support status, EOL risk score and the source of the date.

#### Base Command

`endoflife-ai-product-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| product | The product slug as endoflife.ai tracks it, for example nodejs, python or windows-server. When the slug is not found, the command lists the closest tracked slugs. | Required |
| limit | The maximum number of versions to return, in the order the API returns them. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EndOfLifeAI.Product.product | String | The slug of the tracked product. |
| EndOfLifeAI.Product.alias_of | String | Present only when the slug sent is an alias of a tracked product. The slug as sent. |
| EndOfLifeAI.Product.version_count | Number | The number of versions that endoflife.ai tracks for the product. |
| EndOfLifeAI.Product.product_url | String | The product page on endoflife.ai. |
| EndOfLifeAI.Product.versions.product | String | The slug of the tracked product the answer is for. |
| EndOfLifeAI.Product.versions.version | String | The release cycle the answer is for. |
| EndOfLifeAI.Product.versions.latest_release | String | The latest release published on this release cycle. |
| EndOfLifeAI.Product.versions.release_date | Date | The date the release cycle was first released. |
| EndOfLifeAI.Product.versions.status | String | The lifecycle status. Possible values are active, warn (within 180 days of end of life, still supported), eol and unknown (the published date could not be read). |
| EndOfLifeAI.Product.versions.is_supported | Boolean | Whether the vendor still ships fixes today. True for the status active or warn. |
| EndOfLifeAI.Product.versions.eol_date | Date | The end-of-life date. Empty when the vendor has published no date. |
| EndOfLifeAI.Product.versions.eol_boolean | Boolean | Used when no end-of-life date is published. True means end of life with no exact date, false means not end of life. |
| EndOfLifeAI.Product.versions.eol_date_precision | String | The precision of eol_date. Possible values are day, month and quarter. A month or quarter date is stored as the last day of the period. |
| EndOfLifeAI.Product.versions.date_precision_note | String | Present only when a date has month or quarter precision. Says which date and which period it stands for. |
| EndOfLifeAI.Product.versions.days_until_eol | Number | The number of days until eol_date. Empty when the version is past end of life or has no date. |
| EndOfLifeAI.Product.versions.days_past_eol | Number | The number of days since eol_date. Empty when the version has not reached end of life or has no date. |
| EndOfLifeAI.Product.versions.support_date | Date | The end of the vendor's active (full or standard) support phase, where one is published. |
| EndOfLifeAI.Product.versions.support_date_precision | String | The precision of support_date. Possible values are day, month and quarter. |
| EndOfLifeAI.Product.versions.extended_support_available | Boolean | False when endoflife.ai records that no extended support option exists for the product. True otherwise. |
| EndOfLifeAI.Product.versions.extended_support_date | Date | The end of the vendor's own extended or paid support phase, where one is published. |
| EndOfLifeAI.Product.versions.extended_support_date_precision | String | The precision of extended_support_date. Possible values are day, month and quarter. |
| EndOfLifeAI.Product.versions.extended_support_ships_fixes | Boolean | False when the vendor ships no fixes in the phase that ends on extended_support_date. Empty when no such statement is recorded. |
| EndOfLifeAI.Product.versions.score | Number | The EOL risk score, from 0 to 100. A higher score means a higher risk. |
| EndOfLifeAI.Product.versions.grade | String | The letter grade of the EOL risk score. |
| EndOfLifeAI.Product.versions.grade_label | String | The label of the grade, for example Critical risk. |
| EndOfLifeAI.Product.versions.band | String | The risk band of the EOL risk score, for example Critical. |
| EndOfLifeAI.Product.versions.factors.eol_recency | Number | The end-of-life recency component of the EOL risk score. |
| EndOfLifeAI.Product.versions.factors.attack_surface | Number | The attack surface component of the EOL risk score. |
| EndOfLifeAI.Product.versions.factors.cisa_kev_exposure | Number | The CISA Known Exploited Vulnerabilities (KEV) component of the EOL risk score. |
| EndOfLifeAI.Product.versions.factors.extended_support | Number | The extended support component of the EOL risk score. |
| EndOfLifeAI.Product.versions.kev_exposed | Boolean | Whether the factors.cisa_kev_exposure component is above zero. The integration derives this value from that component. |
| EndOfLifeAI.Product.versions.cpe | String | The verified CPE 2.3 identifiers of the product. Empty when none has been verified. |
| EndOfLifeAI.Product.versions.cpe_scope | String | Present only for hardware products whose versions are models. The value model means cpe lists the identifiers of this model only. |
| EndOfLifeAI.Product.versions.cpe_note | String | Present only when cpe_scope is model and no CPE names this model. |
| EndOfLifeAI.Product.versions.purl | String | The package URLs that resolve a software bill of materials component to this product. Empty when none is known. |
| EndOfLifeAI.Product.versions.eol_date_source | String | Where eol_date comes from. Possible values are vendor-override, vendor-fetched, vendor-verified, custom, upstream and discrepancy. |
| EndOfLifeAI.Product.versions.eol_date_source_url | String | The vendor page or record that the eol_date_source label rests on. |
| EndOfLifeAI.Product.versions.eol_date_verified_at | Date | The date the eol_date_source label was last established. |
| EndOfLifeAI.Product.versions.eol_date_status | String | The state of the source check. Possible values are ok, fallback, mismatch, human, upstream and custom. |
| EndOfLifeAI.Product.versions.eol_date_agreement | Number | The number of independent source classes that agree with eol_date. |
| EndOfLifeAI.Product.versions.eol_date_confidence | String | The confidence label of eol_date. Possible values are high, medium and low. |
| EndOfLifeAI.Product.versions.data_source | String | The URL that the served eol_date was read from. |
| EndOfLifeAI.Product.versions.score_card_url | String | The score card page of this version on endoflife.ai. |
| EndOfLifeAI.Product.versions.product_url | String | The product page on endoflife.ai. |
| EndOfLifeAI.Product.versions.methodology_url | String | The page that describes how the EOL risk score is calculated. |
| EndOfLifeAI.Product.versions.generated_at | Date | The time the API generated the answer. |

### endoflife-ai-version-get

***
Returns the lifecycle status and EOL risk score of one product version. A patch or build number is resolved to its release line.

#### Base Command

`endoflife-ai-version-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| product | The product slug as endoflife.ai tracks it, for example nodejs, python or windows-server. When the slug is not found, the command lists the closest tracked slugs. | Required |
| version | The version, release line or hardware model to check, for example 18 or 18.19.0. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EndOfLifeAI.Version.product | String | The slug of the tracked product the answer is for. |
| EndOfLifeAI.Version.version | String | The release cycle the answer is for. |
| EndOfLifeAI.Version.alias_of | String | Present only when the slug sent is an alias of a tracked product. The slug as sent. |
| EndOfLifeAI.Version.requested_version | String | Present only when the version sent was resolved to its release line or model. The version as sent. |
| EndOfLifeAI.Version.version_matched_by | String | Present only when the version was not matched exactly. Possible values are release-line and model-name. |
| EndOfLifeAI.Version.latest_release | String | The latest release published on this release cycle. |
| EndOfLifeAI.Version.release_date | Date | The date the release cycle was first released. |
| EndOfLifeAI.Version.status | String | The lifecycle status. Possible values are active, warn (within 180 days of end of life, still supported), eol and unknown (the published date could not be read). |
| EndOfLifeAI.Version.is_supported | Boolean | Whether the vendor still ships fixes today. True for the status active or warn. |
| EndOfLifeAI.Version.eol_date | Date | The end-of-life date. Empty when the vendor has published no date. |
| EndOfLifeAI.Version.eol_boolean | Boolean | Used when no end-of-life date is published. True means end of life with no exact date, false means not end of life. |
| EndOfLifeAI.Version.eol_date_precision | String | The precision of eol_date. Possible values are day, month and quarter. A month or quarter date is stored as the last day of the period. |
| EndOfLifeAI.Version.date_precision_note | String | Present only when a date has month or quarter precision. Says which date and which period it stands for. |
| EndOfLifeAI.Version.days_until_eol | Number | The number of days until eol_date. Empty when the version is past end of life or has no date. |
| EndOfLifeAI.Version.days_past_eol | Number | The number of days since eol_date. Empty when the version has not reached end of life or has no date. |
| EndOfLifeAI.Version.support_date | Date | The end of the vendor's active (full or standard) support phase, where one is published. |
| EndOfLifeAI.Version.support_date_precision | String | The precision of support_date. Possible values are day, month and quarter. |
| EndOfLifeAI.Version.extended_support_available | Boolean | False when endoflife.ai records that no extended support option exists for the product. True otherwise. |
| EndOfLifeAI.Version.extended_support_date | Date | The end of the vendor's own extended or paid support phase, where one is published. |
| EndOfLifeAI.Version.extended_support_date_precision | String | The precision of extended_support_date. Possible values are day, month and quarter. |
| EndOfLifeAI.Version.extended_support_ships_fixes | Boolean | False when the vendor ships no fixes in the phase that ends on extended_support_date. Empty when no such statement is recorded. |
| EndOfLifeAI.Version.score | Number | The EOL risk score, from 0 to 100. A higher score means a higher risk. |
| EndOfLifeAI.Version.grade | String | The letter grade of the EOL risk score. |
| EndOfLifeAI.Version.grade_label | String | The label of the grade, for example Critical risk. |
| EndOfLifeAI.Version.band | String | The risk band of the EOL risk score, for example Critical. |
| EndOfLifeAI.Version.factors.eol_recency | Number | The end-of-life recency component of the EOL risk score. |
| EndOfLifeAI.Version.factors.attack_surface | Number | The attack surface component of the EOL risk score. |
| EndOfLifeAI.Version.factors.cisa_kev_exposure | Number | The CISA Known Exploited Vulnerabilities (KEV) component of the EOL risk score. |
| EndOfLifeAI.Version.factors.extended_support | Number | The extended support component of the EOL risk score. |
| EndOfLifeAI.Version.kev_exposed | Boolean | Whether the factors.cisa_kev_exposure component is above zero. The integration derives this value from that component. |
| EndOfLifeAI.Version.cpe | String | The verified CPE 2.3 identifiers of the product. Empty when none has been verified. |
| EndOfLifeAI.Version.cpe_scope | String | Present only for hardware products whose versions are models. The value model means cpe lists the identifiers of this model only. |
| EndOfLifeAI.Version.cpe_note | String | Present only when cpe_scope is model and no CPE names this model. |
| EndOfLifeAI.Version.purl | String | The package URLs that resolve a software bill of materials component to this product. Empty when none is known. |
| EndOfLifeAI.Version.eol_date_source | String | Where eol_date comes from. Possible values are vendor-override, vendor-fetched, vendor-verified, custom, upstream and discrepancy. |
| EndOfLifeAI.Version.eol_date_source_url | String | The vendor page or record that the eol_date_source label rests on. |
| EndOfLifeAI.Version.eol_date_verified_at | Date | The date the eol_date_source label was last established. |
| EndOfLifeAI.Version.eol_date_status | String | The state of the source check. Possible values are ok, fallback, mismatch, human, upstream and custom. |
| EndOfLifeAI.Version.eol_date_agreement | Number | The number of independent source classes that agree with eol_date. |
| EndOfLifeAI.Version.eol_date_confidence | String | The confidence label of eol_date. Possible values are high, medium and low. |
| EndOfLifeAI.Version.data_source | String | The URL that the served eol_date was read from. |
| EndOfLifeAI.Version.score_card_url | String | The score card page of this version on endoflife.ai. |
| EndOfLifeAI.Version.product_url | String | The product page on endoflife.ai. |
| EndOfLifeAI.Version.methodology_url | String | The page that describes how the EOL risk score is calculated. |
| EndOfLifeAI.Version.generated_at | Date | The time the API generated the answer. |

### endoflife-ai-version-batch-get

***
Returns the lifecycle status and EOL risk score of each product version in a list. Entries that cannot be resolved are returned separately with the reason.

#### Base Command

`endoflife-ai-version-batch-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| products | A comma-separated list of product:version pairs, for example nodejs:18,python:3.8,ubuntu:20.04. An entry without a version returns the highest-risk version of that product. | Required |
| chunk_size | The number of pairs to send in one API request. A free API key accepts 5 pairs per request. Each request counts against the daily request allowance of the API key. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EndOfLifeAI.Version.product | String | The slug of the tracked product the answer is for. |
| EndOfLifeAI.Version.version | String | The release cycle the answer is for. |
| EndOfLifeAI.Version.requested_version | String | Present only when the version sent was resolved to its release line or model. The version as sent. |
| EndOfLifeAI.Version.version_matched_by | String | Present only when the version was not matched exactly. Possible values are release-line and model-name. |
| EndOfLifeAI.Version.latest_release | String | The latest release published on this release cycle. |
| EndOfLifeAI.Version.release_date | Date | The date the release cycle was first released. |
| EndOfLifeAI.Version.status | String | The lifecycle status. Possible values are active, warn (within 180 days of end of life, still supported), eol and unknown (the published date could not be read). |
| EndOfLifeAI.Version.is_supported | Boolean | Whether the vendor still ships fixes today. True for the status active or warn. |
| EndOfLifeAI.Version.eol_date | Date | The end-of-life date. Empty when the vendor has published no date. |
| EndOfLifeAI.Version.eol_boolean | Boolean | Used when no end-of-life date is published. True means end of life with no exact date, false means not end of life. |
| EndOfLifeAI.Version.eol_date_precision | String | The precision of eol_date. Possible values are day, month and quarter. A month or quarter date is stored as the last day of the period. |
| EndOfLifeAI.Version.date_precision_note | String | Present only when a date has month or quarter precision. Says which date and which period it stands for. |
| EndOfLifeAI.Version.days_until_eol | Number | The number of days until eol_date. Empty when the version is past end of life or has no date. |
| EndOfLifeAI.Version.days_past_eol | Number | The number of days since eol_date. Empty when the version has not reached end of life or has no date. |
| EndOfLifeAI.Version.support_date | Date | The end of the vendor's active (full or standard) support phase, where one is published. |
| EndOfLifeAI.Version.support_date_precision | String | The precision of support_date. Possible values are day, month and quarter. |
| EndOfLifeAI.Version.extended_support_available | Boolean | False when endoflife.ai records that no extended support option exists for the product. True otherwise. |
| EndOfLifeAI.Version.extended_support_date | Date | The end of the vendor's own extended or paid support phase, where one is published. |
| EndOfLifeAI.Version.extended_support_date_precision | String | The precision of extended_support_date. Possible values are day, month and quarter. |
| EndOfLifeAI.Version.extended_support_ships_fixes | Boolean | False when the vendor ships no fixes in the phase that ends on extended_support_date. Empty when no such statement is recorded. |
| EndOfLifeAI.Version.score | Number | The EOL risk score, from 0 to 100. A higher score means a higher risk. |
| EndOfLifeAI.Version.grade | String | The letter grade of the EOL risk score. |
| EndOfLifeAI.Version.grade_label | String | The label of the grade, for example Critical risk. |
| EndOfLifeAI.Version.band | String | The risk band of the EOL risk score, for example Critical. |
| EndOfLifeAI.Version.factors.eol_recency | Number | The end-of-life recency component of the EOL risk score. |
| EndOfLifeAI.Version.factors.attack_surface | Number | The attack surface component of the EOL risk score. |
| EndOfLifeAI.Version.factors.cisa_kev_exposure | Number | The CISA Known Exploited Vulnerabilities (KEV) component of the EOL risk score. |
| EndOfLifeAI.Version.factors.extended_support | Number | The extended support component of the EOL risk score. |
| EndOfLifeAI.Version.kev_exposed | Boolean | Whether the factors.cisa_kev_exposure component is above zero. The integration derives this value from that component. |
| EndOfLifeAI.Version.cpe | String | The verified CPE 2.3 identifiers of the product. Empty when none has been verified. |
| EndOfLifeAI.Version.cpe_scope | String | Present only for hardware products whose versions are models. The value model means cpe lists the identifiers of this model only. |
| EndOfLifeAI.Version.cpe_note | String | Present only when cpe_scope is model and no CPE names this model. |
| EndOfLifeAI.Version.purl | String | The package URLs that resolve a software bill of materials component to this product. Empty when none is known. |
| EndOfLifeAI.Version.eol_date_source | String | Where eol_date comes from. Possible values are vendor-override, vendor-fetched, vendor-verified, custom, upstream and discrepancy. |
| EndOfLifeAI.Version.eol_date_source_url | String | The vendor page or record that the eol_date_source label rests on. |
| EndOfLifeAI.Version.eol_date_verified_at | Date | The date the eol_date_source label was last established. |
| EndOfLifeAI.Version.eol_date_status | String | The state of the source check. Possible values are ok, fallback, mismatch, human, upstream and custom. |
| EndOfLifeAI.Version.eol_date_agreement | Number | The number of independent source classes that agree with eol_date. |
| EndOfLifeAI.Version.eol_date_confidence | String | The confidence label of eol_date. Possible values are high, medium and low. |
| EndOfLifeAI.Version.data_source | String | The URL that the served eol_date was read from. |
| EndOfLifeAI.Version.score_card_url | String | The score card page of this version on endoflife.ai. |
| EndOfLifeAI.Version.product_url | String | The product page on endoflife.ai. |
| EndOfLifeAI.Version.methodology_url | String | The page that describes how the EOL risk score is calculated. |
| EndOfLifeAI.Version.generated_at | Date | The time the API generated the answer. |
| EndOfLifeAI.BatchError.product | String | The product slug of an entry that was not resolved, as sent. |
| EndOfLifeAI.BatchError.version | String | The version of an entry that was not resolved, as sent. |
| EndOfLifeAI.BatchError.error | String | Why the entry was not resolved, for example Product not found or Version not found. |
| EndOfLifeAI.BatchError.reason | String | More detail about the error, when the API gives one. |
| EndOfLifeAI.BatchError.candidates | String | The release cycles or models the entry could refer to, when it is ambiguous. |
| EndOfLifeAI.BatchError.cycle | String | The release line of a version that is above the last published release of that line. |
| EndOfLifeAI.BatchError.last_published | String | The last published release of the release line named in cycle. |
