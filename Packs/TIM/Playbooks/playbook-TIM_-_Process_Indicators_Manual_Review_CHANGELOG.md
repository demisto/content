## [Unreleased]
Fixed typo.

## [20.3.4] - 2020-03-30
#### New Playbook
This playbook tags indicators ingested by feeds that require manual approval. The playbook is triggered due to a job. The indicators are tagged as requiring a manual review. The playbook optionally concludes with creating a new incident that includes all of the indicators that the analyst must review.
To enable the playbook, the indicator query needs to be configured. An example query is a list of the feeds whose ingested indicators should be manually reviewed. For example, sourceBrands:"Feed A" or sourceBrands:"Feed B".