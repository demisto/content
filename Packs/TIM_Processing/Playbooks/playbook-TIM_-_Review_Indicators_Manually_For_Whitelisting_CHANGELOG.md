## [Unreleased]


## [20.5.0] - 2020-05-12
#### New Playbook
This playbook helps analysts manage the manual process of whitelisting indicators from cloud providers, apps, services etc . The playbook indicator query is set to search for indicators that have the 'whitelist_review' tag. The playbooks layout displays all of the related indicators in the summary page. While reviewing the indicators, the analyst can go to the summary page and tag the indicators accordingly with tags such as, 'approved_black', 'approved_white', etc. Once the analyst completes the review, the playbook can optionally send an email with a list of changes done by the analyst which haven't been approved. Once complete, the playbook removes the 'whitelist review' tag from the indicators.