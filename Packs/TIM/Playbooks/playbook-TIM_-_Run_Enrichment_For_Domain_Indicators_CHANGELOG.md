## [Unreleased]
Fixed input name.

## [20.3.4] - 2020-03-30
#### New Playbook
This playbook processes indicators by enriching indicators based on the indicator feed's reputation, as specified in the playbook inputs. This playbook needs to be used with caution as it might use up the user enrichment integration's API license when running enrichment for large amounts of indicators.