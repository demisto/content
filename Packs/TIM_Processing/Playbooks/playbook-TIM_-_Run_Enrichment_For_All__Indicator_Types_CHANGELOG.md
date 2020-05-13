## [Unreleased]
-


## [20.3.4] - 2020-03-30
#### New Playbook
This playbook performs enrichment on indicators
  based on playbook query, as specified in the playbook
  inputs. This playbook needs to be used with caution as it might use up the user
  enrichment integration's API license when running enrichment for large amounts of
  indicators. Example queries can be "tags:example_tag" for indicators with a specific tag. For a specific feed name"
  the query will be "sourceBrands:example_feed". For a specifc reputation the query will be "reputation:None" etc.