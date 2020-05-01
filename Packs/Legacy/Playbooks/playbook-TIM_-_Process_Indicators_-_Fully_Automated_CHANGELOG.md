## [Unreleased]
Added conditional tasks to check for result scores. 

## [20.3.4] - 2020-03-30
#### New Playbook
This playbook tags indicators ingested from high reliability feeds. The playbook is triggered due to a Cortex XSOAR job. The indicators are tagged as approved_white, approved_black, approved_watchlist. The tagged indicators will be ready for consumption for 3rd party systems such as SIEM, EDR etc.