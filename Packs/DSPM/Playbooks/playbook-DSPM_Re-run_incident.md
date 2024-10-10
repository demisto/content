# DSPM Re-run incident

## Overview
This playbook will check the incident list and re-run the incidents which exceeded the time limit user provided.

## Key Features

- Re-run the incident so that user can take appropriate action on a risk.

## Steps

1. **Start**:
   - The playbook start.

2. **Re-run incident**:
   - Parse the incident list and re-run all the incidents which exceeded the time limit user provided.

## Key Commands and Scripts Used

- `DSPMRerunIncidents`: Check the incidents in the list and compare the time from the user provided time. If time exceeds then re-run that incident and delete that incident from the incident list.


## Script Descriptions and Usage

### 1. `DSPMRerunIncidents` 
- **Description**: This script re-run the incidents which excceded the given time limit.
- **Usage**: Provide the time_duration to compare it with the incident created time.