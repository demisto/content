Compute the distance between two sets of coordinates, in miles.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utilities |
| Cortex XSOAR Version | 5.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* Impossible Traveler

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| src_coords | Latitude and Longitude coordinates for the first location.  Required format 1.23,4.56 |
| dest_coords | Latitude and Longitude coordinates for the second location.  Required format 1.23,4.56 |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Geo.Distance | Distance between two sets of coordinates, in miles. | Unknown |
| Geo.Coordinates | List of coordinates used in the calculation. | Unknown |
