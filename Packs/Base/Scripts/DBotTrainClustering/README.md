This script helps organizes and groups incidents based on their similarities using clustering algorithms.
Clustering is a technique used to group data points (in this case, incidents) that are similar to each other into clusters.
Used to automatically categorize a large number of incidents into meaningful groups.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | ml |
| Cortex XSOAR Version | 6.2.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| fieldsForClustering | Comma-separated list of incident fields to take into account when training the clustering. |
| fieldForClusterName | Incident field that represents the family name for each cluster created. The model determines how many incidents in the cluster have the same value in the fieldForClusterName field. The largest numbers of incidents with the same value determine the cluster name. |
| fromDate | The start date by which to filter incidents. Date format will be the same as in the incidents query page, for example, "3 days ago", ""2019-01-01T00:00:00 \+0200"\). |
| toDate | The end date by which to filter incidents. Date format will be the same as in the incidents query page, for example, "3 days ago", ""2019-01-01T00:00:00 \+0200"\). |
| limit | The maximum number of incidents to query. |
| query | Argument for the query. |
| minNumberofIncidentPerCluster | Minimum number of incidents a cluster should contain for it to be retained. |
| modelName | Name of the model. |
| storeModel | Whether to store the model in the system. |
| minHomogeneityCluster | Keep samples in the cluster when the family ratio is above this number. Will be effective only if fieldForClusterName is given. |
| overrideExistingModel | Whether to override the existing model if a model with the same name exists. Default is "False". |
| type | Type of incident to train the model on. If empty, will consider all types. |
| maxRatioOfMissingValue | If a field has a higher missing value than this ratio it will be removed. |
| debug | Whether to return more information about the clustering. Default is "False". |
| forceRetrain | Whether to re-train the model in any cases. Default is "False". |
| modelExpiration | Period of time \(in hours\) before retraining the model. Default is "24". |
| modelHidden | Whether to hide the model in the ML page. |
| searchQuery | Search query input from the dashboard. |
| fieldsToDisplay | Comma-separated list of additional incident fields to display, but which will not be taken into account when computing similarity. |
| numberOfFeaturesPerField | Number of features per field. |
| analyzer | Whether the feature should be made of word or character n-grams. Possible values: "char" and "word". |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotTrainClustering | The clustering data in JSON format. | String |
