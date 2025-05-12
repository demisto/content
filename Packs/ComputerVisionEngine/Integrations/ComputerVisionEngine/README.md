
### yolo-coco-process-image

***
Detect objects on an picture using the yolo-coco ML.

#### Base Command

`yolo-coco-process-image`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entryid | Image EntryID. | Required |
| confidence | minimum probability to filter weak detections. Default is 0.5. | Optional |
| threshold | threshold when applying non-maxima suppression. Default is 0.3. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ComputerVision | Unknown | The key holds down the information about detected objects in the picture. |
