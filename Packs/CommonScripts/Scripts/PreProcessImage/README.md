This script pre-processes an image file by preforming one of the following actions:

- original - return the original image (the default action).
- sharpen - process that emphasizes the edges in an image to make it appear clearer and more focused.
- grayscale - convert the image to black, white, and gray colors, in which gray has multiple levels (the value of each pixel represents only the intensity information of the light).

Each action can also resize the image when given the width and height.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.8.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| action | The action to perform on the image. |
| image_resize_width | The desired width for resizing the image to. |
| image_resize_height | The desired height for resizing the image to. |
| file_entry_id | The entryID of the file to process. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PreProcessImage.file_entry_id_new | The entryID of the created file. | String |
| PreProcessImage.action | The action that was performed. | String |

## Script Examples


### Example command

```!PreProcessImage action=sharpened file_entry_id=<file_entry_id_example> image_resize_height=1700```

### Context Example

```json
{
    "File": {
        "EntryID": "<EntryIDExample>",
        "Info": "image/jpeg",
        "MD5": "<MD5Example>",
        "Name": "sharpened_IMG_3092",
        "SHA1": "<SHA1Example>",
        "SHA256": "<SHA256Example>",
        "SHA512": "<SHA512Example>",
        "SSDeep": "24576:<SSDeepExample>",
        "Size": 795730,
        "Type": "JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 3024x1700, components 3"
    }
}
```

### Example command

```!PreProcessImage action=original file_entry_id=<file_entry_id_example> image_resize_height=1700 image_resize_width=500```

### Context Example

```json
{
    "File": {
        "EntryID": "<EntryIDExample>",
        "Info": "image/jpeg",
        "MD5": "<MD5Example>",
        "Name": "original_IMG_3092",
        "SHA1": "<SHA1Example>",
        "SHA256": "<SHA256Example>",
        "SHA512": "<SHA512Example>",
        "SSDeep": "3072:<SSDeepExample>",
        "Size": 186613,
        "Type": "JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 500x1700, components 3"
    }
}
```
