This script pre-process an image file by preforming one of the actions:
- original - return the original image.
- sharpen - process that emphasizes the edges in an image to make it appear clearer and more focused.
- grayscale - convert the image to black, white, and gray colors, in which gray has multiple levels (the value of each pixel represents only the intensity information of the light).

Each action can also resize the image when given width and height.

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
| PreProcessImage.action | The action that were performed,. | String |

## Script Examples

### Example command

```!PreProcessImage action=grayscale file_entry_id=4947@5cdf2c6b-3e48-4006-8b8e-bd82410a1943```

### Context Example

```json
{
    "File": {
        "EntryID": "5026@5cdf2c6b-3e48-4006-8b8e-bd82410a1943",
        "Info": "image/jpeg",
        "MD5": "6033cbe2c5a60547321922bac69a8285",
        "Name": "grayscale_grayscale_IMG_3092",
        "SHA1": "21263104b0c3aad7f22e69e422ddabad78a34251",
        "SHA256": "aaddff85b2b6e291113f2c5db35be020e73a829653ec49b0042fcd15005f816c",
        "SHA512": "5fae862e561ac323d127f01ab119ba9be79ad0257bf23f53d2af56d20733206147714cbeec92696937616c1ddf59d2bd805ec72211693fa659362db0e5422d53",
        "SSDeep": "24576:ByvX3qyFM7aOmu1gfr7Hj8jGkoNQRch1kE9inFihhPEgjUBVS2NSNx46n9i:OXayi7aOmu1gfrP8PoaykE9sFDgjUBV9",
        "Size": 1512471,
        "Type": "JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 3024x4032, components 1"
    }
}
```

### Example command

```!PreProcessImage action=sharpened file_entry_id=4947@5cdf2c6b-3e48-4006-8b8e-bd82410a1943```

### Context Example

```json
{
    "File": {
        "EntryID": "5030@5cdf2c6b-3e48-4006-8b8e-bd82410a1943",
        "Info": "image/jpeg",
        "MD5": "f44fa471c8a8925b1056cb042c41b430",
        "Name": "sharpened_grayscale_IMG_3092",
        "SHA1": "04fd37c1fe3e2136d283011fe87e4d16b28e0794",
        "SHA256": "1d19c442f5c26afbdaa744108da73a2174bda79d423203984e103a48b73f9636",
        "SHA512": "4cdb6a3540f7f9bcea5f2dd99cf9a538b5fb0ae3dd68496b8a128245f182582e22798d9e6cc62b9f6f6302d764fddeb7de5100ee659df585baae9bee37046452",
        "SSDeep": "24576:P6woqTXN8goM9lcgw6tW/XJRWNi4Mx3bBmOJi40+wlaEz0Drlbnpsxrz/qcbtqYi:Pxo46gwpqNi4M11mOkTLQ3lbKxrJI",
        "Size": 1757075,
        "Type": "JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 3024x4032, components 3"
    }
}
```

### Example command

```!PreProcessImage action=grayscale file_entry_id=4947@5cdf2c6b-3e48-4006-8b8e-bd82410a1943 image_resize_width=500```

### Context Example

```json
{
    "File": {
        "EntryID": "5034@5cdf2c6b-3e48-4006-8b8e-bd82410a1943",
        "Info": "image/jpeg",
        "MD5": "5c6e299e2fdd6e776a0a99f9328a7d7e",
        "Name": "grayscale_grayscale_IMG_3092",
        "SHA1": "7afe9a8daebc1c364a60d67cdf8728bdfb59bf5c",
        "SHA256": "b4ea6ce9441a76d89f09ba5f17a1c14b5d891834ad8c94b0acf2562cc3566094",
        "SHA512": "57a36dbefecaf22f91508177139d2d2394b82b3b8affbeeb5018a0ee4fcaf8b01e649d63c453bc5721d8d79d84d1a395c9df66e261094276cf080d22f2369e23",
        "SSDeep": "6144:sDj4MUCh0hHeo9vVqYBA3QiswC7rBkvZmbIag+y2wV/Nuz6fxn2QH4WXQ76dt:GCco9vVqRQewrBKADM/NuGfxRLAWr",
        "Size": 352062,
        "Type": "JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 500x4032, components 1"
    }
}
```

### Example command

```!PreProcessImage action=sharpened file_entry_id=4947@5cdf2c6b-3e48-4006-8b8e-bd82410a1943 image_resize_height=1700```

### Context Example

```json
{
    "File": {
        "EntryID": "5038@5cdf2c6b-3e48-4006-8b8e-bd82410a1943",
        "Info": "image/jpeg",
        "MD5": "23b5db279120ab646f0b28752463b454",
        "Name": "sharpened_grayscale_IMG_3092",
        "SHA1": "9070476a6cbdf66934f2fd5a037593d5b5c3db8c",
        "SHA256": "1bc64494c66c1116413aa8732f8114237ed65a405702b0de2cd42502d631ab00",
        "SHA512": "cb03310021a51f691fa1d951e82bbb0359876e850c0b2b242de73e5df7702e480edf4870d5e44050ece7135e290959137b3f62e0befa64c2bd0fe487d4cc0b83",
        "SSDeep": "24576:cDtUM5RPuEvChrwY6izW0bBmIqq1NpDoq2rXW:VmRPuq+rFzZVT1oq2a",
        "Size": 795730,
        "Type": "JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 3024x1700, components 3"
    }
}
```

### Example command

```!PreProcessImage action=original file_entry_id=4947@5cdf2c6b-3e48-4006-8b8e-bd82410a1943 image_resize_height=1700 image_resize_width=500```

### Context Example

```json
{
    "File": {
        "EntryID": "5042@5cdf2c6b-3e48-4006-8b8e-bd82410a1943",
        "Info": "image/jpeg",
        "MD5": "f2cb7f48442800375afcecaa98e2b61e",
        "Name": "original_grayscale_IMG_3092",
        "SHA1": "3f1c8d37dbd4f5e2435deb7391cb43133761b04e",
        "SHA256": "cff1ba06715d11e921624ec294e8656740473b58ab97b2a498bbaaa0c937582b",
        "SHA512": "5a3513e4846657f531749aa081e438e78b1a534bb20bb3948ccc07b4b306bdf9137d06795a865b28884f38e853cbca19687ec564ee9e5469945c52f942227c78",
        "SSDeep": "3072:EqX3SldG1EgGe5lHZ6NEtLw05LQDM+NMAw1eSzooTCIKZrN33JpiTu4xWlKEI5e2:7+ngVUCLwJZNtwl/2IKxtOioVGLt6",
        "Size": 186613,
        "Type": "JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 500x1700, components 3"
    }
}
```
