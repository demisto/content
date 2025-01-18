import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import os

import cv2
import numpy as np

# The command demisto.command() holds the command sent from the user.
if demisto.command() == 'test-module':
    demisto.results('ok')
    sys.exit(0)

if demisto.command() == 'yolo-coco-process-image':
    args = {}
    args["yolo"] = "/yolo-coco"
    args["confidence"] = demisto.args().get('confidence')
    # https://www.pyimagesearch.com/2014/11/17/non-maximum-suppression-object-detection-python/
    args["threshold"] = demisto.args().get('threshold')

    entry_id = demisto.args().get('entryid')

    coco_file = open(args["yolo"] + "/coco.names")
    coco_objects = coco_file.readlines()

    try:
        file_result = demisto.getFilePath(entry_id)
    except Exception as ex:
        return_error(f"Failed to load file entry with entryid: {entry_id}. Error: {ex}")

    args["image"] = file_result.get("path")
    # load the COCO class labels our YOLO model was trained on
    labelsPath = os.path.sep.join([args["yolo"], "coco.names"])
    os.environ['DISPLAY'] = ':0'
    LABELS = open(labelsPath).read().strip().split("\n")

    # initialize a list of colors to represent each possible class label
    np.random.seed(42)
    COLORS = np.random.randint(0, 255, size=(len(LABELS), 3),
                               dtype="uint8")

    # derive the paths to the YOLO weights and model configuration
    weightsPath = os.path.sep.join([args["yolo"], "yolov3.weights"])
    configPath = os.path.sep.join([args["yolo"], "yolov3.cfg"])

    # load our YOLO object detector trained on COCO dataset (80 classes)
    net = cv2.dnn.readNetFromDarknet(configPath, weightsPath)  # pylint: disable=E1101

    # load our input image and grab its spatial dimensions
    image = cv2.imread(args["image"])  # pylint: disable=E1101
    (H, W) = image.shape[:2]

    # determine only the *output* layer names that we need from YOLO
    ln = net.getLayerNames()
    ln = [ln[i[0] - 1] for i in net.getUnconnectedOutLayers()]  # type: ignore[index]

    # construct a blob from the input image and then perform a forward
    # pass of the YOLO object detector, giving us our bounding boxes and
    # associated probabilities
    blob = cv2.dnn.blobFromImage(image, 1 / 255.0, (416, 416),  # pylint: disable=E1101
                                 swapRB=True, crop=False)
    net.setInput(blob)

    layerOutputs = net.forward(ln)

    # initialize our lists of detected bounding boxes, confidences, and
    # class IDs, respectively
    boxes = []
    confidences = []
    classIDs = []
    output_keys = {}
    output_keys['EntryID'] = entry_id
    output_keys['Method'] = "yolo-coco"
    for i in coco_objects:
        globals()[i] = []
    # loop over each of the layer outputs
    for output in layerOutputs:
        # loop over each of the detections
        for detection in output:
            # extract the class ID and confidence (i.e., probability) of
            # the current object detection
            scores = detection[5:]
            classID = np.argmax(scores)
            confidence = scores[classID]

            # filter out weak predictions by ensuring the detected
            # probability is greater than the minimum probability
            if confidence > float(args["confidence"]):
                # scale the bounding box coordinates back relative to the
                # size of the image, keeping in mind that YOLO actually
                # returns the center (x, y)-coordinates of the bounding
                # box followed by the boxes' width and height
                box = detection[0:4] * np.array([W, H, W, H])
                (centerX, centerY, width, height) = box.astype("int")

                # use the center (x, y)-coordinates to derive the top and
                # and left corner of the bounding box
                x = int(centerX - (width / 2))
                y = int(centerY - (height / 2))

                # update our list of bounding box coordinates, confidences,
                # and class IDs
                boxes.append([x, y, int(width), int(height)])
                confidences.append(float(confidence))
                classIDs.append(classID)

    # apply non-maxima suppression to suppress weak, overlapping bounding
    # boxes
    idxs = cv2.dnn.NMSBoxes(boxes, confidences, float(args["confidence"]),  # pylint: disable=E1101
                            float(args["threshold"]))

    # ensure at least one detection exists
    if len(idxs) > 0:
        # loop over the indexes we are keeping
        for i in idxs.flatten():  # type: ignore[attr-defined]
            tmp_list = []
            # extract the bounding box coordinates
            (x, y) = (boxes[i][0], boxes[i][1])  # type: ignore
            (w, h) = (boxes[i][2], boxes[i][3])  # type: ignore

            # draw a bounding box rectangle and label on the image
            color = [int(c) for c in COLORS[classIDs[i]]]  # type: ignore
            cv2.rectangle(image, (x, y), (x + w, y + h), color, 2)  # pylint: disable=E1101
            text = f"{LABELS[classIDs[i]]}: {confidences[i]:.4f}"  # type: ignore
            if LABELS[classIDs[i]] in output_keys:  # type: ignore
                if isinstance(output_keys[LABELS[classIDs[i]]], float):  # type: ignore
                    tmp_list = [output_keys[LABELS[classIDs[i]]]]  # type: ignore
                else:
                    tmp_list = output_keys[LABELS[classIDs[i]]]  # type: ignore
                tmp_list.append(confidences[i])  # type: ignore
                output_keys[LABELS[classIDs[i]]] = tmp_list  # type: ignore
            else:
                output_keys[LABELS[classIDs[i]]] = confidences[i]  # type: ignore
            cv2.putText(image, text, (x, y - 5), cv2.FONT_HERSHEY_SIMPLEX,  # pylint: disable=E1101
                        0.5, color, 2)

    # save the output image
    cv2.imwrite("/tmp/snapshot.jpg", image)  # pylint: disable=E1101
    # cv2.waitKey(0)
    f = open("/tmp/snapshot.jpg", "rb")
    output = f.read()
    filename = "snapshot.jpg"
    file = fileResult(filename=filename, data=output)
    file['Type'] = entryTypes['image']
    demisto.results(file)
    results = [
        CommandResults(
            outputs_prefix='ComputerVision.Images',
            readable_output=tableToMarkdown("Detected Objects", output_keys),
            outputs_key_field=['EntryID', 'Method'],
            outputs=output_keys
        )]
    return_results(results)
    sys.exit(0)
