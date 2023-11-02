import demistomock as demisto
from CommonServerPython import *

from glob import glob
from os.path import abspath, basename

import zxingcpp
from PIL import Image, UnidentifiedImageError


def detect_and_decode_barcode(path: str) -> Dict[str, Any]:
    result = {"File": []}  # type: Dict[str, Any]
    for file in glob(path):
        image_dict = {
            "Name": basename(file),
            "Barcode": [],
            "Image": False,
        }  # type: Dict[str, Any]
        try:
            for barcode in zxingcpp.read_barcodes(Image.open(abspath(file))):
                image_dict["Barcode"].append(
                    {
                        "Type": f"{barcode.format}".split(".")[1],
                        "Data": f"{barcode.text}",
                    }
                )
            image_dict["Image"] = True
        except UnidentifiedImageError:
            image_dict["Image"] = False

        result["File"].append(image_dict)

    return result


def main():
    args = demisto.args()
    entry_id = args.get("entry_id")
    file_path = demisto.getFilePath(entry_id)["path"]
    results = detect_and_decode_barcode(file_path)
    results["File"][-1]["EntryID"] = entry_id
    return_results(results)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
