import demistomock as demisto
from CommonServerPython import *

from glob import glob
from os.path import abspath, basename

from pyzbar.pyzbar import decode
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
            for barcode in decode(Image.open(abspath(file))):
                image_dict["Barcode"].append(
                    {"Type": barcode.type, "Data": barcode.data.decode()}
                )
            image_dict["Image"] = True
        except UnidentifiedImageError:
            image_dict["Image"] = False

        result["File"].append(image_dict)

    return result


def detect_and_decode_barcode_command(args) -> CommandResults:
    entry_id = args.get("entry_id", None)
    if not entry_id:
        raise ValueError("entry_id not specified")

    file_path = demisto.getFilePath(entry_id)["path"]
    result = detect_and_decode_barcode(file_path)
    result["File"][-1]["EntryID"] = entry_id

    return CommandResults(
        outputs_prefix="DetectAndDecodeBarcode.File",
        outputs_key_field="EntryID",
        outputs=result,
    )


def main():
    try:
        return_results(detect_and_decode_barcode_command(demisto.args()))
    except Exception as ex:
        return_error(f"Failed to execute DetectAndDecodeBarcode. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
