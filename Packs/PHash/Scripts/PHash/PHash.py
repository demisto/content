import demistomock as demisto  # noqa: F401
import imagehash
from CommonServerPython import *  # noqa: F401
from PIL import Image

ImageID = demisto.args()['image']
ImageFilePath = demisto.getFilePath(ImageID)

hash = imagehash.phash(Image.open(ImageFilePath['path']))
context = {
    "PHash": str(hash)
}
command_results = CommandResults(outputs=context)

return_results(command_results)
