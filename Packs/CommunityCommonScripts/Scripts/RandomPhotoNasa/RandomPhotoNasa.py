import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import random
from datetime import datetime

import requests

args = demisto.args()
search = args.get("search", "nebula")
widget_type = args.get("widgetType")

date_now = datetime.utcnow()
end_year = date_now.year
headers = {"Accept": "application/json"}
params = {"q": search, "media_type": "image", "year_start": 1920, "year_end": end_year}
res = requests.request("GET", "https://images-api.nasa.gov/search", params=params, headers=headers)
if res.status_code != 200:
    demisto.results("Hmmm, I couldn't a photo. Try refreshing?")
else:
    json_data = res.json()
    items = json_data.get("collection", {}).get("items", [])

    random_index = random.randint(0, len(items) - 1)
    random_list_entry = items[random_index]
    title = random_list_entry.get("data")[0].get("title")
    description = random_list_entry.get("data")[0].get("description")
    url = random_list_entry.get("href")

    res = requests.request("GET", url, headers=headers)
    if res.status_code != 200:
        demisto.results("Hmmm, I couldn't a photo. Try refreshing?")
    else:
        json_data = res.json()
        json_data = [x for x in json_data if "metadata.json" not in x]
        if json_data:
            random_image_index = random.randint(0, len(json_data) - 1)
            image_url = json_data[random_image_index]
            md = f"![{title}]({image_url})\n[{title}]({image_url}) - {description}"
        else:
            md = ""

        if not widget_type:
            command_results = CommandResults(
                outputs_prefix="NASA.Image",
                outputs_key_field="title",
                outputs={"title": title, "description": description, "image": image_url},
                readable_output=md,
            )
            return_results(command_results)
        elif widget_type == "text":
            demisto.results(md)

        elif widget_type == "number":
            demisto.results(42)
