import demistomock as demisto  # noqa: F401
from bs4 import BeautifulSoup
from CommonServerPython import *  # noqa: F401

args = demisto.args()
response = requests.get(args.get("url"))
soup = BeautifulSoup(response.content, "html.parser")
article = soup.find("article").get_text()
_, article = article.split("Phishing Email Campaign", 1)
article = article.replace('[.]', '.')

return_results(CommandResults(readable_output=article, outputs={"http.parsedBlog": article}))
