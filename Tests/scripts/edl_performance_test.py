import demisto_client
from demisto_client.demisto_api.rest import ApiException

# api_instance = demisto_client.configure(base_url="https://localhost:80808", api_key="YOUR_API_KEY")
api_instance = demisto_client.configure(base_url="http://localhost:8080", username="admin", password="admin")
indicator_filter = demisto_client.demisto_api.IndicatorFilter(query="*")  # IndicatorFilter |  (optional)

try:
    # Search indicators
    api_response = api_instance.indicators_search(indicator_filter=indicator_filter)
    print(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->indicators_search: %s\n" % e)
