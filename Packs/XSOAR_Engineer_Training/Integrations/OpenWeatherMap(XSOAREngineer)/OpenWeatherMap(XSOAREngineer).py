import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# This integration gets the current weather or weather forecast for a provided city.
# Example building a demisto integration to get started.
# Reference: https://xsoar.pan.dev/docs/integrations/code-conventions / https://xsoar.pan.dev/docs/tutorials/tut-integration-ui


class Client(BaseClient):
    """
    Client will implement the service API, should not contain Cortex XSOAR logic.
    Inherits from the BaseClient in CommonServerPython, should only do requests and return data
    """

    def __init__(self, base_url, verify, proxy, apikey):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._apikey = apikey

    def get_city_weather(self, city: str) -> Dict[str, Any]:
        """
        Gets the Weather of a city via the API endpoint:
            api.openweathermap.org/data/2.5/weather?q={city}&appid={self._apikey}
        :type city: ``str``

        :return: dict containing the city weather from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
            method='GET',
            url_suffix=f'/weather?q={city}&APPID={self._apikey}'
        )


''' HELPER FUNCTIONS '''


def kelvin_to_celsius(K):
    """
    Function to convert temperature from degree kevlin to celsius
    """

    temp = K - 273.15
    return round(temp)


''' COMMAND FUNCTIONS '''


def get_weather_by_city_command(client, args):
    """
    Gets the current weather for the provided city
    """

    # get the city, send it to lower case.
    city = args.get("city").lower()

    # get the weather for the city
    weather = client.get_city_weather(city)

    # return the full json object to war room for debugging
    # print(weather)

    # Lets make things pretty, and pull out the data we want.
    # These also become the Outputs of this command
    pretty_weather = {
        "City": weather.get("name"),
        "Country": weather.get("sys").get("country"),
        "Current Weather": weather.get("weather")[0].get("description"),
        "High": kelvin_to_celsius(weather.get("main").get("temp_max")),
        "Low": kelvin_to_celsius(weather.get("main").get("temp_min"))
    }

    # tableToMarkdown is useful for creating a readable war room entry
    readable = tableToMarkdown(f"Weather for {pretty_weather.get('City')},{pretty_weather.get('Country')}", pretty_weather, headers=[
                               'City', 'Country', 'Current Weather', 'High', 'Low'])

    # Return results, both the human readable, and the context outputs
    results = CommandResults(
        readable_output=readable,
        outputs_prefix=f'OpenWeather.CurrentWeather',
        outputs_key_field='City',
        outputs=pretty_weather
    )

    return results


def test_module(client):
    """
    This call is made when pressing the integration test button.
    Validate we can get the weather for Calgary from the API.
    """

    res = client.get_city_weather(city="Calgary")
    if res.get('name') == "Calgary":
        return 'ok'
    else:
        return_error(res)


''' EXECUTION '''


def main():
    """
    Main function, grabs both the integration params and arguments.
    Initializes our Class to handle the API calls, and returns results
    """

    # Params - You can use demisto.params().get('paramName') to get a specific params.
    # Params are of the type given in the integration page creation.
    apikey = demisto.params().get("apiKey")
    apiversion = demisto.params().get("apiVersion")

    # Args - You can use demisto.args() to get the arguments passed the command
    args = demisto.args()

    # Remove trailing slash to prevent wrong URL path to service
    base_url = urljoin(demisto.params().get("url"), f"/{apiversion}")

    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    # Command and Conquer
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            apikey=apikey)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'openweather-by-city':
            return_results(get_weather_by_city_command(client, args))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
