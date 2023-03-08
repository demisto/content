This integration gets the current weather using the Open Weather Map API.  Use for training how to write not-as-simple integrations.
This integration was integrated and tested with version xx of OpenWeatherMap (XSOAR Engineer)

## Configure OpenWeatherMap (XSOAR Engineer) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for OpenWeatherMap (XSOAR Engineer).
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Open Weather Map API Key | True |
    | Base API URL | True |
    | Open Weather Map API Version | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### openweather-by-city

***
Retrieves the weather by provided city (where you wish you were)

#### Base Command

`openweather-by-city`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| city | Name of the City (example Calgary or San Francisco). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenWeather.CurrentWeather.City | unknown | city for the forecast | 
| OpenWeather.CurrentWeather.Country | unknown | country code of the city | 
| OpenWeather.CurrentWeather.Current Weather | unknown | current weather | 
| OpenWeather.CurrentWeather.High | unknown | high temp forecasted | 
| OpenWeather.CurrentWeather.Low | unknown | low temp forecasted | 
