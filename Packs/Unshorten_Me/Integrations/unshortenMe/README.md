# `unshorten.me` Integration (Community)

## Overview

This integration allows you to unshorten URLs using the `unshorten.me` service. It is useful for revealing the final destination of shortened links from services like bit.ly, t.co (Twitter), TinyURL, and more, which is a common requirement in threat analysis and phishing investigations.

To use this integration, you must request a free API token from [unshorten.me](https://unshorten.me/api).

## Configure `unshorten.me` on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for `unshorten.me`.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Token | The API token for your `unshorten.me` account. | True |
| Trust any certificate (not secure) | When selected, the integration ignores TLS/SSL certificate validation errors. Use with caution. | False |
| Use system proxy settings | When selected, the integration uses the system's proxy settings. | False |

4. Click **Test** to validate the URL and token.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

### 1. unshorten-me-unshorten-url

***
Unshortens a given URL.

#### Base Command

`unshorten-me-unshorten-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| shortUrl | The shortened URL to expand. e.g., `https://bit.ly/3DKWm5t` | True |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| unshortenMe.unshortened_url | String | The full, original destination URL. |
| unshortenMe.shortened_url | String | The shortened URL that was provided as input. |
| unshortenMe.success | Boolean | `True` if the operation was successful, otherwise `False`. |

#### Command Example

```!unshorten-me-unshorten-url shortUrl="https://bit.ly/3DKWm5t"```

#### Human Readable Output
>
> ### `unshorten.me` results
>
> **Unshortened URL:** `https://www.youtube.com/`
> **Shortened URL:** `https://bit.ly/3DKWm5t`
> **Success:** `True`

#### Context Example

```json
{
    "unshortenMe": {
        "success": true,
        "shortened_url": "https://bit.ly/3DKWm5t",
        "unshortened_url": "https://www.youtube.com/"
    }
}
