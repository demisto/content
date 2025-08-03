import aiohttp
import asyncio



async def send_post_request_async(endpoint):
    url = "https://edl-crtx-cntnt-ownr-xsiam-shahaf-4ce1.xdr-qa2-uat.us.paloaltonetworks.com/xsoar/instance/execute/Generic_Webhook_hayun_workshop/"
    headers = {
        'Authorization': 'Basic YTph',
        'Content-Type': 'application/json' # Important: ensure this header is set
    }
    payload = {
        "payload": {
            "phrase": "Arad naknik!!"
        }
    }
    async with aiohttp.ClientSession(base_url=url, headers=headers) as session:
        try:
            async with session.post(url=endpoint, json=payload) as response:
                response.raise_for_status()  # Check for any HTTP errors
                raw_response = await response.text()
                print(f"Request to {url}{endpoint} successful! Response: {raw_response}")
                return raw_response
        except aiohttp.ClientError as e:
            print(f"An aiohttp client error occurred: {e}")
            if 'response' in locals() and response is not None:
                try:
                    error_content = await response.text()
                    print(f"Error Response Content: {error_content}")
                except Exception as text_e:
                    print(f"Could not read error response text: {text_e}")
            return ''
        except Exception as e:
            print(f"An unexpected error occurred during POST: {e}")
            return ''


async def send_get_request_async(endpoint):
    url = "https://edl-crtx-cntnt-ownr-xsiam-shahaf-4ce1.xdr-qa2-uat.us.paloaltonetworks.com/xsoar/instance/execute/Generic_Webhook_hayun_workshop/"
    headers = {
    'Authorization': 'Basic YTph',
    }
    async with aiohttp.ClientSession(base_url=url, headers=headers) as session, session.get(url=endpoint, params={}) as response:
        try:
            response.raise_for_status()  # Check for any HTTP errors
            raw_response = await response.text()
            return raw_response
        except aiohttp.ClientError as e:
            print(e)
            raw_response = ''
    return raw_response


async def main():
    tasks = [asyncio.create_task(send_post_request_async("example_7"))]
    phrase = await send_get_request_async("example_7")
    print(phrase)

asyncio.run(main())
