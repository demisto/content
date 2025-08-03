import re
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
            "name": "yuval"
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


async def send_get_request_async(endpoint, params):
    url = "https://edl-crtx-cntnt-ownr-xsiam-shahaf-4ce1.xdr-qa2-uat.us.paloaltonetworks.com/xsoar/instance/execute/Generic_Webhook_hayun_workshop/"
    headers = {
    'Authorization': 'Basic YTph',
    }
    async with aiohttp.ClientSession(base_url=url, headers=headers) as session, session.get(url=endpoint, params=params) as response:
        try:
            response.raise_for_status()  # Check for any HTTP errors
            raw_response = await response.text()
            return raw_response
        except aiohttp.ClientError as e:
            print(e)
            raw_response = ''
    print(raw_response)
    return raw_response


async def main():
    asyncio.create_task(send_post_request_async("step_3"))
    password = await send_get_request_async("step_3/get_pass", {"name": "yuval"})
    print(f"{password=}")
    pattern = r'password is: "(\d+)"'

    # Use re.search to find the first occurrence of the pattern
    match = re.search(pattern, password)

    if match:
        # If a match is found, group(1) contains the content of the first capturing group
        password = match.group(1)
        print(f"Extracted password: {password}")
    else:
        print("Password not found in the string.")
    step_3_res = await send_get_request_async("step_3/enter_password", {"name": "yuval", "password": password})
    print(step_3_res)
    

asyncio.run(main())