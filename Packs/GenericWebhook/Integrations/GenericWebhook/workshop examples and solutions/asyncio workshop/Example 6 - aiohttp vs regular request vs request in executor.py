import functools
import aiohttp
import asyncio

import requests


async def send_request_async(endpoint):
    url = "https://edl-crtx-cntnt-ownr-xsiam-shahaf-4ce1.xdr-qa2-uat.us.paloaltonetworks.com/xsoar/instance/execute/Generic_Webhook_hayun_workshop/"
    headers = {
    'Authorization': 'Basic YTph',
    }
    async with aiohttp.ClientSession(base_url=url, headers=headers) as session, session.get(url=endpoint) as response:
        try:
            response.raise_for_status()  # Check for any HTTP errors
            raw_response = await response.text()
            return raw_response
        except aiohttp.ClientError as e:
            print(e)
            raw_response = ''
    print(raw_response)
    return raw_response


async def send_request_sync(endpoint):
    url = "https://edl-crtx-cntnt-ownr-xsiam-shahaf-4ce1.xdr-qa2-uat.us.paloaltonetworks.com/xsoar/instance/execute/Generic_Webhook_hayun_workshop/"
    headers = {
        'Authorization': 'Basic YTph',
    }

    try:
        # Construct the full URL by appending the endpoint
        full_url = f"{url}{endpoint}"
        
        response = requests.get(full_url, headers=headers)
        response.raise_for_status()  # Check for any HTTP errors (4xx or 5xx)
        raw_response = response.text
        return raw_response
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        raw_response = ''
        return raw_response
        
        
async def send_request_in_executor(endpoint):
    loop = asyncio.get_event_loop()
    url = "https://edl-crtx-cntnt-ownr-xsiam-shahaf-4ce1.xdr-qa2-uat.us.paloaltonetworks.com/xsoar/instance/execute/Generic_Webhook_hayun_workshop/"
    headers = {
        'Authorization': 'Basic YTph',
    }

    try:
        full_url = f"{url}{endpoint}"
        # Arrange for func to be called in the specified executor. a concurrent.futures.ThreadPoolExecutor will be lazy-initialized and used if none is mentioned.
        response = await loop.run_in_executor(
            None,
            functools.partial(
                requests.get,
                url=full_url,
                headers=headers,
            ),
        )
        response.raise_for_status()  # Check for any HTTP errors (4xx or 5xx)
        raw_response = response.text
        return raw_response
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        raw_response = ''
        return raw_response


async def main():
    import time

    print("Starting to make request using asyncio")
    start = time.time()
    tasks = [asyncio.create_task(send_request_async("example_6")), asyncio.create_task(send_request_async("example_6"))]
    results = await asyncio.gather(*tasks)
    for result in results:
        print(result)
    end = time.time()
    print(f"Finished making request using asyncio, took {end - start} seconds.")

   
    print("Starting to make request using regular python request")
    start = time.time()
    tasks = [asyncio.create_task(send_request_sync("example_6")), asyncio.create_task(send_request_sync("example_6"))]
    results = await asyncio.gather(*tasks)
    for result in results:
        print(result)
    end = time.time()
    print(f"Finished making request using regular python request, took {end - start} seconds.")

   
    print("Starting to make request using regular python request in executor")
    start = time.time()
    tasks = [asyncio.create_task(send_request_in_executor("example_6")), asyncio.create_task(send_request_in_executor("example_6"))]
    results = await asyncio.gather(*tasks)
    for result in results:
        print(result)
    end = time.time()
    print(f"Finished making request using regular python request in executor, took {end - start} seconds.")

asyncio.run(main())