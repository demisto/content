import aiohttp
import asyncio


async def send_request(params):
    url = "https://edl-crtx-cntnt-ownr-xsiam-shahaf-4ce1.xdr-qa2-uat.us.paloaltonetworks.com/xsoar/instance/execute/Generic_Webhook_hayun_workshop/"
    headers = {
    'Authorization': 'Basic YTph',
    }
    async with aiohttp.ClientSession(base_url=url, headers=headers) as session, session.get(url="example_5", params=params) as response:
        try:
            response.raise_for_status()  # Check for any HTTP errors
            raw_response = await response.text()
            return raw_response
        except aiohttp.ClientError as e:
            print(e)
            raw_response = ''
        return raw_response
            
async def main():
    params = {"query": "Arad is a?"}
    print(f"going to send request with {params=}")
    raw_response = await send_request(params)
    print(f"done, {raw_response=}")
    params = {"query": "Who's a naknik?"}
    print(f"going to send request with {params=}")
    raw_response = await send_request(params)
    print(f"done, {raw_response=}")
    params = {"query": "random query.."}
    print(f"going to send request with {params=}")
    raw_response = await send_request(params)
    print(f"done, {raw_response=}")

asyncio.run(main())