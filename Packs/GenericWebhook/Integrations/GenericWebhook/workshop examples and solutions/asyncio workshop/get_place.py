import aiohttp
import asyncio


async def send_request_async(endpoint):
    url = "https://edl-crtx-cntnt-ownr-xsiam-shahaf-6606.xdr-qa2-uat.us.paloaltonetworks.com/xsoar/instance/execute/Generic_Webhook_hayun_workshop/"
    headers = {
    'Authorization': 'Basic YTph',
    }
    params = {"name": "yuval"}
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
    results = await send_request_async("finish_line/get_place")
    print(results)

asyncio.run(main())