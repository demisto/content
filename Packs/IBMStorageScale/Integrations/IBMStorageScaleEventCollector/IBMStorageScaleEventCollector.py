import asyncio
import demistomock as demisto  # noqa: F401
from CommonServerPython import * # noqa: F401

import httpx
from typing import Dict, Any, Tuple, List, Optional

# --- CONSTANTS ---
API_ENDPOINT = "/scalemgmt/v2/cliauditlog"
DEFAULT_PAGE_SIZE = 1000  # Default page size for IBM Storage Scale API


class Client:
    """
    A unified, high-performance async client for the IBM Storage Scale API.

    This class manages all API interactions, using httpx.AsyncClient for
    connection pooling and asyncio for concurrent operations. It does not use
    the synchronous BaseClient to ensure all network operations follow the
    same asynchronous pattern.
    """

    def __init__(self, server_url: str, auth: tuple, verify: bool, proxy: Optional[str], concurrency: int = 5):
        self.base_url = server_url
        self.auth = auth
        self.verify = verify
        self.proxy = proxy
        self.concurrency = concurrency

    async def test_connection(self):
        """
        Performs a connection test using the async client to validate credentials and connectivity.
        This ensures the test path is identical to the operational path.
        """
        async with httpx.AsyncClient(base_url=self.base_url, auth=self.auth, verify=self.verify, proxies=self.proxy) as client:
            try:
                # Fetch a single event to confirm API access
                response = await client.get(f"{API_ENDPOINT}?limit=1&fields=oid")
                response.raise_for_status()
            except httpx.HTTPStatusError as e:
                if e.response.status_code in (401, 403):
                    raise DemistoException(
                        'Authorization Error: Ensure the credentials are correct and have the required permissions.'
                    )
                raise DemistoException(f"HTTP Error: Failed to connect to API. Status code: {e.response.status_code}")
            except httpx.RequestError as e:
                raise DemistoException(f"Connection Error: Could not connect to {self.base_url}. Reason: {e}")

    async def get_events(self, limit: int) -> Tuple[List[Dict[str, Any]], bool]:
        """
        Orchestrates fetching events for manual commands, returning them for display.
        """
        fetcher = _ConcurrentEventFetcher(self, limit)
        events, has_more = await fetcher.run()
        return events, has_more

    async def fetch_events(self, max_events: int) -> None:
        """
        Orchestrates the high-performance, concurrent fetching of events for ingestion.
        """
        fetcher = _ConcurrentEventFetcher(self, max_events)
        events, has_more = await fetcher.run()
        demisto.info(f"Concurrently fetched {len(events)} events.")

        for event in events:
            event['_time'] = event.get('entryTime')

        send_events_to_xsiam(events, vendor='IBM', product='Storage Scale')

        if has_more:
            demisto.info("Fetch cycle reached the event limit. More events may be available on the server.")


class _ConcurrentEventFetcher:
    """
    Internal helper class to manage the producer-consumer fetching logic.
    It is instantiated and used by the main Client class.
    """

    def __init__(self, client: Client, max_events: int):
        self.client = client
        self.max_events = max_events
        self.queue = asyncio.Queue()
        self.collected_events: List[Dict[str, Any]] = []
        self.has_more_available = False
        self._producer_done = False

    async def _producer(self, async_client: httpx.AsyncClient):
        """Discovers page URLs and puts them in the queue for workers."""
        next_url_suffix = f"{API_ENDPOINT}?fields=:all:&limit={DEFAULT_PAGE_SIZE}"
        while next_url_suffix:
            if len(self.collected_events) + self.queue.qsize() * DEFAULT_PAGE_SIZE >= self.max_events:
                self.has_more_available = True
                demisto.info("Producer hit max event limit. Halting production of new page tasks.")
                break

            await self.queue.put(next_url_suffix)
            try:
                response = await async_client.get(next_url_suffix)
                response.raise_for_status()
                data = response.json()
                paging_info = data.get("paging", {})
                next_full_url = paging_info.get("next")
                next_url_suffix = f"{urlparse(next_full_url).path}?{urlparse(next_full_url).query}" if next_full_url else None
            except httpx.HTTPStatusError as e:
                demisto.error(f"Producer failed to get next page link: {e}")
                break
        self._producer_done = True

    async def _worker(self, name: str, async_client: httpx.AsyncClient):
        """Pulls a URL from the queue, fetches events, and adds them to the results."""
        while not (self._producer_done and self.queue.empty()):
            try:
                url_suffix = await asyncio.wait_for(self.queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            try:
                response = await async_client.get(url_suffix)
                response.raise_for_status()
                if self.max_events > len(self.collected_events):
                    self.collected_events.extend(response.json().get("auditLogRecords", []))
                self.queue.task_done()
            except Exception as e:
                demisto.error(f"{name} failed to process page {url_suffix}: {e}")
                self.queue.task_done()

    async def run(self) -> Tuple[List[Dict[str, Any]], bool]:
        """Orchestrates the producer and workers to fetch all events."""
        async with httpx.AsyncClient(
            base_url=self.client.base_url, auth=self.client.auth, verify=self.client.verify, proxies=self.client.proxy
        ) as async_client:
            producer_task = asyncio.create_task(self._producer(async_client))
            worker_tasks = [
                asyncio.create_task(self._worker(f"Worker-{i}", async_client)) for i in range(self.client.concurrency)
            ]
            await producer_task
            await self.queue.join()
            for task in worker_tasks:
                task.cancel()
            await asyncio.gather(*worker_tasks, return_exceptions=True)
        return self.collected_events[:self.max_events], self.has_more_available


def main() -> None:
    """Main function, serves as the orchestra for the integration."""
    params = demisto.params()
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    # Get proxy settings as a dictionary
    proxies = handle_proxy()

    # Select a single proxy URL, prioritizing HTTPS, then HTTP
    proxy_url = proxies.get('https') or proxies.get('http') or None

    try:
        client = Client(
            server_url=params.get('server_url'),
            auth=(params.get('credentials', {}).get('identifier'), params.get('credentials', {}).get('password')),
            verify=not params.get('insecure', False),
            proxy=proxy_url
        )

        if command == 'test-module':
            asyncio.run(client.test_connection())
            return_results('ok')
        elif command == 'fetch-events':
            max_fetch = arg_to_number(params.get('max_fetch', '10000'))
            asyncio.run(client.fetch_events(max_fetch))
        elif command == 'ibm-storage-scale-get-events':
            limit = arg_to_number(demisto.args().get('limit', 50))
            events, _ = asyncio.run(client.get_events(limit))
            command_results = CommandResults(
                outputs_prefix='IBMStorageScale.AuditLog',
                outputs_key_field='oid',
                outputs=events,
                readable_output=tableToMarkdown(
                    f'IBM Storage Scale Events (first {len(events)} events)',
                    events,
                    headers=['entryTime', 'user', 'command', 'node', 'returnCode', 'originator'],
                    removeNull=True
                )
            )
            return_results(command_results)
        else:
            raise NotImplementedError(f"Command '{command}' is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command}. Error: {e}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
