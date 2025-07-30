import asyncio
from asyncio import Queue
from urllib.parse import urlparse

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import httpx
import time
from typing import Any


# --- CONSTANTS ---
API_ENDPOINT = "/scalemgmt/v2/cliauditlog"
DEFAULT_PAGE_SIZE = 1000  # Default page size for IBM Storage Scale API
PRODUCT = "StorageScale"
VENDOR = "IBM"


class Client:
    """
    A unified, high-performance async client for the IBM Storage Scale API.

    This class manages all API interactions, using httpx.AsyncClient for
    connection pooling and asyncio for concurrent operations.
    """

    def __init__(
        self, server_url: str, auth: tuple[str | bytes, str | bytes], verify: bool, proxy: str | None, concurrency: int = 5
    ):
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
        async with httpx.AsyncClient(base_url=self.base_url, auth=self.auth, verify=self.verify, proxy=self.proxy) as client:
            try:
                response = await client.get(f"{API_ENDPOINT}?limit=1&fields=oid")
                response.raise_for_status()
            except httpx.HTTPStatusError as e:
                if e.response.status_code in (401, 403):
                    raise DemistoException(
                        "Authorization Error: Ensure the credentials are correct and have the required permissions."
                    )
                raise DemistoException(f"HTTP Error: Failed to connect to API. Status code: {e.response.status_code}")
            except httpx.RequestError as e:
                raise DemistoException(f"Connection Error: Could not connect to {self.base_url}. Reason: {e}")

    async def get_events(self, limit: int | None) -> tuple[list[dict[str, Any]], bool]:
        """
        Orchestrates fetching events for manual commands, returning them for display.
        """
        fetcher = _ConcurrentEventFetcher(self, limit or DEFAULT_PAGE_SIZE)
        events, has_more = await fetcher.run()
        return events, has_more

    async def fetch_events(self, max_events: int | None) -> None:
        """
        Orchestrates the high-performance, concurrent fetching of events for ingestion.
        """
        demisto.info("Starting fetch-events cycle.")
        start_time = time.monotonic()

        fetcher = _ConcurrentEventFetcher(self, max_events or DEFAULT_PAGE_SIZE)
        events, has_more = await fetcher.run()

        end_time = time.monotonic()
        duration = end_time - start_time
        total_events = len(events)
        eps = total_events / duration if duration > 0 else 0

        performance_summary = (
            f"Fetch cycle finished. Fetched {total_events} events in " f"{duration:.2f} seconds ({eps:.2f} events/sec)."
        )
        demisto.info(performance_summary)

        for event in events:
            event["_time"] = event.get("entryTime")

        push_events_start_time = time.monotonic()
        demisto.debug("Pushing events to XSIAM.")
        send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
        push_events_end_time = time.monotonic()
        push_events_duration = push_events_end_time - push_events_start_time
        demisto.info(f"Pushed events to XSIAM. Completed push process in {push_events_duration} seconds.")
        demisto.info(f"Fetched {total_events} events in {duration:.2f} seconds.")

        if has_more:
            demisto.info("Fetch cycle reached the event limit. More events may be available on the server.")


class _ConcurrentEventFetcher:
    """
    Internal helper class to manage the producer-consumer fetching logic.
    This revised implementation uses a more robust concurrent crawling model where any worker
    can queue the next page of work.
    """

    def __init__(self, client: Client, max_events: int):
        self.client = client
        self.max_events = max_events
        self.queue: Queue = asyncio.Queue()
        self.collected_events: list[dict[str, Any]] = []
        self.has_more_available = False
        self._lock = asyncio.Lock()

    async def _worker(self, name: str, async_client: httpx.AsyncClient):
        """Pulls a URL from the queue, fetches events, and queues the next URL."""
        while True:
            url_suffix = None
            try:
                url_suffix = await self.queue.get()
                demisto.debug(f"[{name}] got task: {url_suffix}")

                # Check if we should stop before making the API call
                async with self._lock:
                    if len(self.collected_events) >= self.max_events:
                        demisto.debug(f"[{name}] stopping, max events limit reached before processing task.")
                        self.has_more_available = True
                        continue  # Don't call task_done here — skip fetch

                response = await async_client.get(url_suffix)
                response.raise_for_status()
                data = await response.json()
                events = data.get("auditLogRecords", [])
                demisto.debug(f"[{name}] fetched {len(events)} events from {url_suffix}")

                # Add events to the shared list under a lock
                async with self._lock:
                    if len(self.collected_events) < self.max_events:
                        remaining_space = self.max_events - len(self.collected_events)
                        self.collected_events.extend(events[:remaining_space])
                        demisto.debug(f"[{name}] total events collected: {len(self.collected_events)}")

                # Queue next page if present
                paging_info = data.get("paging", {})
                next_full_url = paging_info.get("next")
                if next_full_url:
                    next_url_suffix = f"{urlparse(next_full_url).path}?{urlparse(next_full_url).query}"
                    demisto.debug(f"[{name}] queuing next URL: {next_url_suffix}")
                    await self.queue.put(next_url_suffix)

            except httpx.HTTPStatusError as e:
                demisto.error(f"[{name}] failed to process page {url_suffix} with status {e.response.status_code}: {e}")
            except Exception as e:
                demisto.error(f"[{name}] failed to process page {url_suffix}: {e}")
            finally:
                if url_suffix is not None:
                    self.queue.task_done()

    async def run(self) -> tuple[list[dict[str, Any]], bool]:
        """Orchestrates the workers to fetch all events."""
        # Seed the queue with the first page
        initial_url = f"{API_ENDPOINT}?fields=:all:&limit={DEFAULT_PAGE_SIZE}"
        self.queue.put_nowait(initial_url)

        async with httpx.AsyncClient(
            base_url=self.client.base_url, auth=self.client.auth, verify=self.client.verify, proxy=self.client.proxy
        ) as async_client:
            # Create a pool of workers to process the queue
            worker_tasks = [
                asyncio.create_task(self._worker(f"Worker-{i}", async_client)) for i in range(self.client.concurrency)
            ]

            # Wait for the queue to be fully processed
            await self.queue.join()
            demisto.debug("Queue processing complete. Cancelling workers.")

            # Cancel all worker tasks
            for task in worker_tasks:
                task.cancel()
            await asyncio.gather(*worker_tasks, return_exceptions=True)

        demisto.debug(f"Fetcher finished. Total events: {len(self.collected_events)}")
        return self.collected_events[: self.max_events], self.has_more_available


async def main() -> None:
    """Main function, serves as the orchestra for the integration."""
    params = demisto.params()
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    # Get proxy settings as a dictionary
    proxies = handle_proxy()

    # Select a single proxy URL, prioritizing HTTPS, then HTTP
    proxy_url = proxies.get("https") or proxies.get("http") or None

    try:
        client = Client(
            server_url=params.get("server_url"),
            auth=(params.get("credentials", {}).get("identifier"), params.get("credentials", {}).get("password")),
            verify=not params.get("insecure", False),
            proxy=proxy_url,
        )

        if command == "test-module":
            await client.test_connection()
            return_results("ok")
        elif command == "fetch-events":
            max_fetch = arg_to_number(params.get("max_fetch", "10000"))
            await client.fetch_events(
                max_fetch,
            )
        elif command == "ibm-storage-scale-get-events":
            limit = arg_to_number(demisto.args().get("limit", 50))
            should_push_events = argToBoolean(demisto.args().get("should_push_events", False))
            events, _ = await client.get_events(limit=limit)
            if should_push_events:
                push_events_start_time = time.monotonic()
                demisto.debug("Pushing events to XSIAM.")
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
                push_events_end_time = time.monotonic()
                push_events_duration = push_events_end_time - push_events_start_time
                demisto.info(f"Pushed events to XSIAM. Completed in {push_events_duration} seconds.")
            command_results = CommandResults(
                outputs_prefix="IBMStorageScale.AuditLog",
                outputs_key_field="oid",
                outputs=events,
                readable_output=tableToMarkdown(
                    f"IBM Storage Scale Events (first {len(events)} events)",
                    events,
                    headers=["entryTime", "user", "command", "node", "returnCode", "originator"],
                    removeNull=True,
                    headerTransform=pascalToSpace,
                ),
            )
            return_results(command_results)
        else:
            raise NotImplementedError(f"Command '{command}' is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command}. Error: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    asyncio.run(main())
