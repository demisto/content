# SiemAPIModule

## Usage

To use this API Module, implement the next methods:

The `IntegrationEventsClient` Object:

```python

class MyIntegrationEventsClient(IntegrationEventsClient):
    def set_request_filter(self, after: Any):
        """Implement the next call run

        Example:
        >>> from datetime import datetime
        >>> set_request_filter(datetime(year=2022, month=4, day=16))            
        """
        self.client.request.headers['after'] = after.isoformat()

```

The `IntegrationGetEvents` Object:

```python
class MyIntegrationGetEvents(IntegrationGetEvents):
    def get_last_run(events) -> dict:
        """Implement how to get the last run.

        Example:
        >>> get_last_run([{'created': '2022-4-16'}])
        """
        return {'after': events[-1]['created']}

    def _iter_events(self):
        """Create an iterator on the events.
        If need extra authorisation, do that in the beggining of the command.
        Example:
        >>> for event in _iter_events():
        ...
        """
        response = self.call(self.request)
        while True:
            events = response.json()
            yield events
            self.client.set_request_filter(events[-1]['created'])
            self.call(self.request)
```
