# BaseApiModule (Collector Framework)

`BaseApiModule` provides the `BaseCollector` class and the `CollectorBlueprint` system, which together form a powerful framework for building XSOAR/XSIAM event collectors. It abstracts away the complexity of pagination, state management, deduplication, and sharding.

## 🚀 Key Features

- **Declarative Configuration**: Define *what* to collect using `CollectorBlueprint`, not *how* to collect it.
- **Pagination Engine**: Supports Cursor, Page, Offset, and Link-based pagination out of the box.
- **State Management**: Automatically handles state persistence, resumption, and sharding.
- **Deduplication**: Built-in event deduplication by timestamp and ID/Hash.
- **Collection Strategies**: Sequential, Batch, and Stream strategies for different use cases.
- **Builder Pattern**: Fluent `CollectorBlueprintBuilder` for easy configuration.

## 📦 Installation

```python
from BaseApiModule import *
```

## 🛠 Usage

### 1. Define the Blueprint

Use the `CollectorBlueprintBuilder` to define your collector's behavior.

```python
def build_blueprint(params):
    return (
        CollectorBlueprintBuilder("MyCollector", params["url"])
        .with_endpoint(
            endpoint="/v1/events", 
            data_path="data.events"
        )
        .with_cursor_pagination(
            next_cursor_path="meta.next_cursor",
            cursor_param="cursor"
        )
        .with_api_key_auth(
            key=params["api_key"], 
            header_name="X-API-Key"
        )
        .with_deduplication(
            timestamp_path="created_at",
            key_path="id"
        )
        .build()
    )
```

### 2. Instantiate and Collect

```python
def fetch_events_command():
    # 1. Build Blueprint
    blueprint = build_blueprint(demisto.params())
    
    # 2. Create Collector
    collector = BaseCollector(blueprint)
    
    # 3. Load State
    context = demisto.getIntegrationContext() or {}
    resume_state = CollectorState.from_dict(context.get("state"))
    
    # 4. Collect
    result = collector.collect_events_sync(
        limit=1000, 
        resume_state=resume_state
    )
    
    # 5. Deduplicate
    unique_events = collector.deduplicate_events(result.events, result.state)
    
    # 6. Save State & Return
    demisto.setIntegrationContext({"state": result.state.to_dict()})
    
    return unique_events
```

## 📖 Pagination Modes

| Mode | Builder Method | Description |
|------|----------------|-------------|
| **Cursor** | `.with_cursor_pagination()` | Uses a cursor string from the response to fetch the next page. |
| **Page** | `.with_page_pagination()` | Increments a page number parameter. |
| **Offset** | (Manual Config) | Uses skip/limit or offset/limit parameters. |
| **Link** | (Manual Config) | Follows a full URL provided in the response. |

## 🧩 Advanced Features

### Sharding
Split collection across multiple "shards" (e.g., regions, tenants) automatically.

```python
request = CollectorRequest(
    endpoint="/v1/events",
    shards=[
        {"params": {"region": "us"}, "state_key": "events-us"},
        {"params": {"region": "eu"}, "state_key": "events-eu"},
    ]
)
```

### Collection Strategies
- **Sequential**: Fetches pages one by one (Default).
- **Batch**: Flushes events in batches (useful for memory constrained environments).
- **Stream**: Yields events as they are fetched (Async only).

### Deduplication
Automatically filters out duplicate events based on a timestamp and unique key.

```python
.with_deduplication(
    timestamp_path="time",  # Path to timestamp field
    key_path="id"           # Path to unique ID field (optional, hashes event if missing)
)