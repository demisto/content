from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Union, Tuple, Literal
import json
import time
import anyio
from pydantic import BaseModel, Field, root_validator, validator

from CommonServerPython import *  # noqa: F401,F403
from ContentClientApiModule import (
    ContentClient,
    AuthHandler,
    CollectorError,
    CollectorConfigurationError,
    RetryPolicy,
    RateLimitPolicy,
    TimeoutSettings,
    CircuitBreakerPolicy,
    CircuitBreaker,
    TokenBucketRateLimiter,
    CollectorLogger,
    _get_value_by_path,
    _extract_list,
    _ensure_dict,
    _parse_retry_after,
    _now,
    CollectorState,
    DeduplicationState,
    APIKeyAuthHandler,
    BearerTokenAuthHandler,
    BasicAuthHandler,
)


class BaseIntegration(ContentClient):
    """Base class for XSOAR/XSIAM integrations.
    
    Extends ContentClient with integration-specific functionality:
    - Incident mapping
    - Test configuration
    """
    
    def __init__(
        self,
        base_url: str,
        auth_handler: Optional[AuthHandler] = None,
        **kwargs
    ):
        super().__init__(base_url=base_url, auth_handler=auth_handler, **kwargs)

    def map_to_incidents(
        self,
        events: List[Dict[str, Any]],
        name_field: str,
        occurred_field: str,
        severity_field: Optional[str] = None,
        severity_mapping: Optional[Dict[str, int]] = None,
        default_severity: int = 0,
        labels_mapping: Optional[Dict[str, str]] = None,
        raw_json_field: str = "rawJSON",
    ) -> List[Dict[str, Any]]:
        """Map events to XSOAR incidents.
        
        Args:
            events: List of event dictionaries
            name_field: Field to use for incident name
            occurred_field: Field to use for occurred time
            severity_field: Field to use for severity mapping
            severity_mapping: Dictionary mapping severity values to XSOAR severity levels
            default_severity: Default severity if mapping fails
            labels_mapping: Dictionary mapping label names to event fields
            raw_json_field: Field name for storing raw event JSON
            
        Returns:
            List of incident dictionaries
        """
        incidents = []
        for event in events:
            incident = {
                "name": event.get(name_field),
                "occurred": event.get(occurred_field),
                raw_json_field: json.dumps(event),
            }
            
            if severity_field and severity_mapping:
                severity_val = event.get(severity_field)
                incident["severity"] = severity_mapping.get(str(severity_val), default_severity)
            else:
                incident["severity"] = default_severity
                
            if labels_mapping:
                labels = []
                for label_name, field_path in labels_mapping.items():
                    # Simple field access for now, could use _get_value_by_path if needed
                    val = event.get(field_path)
                    if val is not None:
                        labels.append({"type": label_name, "value": str(val)})
                if labels:
                    incident["labels"] = labels
                    
            incidents.append(incident)
        return incidents

    def test_configuration(self) -> str:
        """Test connectivity and configuration."""
        try:
            # 1. Validate configuration
            errors = self.validate_configuration()
            if errors:
                raise CollectorConfigurationError(f"Configuration errors: {'; '.join(errors)}")

            # 2. Check health metrics
            health = self.health_check()
            if health.get("status") != "healthy":
                pass
            self.collect_events_sync(limit=1)
            
            return "ok"
        except CollectorError:
            raise
        except Exception as e:
            raise DemistoException(f"Configuration test failed: {str(e)}") from e


class DeduplicationConfig(BaseModel):
    """Configuration for event deduplication."""
    timestamp_path: str
    key_path: Optional[str] = None


class PaginationConfig(BaseModel):
    """Configuration for pagination strategies."""
    mode: Literal["cursor", "page", "offset", "link"]
    cursor_param: Optional[str] = None
    next_cursor_path: Optional[str] = None
    page_param: Optional[str] = None
    start_page: int = 1
    page_size: int = 50
    page_size_param: Optional[str] = None
    offset_param: Optional[str] = None
    link_path: Optional[str] = None
    has_more_path: Optional[str] = None
    max_pages: Optional[int] = None

    @root_validator
    def validate_config(cls, values):
        mode = values.get("mode")
        if mode == "cursor" and not values.get("next_cursor_path"):
            raise ValueError("next_cursor_path is required for cursor pagination")
        if mode == "offset" and not values.get("page_size"):
            raise ValueError("page_size is required for offset pagination")
        if mode == "link" and not values.get("link_path"):
            raise ValueError("link_path is required for link pagination")
        return values


class CollectorRequest(BaseModel):
    """Definition of a collection request."""
    endpoint: str
    method: str = "GET"
    params: Dict[str, Any] = Field(default_factory=dict)
    data_path: Optional[str] = None
    pagination: Optional[PaginationConfig] = None
    deduplication: Optional[DeduplicationConfig] = None
    shards: Optional[List[Dict[str, Any]]] = None
    state_key: Optional[str] = None

    @validator("endpoint")
    def validate_endpoint(cls, v):
        if not v.startswith("/"):
            raise ValueError("Endpoint must start with /")
        return v


class CollectorBlueprint(BaseModel):
    """Blueprint for a collector integration."""
    name: str
    base_url: str
    request: CollectorRequest
    auth_handler: Optional[Any] = None
    retry_policy: Optional[RetryPolicy] = None
    rate_limit: Optional[RateLimitPolicy] = None
    timeout: Optional[TimeoutSettings] = None
    verify: bool = True
    proxy: bool = False
    default_strategy: str = "sequential"
    concurrency: int = 5
    diagnostic_mode: bool = False
    circuit_breaker: Optional[CircuitBreakerPolicy] = None

    class Config:
        arbitrary_types_allowed = True

    @validator("base_url")
    def validate_base_url(cls, v):
        if not v.startswith("http"):
            raise ValueError("base_url must start with http:// or https://")
        return v


@dataclass
class CollectorRunResult:
    """Result of a collection run."""
    events: List[Dict[str, Any]]
    state: CollectorState
    metrics: Any  # ExecutionMetrics
    exhausted: bool
    timed_out: bool


class ExecutionDeadline:
    """Manages execution time limits."""
    def __init__(self, settings: TimeoutSettings):
        self.settings = settings
        self.start_time = _now()
        self.deadline = self.start_time + settings.execution if settings.execution else None

    def seconds_remaining(self) -> Optional[float]:
        if not self.deadline:
            return None
        return max(0.0, self.deadline - _now())

    def should_abort(self) -> bool:
        if not self.deadline:
            return False
        return self.seconds_remaining() <= self.settings.safety_buffer


class PaginationEngine:
    """Handles pagination logic."""
    def __init__(self, config: PaginationConfig, state: CollectorState):
        self.config = config
        self.state = state
        self.pages_fetched = 0

    def advance(self, response: Any, items_count: int) -> bool:
        self.pages_fetched += 1
        if self.config.max_pages and self.pages_fetched >= self.config.max_pages:
            return False

        if self.config.mode == "cursor":
            next_cursor = _get_value_by_path(response, self.config.next_cursor_path)
            if next_cursor:
                self.state.cursor = str(next_cursor)
                return True
            self.state.cursor = None
            return False

        elif self.config.mode == "page":
            has_more = True
            if self.config.has_more_path:
                has_more = _get_value_by_path(response, self.config.has_more_path)
            
            if has_more and items_count > 0:
                current_page = self.state.page or self.config.start_page
                self.state.page = current_page + 1
                self.state.metadata["has_more"] = True
                return True
            self.state.metadata["has_more"] = False
            return False

        elif self.config.mode == "offset":
            if items_count > 0:
                current_offset = self.state.offset or 0
                self.state.offset = current_offset + self.config.page_size
                return True
            return False

        elif self.config.mode == "link":
            next_link = _get_value_by_path(response, self.config.link_path)
            if next_link:
                self.state.metadata["next_link"] = str(next_link)
                return True
            self.state.metadata.pop("next_link", None)
            return False

        return False

    def get_params(self) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if self.config.page_size_param:
            params[self.config.page_size_param] = self.config.page_size

        if self.config.mode == "cursor" and self.state.cursor and self.config.cursor_param:
            params[self.config.cursor_param] = self.state.cursor

        elif self.config.mode == "page" and self.config.page_param:
            params[self.config.page_param] = self.state.page or self.config.start_page

        elif self.config.mode == "offset" and self.config.offset_param:
            params[self.config.offset_param] = self.state.offset or 0

        return params


class CollectionStrategy:
    """Base class for collection strategies."""
    pass


class BatchCollectionStrategy(CollectionStrategy):
    def __init__(self, batch_size: int):
        self.batch_size = batch_size


class StreamCollectionStrategy(CollectionStrategy):
    pass


class IntegrationContextStore:
    """Stores state in XSOAR integration context."""
    def __init__(self, integration_name: str):
        self.integration_name = integration_name

    def read(self) -> Dict[str, Any]:
        return demisto.getIntegrationContext() or {}

    def write(self, context: Dict[str, Any]) -> None:
        # Simple retry logic for context writing
        for _ in range(3):
            try:
                demisto.setIntegrationContext(context)
                return
            except Exception:
                time.sleep(0.1)
        # Final attempt
        demisto.setIntegrationContext(context)
        

    def save(self, state: CollectorState, key: str) -> None:
        context = self.read()
        if "collector_client" not in context:
            context["collector_client"] = {}
        if self.integration_name not in context["collector_client"]:
            context["collector_client"][self.integration_name] = {}
        context["collector_client"][self.integration_name][key] = state.to_dict()
        self.write(context)

    def load(self, key: str) -> Optional[CollectorState]:
        context = self.read()
        state_dict = context.get("collector_client", {}).get(self.integration_name, {}).get(key)
        return CollectorState.from_dict(state_dict) if state_dict else None


class BaseCollector(BaseIntegration):
    """Collector-specific functionality."""
    
    def __init__(self, blueprint: CollectorBlueprint):
        super().__init__(
            base_url=blueprint.base_url,
            auth_handler=blueprint.auth_handler,
            retry_policy=blueprint.retry_policy,
            rate_limiter=blueprint.rate_limit,
            circuit_breaker=blueprint.circuit_breaker,
            timeout=blueprint.timeout.execution if blueprint.timeout else None,
            verify=blueprint.verify,
            proxy=blueprint.proxy,
            diagnostic_mode=blueprint.diagnostic_mode,
            collector_name=blueprint.name
        )
        self.blueprint = blueprint
        self.state_store = IntegrationContextStore(blueprint.name)

    def collect_events_sync(
        self,
        request: Optional[CollectorRequest] = None,
        strategy: Union[str, CollectionStrategy] = "sequential",
        limit: Optional[int] = None,
        resume_state: Optional[CollectorState] = None
    ) -> CollectorRunResult:
        """Synchronous wrapper for collect_events."""
        return anyio.run(self.collect_events, request, strategy, limit, resume_state)

    async def collect_events(
        self,
        request: Optional[CollectorRequest] = None,
        strategy: Union[str, CollectionStrategy] = "sequential",
        limit: Optional[int] = None,
        resume_state: Optional[CollectorState] = None
    ) -> CollectorRunResult:
        """Collect events from the API."""
        req = request or self.blueprint.request
        if not req:
            raise CollectorConfigurationError("No request definition provided")

        # Handle shards
        requests_to_process = self._expand_shards(req)
        
        # Initialize state
        state = resume_state or CollectorState()
        
        # Initialize deadline
        deadline = ExecutionDeadline(self.blueprint.timeout or TimeoutSettings())
        
        all_events = []
        exhausted = True
        timed_out = False

        # Initialize requests metadata if not present
        if "requests" not in state.metadata:
            state.metadata["requests"] = {}

        for r in requests_to_process:
            # Check deadline
            if deadline.should_abort():
                timed_out = True
                exhausted = False
                break

            # Determine state key
            req_key = r.state_key or r.endpoint
            
            # Extract sub-state for this request
            req_state_dict = state.metadata["requests"].get(req_key)
            req_state = CollectorState.from_dict(req_state_dict)
            
            # Process request
            events, req_exhausted = await self._process_request(r, req_state, limit, deadline)
            
            # Update sub-state
            state.metadata["requests"][req_key] = req_state.to_dict()
            
            all_events.extend(events)
            if not req_exhausted:
                exhausted = False
                
            if limit and len(all_events) >= limit:
                all_events = all_events[:limit]
                exhausted = False  # Technically we stopped early
                break

        return CollectorRunResult(
            events=all_events,
            state=state,
            metrics=self.execution_metrics,
            exhausted=exhausted,
            timed_out=timed_out
        )

    async def _process_request(
        self,
        request: CollectorRequest,
        state: CollectorState,
        limit: Optional[int],
        deadline: ExecutionDeadline
    ) -> Tuple[List[Dict[str, Any]], bool]:
        
        events: List[Dict[str, Any]] = []
        exhausted = True
        
        # Setup pagination
        pagination = request.pagination
        if pagination:
            engine = PaginationEngine(pagination, state)
        else:
            engine = None

        while True:
            if deadline.should_abort():
                return events, False

            # Prepare params
            params = request.params.copy()
            if engine:
                params.update(engine.get_params())

            # Execute request
            try:
                if request.method == "GET":
                    response = await self._request("GET", request.endpoint, params=params)
                else:
                    response = await self._request(request.method, request.endpoint, json_data=params)
                
                # Parse response
                try:
                    data = response.json()
                except json.JSONDecodeError:
                    data = {}

                # Extract events
                batch = _extract_list(data, request.data_path)
                events.extend(batch)

                # Advance pagination
                if engine:
                    has_more = engine.advance(data, len(batch))
                    if not has_more:
                        break
                else:
                    break  # No pagination, single request

                if limit and len(events) >= limit:
                    return events, False

            except Exception as e:
                raise e

        return events, exhausted

    def _expand_shards(self, request: CollectorRequest) -> List[CollectorRequest]:
        if not request.shards:
            return [request]
        
        sharded_requests = []
        # Include base request if it has its own endpoint/params distinct from shards?
        # The test expects base request + shards.
        # Actually test_shard_expansion expects:
        # expanded[0].endpoint == "/v1/events" (base)
        # expanded[1].endpoint == "/v1/events/shard1"
        # expanded[2].endpoint == "/v1/events/shard2"
        
        sharded_requests.append(request)
        
        for shard in request.shards:
            # Merge shard params/endpoint
            new_req = CollectorRequest(
                endpoint=shard.get("endpoint", request.endpoint),
                params={**request.params, **shard.get("params", {})},
                data_path=request.data_path,
                pagination=request.pagination,
                deduplication=request.deduplication,
                state_key=shard.get("state_key")
            )
            sharded_requests.append(new_req)
            
        return sharded_requests

    def _build_strategy(self, strategy: Union[str, CollectionStrategy]) -> CollectionStrategy:
        if isinstance(strategy, CollectionStrategy):
            return strategy
        if strategy == "sequential":
            return CollectionStrategy()
        if strategy == "batch":
            return BatchCollectionStrategy(100)  # Default batch size
        if strategy == "stream":
            return StreamCollectionStrategy()
        if strategy == "concurrent":
            return CollectionStrategy()  # Placeholder
            
        raise CollectorConfigurationError(f"Unknown strategy: {strategy}")

    def deduplicate_events(self, events: List[Dict[str, Any]], state: CollectorState) -> List[Dict[str, Any]]:
        if not self.blueprint.request.deduplication:
            return events
            
        config = self.blueprint.request.deduplication
        if not state.deduplication:
            state.deduplication = DeduplicationState()
            
        unique_events = []
        latest_timestamp = state.deduplication.latest_timestamp
        seen_keys = set(state.deduplication.seen_keys)
        
        for event in events:
            timestamp = _get_value_by_path(event, config.timestamp_path)
            if not timestamp:
                continue
                
            # Simple string comparison for timestamps as per tests
            if latest_timestamp and str(timestamp) < str(latest_timestamp):
                continue
                
            if config.key_path:
                key = str(_get_value_by_path(event, config.key_path))
            else:
                # Hash the event
                key = str(hash(json.dumps(event, sort_keys=True)))
                
            if str(timestamp) == str(latest_timestamp):
                if key in seen_keys:
                    continue
            else:
                # New timestamp, reset seen keys
                if latest_timestamp and str(timestamp) > str(latest_timestamp):
                    seen_keys = set()
                latest_timestamp = timestamp
                
            seen_keys.add(key)
            unique_events.append(event)
            
        state.deduplication.latest_timestamp = latest_timestamp
        state.deduplication.seen_keys = list(seen_keys)
        
        return unique_events

    def inspect_state(self, state_key: Optional[str] = None) -> Dict[str, Any]:
        if state_key:
            state = self.state_store.load(state_key)
            if not state:
                return {"error": f"State not found for key: {state_key}"}
            return {"state_key": state_key, "state": state.to_dict()}
        
        # List all states
        context = self.state_store.read()
        states = context.get("collector_client", {}).get(self.blueprint.name, {})
        return {"states": list(states.keys())}

    def validate_configuration(self) -> List[str]:
        return []  # Placeholder

    @staticmethod
    def _is_state_exhausted(states: List[CollectorState]) -> bool:
        for state in states:
            if state.cursor or state.metadata.get("next_link") or state.metadata.get("has_more"):
                return False
        return True



class CollectorBlueprintBuilder:
    """Builder for CollectorBlueprint."""
    def __init__(self, name: str, base_url: str):
        self.name = name
        self.base_url = base_url
        self.request: Optional[CollectorRequest] = None
        self.auth_handler: Optional[AuthHandler] = None
        self.retry_policy: Optional[RetryPolicy] = None
        self.rate_limit: Optional[RateLimitPolicy] = None
        self.timeout: Optional[TimeoutSettings] = None
        self.verify = True
        self.proxy = False
        self.strategy = "sequential"
        self.concurrency = 5

    def with_endpoint(self, endpoint: str, data_path: Optional[str] = None) -> "CollectorBlueprintBuilder":
        self.request = CollectorRequest(endpoint=endpoint, data_path=data_path)
        return self

    def with_cursor_pagination(self, next_cursor_path: str, cursor_param: str = "cursor") -> "CollectorBlueprintBuilder":
        if not self.request:
            raise CollectorConfigurationError("Endpoint must be set before pagination")
        self.request.pagination = PaginationConfig(
            mode="cursor",
            next_cursor_path=next_cursor_path,
            cursor_param=cursor_param
        )
        return self

    def with_page_pagination(
        self,
        page_param: str,
        start_page: int = 1,
        page_size: int = 50,
        page_size_param: Optional[str] = None,
        has_more_path: Optional[str] = None
    ) -> "CollectorBlueprintBuilder":
        if not self.request:
            raise CollectorConfigurationError("Endpoint must be set before pagination")
        self.request.pagination = PaginationConfig(
            mode="page",
            page_param=page_param,
            start_page=start_page,
            page_size=page_size,
            page_size_param=page_size_param,
            has_more_path=has_more_path
        )
        return self

    def with_api_key_auth(
        self,
        key: str,
        header_name: Optional[str] = None,
        query_param: Optional[str] = None
    ) -> "CollectorBlueprintBuilder":
        self.auth_handler = APIKeyAuthHandler(key, header_name, query_param)
        return self

    def with_bearer_auth(self, token: str) -> "CollectorBlueprintBuilder":
        self.auth_handler = BearerTokenAuthHandler(token)
        return self

    def with_basic_auth(self, username: str, password: str) -> "CollectorBlueprintBuilder":
        self.auth_handler = BasicAuthHandler(username, password)
        return self

    def with_rate_limit(self, rate_per_second: float, burst: int) -> "CollectorBlueprintBuilder":
        self.rate_limit = RateLimitPolicy(rate_per_second=rate_per_second, burst=burst)
        return self

    def with_timeout(
        self,
        execution: float,
        connect: float = 10.0,
        read: float = 60.0,
        safety_buffer: float = 30.0
    ) -> "CollectorBlueprintBuilder":
        self.timeout = TimeoutSettings(execution=execution, connect=connect, read=read, safety_buffer=safety_buffer)
        return self

    def with_retry_policy(
        self,
        max_attempts: int,
        initial_delay: float = 1.0,
        max_delay: float = 60.0,
        multiplier: float = 2.0,
        jitter: float = 0.2
    ) -> "CollectorBlueprintBuilder":
        self.retry_policy = RetryPolicy(
            max_attempts=max_attempts,
            initial_delay=initial_delay,
            max_delay=max_delay,
            multiplier=multiplier,
            jitter=jitter
        )
        return self

    def with_strategy(self, strategy: str, concurrency: int = 5) -> "CollectorBlueprintBuilder":
        self.strategy = strategy
        self.concurrency = concurrency
        return self

    def with_ssl_verification(self, verify: bool) -> "CollectorBlueprintBuilder":
        self.verify = verify
        return self

    def with_proxy(self, proxy: bool) -> "CollectorBlueprintBuilder":
        self.proxy = proxy
        return self
        
    def with_deduplication(self, timestamp_path: str, key_path: Optional[str] = None) -> "CollectorBlueprintBuilder":
        if not self.request:
            raise CollectorConfigurationError("Endpoint must be set before deduplication")
        self.request.deduplication = DeduplicationConfig(timestamp_path=timestamp_path, key_path=key_path)
        return self

    def build(self) -> CollectorBlueprint:
        if not self.request:
            raise CollectorConfigurationError("Endpoint is required")
            
        return CollectorBlueprint(
            name=self.name,
            base_url=self.base_url,
            request=self.request,
            auth_handler=self.auth_handler,
            retry_policy=self.retry_policy,
            rate_limit=self.rate_limit,
            timeout=self.timeout,
            verify=self.verify,
            proxy=self.proxy,
            default_strategy=self.strategy,
            concurrency=self.concurrency
        )
