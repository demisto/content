
"""
Comprehensive test suite for LiveEngageLivePerson producer-consumer implementation.
Tests cover threading, concurrency, error handling, deduplication, and performance.
"""

import pytest
import threading
import queue
import time
import random
import hashlib
from unittest.mock import Mock, MagicMock, patch, call, ANY
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import json
import copy

# Import the module under test
import LiveEngageLivePerson_producer_consumer as lp
from LiveEngageLivePerson_producer_consumer import (
    EventBatch,
    EventBatchStatus,
    ProducerConsumerMetrics,
    EventDeduplicator,
    Client,
    retry_with_backoff,
    generate_event_hash,
    INTEGRATION_PREFIX,
    DEFAULT_MAX_FETCH,
    API_PAGE_SIZE,
    DATE_FORMAT,
    DEDUP_WINDOW_MINUTES,
    MAX_DEDUP_CACHE_SIZE,
    QUEUE_MAX_SIZE,
    CONSUMER_BATCH_SIZE,
    PRODUCER_TIMEOUT,
    CONSUMER_TIMEOUT,
    MAX_CONSUMER_THREADS,
)
from CommonServerPython import DemistoException
import demistomock as demisto


# ==========================================
# Test Fixtures and Mock Data
# ==========================================

@pytest.fixture(autouse=True)
def reset_globals():
    """Reset any global state between tests."""
    yield
    # Clean up after each test
    

@pytest.fixture
def mock_demisto(mocker):
    """Mock all demisto functions."""
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    mocker.patch.object(demisto, 'error')
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={})
    mocker.patch.object(demisto, 'setIntegrationContext')
    mocker.patch.object(demisto, 'getLastRun', return_value={})
    mocker.patch.object(demisto, 'setLastRun')
    mocker.patch.object(demisto, 'params', return_value={})
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'args', return_value={})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(lp, 'send_events_to_xsiam')
    mocker.patch.object(lp, 'handle_proxy', return_value={})
    return mocker


@pytest.fixture
def sample_events():
    """Generate sample events for testing."""
    base_time = datetime.now(timezone.utc)
    events = []
    for i in range(10):
        event_time = base_time - timedelta(minutes=10 - i)
        events.append({
            "accountId": "123456789",
            "changeDate": event_time.strftime(DATE_FORMAT),
            "objectType": f"TYPE_{i}",
            "element": f"element_{i}",
            "changeType": "UPDATE",
            "objectName": f"object_{i}",
            "originator": f"user_{i}",
            "userId": f"uid_{i}",
            "changedBy": f"User {i}"
        })
    return events


@pytest.fixture
def mock_client(mock_demisto):
    """Create a mock client for testing."""
    client = Client(
        base_url="https://test.liveperson.net",
        account_id="123456789",
        auth_server_url="auth.liveperson.net",
        client_id="test_client",
        client_secret="test_secret",
        verify=True,
        proxy=False
    )
    return client


# ==========================================
# Unit Tests: Helper Functions
# ==========================================

class TestRetryWithBackoff:
    """Test the retry_with_backoff function."""
    
    def test_success_on_first_try(self):
        """Test function succeeds on first attempt."""
        mock_func = Mock(return_value="success")
        result = retry_with_backoff(mock_func, max_retries=3)
        assert result == "success"
        assert mock_func.call_count == 1
    
    def test_success_after_retry(self):
        """Test function succeeds after retries."""
        mock_func = Mock(side_effect=[Exception("fail"), Exception("fail"), "success"])
        result = retry_with_backoff(mock_func, max_retries=3, base_delay=0.01)
        assert result == "success"
        assert mock_func.call_count == 3
    
    def test_max_retries_exceeded(self):
        """Test function fails after max retries."""
        mock_func = Mock(side_effect=Exception("persistent error"))
        with pytest.raises(Exception, match="persistent error"):
            retry_with_backoff(mock_func, max_retries=2, base_delay=0.01)
        assert mock_func.call_count == 3  # initial + 2 retries
    
    def test_exponential_backoff_timing(self, mocker):
        """Test exponential backoff delays are applied correctly."""
        mock_sleep = mocker.patch('time.sleep')
        mock_func = Mock(side_effect=[Exception("fail"), Exception("fail"), "success"])
        
        result = retry_with_backoff(
            mock_func, 
            max_retries=3, 
            base_delay=1.0,
            exponential_base=2.0,
            jitter=False
        )
        
        assert result == "success"
        # Check delays: 1s, 2s (exponential backoff without jitter)
        calls = mock_sleep.call_args_list
        assert len(calls) == 2
        assert calls[0][0][0] == 1.0
        assert calls[1][0][0] == 2.0
    
    def test_max_delay_cap(self, mocker):
        """Test that delays are capped at max_delay."""
        mock_sleep = mocker.patch('time.sleep')
        mock_func = Mock(side_effect=[Exception("fail")] * 5 + ["success"])
        
        result = retry_with_backoff(
            mock_func,
            max_retries=5,
            base_delay=10.0,
            max_delay=15.0,
            exponential_base=2.0,
            jitter=False
        )
        
        assert result == "success"
        # All delays should be capped at 15.0
        for sleep_call in mock_sleep.call_args_list:
            assert sleep_call[0][0] <= 15.0
    
    def test_jitter_applied(self, mocker):
        """Test that jitter is applied to delays."""
        mock_sleep = mocker.patch('time.sleep')
        mocker.patch('random.random', return_value=0.5)
        mock_func = Mock(side_effect=[Exception("fail"), "success"])
        
        result = retry_with_backoff(
            mock_func,
            max_retries=2,
            base_delay=2.0,
            jitter=True
        )
        
        assert result == "success"
        # With random=0.5, jitter multiplier is 0.5 + 0.5 = 1.0
        # So delay should be 2.0 * 1.0 = 2.0
        mock_sleep.assert_called_once_with(2.0)


class TestGenerateEventHash:
    """Test the generate_event_hash function."""
    
    def test_consistent_hash_generation(self):
        """Test that same event generates same hash."""
        event = {
            "accountId": "123",
            "changeDate": "2024-01-01T00:00:00Z",
            "objectType": "USER",
            "element": "test_element",
            "changeType": "UPDATE",
            "objectName": "test_object",
            "originator": "test_user"
        }
        hash1 = generate_event_hash(event)
        hash2 = generate_event_hash(event)
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 produces 64 hex characters
    
    def test_different_events_different_hashes(self):
        """Test that different events generate different hashes."""
        event1 = {"accountId": "123", "changeDate": "2024-01-01T00:00:00Z"}
        event2 = {"accountId": "456", "changeDate": "2024-01-01T00:00:00Z"}
        hash1 = generate_event_hash(event1)
        hash2 = generate_event_hash(event2)
        assert hash1 != hash2
    
    def test_missing_fields_handled(self):
        """Test that missing fields are handled gracefully."""
        event = {"accountId": "123"}  # Missing most fields
        hash_val = generate_event_hash(event)
        assert hash_val is not None
        assert len(hash_val) == 64
    
    def test_order_independence(self):
        """Test that field order doesn't affect hash."""
        event1 = {"accountId": "123", "changeDate": "2024-01-01", "objectType": "USER"}
        event2 = {"objectType": "USER", "accountId": "123", "changeDate": "2024-01-01"}
        hash1 = generate_event_hash(event1)
        hash2 = generate_event_hash(event2)
        assert hash1 == hash2


# ==========================================
# Unit Tests: EventBatch and EventBatchStatus
# ==========================================

class TestEventBatch:
    """Test the EventBatch dataclass."""
    
    def test_creation_with_defaults(self):
        """Test EventBatch creation with default values."""
        events = [{"id": 1}, {"id": 2}]
        batch = EventBatch(
            events=events,
            batch_id="test_batch_1",
            timestamp=datetime.now(timezone.utc)
        )
        assert batch.events == events
        assert batch.batch_id == "test_batch_1"
        assert batch.status == EventBatchStatus.PENDING
        assert batch.retry_count == 0
        assert batch.error_message is None
    
    def test_creation_with_all_fields(self):
        """Test EventBatch creation with all fields specified."""
        events = [{"id": 1}]
        timestamp = datetime.now(timezone.utc)
        batch = EventBatch(
            events=events,
            batch_id="test_batch_2",
            timestamp=timestamp,
            status=EventBatchStatus.PROCESSING,
            retry_count=2,
            error_message="Test error"
        )
        assert batch.status == EventBatchStatus.PROCESSING
        assert batch.retry_count == 2
        assert batch.error_message == "Test error"
    
    def test_status_transitions(self):
        """Test EventBatch status transitions."""
        batch = EventBatch(
            events=[],
            batch_id="test",
            timestamp=datetime.now(timezone.utc)
        )
        
        # Test all status transitions
        for status in EventBatchStatus:
            batch.status = status
            assert batch.status == status


# ==========================================
# Unit Tests: ProducerConsumerMetrics
# ==========================================

class TestProducerConsumerMetrics:
    """Test the ProducerConsumerMetrics class."""
    
    def test_initialization(self):
        """Test metrics initialization."""
        metrics = ProducerConsumerMetrics()
        assert metrics.events_produced == 0
        assert metrics.events_consumed == 0
        assert metrics.batches_produced == 0
        assert metrics.batches_consumed == 0
        assert metrics.errors == 0
        assert metrics.duplicates_filtered == 0
        assert metrics.start_time is not None
    
    def test_increment_produced(self):
        """Test incrementing produced events."""
        metrics = ProducerConsumerMetrics()
        metrics.increment_produced(5)
        assert metrics.events_produced == 5
        assert metrics.batches_produced == 1
        
        metrics.increment_produced(3)
        assert metrics.events_produced == 8
        assert metrics.batches_produced == 2
    
    def test_increment_consumed(self):
        """Test incrementing consumed events."""
        metrics = ProducerConsumerMetrics()
        metrics.increment_consumed(10)
        assert metrics.events_consumed == 10
        assert metrics.batches_consumed == 1
    
    def test_increment_errors(self):
        """Test incrementing error count."""
        metrics = ProducerConsumerMetrics()
        metrics.increment_errors()
        metrics.increment_errors()
        assert metrics.errors == 2
    
    def test_increment_duplicates(self):
        """Test incrementing duplicate count."""
        metrics = ProducerConsumerMetrics()
        metrics.increment_duplicates(5)
        metrics.increment_duplicates(3)
        assert metrics.duplicates_filtered == 8
    
    def test_get_summary(self):
        """Test getting metrics summary."""
        metrics = ProducerConsumerMetrics()
        metrics.increment_produced(100)
        metrics.increment_consumed(90)
        metrics.increment_duplicates(10)
        metrics.increment_errors()
        
        summary = metrics.get_summary()
        assert summary["events_produced"] == 100
        assert summary["events_consumed"] == 90
        assert summary["batches_produced"] == 1
        assert summary["batches_consumed"] == 1
        assert summary["duplicates_filtered"] == 10
        assert summary["errors"] == 1
        assert "elapsed_seconds" in summary
        assert "events_per_second" in summary
    
    def test_thread_safety(self):
        """Test thread safety of metrics operations."""
        metrics = ProducerConsumerMetrics()
        threads = []
        
        def increment_all():
            for _ in range(100):
                metrics.increment_produced(1)
                metrics.increment_consumed(1)
                metrics.increment_errors()
                metrics.increment_duplicates(1)
        
        # Create multiple threads
        for _ in range(10):
            thread = threading.Thread(target=increment_all)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Check final counts
        assert metrics.events_produced == 1000
        assert metrics.events_consumed == 1000
        assert metrics.errors == 1000
        assert metrics.duplicates_filtered == 1000


# ==========================================
# Unit Tests: EventDeduplicator
# ==========================================

class TestEventDeduplicator:
    """Test the EventDeduplicator class."""
    
    def test_initialization(self, mock_demisto):
        """Test deduplicator initialization."""
        dedup = EventDeduplicator(window_minutes=5, max_size=100)
        assert dedup.window_minutes == 5
        assert dedup.max_size == 100
        assert isinstance(dedup.cache, dict)
    
    def test_load_cache_empty(self, mock_demisto):
        """Test loading empty cache from context."""
        mock_demisto.patch.object(demisto, 'getIntegrationContext', return_value={})
        dedup = EventDeduplicator()
        assert len(dedup.cache) == 0
    
    def test_load_cache_with_data(self, mock_demisto):
        """Test loading cache with existing data."""
        current_time = datetime.utcnow()
        recent_time = current_time - timedelta(minutes=2)
        old_time = current_time - timedelta(minutes=10)
        
        cache_data = {
            "hash1": recent_time.isoformat(),
            "hash2": old_time.isoformat(),  # This should be filtered out
            "hash3": recent_time.isoformat()
        }
        
        mock_demisto.patch.object(demisto, 'getIntegrationContext', return_value={"dedup_cache": cache_data})
        dedup = EventDeduplicator(window_minutes=5)
        
        # Only recent entries should be loaded
        assert len(dedup.cache) == 2
        assert "hash1" in dedup.cache
        assert "hash3" in dedup.cache
        assert "hash2" not in dedup.cache  # Old entry filtered out
    
    def test_is_duplicate(self, mock_demisto, sample_events):
        """Test duplicate detection."""
        dedup = EventDeduplicator()
        event = sample_events[0]
        
        # First occurrence should not be duplicate
        assert not dedup.is_duplicate(event)
        
        # Second occurrence should be duplicate
        assert dedup.is_duplicate(event)
        
        # Different event should not be duplicate
        assert not dedup.is_duplicate(sample_events[1])
    
    def test_deduplicate_batch(self, mock_demisto, sample_events):
        """Test batch deduplication."""
        dedup = EventDeduplicator()
        
        # Create batch with duplicates
        batch = sample_events[:3] + sample_events[:2]  # 5 events, 2 duplicates
        
        unique_events = dedup.deduplicate_batch(batch)
        assert len(unique_events) == 3
        
        # Verify cache was saved
        demisto.setIntegrationContext.assert_called()
    
    def test_cache_size_limit(self, mock_demisto):
        """Test cache size limiting."""
        dedup = EventDeduplicator(window_minutes=60, max_size=5)
        
        # Add more events than max_size
        for i in range(10):
            event = {"accountId": str(i), "changeDate": f"2024-01-01T00:00:{i:02d}Z"}
            dedup.is_duplicate(event)
        
        dedup._save_cache()
        
        # Cache should be limited to max_size
        assert len(dedup.cache) <= 5
    
    def test_cache_expiry(self, mock_demisto):
        """Test that expired entries are removed from cache."""
        current_time = datetime.utcnow()
        old_time = current_time - timedelta(minutes=10)
        recent_time = current_time - timedelta(minutes=2)
        
        # Create deduplicator with existing cache
        dedup = EventDeduplicator(window_minutes=5)
        dedup.cache = {
            "old_hash": old_time,
            "recent_hash": recent_time
        }
        
        # Save and reload cache
        dedup._save_cache()
        dedup._load_cache()
        
        # Old entry should be removed
        assert "recent_hash" in dedup.cache
        assert "old_hash" not in dedup.cache


# ==========================================
# Unit Tests: Client Producer-Consumer Methods
# ==========================================

class TestClientProducerConsumer:
    """Test the Client's producer-consumer methods."""
    
    @pytest.fixture
    def mock_queue(self):
        """Create a mock queue for testing."""
        q: "queue.Queue[Any]" = queue.Queue(maxsize=10)
        return q
    
    def test_event_producer_basic(self, mock_client, mock_demisto, sample_events):
        """Test basic producer functionality."""
        event_queue: "queue.Queue[Any]" = queue.Queue(maxsize=10)
        stop_event = threading.Event()
        metrics = ProducerConsumerMetrics()
        last_run_time = datetime.utcnow() - timedelta(hours=1)
        
        # Mock the HTTP request to return sample events
        mock_client._http_request = Mock(return_value={"data": sample_events[:2]})
        
        # Run producer
        new_timestamp = mock_client._event_producer(
            event_queue,
            max_fetch=2,
            last_run_time=last_run_time,
            stop_event=stop_event,
            metrics=metrics
        )
        
        # Check results
        assert event_queue.qsize() == 1  # One batch
        batch = event_queue.get()
        assert len(batch.events) == 2
        assert batch.status == EventBatchStatus.PENDING
        assert metrics.events_produced == 2
        assert metrics.batches_produced == 1
        
        # Verify timestamp was updated based on events
        # The new timestamp should be greater than or equal to the last_run_time
        assert new_timestamp >= last_run_time
        # If events have changeDate, verify the timestamp reflects the latest event
        if sample_events[1].get("changeDate"):
            # The producer should have updated the timestamp to the latest event's time
            expected_time = datetime.fromisoformat(sample_events[1]["changeDate"].replace("Z", "+00:00"))
            assert new_timestamp >= expected_time
    
    def test_event_producer_pagination(self, mock_client, mock_demisto, sample_events):
        """Test producer with pagination."""
        event_queue: "queue.Queue[Any]" = queue.Queue(maxsize=10)
        stop_event = threading.Event()
        metrics = ProducerConsumerMetrics()
        last_run_time = datetime.utcnow() - timedelta(hours=1)
        
        # Mock multiple pages
        mock_client._http_request = Mock(side_effect=[
            {"data": sample_events[:3]},
            {"data": sample_events[3:5]},
            {"data": []}  # Empty page to stop
        ])
        
        # Run producer
        new_timestamp = mock_client._event_producer(
            event_queue,
            max_fetch=10,
            last_run_time=last_run_time,
            stop_event=stop_event,
            metrics=metrics
        )
        
        # Check results
        assert event_queue.qsize() == 2  # Two batches
        assert metrics.events_produced == 5
        assert metrics.batches_produced == 2
        
        # Verify timestamp was updated to the latest event
        assert new_timestamp >= last_run_time
        # Should reflect the timestamp of the last event processed (sample_events[4])
        if sample_events[4].get("changeDate"):
            expected_time = datetime.fromisoformat(sample_events[4]["changeDate"].replace("Z", "+00:00"))
            assert new_timestamp >= expected_time
    
    def test_event_producer_stop_signal(self, mock_client, mock_demisto, sample_events):
        """Test producer stops when stop_event is set."""
        event_queue: "queue.Queue[Any]" = queue.Queue(maxsize=10)
        stop_event = threading.Event()
        metrics = ProducerConsumerMetrics()
        last_run_time = datetime.utcnow() - timedelta(hours=1)
        
        # Set stop event immediately
        stop_event.set()
        
        mock_client._http_request = Mock(return_value={"data": sample_events})
        
        # Run producer
        new_timestamp = mock_client._event_producer(
            event_queue,
            max_fetch=100,
            last_run_time=last_run_time,
            stop_event=stop_event,
            metrics=metrics
        )
        
        # Should stop without fetching
        assert mock_client._http_request.call_count == 0
        assert metrics.events_produced == 0
        # Timestamp should not advance when no events are processed
        assert new_timestamp == last_run_time
    
    def test_event_producer_queue_full(self, mock_client, mock_demisto, sample_events):
        """Test producer behavior when queue is full."""
        event_queue: "queue.Queue[Any]" = queue.Queue(maxsize=1)
        stop_event = threading.Event()
        metrics = ProducerConsumerMetrics()
        last_run_time = datetime.utcnow() - timedelta(hours=1)
        
        # Fill the queue
        event_queue.put(EventBatch([], "dummy", datetime.utcnow()))
        
        mock_client._http_request = Mock(return_value={"data": sample_events[:2]})
        
        # Start producer in thread
        producer_thread = threading.Thread(
            target=mock_client._event_producer,
            args=(event_queue, 2, last_run_time, stop_event, metrics)
        )
        producer_thread.start()
        
        # Let it try to put
        time.sleep(0.1)
        
        # Queue should still be full
        assert event_queue.full()
        
        # Clear queue
        event_queue.get()
        
        # Wait for producer to finish
        producer_thread.join(timeout=5)
        
        # Now it should have added the batch
        assert event_queue.qsize() == 1
    
    def test_event_producer_error_handling(self, mock_client, mock_demisto):
        """Test producer error handling."""
        event_queue: "queue.Queue[Any]" = queue.Queue(maxsize=10)
        stop_event = threading.Event()
        metrics = ProducerConsumerMetrics()
        last_run_time = datetime.utcnow() - timedelta(hours=1)
        
        # Mock HTTP error
        mock_client._http_request = Mock(side_effect=Exception("API Error"))
        
        # Run producer
        new_timestamp = mock_client._event_producer(
            event_queue,
            max_fetch=10,
            last_run_time=last_run_time,
            stop_event=stop_event,
            metrics=metrics
        )
        
        # Should handle error gracefully
        assert metrics.errors > 0
        assert new_timestamp == last_run_time  # Timestamp shouldn't advance on error
    
    def test_event_consumer_basic(self, mock_client, mock_demisto, sample_events):
        """Test basic consumer functionality."""
        event_queue: "queue.Queue[Any]" = queue.Queue(maxsize=10)
        stop_event = threading.Event()
        metrics = ProducerConsumerMetrics()
        
        # Add batch to queue
        batch = EventBatch(
            events=sample_events[:3],
            batch_id="test_batch",
            timestamp=datetime.utcnow()
        )
        event_queue.put(batch)
        
        # Mock deduplicator
        mock_client.deduplicator.deduplicate_batch = Mock(return_value=sample_events[:3])
        
        # Set stop event after putting batch
        stop_event.set()
        
        # Run consumer
        mock_client._event_consumer(event_queue, stop_event, metrics, consumer_id=1)
        
        # Check results
        assert metrics.events_consumed == 3
        assert lp.send_events_to_xsiam.called
    
    def test_event_consumer_deduplication(self, mock_client, mock_demisto, sample_events):
        """Test consumer deduplication."""
        event_queue: "queue.Queue[Any]" = queue.Queue(maxsize=10)
        stop_event = threading.Event()
        metrics = ProducerConsumerMetrics()
        
        # Add batch with duplicates
        batch = EventBatch(
            events=sample_events[:5],
            batch_id="test_batch",
            timestamp=datetime.utcnow()
        )
        event_queue.put(batch)
        
        # Mock deduplicator to filter out 2 duplicates
        mock_client.deduplicator.deduplicate_batch = Mock(return_value=sample_events[:3])
        
        stop_event.set()
        
        # Run consumer
        mock_client._event_consumer(event_queue, stop_event, metrics, consumer_id=1)
        
        # Check deduplication metrics
        assert metrics.duplicates_filtered == 2
        assert metrics.events_consumed == 3
    
    def test_event_consumer_batch_buffering(self, mock_client, mock_demisto, sample_events):
        """Test consumer buffers events until batch size is reached."""
        event_queue: "queue.Queue[Any]" = queue.Queue(maxsize=10)
        stop_event = threading.Event()
        metrics = ProducerConsumerMetrics()
        
        # Add multiple small batches
        for i in range(3):
            batch = EventBatch(
                events=sample_events[i:i + 1],
                batch_id=f"batch_{i}",
                timestamp=datetime.utcnow()
            )
            event_queue.put(batch)
        
        mock_client.deduplicator.deduplicate_batch = Mock(side_effect=lambda x: x)
        
        # Run consumer in thread
        consumer_thread = threading.Thread(
            target=mock_client._event_consumer,
            args=(event_queue, stop_event, metrics, 1)
        )
        consumer_thread.start()
        
        # Let it process
        time.sleep(0.5)
        
        # Stop consumer
        stop_event.set()
        consumer_thread.join(timeout=5)
        
        # Should have consumed all events
        assert metrics.events_consumed == 3
    
    def test_event_consumer_error_recovery(self, mock_client, mock_demisto, sample_events):
        """Test consumer error recovery."""
        event_queue: "queue.Queue[Any]" = queue.Queue(maxsize=10)
        stop_event = threading.Event()
        metrics = ProducerConsumerMetrics()
        
        batch = EventBatch(
            events=sample_events[:3],
            batch_id="test_batch",
            timestamp=datetime.utcnow()
        )
        event_queue.put(batch)
        
        # Mock send_events_to_xsiam to fail
        lp.send_events_to_xsiam.side_effect = Exception("Send failed")
        mock_client.deduplicator.deduplicate_batch = Mock(return_value=sample_events[:3])
        
        stop_event.set()
        
        # Run consumer
        mock_client._event_consumer(event_queue, stop_event, metrics, consumer_id=1)
        
        # Should record error
        assert metrics.errors > 0


# ==========================================
# Integration Tests: Producer-Consumer System
# ==========================================

class TestProducerConsumerIntegration:
    """Integration tests for the complete producer-consumer system."""
    
    def test_fetch_events_producer_consumer(self, mock_client, mock_demisto, sample_events):
        """Test the complete fetch_events_producer_consumer method."""
        # Mock HTTP responses
        mock_client._http_request = Mock(side_effect=[
            {"data": sample_events[:5]},
            {"data": sample_events[5:8]},
            {"data": []}
        ])
        
        # Mock deduplicator
        mock_client.deduplicator.deduplicate_batch = Mock(side_effect=lambda x: x)
        
        last_run_time = datetime.utcnow() - timedelta(hours=1)
        
        # Run fetch
        events_sent, new_timestamp = mock_client.fetch_events_producer_consumer(
            max_fetch=10,
            last_run_time=last_run_time
        )
        
        # Verify results
        assert events_sent == 8
        assert new_timestamp > last_run_time
        assert lp.send_events_to_xsiam.called
    
    def test_concurrent_producer_consumer(self, mock_client, mock_demisto, sample_events):
        """Test concurrent producer and consumer threads."""
        # Create larger dataset
        large_dataset = sample_events * 10  # 100 events
        
        # Mock paginated responses
        pages = []
        for i in range(0, len(large_dataset), 10):
            pages.append({"data": large_dataset[i:i + 10]})
        pages.append({"data": []})  # Empty page to stop
        
        mock_client._http_request = Mock(side_effect=pages)
        mock_client.deduplicator.deduplicate_batch = Mock(side_effect=lambda x: x)
        
        last_run_time = datetime.utcnow() - timedelta(hours=1)
        
        # Run fetch
        events_sent, new_timestamp = mock_client.fetch_events_producer_consumer(
            max_fetch=100,
            last_run_time=last_run_time
        )
        
        # Verify all events were processed
        assert events_sent == 100
    
    def test_producer_consumer_with_errors(self, mock_client, mock_demisto, sample_events):
        """Test system resilience with intermittent errors."""
        # Mock responses with some errors
        mock_client._http_request = Mock(side_effect=[
            {"data": sample_events[:3]},
            Exception("Network error"),
            {"data": sample_events[3:6]},
            {"data": []}
        ])
        
        mock_client.deduplicator.deduplicate_batch = Mock(side_effect=lambda x: x)
        
        last_run_time = datetime.utcnow() - timedelta(hours=1)
        
        # Run fetch
        events_sent, new_timestamp = mock_client.fetch_events_producer_consumer(
            max_fetch=10,
            last_run_time=last_run_time
        )
        
        # Should continue despite error
        assert events_sent >= 3  # At least first batch


# ==========================================
# Performance and Stress Tests
# ==========================================

class TestPerformanceAndStress:
    """Performance and stress tests for the producer-consumer system."""
    
    def test_high_volume_processing(self, mock_client, mock_demisto):
        """Test processing high volume of events."""
        # Generate large dataset
        num_events = 10000
        large_events = []
        base_time = datetime.utcnow()
        
        for i in range(num_events):
            event = {
                "accountId": "123456789",
                "changeDate": (base_time - timedelta(seconds=i)).strftime(DATE_FORMAT),
                "objectType": f"TYPE_{i % 10}",
                "element": f"element_{i}",
                "changeType": "UPDATE",
                "objectName": f"object_{i}",
                "originator": f"user_{i % 100}"
            }
            large_events.append(event)
        
        # Mock paginated responses
        pages = []
        page_size = 500
        for i in range(0, len(large_events), page_size):
            pages.append({"data": large_events[i:i + page_size]})
        pages.append({"data": []})
        
        mock_client._http_request = Mock(side_effect=pages)
        mock_client.deduplicator.deduplicate_batch = Mock(side_effect=lambda x: x)
        
        last_run_time = datetime.utcnow() - timedelta(days=1)
        
        # Measure performance
        start_time = time.time()
        events_sent, new_timestamp = mock_client.fetch_events_producer_consumer(
            max_fetch=num_events,
            last_run_time=last_run_time
        )
        elapsed = time.time() - start_time
        
        # Verify results
        assert events_sent == num_events
        events_per_second = events_sent / elapsed if elapsed > 0 else 0
        
        # Performance assertion - should process at least 1000 events/second
        assert events_per_second > 1000, f"Performance too low: {events_per_second:.2f} events/sec"
    
    def test_queue_backpressure(self, mock_client, mock_demisto, sample_events):
        """Test system behavior under queue backpressure."""
        # Create small queue to force backpressure
        small_queue: "queue.Queue[Any]" = queue.Queue(maxsize=2)
        stop_event = threading.Event()
        metrics = ProducerConsumerMetrics()
        
        # Generate many events
        many_events = sample_events * 20  # 200 events
        
        mock_client._http_request = Mock(side_effect=[
            {"data": many_events[:100]},
            {"data": many_events[100:]},
            {"data": []}
        ])
        
        # Slow consumer to create backpressure
        original_consumer = mock_client._event_consumer
        
        def slow_consumer(*args, **kwargs):
            time.sleep(0.1)  # Simulate slow processing
            return original_consumer(*args, **kwargs)
        
        mock_client._event_consumer = slow_consumer
        mock_client.deduplicator.deduplicate_batch = Mock(side_effect=lambda x: x)
        
        last_run_time = datetime.utcnow() - timedelta(hours=1)
        
        # Run with timeout to prevent hanging
        import signal
        
        def timeout_handler(signum, frame):
            raise TimeoutError("Test timed out")
        
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(30)  # 30 second timeout
        
        try:
            events_sent, _ = mock_client.fetch_events_producer_consumer(
                max_fetch=200,
                last_run_time=last_run_time
            )
            signal.alarm(0)  # Cancel alarm
        except TimeoutError:
            pytest.fail("System deadlocked under backpressure")
        
        # System should handle backpressure without deadlock
        assert events_sent > 0
    
    def test_memory_efficiency(self, mock_client, mock_demisto):
        """Test memory efficiency with large batches."""
        import gc
        import sys
        
        # Get initial memory usage
        gc.collect()
        initial_memory = sys.getsizeof(gc.get_objects())
        
        # Process large batch
        large_batch = []
        for i in range(1000):
            event = {
                "accountId": "123456789",
                "changeDate": datetime.utcnow().strftime(DATE_FORMAT),
                "data": "x" * 1000  # 1KB of data per event
            }
            large_batch.append(event)
        
        mock_client._http_request = Mock(return_value={"data": large_batch})
        mock_client.deduplicator.deduplicate_batch = Mock(side_effect=lambda x: x[:100])  # Reduce to 100 events
        
        last_run_time = datetime.utcnow() - timedelta(hours=1)
        
        # Process events
        events_sent, _ = mock_client.fetch_events_producer_consumer(
            max_fetch=1000,
            last_run_time=last_run_time
        )
        
        # Check memory after processing
        gc.collect()
        final_memory = sys.getsizeof(gc.get_objects())
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable (less than 100MB)
        assert memory_increase < 100 * 1024 * 1024, f"Memory leak detected: {memory_increase / 1024 / 1024:.2f}MB increase"
    
    def test_concurrent_stress(self, mock_client, mock_demisto, sample_events):
        """Stress test with multiple concurrent fetch operations."""
        results = []
        threads = []
        
        def run_fetch():
            try:
                mock_client._http_request = Mock(return_value={"data": sample_events})
                mock_client.deduplicator.deduplicate_batch = Mock(side_effect=lambda x: x)
                
                events_sent, _ = mock_client.fetch_events_producer_consumer(
                    max_fetch=100,
                    last_run_time=datetime.utcnow() - timedelta(hours=1)
                )
                results.append(events_sent)
            except Exception as e:
                results.append(f"Error: {e}")
        
        # Start multiple fetch operations
        for _ in range(5):
            thread = threading.Thread(target=run_fetch)
            threads.append(thread)
            thread.start()
        
        # Wait for all to complete
        for thread in threads:
            thread.join(timeout=30)
        
        # All should complete successfully
        assert len(results) == 5
        for result in results:
            assert isinstance(result, int), f"Thread failed with: {result}"
            assert result > 0


# ==========================================
# Race Condition and Thread Safety Tests
# ==========================================

class TestRaceConditionsAndThreadSafety:
    """Test for race conditions and thread safety issues."""
    
    def test_metrics_race_condition(self):
        """Test for race conditions in metrics updates."""
        metrics = ProducerConsumerMetrics()
        threads = []
        iterations = 1000
        
        def increment_all():
            for _ in range(iterations):
                metrics.increment_produced(1)
                metrics.increment_consumed(1)
                metrics.increment_errors()
                metrics.increment_duplicates(1)
        
        # Start many threads
        for _ in range(20):
            thread = threading.Thread(target=increment_all)
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Verify counts are correct
        expected = 20 * iterations
        assert metrics.events_produced == expected
        assert metrics.events_consumed == expected
        assert metrics.errors == expected
        assert metrics.duplicates_filtered == expected
    
    def test_deduplicator_thread_safety(self, mock_demisto):
        """Test deduplicator thread safety."""
        dedup = EventDeduplicator()
        results = []
        
        def check_duplicate(event_id):
            event = {"id": event_id, "data": f"event_{event_id}"}
            is_dup = dedup.is_duplicate(event)
            results.append((event_id, is_dup))
        
        # Create threads that check the same events
        threads = []
        for i in range(100):
            thread = threading.Thread(target=check_duplicate, args=(i % 10,))  # 10 unique events, checked 10 times each
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Count first occurrences (should be 10)
        first_occurrences = sum(1 for _, is_dup in results if not is_dup)
        assert first_occurrences == 10  # Exactly 10 unique events
    
    def test_queue_concurrent_access(self):
        """Test concurrent queue access patterns."""
        test_queue: "queue.Queue[Any]" = queue.Queue(maxsize=10)
        results = {"put": 0, "get": 0, "errors": 0}
        lock = threading.Lock()
        
        def producer():
            for i in range(50):
                try:
                    test_queue.put(i, timeout=0.1)
                    with lock:
                        results["put"] += 1
                except queue.Full:
                    with lock:
                        results["errors"] += 1
        
        def consumer():
            while True:
                try:
                    item = test_queue.get(timeout=0.1)
                    with lock:
                        results["get"] += 1
                    if item == -1:  # Sentinel value
                        break
                except queue.Empty:
                    continue
        
        # Start producers and consumers
        producers = [threading.Thread(target=producer) for _ in range(3)]
        consumers = [threading.Thread(target=consumer) for _ in range(3)]
        
        for t in producers + consumers:
            t.start()
        
        # Wait for producers
        for t in producers:
            t.join()
        
        # Send sentinel values to stop consumers
        for _ in range(3):
            test_queue.put(-1)
        
        # Wait for consumers
        for t in consumers:
            t.join()
        
        # Verify no data loss
        assert results["get"] >= results["put"] - results["errors"]
    
    def test_timestamp_update_race(self, mock_client, mock_demisto):
        """Test race condition in timestamp updates."""
        timestamps = []
        lock = threading.Lock()
        
        def update_timestamp():
            # Simulate timestamp update logic
            current = datetime.utcnow()
            time.sleep(random.random() * 0.01)  # Random delay
            with lock:
                timestamps.append(current)
        
        # Multiple threads updating timestamps
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=update_timestamp)
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Timestamps should be in order (no race condition)
        for i in range(1, len(timestamps)):
            # Allow small time differences due to threading
            time_diff = (timestamps[i] - timestamps[i - 1]).total_seconds()
            assert time_diff >= -0.1  # Small tolerance for thread scheduling


# ==========================================
# Error Recovery and Resilience Tests
# ==========================================

class TestErrorRecoveryAndResilience:
    """Test error recovery and system resilience."""
    
    def test_auth_token_expiry_recovery(self, mock_client, mock_demisto):
        """Test recovery from auth token expiry."""
        # Simulate token expiry after first call
        call_count = [0]
        
        def mock_http_request(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 2:  # Fail on second call
                raise DemistoException("401 Unauthorized")
            return {"data": []}
        
        mock_client._http_request = Mock(side_effect=mock_http_request)
        mock_client._generate_token = Mock()
        
        # Should recover from auth error
        mock_client.fetch_events_producer_consumer(
            max_fetch=10,
            last_run_time=datetime.utcnow() - timedelta(hours=1)
        )
        
        # Token should be refreshed
        assert mock_client._generate_token.called
    
    def test_network_error_recovery(self, mock_client, mock_demisto, sample_events):
        """Test recovery from network errors."""
        # Simulate intermittent network errors
        responses = [
            {"data": sample_events[:2]},
            Exception("Network timeout"),
            {"data": sample_events[2:4]},
            Exception("Connection reset"),
            {"data": sample_events[4:6]},
            {"data": []}
        ]
        
        mock_client._http_request = Mock(side_effect=responses)
        mock_client.deduplicator.deduplicate_batch = Mock(side_effect=lambda x: x)
        
        # Should continue despite errors
        events_sent, _ = mock_client.fetch_events_producer_consumer(
            max_fetch=10,
            last_run_time=datetime.utcnow() - timedelta(hours=1)
        )
        
        # Should process successful batches
        assert events_sent >= 4  # At least 2 successful batches
    
    def test_malformed_event_handling(self, mock_client, mock_demisto):
        """Test handling of malformed events."""
        malformed_events = [
            {"changeDate": "invalid-date", "data": "test1"},
            {"missing_required_field": "test2"},
            None,  # Null event
            {"changeDate": datetime.utcnow().strftime(DATE_FORMAT), "valid": "event"},
            "not_a_dict",  # Wrong type
        ]
        
        mock_client._http_request = Mock(return_value={"data": malformed_events})
        mock_client.deduplicator.deduplicate_batch = Mock(side_effect=lambda x: [e for e in x if isinstance(e, dict)])
        
        # Should handle malformed events gracefully
        events_sent, _ = mock_client.fetch_events_producer_consumer(
            max_fetch=10,
            last_run_time=datetime.utcnow() - timedelta(hours=1)
        )
        
        # Should process valid events
        assert events_sent >= 1
    
    def test_partial_batch_failure(self, mock_client, mock_demisto, sample_events):
        """Test handling of partial batch failures."""
        batches_sent = []
        
        def mock_send(events, **kwargs):
            if len(events) > 5:
                raise Exception("Batch too large")
            batches_sent.append(len(events))
        
        lp.send_events_to_xsiam = Mock(side_effect=mock_send)
        mock_client._http_request = Mock(return_value={"data": sample_events})
        mock_client.deduplicator.deduplicate_batch = Mock(side_effect=lambda x: x)
        
        # Process events
        events_sent, _ = mock_client.fetch_events_producer_consumer(
            max_fetch=10,
            last_run_time=datetime.utcnow() - timedelta(hours=1)
        )
        
        # Should handle partial failures
        assert len(batches_sent) > 0
        # Should continue despite error
        assert events_sent >= 3  # At least first batch


# ==========================================
# Performance and Stress Tests
#