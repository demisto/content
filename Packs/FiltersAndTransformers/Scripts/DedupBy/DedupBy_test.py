import json
import DedupBy
import demistomock as demisto


def test_1(mocker):
    with open("./test_data/test-1.json") as f:
        test_list = json.load(f)

    for case in test_list:
        value = case["value"]
        expected = case["result"]
        for args in case.get("args") or [{}]:
            keys = args.get("keys")

            mocker.patch.object(demisto, "args", return_value={"value": value, "keys": keys})
            mocker.patch.object(DedupBy, "return_results")
            DedupBy.main()
            assert DedupBy.return_results.call_count == 1
            ret = DedupBy.return_results.call_args[0][0]
            assert json.dumps(ret) == json.dumps(expected)


def test_performance_large_input(mocker):
    """
    Given: A large dataset with 10,000 items (100 unique items with 100 duplicates each)
    When: Deduplicating by SourceIP and DestinationIP keys
    Then: Should return exactly 100 unique items
    """
    
    # Create a large dataset with duplicates
    # Each item is a dict with nested structures
    large_value = []
    num_unique = 100
    duplicates_per_item = 100
    
    for i in range(num_unique):
        # Create multiple duplicates of each unique item
        for _ in range(duplicates_per_item):
            large_value.append({
                "SourceIP": f"192.168.1.{i}",
                "DestinationIP": f"10.0.0.{i}",
                "Port": 443,
                "Protocol": "HTTPS",
                "Metadata": {
                    "timestamp": "2026-02-18T00:00:00Z",
                    "severity": "high",
                    "tags": ["network", "security", "monitoring"]
                }
            })
    
    mocker.patch.object(demisto, "args", return_value={
        "value": large_value,
        "keys": "SourceIP,DestinationIP"
    })
    mocker.patch.object(DedupBy, "return_results")

    DedupBy.main()
    result = DedupBy.return_results.call_args[0][0]

    assert len(result) == num_unique, f"Expected {num_unique} unique items, got {len(result)}"


def test_performance_comparison_no_keys(mocker):
    """
    Given: A dataset with 2,500 items (500 unique items with 5 duplicates each) containing complex nested objects
    When: Deduplicating entire objects without specifying keys
    Then: Should return exactly 500 unique items
    """
    
    # Create dataset with complex nested objects
    large_value = []
    for i in range(500):
        for _ in range(5):  # 5 duplicates each
            large_value.append({
                "id": i,
                "data": {
                    "nested": {
                        "deep": {
                            "value": f"item_{i}",
                            "list": [1, 2, 3, 4, 5]
                        }
                    }
                }
            })
    
    mocker.patch.object(demisto, "args", return_value={"value": large_value})
    mocker.patch.object(DedupBy, "return_results")

    DedupBy.main()
    result = DedupBy.return_results.call_args[0][0]

    assert len(result) == 500, f"Expected 500 unique items, got {len(result)}"
