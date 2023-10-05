from ExtractIndicatorsCloudLogging import extract_aws_info, extract_gcp_info, extract_event_info


def test_extract_event_info():
    aws_event = {
        "userIdentity": {
            "arn": "arn:aws:sts::1111111111:assumed-role/test-1111111034205526016/test",
            "accessKeyId": "1111111111",
            "instanceId": "i-1234567890",
            "sessionContext": {
                "sessionIssuer": {
                    "userName": "test-user"
                }
            }
        },
        "sourceIPAddress": "1.1.1.1",
        "eventName": "CreateSnapshot",
        "eventSource": "ec2.amazonaws.com",
        "userAgent": "aws-sdk-go/1.43.16 (go1.20.4 X:boringcrypto; linux; amd64)",
    }
    # Test AWS event
    event_type, event_info = extract_event_info(aws_event)
    assert event_type == "AWS"
    assert len(event_info) == 7  # Make assertions for individual extracted values

    gcp_event = {
        "logName": "projects/gcp-integrations/logs/cloudaudit.googleapis.com%2Factivity",
        "protoPayload": {
            "resourceName": "coordination.test.io/v1/namespaces/test-test/leases/test-test",
            "requestMetadata": {
                "callerIp": "10.128.0.6",
                "callerSuppliedUserAgent": "test-test/v1.23.17 (linux/amd64) kubernetes/f26d814/test-test"
            },
            "authenticationInfo": {
                "principalEmail": "system:test-test"
            },
            "methodName": "io.k8s.coordination.v1.leases.update"
        }
    }

    # Test GCP event
    event_type, event_info = extract_event_info(gcp_event)
    assert event_type == "GCP"
    assert len(event_info) == 5  # Make assertions for individual extracted values


def test_extract_aws_info():
    event = {
        "userIdentity": {
            "arn": "arn:aws:sts::1111111111:assumed-role/test-1111111034205526016/test",
            "accessKeyId": "1111111111",
            "instanceId": "i-1234567890",
            "sessionContext": {
                "sessionIssuer": {
                    "userName": "test-user"
                }
            }
        },
        "sourceIPAddress": "1.1.1.1",
        "eventName": "CreateSnapshot",
        "userAgent": "aws-sdk-go/1.43.16 (go1.20.4 X:boringcrypto; linux; amd64)",
    }
    result = extract_aws_info(event)
    expected_result = (
        "arn:aws:sts::1111111111:assumed-role/test-1111111034205526016/test",
        "1111111111",
        "i-1234567890",
        "1.1.1.1",
        "test-user",
        "CreateSnapshot",
        "aws-sdk-go/1.43.16 (go1.20.4 X:boringcrypto; linux; amd64)"
    )
    assert result == expected_result


def test_extract_gcp_info():
    event = {
        "protoPayload": {
            "resourceName": "coordination.test.io/v1/namespaces/test-test/leases/test-test",
            "requestMetadata": {
                "callerIp": "10.128.0.6",
                "callerSuppliedUserAgent": "test-test/v1.23.17 (linux/amd64) kubernetes/f26d814/test-test"
            },
            "authenticationInfo": {
                "principalEmail": "system:test-test"
            },
            "methodName": "io.k8s.coordination.v1.leases.update"
        }
    }
    result = extract_gcp_info(event)
    expected_result = (
        "coordination.test.io/v1/namespaces/test-test/leases/test-test",
        "10.128.0.6",
        "system:test-test",
        "io.k8s.coordination.v1.leases.update",
        "test-test/v1.23.17 (linux/amd64) kubernetes/f26d814/test-test"
    )
    assert result == expected_result
