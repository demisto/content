AUDIT_RAW_RESPONSE = {
    "meta": {
        "pagination": {
            "pageSize": 1,
            "next": "mock_pagination_token_abc123xyz"
        },
        "status": 200
    },
    "data": [
        {
            "id": "mock_audit_event_id_12345",
            "auditType": "User Logged On",
            "user": "test.user@example.com",
            "eventTime": "2025-01-01T10:00:00+0000",
            "eventInfo": "Successful authentication for test.user@example.com, Date: 2025-01-01, Time: 10:00:00 GMT, IP: 192.0.2.1, Application: Web, Method: Cloud",
            "category": "authentication_logs"
        }
    ],
    "fail": []
}

SIEM_RAW_RESPONSE = {
    "value": [
        {
            "numberAttachments": "0",
            "subject": "Test Email Subject",
            "senderEnvelope": "sender@example.com",
            "rejectionType": "Header Rejected",
            "aggregateId": "mock_aggregate_id_abc123",
            "processingId": "mock_processing_id_xyz789_1234567890",
            "tlsCipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "action": "Rej",
            "spamInfo": None,
            "senderIp": "192.0.2.100",
            "timestamp": 1704067200000,
            "direction": "internal",
            "spamProcessingDetail": None,
            "spamDetectionLevel": None,
            "tlsVersion": "TLSv1.2",
            "messageId": "<mock.message.id.12345@example.mimecast.lan>",
            "senderHeader": "sender@example.com",
            "eventType": "receipt",
            "accountId": "MOCK_ACCOUNT_123",
            "virusFound": "Rejected by header based Blocked Senders: sender@example.com",
            "rejectionInfo": "Rejected by header based Blocked Senders: sender@example.com",
            "recipients": "recipient@example.com",
            "rejectionCode": "0",
            "spamScore": None,
            "subType": "Rej",
            "receiptErrors": None
        },
        {
            "numberAttachments": "1",
            "subject": "Another Test Email",
            "senderEnvelope": "another.sender@example.com",
            "rejectionType": "Header Rejected",
            "aggregateId": "mock_aggregate_id_def456",
            "processingId": "mock_processing_id_uvw321_9876543210",
            "tlsCipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "action": "Rej",
            "spamInfo": None,
            "senderIp": "192.0.2.200",
            "timestamp": 1704070800000,
            "direction": "internal",
            "spamProcessingDetail": None,
            "spamDetectionLevel": None,
            "tlsVersion": "TLSv1.2",
            "messageId": "<mock.message.id.67890@example.mimecast.lan>",
            "senderHeader": "another.sender@example.com",
            "eventType": "receipt",
            "accountId": "MOCK_ACCOUNT_456",
            "virusFound": "Rejected by header based Blocked Senders: another.sender@example.com",
            "rejectionInfo": "Rejected by header based Blocked Senders: another.sender@example.com",
            "recipients": "another.recipient@example.com",
            "rejectionCode": "0",
            "spamScore": None,
            "subType": "Rej",
            "receiptErrors": None
        }
    ],
    "@nextLink": "mock_next_link_token_base64_encoded_string",
    "@nextPage": "mock_next_page_token_base64_encoded_string",
    "pageSize": 2,
    "isCaughtUp": False
}
