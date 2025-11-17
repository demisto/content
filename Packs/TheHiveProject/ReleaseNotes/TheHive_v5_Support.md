# TheHive v5 Support Release Notes

## New Features
- **TheHive v5 Compatibility**: Added full support for TheHive version 5 API while maintaining backward compatibility with versions 3 and 4.

## Changes Made

### Version Detection
- Enhanced version detection to automatically identify TheHive v5 instances
- The integration now checks the v5 endpoint (`/api/v1/status/public`) first, then falls back to v3/v4 endpoints
- Automatic version detection ensures the correct API endpoints are used

### Updated Commands for v5 Support
The following commands have been updated to work with TheHive v5:

1. **thehive-get-case**
   - Now uses `/api/v1/case/{caseId}` endpoint for v5
   - Automatically normalizes v5 response format to maintain consistency
   - Maps v5 field names (e.g., `_id`, `_createdAt`) to standard field names

2. **thehive-get-case-tasks**
   - Uses `/api/v1/case/{caseId}/task` endpoint for v5
   - Handles v5's paginated response format

3. **thehive-get-task**
   - Uses `/api/v1/task/{taskId}` endpoint for v5
   - Normalizes task response structure

4. **thehive-list-observables**
   - Uses `/api/v1/case/{caseId}/observable` endpoint for v5
   - Handles v5's observable response format

5. **thehive-search-cases**
   - Uses `/api/v1/case/_search` endpoint for v5
   - Maintains search functionality across all versions

### Field Mapping
The integration automatically maps TheHive v5 field names to maintain consistency:
- `_id` → `id`
- `_createdAt` → `createdAt`
- `_createdBy` → `createdBy`
- `_updatedAt` → `updatedAt`

## Testing Instructions

### 1. Version Detection Test
```python
# The integration will automatically detect the version
# Check the version in the integration logs or use:
!thehive-get-version
```

### 2. Get Case Test
```python
# Test getting a case (works with v3, v4, and v5)
!thehive-get-case id="~12345678"
```

### 3. Get Case Tasks Test
```python
# Test getting tasks for a case
!thehive-get-case-tasks id="~12345678"
```

### 4. List Observables Test
```python
# Test listing observables for a case
!thehive-list-observables id="~12345678"
```

## Backward Compatibility
- All existing integrations with TheHive v3 and v4 will continue to work without any changes
- The integration automatically detects the version and uses the appropriate API endpoints
- No configuration changes are required when upgrading from v3/v4 to v5

## Known Limitations
- Some v5-specific features may not be fully exposed yet
- Custom fields handling may vary between versions
- Authentication remains Bearer token-based for all versions

## Troubleshooting

### Version Detection Issues
If the integration fails to detect v5:
1. Ensure the API endpoint is accessible at `https://your-thehive-instance/api/v1/status/public`
2. Check that the Bearer token has appropriate permissions
3. Review the integration logs for connection errors

### Field Mapping Issues
If fields appear with underscore prefixes (_id, _createdAt):
- The field normalization may have failed
- Check the integration logs for mapping errors
- Report the issue with the specific command and response

## Support
For issues or questions about TheHive v5 support:
1. Check the integration logs for detailed error messages
2. Verify your TheHive instance version
3. Ensure your API token has the necessary permissions for v5