# CSP Command Implementation Rules

This document provides guidelines for implementing commands in Cloud Service Provider (CSP) packs: AWS, GCP, Azure, and OCI.

---

## Quick Start

When you receive a command specification JSON, follow these steps:

### Step 1: Read This Rules File
Always start by reading this file to understand the implementation guidelines.

### Step 2: Analyze the JSON Specification

The JSON will contain:
```json
{
  "command_name": "csp-service-resource-action",
  "is_command_exists": true|false,
  "documentation_url": "https://...",
  "permissions": "service:Action",
  "arguments": ["arg1", "arg2"],
  "human_readable_output": "Template with {placeholders}",
  "outputs": "*",
  "context_output_base_path": "CSP.Service.Resource",
  "is_potentially_harmful": false,
  "should_generate_unittests": true
}
```

### Step 3: Determine the CSP and Pack

From `command_name`, identify the CSP:
- `aws-*` → AWS pack (`Packs/AWS/`)
- `gcp-*` → GCP pack (`Packs/GCP/`)
- `azure-*` → Azure pack (`Packs/Azure/`)
- `oci-*` → OCI pack (`Packs/OCI/`)

### Step 4: Check for Legacy Implementation

**If `is_command_exists: true`:**

1. Identify the legacy pack from the command name:
   - `aws-s3-*` → `Packs/AWS-S3/Integrations/AWS-S3/AWS-S3.py`
   - `aws-ec2-*` → `Packs/AWS-EC2/Integrations/AWS-EC2/AWS-EC2.py`
   - `aws-iam-*` → `Packs/AWS-IAM/Integrations/AWS-IAM/AWS-IAM.py`
   - Similar pattern for other CSPs

2. Search for the command implementation in the legacy pack
3. Understand the logic, API calls, and response handling
4. Use it as a reference for the new implementation

**If `is_command_exists: false`:**

1. Read the `documentation_url` to understand the API
2. Implement from scratch following the patterns in the target pack

### Step 5: Read API Documentation

Always review the official API documentation at `documentation_url` to understand:
- Required and optional parameters
- Response structure
- Error conditions
- Special behaviors

### Step 6: Implement the Command

Implement in three files:

1. **{CSP}.py** - Python implementation
2. **{CSP}.yml** - YAML configuration
3. **{CSP}_test.py** - Unit tests (if `should_generate_unittests: true`)

---

## Implementation Details

### File 1: Python Implementation ({CSP}.py)

#### Location in File

Commands are organized by service in class-based structure:

```python
class ServiceName:
    """CSP ServiceName operations"""
    
    @staticmethod
    def action_resource_command(client, args: Dict[str, Any]) -> CommandResults:
        """Command implementation"""
        pass
```

**Find the right class:**
- `aws-ec2-*` → `EC2` class
- `aws-s3-*` → `S3` class
- `gcp-compute-*` → `Compute` class
- `azure-vm-*` → `VirtualMachines` class

#### Implementation Template

```python
@staticmethod
def action_resource_command(client, args: Dict[str, Any]) -> CommandResults:
    """
    Brief description from JSON specification.
    
    Args:
        client: CSP SDK client
        args: Command arguments
        
    Returns:
        CommandResults with outputs and human readable
    """
    # 1. Extract arguments (use snake_case)
    arg1 = args.get('arg1')
    arg2 = args.get('arg2')
    
    # 2. Build API parameters
    params = {
        'Arg1': arg1,  # SDK might use different casing
    }
    
    if arg2:
        params['Arg2'] = arg2
    
    # 3. Call API with error handling
    try:
        response = client.api_method(**params)
    except Exception as e:
        # Use CSP-specific error handler
        ErrorHandler.handle_error(e, 'ServiceName', 'api_method')
    
    # 4. Validate response (CSP-specific)
    # AWS: Check HTTPStatusCode
    # Others: Check response structure
    
    # 5. Extract data
    data = response.get('DataKey', {})
    
    # 6. Serialize (handle dates, complex objects)
    serialized = serialize_response(data)
    
    # 7. Create human-readable using template from JSON
    # Replace {placeholders} with actual values
    human_readable = "Template with actual values"
    
    # 8. Return CommandResults
    return CommandResults(
        outputs_prefix='CSP.Service.Resource',  # From context_output_base_path
        outputs_key_field='UniqueField',
        outputs=serialized,
        readable_output=human_readable,
        raw_response=response
    )
```

#### Register Command

Add to `COMMANDS_MAPPING` dictionary (near end of file):

```python
COMMANDS_MAPPING = {
    'command-name': ServiceClass.method_name,
}
```

#### Add Permissions

Add to permissions list (near end of file):

**AWS:**
```python
REQUIRED_ACTIONS = [
    'service:Action',  # From JSON 'permissions' field
]
```

**GCP/Azure/OCI:** Similar pattern with their permission lists

---

### File 2: YAML Configuration ({CSP}.yml)

Add command definition under `script.commands`:

```yaml
  - name: command-name-from-json
    description: Description from JSON
    execution: true  # ONLY if is_potentially_harmful=true
    arguments:
    # Standard CSP arguments (account_id/project_id/subscription_id, region/zone)
    - name: account_id  # or project_id, subscription_id, etc.
      description: The CSP account identifier.
      required: true
    - name: region  # or zone, location, etc.
      description: The CSP region/zone.
      required: true
      auto: PREDEFINED
      predefined:
      - region1
      - region2
      # ... all regions
    
    # Custom arguments from JSON 'arguments' field
    - name: arg1
      description: Description from documentation.
      required: true
    - name: arg2
      description: Description from documentation.
      required: false
      auto: PREDEFINED
      predefined:
      - value1
      - value2
    
    outputs:
    # If JSON outputs="*", include all relevant fields from API response
    # Otherwise, use specific fields from JSON outputs array
    - contextPath: CSP.Service.Resource.Field1
      description: Description.
      type: string
    - contextPath: CSP.Service.Resource.Field2
      description: Description.
      type: number
```

**Key Points:**
- Use `execution: true` if `is_potentially_harmful: true`
- Arguments use `snake_case` naming
- Include all CSP-standard arguments (account_id, region, etc.)
- If `outputs: "*"`, determine fields from API documentation
- Context paths follow `context_output_base_path` from JSON

---

### File 3: Unit Tests ({CSP}_test.py)

**Only if `should_generate_unittests: true`**

Add test function following existing patterns:

```python
def test_command_name(mocker):
    """Test command_name command"""
    # Mock the client
    mock_client = mocker.Mock()
    
    # Mock the API response
    mock_client.api_method.return_value = {
        'ResponseMetadata': {'HTTPStatusCode': 200},
        'DataKey': {
            'Field1': 'value1',
            'Field2': 'value2'
        }
    }
    
    # Prepare arguments
    args = {
        'arg1': 'test_value1',
        'arg2': 'test_value2'
    }
    
    # Execute command
    result = ServiceClass.command_name_command(mock_client, args)
    
    # Assertions
    assert result.outputs_prefix == 'CSP.Service.Resource'
    assert result.outputs['Field1'] == 'value1'
    assert 'success' in result.readable_output.lower()
    
    # Verify API was called correctly
    mock_client.api_method.assert_called_once()
```

---

## CSP-Specific Patterns

### AWS

**Files:**
- Implementation: `Packs/AWS/Integrations/AWS/AWS.py`
- Configuration: `Packs/AWS/Integrations/AWS/AWS.yml`
- Tests: `Packs/AWS/Integrations/AWS/AWS_test.py`

**Error Handler:** `AWSErrorHandler.handle_error(e, service, operation)`

**Response Validation:**
```python
if response.get('ResponseMetadata', {}).get('HTTPStatusCode') != 200:
    raise Exception(f"Failed: {response}")
```

**Serialization:** `serialize_response_with_datetime_encoding(obj)`

**Standard Arguments:** `account_id`, `region`

**Permissions Format:** `service:Action` (e.g., `s3:PutBucketOwnershipControls`)

### GCP

**Files:**
- Implementation: `Packs/GCP/Integrations/GCP/GCP.py`
- Configuration: `Packs/GCP/Integrations/GCP/GCP.yml`
- Tests: `Packs/GCP/Integrations/GCP/GCP_test.py`

**Standard Arguments:** `project_id`, `zone` (optional)

**Permissions Format:** `roles/service.role`

### Azure

**Files:**
- Implementation: `Packs/Azure/Integrations/Azure/Azure.py`
- Configuration: `Packs/Azure/Integrations/Azure/Azure.yml`
- Tests: `Packs/Azure/Integrations/Azure/Azure_test.py`

**Standard Arguments:** `subscription_id`, `resource_group_name`

**Permissions Format:** `Microsoft.Service/resource/action`

### OCI

**Files:**
- Implementation: `Packs/OCI/Integrations/OCI/OCI.py`
- Configuration: `Packs/OCI/Integrations/OCI/OCI.yml`
- Tests: `Packs/OCI/Integrations/OCI/OCI_test.py`

**Standard Arguments:** `compartment_id`, `region`

---

## Working with the JSON Specification

### Example Workflow

Given this JSON:
```json
{
  "command_name": "aws-s3api-put-bucket-ownership-controls",
  "is_command_exists": true,
  "documentation_url": "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketOwnershipControls.html",
  "permissions": "s3:PutBucketOwnershipControls",
  "arguments": ["bucket", "OwnershipControls", "Rule"],
  "human_readable_output": "Bucket Ownership Controls successfully updated for {bucket}",
  "outputs": "*",
  "context_output_base_path": "AWS.S3-Bucket",
  "is_potentially_harmful": false,
  "should_generate_unittests": true
}
```

**Step-by-step:**

1. **Identify CSP**: `aws-*` → AWS pack
2. **Check legacy**: `is_command_exists: true` → Search in `Packs/AWS-S3/`
3. **Read docs**: Visit the `documentation_url`
4. **Implement**:
   - Add method to `S3` class in `AWS.py`
   - Add to `COMMANDS_MAPPING`
   - Add `s3:PutBucketOwnershipControls` to `REQUIRED_ACTIONS`
5. **Configure YAML**: Add command definition in `AWS.yml`
6. **Write tests**: Add test in `AWS_test.py` (because `should_generate_unittests: true`)
7. **Release notes**: Create release note file

### Understanding JSON Fields

#### `command_name`
The full command name. Extract:
- CSP: First part before first `-` (aws, gcp, azure, oci)
- Service: Second part (s3api, ec2, compute, vm)
- Action: Remaining parts (put-bucket-ownership-controls)

#### `is_command_exists`
- `true`: Search legacy pack for reference implementation
- `false`: Implement from scratch using API docs

#### `documentation_url`
Official API documentation. Read to understand:
- Request parameters
- Response structure
- Error conditions
- Examples

#### `permissions`
Add to the pack's permissions list:
- AWS: `REQUIRED_ACTIONS` list
- GCP: `REQUIRED_ROLES` list
- Azure: `REQUIRED_PERMISSIONS` list
- OCI: `REQUIRED_POLICIES` list

#### `arguments`
List of argument names. For each:
1. Check API docs for parameter details
2. Use snake_case in implementation
3. Add to YAML with proper description and type

#### `human_readable_output`
Template for success message. Replace `{placeholders}` with actual values:
```python
human_readable = f"Bucket Ownership Controls successfully updated for {bucket_name}"
```

#### `outputs`
- `"*"`: Include all relevant fields from API response
- Array: Include only specified fields

#### `context_output_base_path`
Base path for context outputs. Append field names:
- `AWS.S3-Bucket` → `AWS.S3-Bucket.BucketName`, `AWS.S3-Bucket.Region`

#### `is_potentially_harmful`
- `true`: Add `execution: true` to YAML
- `false`: Don't add execution flag

#### `should_generate_unittests`
- `true`: Add test function to `{CSP}_test.py`
- `false`: Skip unit tests

---

## Implementation Patterns

### Pattern 1: Command Exists in Legacy Pack

**Workflow:**
1. Navigate to legacy pack (e.g., `Packs/AWS-S3/`)
2. Search for command implementation
3. Understand the logic and API calls
4. Adapt to new structure:
   - Convert function → static method in service class
   - Change camelCase → snake_case for arguments
   - Use centralized error handler
   - Apply response serialization
   - Update SDK calls if needed

**Example:**

Legacy (`AWS-S3.py`):
```python
def put_bucket_ownership_controls(args):
    client = get_client('s3')
    bucket = args.get('bucket')
    rule = args.get('Rule')
    
    response = client.put_bucket_ownership_controls(
        Bucket=bucket,
        OwnershipControls={'Rules': [{'ObjectOwnership': rule}]}
    )
    return response
```

New (`AWS.py`):
```python
@staticmethod
def put_bucket_ownership_controls_command(client: BotoClient, args: Dict[str, Any]) -> CommandResults:
    """Creates or modifies OwnershipControls for an Amazon S3 bucket."""
    
    bucket = args.get('bucket')
    rule = args.get('ownership_controls_rule')  # snake_case
    
    try:
        response = client.put_bucket_ownership_controls(
            Bucket=bucket,
            OwnershipControls={'Rules': [{'ObjectOwnership': rule}]}
        )
    except ClientError as e:
        AWSErrorHandler.handle_error(e, 'S3', 'put_bucket_ownership_controls')
    
    if response.get('ResponseMetadata', {}).get('HTTPStatusCode') != 200:
        raise Exception(f"Failed to update ownership controls: {response}")
    
    return CommandResults(
        readable_output=f"Bucket Ownership Controls successfully updated for {bucket}",
        raw_response=response
    )
```

### Pattern 2: New Command (No Legacy)

**Workflow:**
1. Read API documentation thoroughly
2. Identify required and optional parameters
3. Understand response structure
4. Implement following existing patterns in the pack
5. Test with various argument combinations

---

## Code Requirements

### Mandatory Elements

1. **Error Handling**: Always use centralized error handler
   ```python
   try:
       response = client.api_call(**params)
   except Exception as e:
       ErrorHandler.handle_error(e, 'Service', 'operation')
   ```

2. **Response Validation**: Validate API responses
   ```python
   # AWS
   if response.get('ResponseMetadata', {}).get('HTTPStatusCode') != 200:
       raise Exception(f"Failed: {response}")
   ```

3. **Serialization**: Use pack-specific serialization helpers
   ```python
   # AWS
   serialized = serialize_response_with_datetime_encoding(data)
   ```

4. **Human-Readable Output**: Use template from JSON
   ```python
   # Replace {placeholders} with actual values
   readable = f"Template with {actual_value}"
   ```

5. **Command Registration**: Add to COMMANDS_MAPPING
   ```python
   COMMANDS_MAPPING = {
       'command-name': ServiceClass.method_name,
   }
   ```

6. **Permissions**: Add to permissions list
   ```python
   REQUIRED_ACTIONS = ['permission:from:json']
   ```

### Argument Naming

**Always use snake_case in Python:**
- JSON: `["bucket", "OwnershipControls"]`
- Python: `args.get('bucket')`, `args.get('ownership_controls')`
- YAML: `name: ownership_controls`

**SDK calls may use different casing:**
```python
# Argument in Python: ownership_controls_rule
# SDK parameter: OwnershipControls
client.put_bucket_ownership_controls(
    Bucket=bucket,
    OwnershipControls={'Rules': [{'ObjectOwnership': ownership_controls_rule}]}
)
```

---

## YAML Configuration

### Template

```yaml
  - name: {command_name from JSON}
    description: {description from JSON or API docs}
    execution: true  # ONLY if is_potentially_harmful=true
    arguments:
    # CSP-standard arguments
    - name: account_id  # or project_id, subscription_id, compartment_id
      description: The CSP account identifier.
      required: true
    
    - name: region  # or zone, location
      description: The CSP region/zone.
      required: true
      auto: PREDEFINED
      predefined:
      - location1
      - location2
      # ... all locations
    
    # Custom arguments from JSON
    - name: arg1
      description: From API documentation.
      required: true
    
    - name: arg2
      description: From API documentation.
      required: false
      auto: PREDEFINED
      predefined:
      - value1
      - value2
      defaultValue: value1
    
    outputs:
    # If JSON outputs="*", list all relevant fields from API docs
    # Otherwise, use fields from JSON outputs array
    - contextPath: {context_output_base_path}.Field1
      description: Description from API docs.
      type: string
    - contextPath: {context_output_base_path}.Field2
      description: Description from API docs.
      type: number
```

---

## Unit Tests

### When to Generate

Only if `should_generate_unittests: true` in JSON.

### Test Template

```python
def test_command_name(mocker):
    """
    Given: Command arguments
    When: Calling command_name_command
    Then: Verify correct API call and output
    """
    # Arrange
    mock_client = mocker.Mock()
    mock_client.api_method.return_value = {
        'ResponseMetadata': {'HTTPStatusCode': 200},
        'Field1': 'value1',
        'Field2': 'value2'
    }
    
    args = {
        'arg1': 'test1',
        'arg2': 'test2'
    }
    
    # Act
    result = ServiceClass.command_name_command(mock_client, args)
    
    # Assert
    assert result.outputs_prefix == 'CSP.Service.Resource'
    assert result.outputs['Field1'] == 'value1'
    assert 'success' in result.readable_output.lower()
    mock_client.api_method.assert_called_once()
```

---

## Release Notes

### Create Release Note File

`Packs/{PackName}/ReleaseNotes/X_Y_Z.md`:

```markdown
#### Integrations

##### {Integration Display Name}

- Added the **{command-name}** command.
```

Or for multiple commands:
```markdown
#### Integrations

##### {Integration Display Name}

- Added {N} new commands for {service}:
  - **command-1** - Description.
  - **command-2** - Description.
```

### Update Pack Version

`Packs/{PackName}/pack_metadata.json`:
```json
{
  "currentVersion": "X.Y.Z"
}
```

Increment:
- **Patch (Z)**: Bug fixes, small updates
- **Minor (Y)**: New commands, new features
- **Major (X)**: Breaking changes

---

## Complete Example

### Given JSON:
```json
{
  "command_name": "aws-s3api-put-bucket-ownership-controls",
  "is_command_exists": true,
  "documentation_url": "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketOwnershipControls.html",
  "permissions": "s3:PutBucketOwnershipControls",
  "arguments": ["bucket", "ownership_controls_rule"],
  "human_readable_output": "Bucket Ownership Controls successfully updated for {bucket}",
  "outputs": "*",
  "context_output_base_path": "AWS.S3-Bucket",
  "is_potentially_harmful": false,
  "should_generate_unittests": true
}
```

### Implementation Steps:

1. ✅ Read this rules file
2. ✅ Identify: AWS pack, S3 service
3. ✅ Check legacy: `Packs/AWS-S3/Integrations/AWS-S3/AWS-S3.py`
4. ✅ Read API docs at documentation_url
5. ✅ Implement in `S3` class in `AWS.py`
6. ✅ Add to `COMMANDS_MAPPING`
7. ✅ Add `s3:PutBucketOwnershipControls` to `REQUIRED_ACTIONS`
8. ✅ Add YAML definition in `AWS.yml` (no `execution: true` since not harmful)
9. ✅ Add test in `AWS_test.py`
10. ✅ Create release notes
11. ✅ Update pack version

---

## Quick Reference

### Command Name → Pack Location

| Command Prefix | Pack | Implementation File |
|---------------|------|-------------------|
| `aws-*` | AWS | `Packs/AWS/Integrations/AWS/AWS.py` |
| `gcp-*` | GCP | `Packs/GCP/Integrations/GCP/GCP.py` |
| `azure-*` | Azure | `Packs/Azure/Integrations/Azure/Azure.py` |
| `oci-*` | OCI | `Packs/OCI/Integrations/OCI/OCI.py` |

### Legacy Pack Patterns

| Command Prefix | Legacy Pack Path |
|---------------|-----------------|
| `aws-s3-*` | `Packs/AWS-S3/Integrations/AWS-S3/AWS-S3.py` |
| `aws-ec2-*` | `Packs/AWS-EC2/Integrations/AWS-EC2/AWS-EC2.py` |
| `aws-iam-*` | `Packs/AWS-IAM/Integrations/AWS-IAM/AWS-IAM.py` |
| `gcp-compute-*` | `Packs/GCP-Compute/Integrations/GCP-Compute/GCP-Compute.py` |
| `azure-vm-*` | `Packs/AzureCompute/Integrations/AzureCompute/AzureCompute.py` |

### Files to Modify

For every command implementation:

1. **{CSP}.py** - Add method to service class, register in COMMANDS_MAPPING, add permissions
2. **{CSP}.yml** - Add command definition with arguments and outputs
3. **{CSP}_test.py** - Add unit test (if `should_generate_unittests: true`)
4. **ReleaseNotes/X_Y_Z.md** - Document the change
5. **pack_metadata.json** - Increment version

---

## Common Mistakes to Avoid

1. ❌ Not reading the rules file first
2. ❌ Not checking legacy implementation when `is_command_exists: true`
3. ❌ Using camelCase for argument names
4. ❌ Forgetting to register command in COMMANDS_MAPPING
5. ❌ Missing permissions in permissions list
6. ❌ Not setting `execution: true` when `is_potentially_harmful: true`
7. ❌ Not generating tests when `should_generate_unittests: true`
8. ❌ Not creating release notes
9. ❌ Not updating pack version
10. ❌ Not using centralized error handler

---

## Summary

**When you receive a command specification JSON:**

1. Read this rules file
2. Identify CSP and target pack
3. Check for legacy implementation if `is_command_exists: true`
4. Read API documentation at `documentation_url`
5. Implement in {CSP}.py following patterns
6. Configure in {CSP}.yml
7. Write tests if `should_generate_unittests: true`
8. Create release notes
9. Update pack version

**Remember:** Consistency with existing code is more important than perfection. Follow the patterns already established in the target pack.

---

## Continuous Improvement Through Feedback

### The Iterative Learning Process

This rules file is a **living document** that evolves through implementation feedback. Every command implementation is an opportunity to refine and improve these guidelines.

### How the Feedback Loop Works

**During Implementation:**

1. **Initial Implementation**: Follow the current rules
2. **Receive Feedback**: User provides corrections or improvements
3. **Iterate**: Fix the implementation based on feedback
4. **Repeat**: Continue until implementation is approved
5. **Learn**: Analyze what needed correction and why

**After Implementation:**

6. **Update This File**: Incorporate lessons learned into these rules
7. **Sharpen Guidelines**: Make rules more precise based on real issues encountered
8. **Add Examples**: Document the corrected approach for future reference

### What to Update After Feedback

When you receive feedback during implementation, note:

1. **What was incorrect?**
   - Specific code that needed fixing
   - Misunderstood requirements
   - Missing elements

2. **Why was it incorrect?**
   - Unclear rule in this file
   - Missing information
   - Incorrect assumption
   - Overlooked detail

3. **How to prevent it?**
   - What rule would have caught this?
   - What example would have clarified?
   - What checklist item was missing?

### Updating This File

**After completing an implementation with feedback, update:**

#### 1. Common Mistakes Section
Add new pitfalls discovered:
```markdown
❌ [New mistake identified from feedback]
```

#### 2. Code Templates
Enhance templates with corrections:
```python
# Add missing validation, error handling, or pattern
```

#### 3. Examples
Add real examples from the implementation:
```markdown
**Example from [command-name] implementation:**
[Show the corrected approach]
```

#### 4. Checklists
Add missing checklist items:
```markdown
- [ ] [New validation step discovered]
```

#### 5. Best Practices
Document new patterns:
```markdown
### [New Pattern Name]
[Description and example from feedback]
```

### Self-Sharpening Principles

**With each feedback iteration:**

1. **Be Specific**: Don't add vague rules - add concrete, actionable guidelines
2. **Be Clear**: If something was misunderstood, clarify it
3. **Be Complete**: If something was missing, add it
4. **Be Practical**: Focus on real issues, not theoretical ones
5. **Be Organized**: Add to the appropriate section

### Example: Learning from Feedback

**Scenario 1: YAML Indentation Feedback**

*Feedback received:* "The YAML indentation is wrong - commands should be indented with 2 spaces under `script.commands`"

*Action after fixing:*
```markdown
### YAML Indentation Rules (Added after feedback)
- Commands: 2 spaces under `script.commands` (use `  - name:`)
- Arguments: 4 spaces under command (use `    - name:`)
- Outputs: 4 spaces under command (use `    - contextPath:`)
- Nested items: Add 2 spaces per level

**Common mistake:** Using inconsistent indentation or tabs instead of spaces.
```

**Scenario 2: Missing Response Validation**

*Feedback received:* "You forgot to validate the HTTP status code"

*Action after fixing:*
```markdown
### Response Validation (Enhanced after feedback)
**ALWAYS validate responses for state-changing operations:**

```python
# For AWS - MANDATORY for create/update/delete operations
if response.get('ResponseMetadata', {}).get('HTTPStatusCode') != 200:
    raise Exception(f"Failed to execute command: {response}")
```

**Why:** Ensures the operation actually succeeded before returning success.
**When:** All commands with `is_potentially_harmful: true`
```

**Scenario 3: Incorrect Context Path**

*Feedback received:* "Context path should be `AWS.S3-Buckets` not `AWS.S3.Buckets`"

*Action after fixing:*
```markdown
### Context Path Conventions (Clarified after feedback)

**AWS-specific patterns:**
- S3 Buckets: `AWS.S3-Buckets` (note the hyphen)
- EC2 Instances: `AWS.EC2.Instances` (note the dot)
- IAM Users: `AWS.IAM.Users`

**Rule:** Check existing commands in the same service for the correct pattern.
```

### Commitment to Continuous Improvement

**Every feedback is valuable:**
- It reveals gaps in the rules
- It highlights unclear instructions
- It shows real-world edge cases
- It improves future implementations

**Your responsibility:**
- Don't just fix the code
- Understand the underlying principle
- Update this file to prevent the same issue
- Make the next implementation smoother

### The Goal

**Eventually, this rules file should be so comprehensive that:**
- Implementations require minimal feedback
- Common mistakes are prevented upfront
- Patterns are clear and well-documented
- Examples cover most scenarios

**Each iteration brings us closer to this goal.**

---

## Version History

Track major updates to this rules file:

- **v1.0** - Initial creation with basic guidelines
- **v1.1** - Added feedback loop section (current)
- *Future versions will be added as the file evolves through feedback*

---

**Final Note:** This file is never "complete" - it grows and improves with every command implementation. Treat feedback as an opportunity to make this resource better for everyone.