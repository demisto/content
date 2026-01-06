# Automation Command Generator

| Section   | Purpose |
|-----------|---------|
| SETUP     | Verify prerequisites before command generation |
| PURPOSE   | Define command generation goals and scope |
| WORKFLOW  | Step-by-step command implementation process |
| BEHAVIOR  | Deterministic command generation rules |
| FORMAT    | Code structure and formatting standards |
| VALIDATION| Quality checks before finalizing implementation |
| EXAMPLES  | Illustrative command patterns |

---

## SETUP

MUST verify the following prerequisites exist before proceeding:

1. **Command Template File**: `Packs/COMMAND_TEMPLATE.json` MUST exist in the workspace.
2. **Implementation Rules**: `Packs/<PackName>/COMMAND_IMPLEMENTATION_RULES.md` SHOULD exist for pack-specific guidelines.
3. **Legacy Pack Access** (if `is_command_exists: true`):
   - For AWS commands: Legacy pack at `Packs/AWS-EC2/` MUST be accessible
   - For GCP commands: Legacy pack at `Packs/GCP-Compute/` MUST be accessible
   - For Azure commands: Legacy pack at `Packs/Azure-Compute/` MUST be accessible
   - For OCI commands: Legacy pack at `Packs/OCI-Compute/` MUST be accessible

IF any required file is missing, MUST instruct the user how to create or access it.
MUST NOT proceed with command generation if prerequisites are not met.

---

## PURPOSE

MUST generate complete, production-ready command implementations for cloud service provider (CSP) integrations including:
1. **Python Implementation**: Command function with proper error handling and parameter validation
2. **YAML Definition**: Command configuration with arguments, outputs, and descriptions
3. **Unit Tests**: Comprehensive test coverage (15-20 tests per command)
4. **Release Notes**: Version-specific changelog entry
5. **Pack Version Update**: Increment pack version appropriately

MUST enforce strict quality standards:
- Type-safe parameter handling
- Comprehensive error handling
- Consistent naming conventions (snake_case for arguments)
- Proper indentation and formatting
- Complete documentation

---

## WORKFLOW

### Workflow 1: Analyze Command Specification

1. **Read Command Template**: Parse `Packs/COMMAND_TEMPLATE.json` for the target command
2. **Extract Required Fields**:
   - `command_name`: The command identifier (e.g., "aws-ec2-image-copy")
   - `is_command_exists`: Boolean indicating if legacy implementation exists
   - `documentation_url`: Official API documentation URL (optional but recommended)
   - `additional_context`: Any extra implementation notes (optional)

3. **Determine Implementation Strategy**:
   - IF `is_command_exists: true`: Search for legacy implementation in corresponding pack
   - IF `is_command_exists: false`: Use documentation_url and additional_context to design from scratch

### Workflow 2: Find Legacy Implementation (if exists)

1. **Locate Legacy Pack**:
   - AWS commands: Search in `Packs/AWS-EC2/Integrations/AWS-EC2/`
   - GCP commands: Search in `Packs/GCP-Compute/Integrations/GCP-Compute/`
   - Azure commands: Search in `Packs/Azure-Compute/Integrations/Azure-Compute/`
   - OCI commands: Search in `Packs/OCI-Compute/Integrations/OCI-Compute/`

2. **Search for Implementation**:
   - Use `search_files` to find the command name in Python files
   - Read the legacy Python implementation
   - Read the legacy YAML definition
   - Note all parameters, return values, and error handling patterns

3. **Extract Implementation Details**:
   - Function signature and parameters
   - API client method calls
   - Parameter transformations (e.g., comma-separated strings to lists)
   - Error handling patterns
   - Return value structure
   - Output context paths

### Workflow 3: Design New Implementation (if no legacy exists)

1. **Analyze Documentation**:
   - Read the `documentation_url` to understand the API
   - Identify required and optional parameters
   - Understand the response structure
   - Note any special considerations (pagination, waiters, etc.)

2. **Design Command Structure**:
   - Determine command category (describe, create, modify, delete, waiter)
   - Identify required parameters (account_id, region always required)
   - Map API parameters to command arguments (use snake_case)
   - Design output context paths following AWS.ServiceName.ResourceType pattern
   - Determine if command modifies resources (needs `execution: true`)

3. **Ask User for Clarification** (if needed):
   - Ambiguous parameter mappings
   - Missing documentation details
   - Special handling requirements

### Workflow 4: Implement Python Command

1. **Locate Target File**: `Packs/<PackName>/Integrations/<PackName>/<PackName>.py`

2. **Identify Service Class**:
   - AWS: EC2, S3, IAM, EKS, RDS, CloudTrail, ECS, Lambda, KMS, ELB, ACM, CostExplorer, Budgets
   - Determine which class the command belongs to based on service

3. **Implement Command Function**:
   ```python
   @staticmethod
   def command_name_command(client: Any, args: dict[str, Any]) -> CommandResults:
       """
       Command description.
       
       Args:
           client: Boto3 service client
           args: Command arguments from XSOAR
           
       Returns:
           CommandResults with outputs and readable output
       """
       try:
           # Extract and validate parameters
           required_param = args.get("required_param")
           if not required_param:
               raise DemistoException("required_param parameter is required")
           
           # Transform parameters (e.g., comma-separated to list)
           optional_list = parse_resource_ids(args.get("optional_list")) if args.get("optional_list") else None
           
           # Build API call parameters
           api_params = remove_nulls_from_dictionary({
               "RequiredParam": required_param,
               "OptionalList": optional_list,
           })
           
           # Call AWS API
           print_debug_logs(client, f"Calling API with params: {api_params}")
           response = client.api_method(**api_params)
           
           # Validate response
           if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
               AWSErrorHandler.handle_response_error(response, args.get("account_id"))
           
           # Extract and format outputs
           result_data = response.get("ResultKey", {})
           outputs = serialize_response_with_datetime_encoding(result_data)
           
           # Build readable output
           readable_output = tableToMarkdown(
               "Command Result",
               outputs,
               headers=["Key1", "Key2"],
               headerTransform=pascalToSpace
           )
           
           return CommandResults(
               outputs_prefix="AWS.ServiceName.ResourceType",
               outputs_key_field="UniqueIdentifier",
               outputs=outputs,
               readable_output=readable_output,
               raw_response=response
           )
           
       except ClientError as e:
           AWSErrorHandler.handle_client_error(e, args.get("account_id"))
       except Exception as e:
           raise DemistoException(f"Error executing command: {str(e)}")
   ```

4. **Special Patterns**:
   - **Waiter Commands**: Use `client.get_waiter("waiter_name")` with WaiterConfig
   - **List Commands**: Support pagination with `next_token` and `limit`
   - **Modify Commands**: Include `execution: true` in YAML
   - **Boolean Parameters**: Convert string "true"/"false" to Python bool using `argToBoolean()`
   - **Array Parameters**: Parse comma-separated strings using `parse_resource_ids()` or `argToList()`

5. **Add to COMMANDS_MAPPING**:
   - Locate the `COMMANDS_MAPPING` dictionary (usually near end of file)
   - Add entry: `"command-name": ServiceClass.command_name_command`

6. **Verify IAM Permissions**:
   - Check if required IAM action exists in `REQUIRED_ACTIONS` list
   - Add if missing (e.g., "ec2:DescribeImages", "s3:PutBucketPolicy")

### Workflow 5: Add YAML Definition

1. **Locate Target File**: `Packs/<PackName>/Integrations/<PackName>/<PackName>.yml`

2. **Find Insertion Point**:
   - Commands are organized by service (S3, IAM, EC2, etc.)
   - Insert in alphabetical order within the service section
   - Maintain consistent indentation (2 spaces for command level, 4 for arguments, 6 for properties)

3. **Create Command Definition**:
   ```yaml
   - name: command-name
     description: Clear description of what the command does.
     execution: true  # Only if command modifies resources
     arguments:
     - name: account_id
       description: The AWS account ID.
       required: true
     - name: region
       description: The AWS region.
       required: true
       auto: PREDEFINED
       predefined:
       - us-east-1
       - us-east-2
       # ... all AWS regions
     - name: required_param
       description: Description of the parameter.
       required: true
     - name: optional_param
       description: Description of the parameter.
       required: false
       auto: PREDEFINED  # If parameter has predefined values
       predefined:
       - value1
       - value2
     - name: list_param
       description: Comma-separated list of values.
       required: false
       isArray: true
     outputs:
     - contextPath: AWS.ServiceName.ResourceType.Field1
       description: Description of field1.
       type: string
     - contextPath: AWS.ServiceName.ResourceType.Field2
       description: Description of field2.
       type: number
   ```

4. **Indentation Rules** (CRITICAL):
   - Command level (`- name:`): 2 spaces from `commands:`
   - Arguments/outputs level (`arguments:`, `outputs:`): 4 spaces
   - Argument properties (`- name:`, `description:`, etc.): 4 spaces
   - Argument sub-properties (`predefined:` list items): 6 spaces
   - MUST align with existing commands in the file

5. **Region Predefined Values**:
   - MUST include all AWS regions (copy from existing commands)
   - Standard regions: us-east-1, us-east-2, us-west-1, us-west-2, etc.
   - GovCloud regions: us-gov-east-1, us-gov-west-1
   - Special regions: af-south-1, ap-east-1, eu-south-1, me-south-1, etc.

### Workflow 6: Generate Unit Tests

1. **Locate Test File**: `Packs/<PackName>/Integrations/<PackName>/<PackName>_test.py`

2. **Analyze Existing Test Patterns**:
   - Read similar command tests to understand mocking patterns
   - Note how boto3 clients are mocked
   - Understand assertion patterns

3. **Generate Test Cases** (15-20 tests minimum):
   - **Success Cases** (5-8 tests):
     - Minimal parameters
     - All parameters
     - With optional parameters
     - With multiple values (for array parameters)
     - With different parameter combinations
   
   - **Parameter Validation** (3-5 tests):
     - Missing required parameters
     - Empty required parameters
     - None values for required parameters
     - Invalid parameter types
   
   - **Error Handling** (3-5 tests):
     - ClientError handling
     - WaiterError handling (for waiter commands)
     - Unexpected response status codes
     - Missing response fields
   
   - **Edge Cases** (2-4 tests):
     - Whitespace in parameters
     - Maximum/minimum values
     - Special characters
     - Complex nested structures

4. **Test Structure Pattern**:
   ```python
   def test_command_name_success_minimal_params(mocker):
       """
       Given: A mocked boto3 client and minimal required parameters.
       When: command_name_command is called successfully.
       Then: It should return CommandResults with expected outputs.
       """
       from AWS import ServiceClass
       
       mock_client = mocker.Mock()
       mock_client.api_method.return_value = {
           "ResponseMetadata": {"HTTPStatusCode": HTTPStatus.OK},
           "ResultKey": {"Field1": "value1"}
       }
       
       args = {"required_param": "value"}
       
       result = ServiceClass.command_name_command(mock_client, args)
       assert isinstance(result, CommandResults)
       assert result.outputs_prefix == "AWS.ServiceName.ResourceType"
       assert "success message" in result.readable_output
   ```

5. **Add Tests to File**:
   - Append tests at the end of the file
   - Maintain consistent naming: `test_<service>_<command>_<scenario>`
   - Use descriptive docstrings following Given-When-Then pattern

### Workflow 7: Update Release Notes

1. **Determine Version Number**:
   - Read current version from `pack_metadata.json`
   - Increment patch version (e.g., 2.1.8 → 2.1.9)
   - For multiple commands in same release, use same version

2. **Create Release Notes File**: `Packs/<PackName>/ReleaseNotes/<version>.md`
   ```markdown
   #### Integrations
   
   ##### <PackName> - <ServiceName>
   
   - Added the **command-name** command to <brief description of functionality>.
   ```

3. **Format Rules**:
   - Use bold for command names: `**command-name**`
   - Keep description concise (one sentence)
   - Use proper grammar and punctuation

### Workflow 8: Update Pack Version

1. **Locate Pack Metadata**: `Packs/<PackName>/pack_metadata.json`

2. **Update Version**:
   - Change `currentVersion` field to new version
   - Maintain JSON formatting

3. **Verify**:
   - Version matches release notes filename
   - Version follows semantic versioning (MAJOR.MINOR.PATCH)

### Workflow 9: Final Validation

1. **Python Implementation**:
   - [ ] Function added to correct service class
   - [ ] Added to COMMANDS_MAPPING
   - [ ] IAM permission in REQUIRED_ACTIONS (if needed)
   - [ ] Proper error handling (ClientError, WaiterError)
   - [ ] Parameter validation for required fields
   - [ ] Response validation
   - [ ] Datetime serialization for outputs

2. **YAML Definition**:
   - [ ] Correct indentation (2/4/6 space pattern)
   - [ ] All regions included in predefined list
   - [ ] Required parameters marked correctly
   - [ ] Output context paths follow convention
   - [ ] execution: true for modify/delete/create commands
   - [ ] isArray: true for list parameters

3. **Unit Tests**:
   - [ ] 15-20 tests minimum
   - [ ] Success cases covered
   - [ ] Error cases covered
   - [ ] Parameter validation tested
   - [ ] Edge cases included
   - [ ] Proper mocking patterns
   - [ ] Given-When-Then docstrings

4. **Release Notes**:
   - [ ] Version number matches pack_metadata.json
   - [ ] Command name in bold
   - [ ] Clear, concise description
   - [ ] Proper markdown formatting

5. **Pack Version**:
   - [ ] Version incremented correctly
   - [ ] Matches release notes filename

---

## BEHAVIOR

### Command Template Structure

The command template MUST follow this JSON structure:
```json
{
  "command_name": "csp-service-resource-action",
  "is_command_exists": true|false,
  "documentation_url": "https://...",
  "additional_context": "Optional implementation notes"
}
```

### Naming Conventions (STRICT)

- **Command Names**: `csp-service-resource-action` (e.g., `aws-ec2-image-copy`)
  - CSP: aws, gcp, azure, oci
  - Service: ec2, s3, iam, compute, storage
  - Resource: image, instance, bucket, user
  - Action: create, delete, modify, describe, list, copy, wait

- **Python Functions**: `action_resource_command` (e.g., `copy_image_command`)
  - Use snake_case
  - Suffix with `_command`
  - Verb comes first for clarity

- **Python Arguments**: `snake_case` (e.g., `source_image_id`, `waiter_max_attempts`)
  - MUST match YAML argument names
  - Use descriptive names
  - Avoid abbreviations unless standard (e.g., `id`, `arn`)

- **YAML Arguments**: `snake_case` (e.g., `source_image_id`, `waiter_max_attempts`)
  - MUST match Python argument names
  - Use descriptive names

- **Output Context Paths**: `AWS.ServiceName.ResourceType.Field` (e.g., `AWS.EC2.Images.ImageId`)
  - Use PascalCase for service, resource, and field names
  - Follow hierarchical structure

### Parameter Handling Patterns

1. **Required String Parameters**:
   ```python
   param = args.get("param_name")
   if not param:
       raise DemistoException("param_name parameter is required")
   param = param.strip()  # Remove whitespace
   ```

2. **Optional String Parameters**:
   ```python
   param = args.get("param_name")
   if param:
       param = param.strip()
   ```

3. **Boolean Parameters**:
   ```python
   from CommonServerPython import argToBoolean
   param = argToBoolean(args.get("param_name", "false"))
   ```

4. **List Parameters** (comma-separated):
   ```python
   param_list = parse_resource_ids(args.get("param_name")) if args.get("param_name") else None
   # OR for simple cases:
   param_list = argToList(args.get("param_name"))
   ```

5. **Integer Parameters**:
   ```python
   param = int(args.get("param_name", "15"))  # With default
   # OR
   param = int(args.get("param_name")) if args.get("param_name") else None
   ```

6. **JSON Parameters**:
   ```python
   import json
   param_str = args.get("param_name")
   if param_str:
       try:
           param = json.loads(param_str) if isinstance(param_str, str) else param_str
       except json.JSONDecodeError:
           raise DemistoException("Received invalid `param_name` JSON object")
   ```

### Error Handling Patterns

1. **Standard Pattern**:
   ```python
   try:
       response = client.api_method(**params)
       
       if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
           AWSErrorHandler.handle_response_error(response, args.get("account_id"))
       
       # Process response...
       
   except ClientError as e:
       AWSErrorHandler.handle_client_error(e, args.get("account_id"))
   except Exception as e:
       raise DemistoException(f"Error message: {str(e)}")
   ```

2. **Waiter Pattern**:
   ```python
   try:
       waiter = client.get_waiter("waiter_name")
       waiter_config = {
           "Delay": int(args.get("waiter_delay", "15")),
           "MaxAttempts": int(args.get("waiter_max_attempts", "40"))
       }
       waiter.wait(WaiterConfig=waiter_config, **params)
       
       return CommandResults(
           readable_output="Resource is now in desired state."
       )
       
   except WaiterError as e:
       raise DemistoException(f"Waiter error: {str(e)}")
   except ClientError as e:
       AWSErrorHandler.handle_client_error(e, args.get("account_id"))
   ```

### YAML Indentation Rules (CRITICAL)

MUST follow this exact indentation pattern:
```yaml
script:
  commands:
  - name: command-name              # 2 spaces from 'commands:'
    description: Description.       # 4 spaces
    execution: true                 # 4 spaces (if needed)
    arguments:                      # 4 spaces
    - name: param1                  # 4 spaces (dash counts as 2)
      description: Description.     # 6 spaces
      required: true                # 6 spaces
    - name: param2                  # 4 spaces
      description: Description.     # 6 spaces
      required: false               # 6 spaces
      auto: PREDEFINED              # 6 spaces
      predefined:                   # 6 spaces
      - value1                      # 6 spaces (dash counts as 2)
      - value2                      # 6 spaces
    outputs:                        # 4 spaces
    - contextPath: AWS.Service.Field  # 4 spaces
      description: Description.     # 6 spaces
      type: string                  # 6 spaces
```

### Test Generation Rules

1. **Test Quantity**:
   - Simple commands (1-3 params): 15 tests
   - Moderate commands (4-6 params): 18 tests
   - Complex commands (7+ params): 20 tests

2. **Test Categories Distribution**:
   - Success cases: 40% (6-8 tests)
   - Parameter validation: 25% (4-5 tests)
   - Error handling: 25% (4-5 tests)
   - Edge cases: 10% (2-3 tests)

3. **Test Naming**:
   - Pattern: `test_<service>_<command>_<scenario>`
   - Examples:
     - `test_ec2_copy_image_command_success_minimal_params`
     - `test_ec2_copy_image_command_missing_required_param`
     - `test_ec2_copy_image_command_client_error`

4. **Docstring Format** (MUST use Given-When-Then):
   ```python
   """
   Given: A mocked boto3 client and specific conditions.
   When: command_name_command is called with certain parameters.
   Then: It should produce expected behavior and outputs.
   """
   ```

### Response Serialization

MUST use `serialize_response_with_datetime_encoding()` for outputs containing datetime objects:
```python
from AWS import serialize_response_with_datetime_encoding

outputs = serialize_response_with_datetime_encoding(response_data)
```

This ensures datetime objects are converted to ISO format strings.

### Null Value Handling

MUST use `remove_nulls_from_dictionary()` before API calls:
```python
from AWS import remove_nulls_from_dictionary

api_params = remove_nulls_from_dictionary({
    "RequiredParam": required_value,
    "OptionalParam": optional_value  # Will be removed if None
})
```

### Debug Logging

MUST use `print_debug_logs()` before API calls:
```python
from AWS import print_debug_logs

print_debug_logs(client, f"Calling API method with params: {api_params}")
```

---

## FORMAT

### Python Code Style

- **Imports**: Group by standard library, third-party, local
- **Type Hints**: Use `Any` from typing for boto3 clients
- **Docstrings**: Clear, concise function descriptions
- **Line Length**: Maximum 120 characters
- **Spacing**: Two blank lines between functions

### YAML Style

- **Indentation**: Spaces only (no tabs)
- **Quoting**: Use single quotes for string values with special characters
- **Line Length**: Maximum 120 characters for descriptions
- **Boolean Values**: Use `true`/`false` (lowercase)

### Test Code Style

- **Mocking**: Use `mocker.Mock()` for boto3 clients
- **Assertions**: One assertion per logical check
- **Setup**: Clear arrange-act-assert pattern
- **Cleanup**: Not needed for unit tests (mocks are isolated)

---

## VALIDATION

### Pre-Implementation Checklist

Before starting implementation:
- [ ] Command template exists and is valid JSON
- [ ] Legacy implementation found (if `is_command_exists: true`)
- [ ] Documentation URL accessible (if provided)
- [ ] Target pack exists in workspace
- [ ] Service class identified

### During Implementation Checklist

For each component:
- [ ] Python function follows naming convention
- [ ] All required parameters validated
- [ ] Error handling implemented
- [ ] Response validation included
- [ ] YAML indentation correct
- [ ] All regions included in predefined list
- [ ] Tests cover all scenarios
- [ ] Test count meets minimum (15-20)

### Post-Implementation Checklist

After completing all components:
- [ ] Command in COMMANDS_MAPPING
- [ ] IAM permission in REQUIRED_ACTIONS (if needed)
- [ ] YAML definition added in correct location
- [ ] Unit tests added to test file
- [ ] Release notes created
- [ ] Pack version updated
- [ ] All files saved successfully

### Quality Checks

MUST verify:
- [ ] No syntax errors in Python code
- [ ] No YAML parsing errors
- [ ] Test file imports work correctly
- [ ] Command name consistent across all files
- [ ] Version numbers match (pack_metadata.json and release notes)

---

## EXAMPLES

### Example 1: Describe Command (Read-Only)

**Command Template**:
```json
{
  "command_name": "aws-ec2-images-describe",
  "is_command_exists": true,
  "documentation_url": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/describe_images.html"
}
```

**Python Implementation**:
```python
@staticmethod
def describe_images_command(client: Any, args: dict[str, Any]) -> CommandResults:
    """Describes EC2 AMIs."""
    try:
        filters = parse_filter_field(args.get("filters"))
        image_ids = parse_resource_ids(args.get("image_ids")) if args.get("image_ids") else None
        
        api_params = remove_nulls_from_dictionary({
            "Filters": filters,
            "ImageIds": image_ids,
        })
        
        response = client.describe_images(**api_params)
        
        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))
        
        images = response.get("Images", [])
        outputs = serialize_response_with_datetime_encoding(images)
        
        if not images:
            return CommandResults(readable_output="No images were found.")
        
        readable_output = tableToMarkdown(
            "AWS EC2 Images",
            outputs,
            headers=["ImageId", "Name", "State"],
            headerTransform=pascalToSpace
        )
        
        return CommandResults(
            outputs_prefix="AWS.EC2.Images",
            outputs_key_field="ImageId",
            outputs=outputs,
            readable_output=readable_output,
            raw_response=response
        )
        
    except ClientError as e:
        AWSErrorHandler.handle_client_error(e, args.get("account_id"))
```

**YAML Definition**:
```yaml
  - name: aws-ec2-images-describe
    description: Describes the specified images (AMIs, AKIs, and ARIs) available to you or all of the images available to you.
    arguments:
    - name: account_id
      description: The AWS account ID.
      required: true
    - name: region
      description: The AWS region.
      required: true
      auto: PREDEFINED
      predefined:
      - us-east-1
      - us-east-2
      # ... all regions
    - name: filters
      description: "One or more filters separated by ';' (for example, name=<name>;values=<values>)."
      required: false
    - name: image_ids
      description: "A comma-separated list of image IDs to describe."
      required: false
      isArray: true
    outputs:
    - contextPath: AWS.EC2.Images.ImageId
      description: The ID of the AMI.
      type: string
    - contextPath: AWS.EC2.Images.Name
      description: The name of the AMI.
      type: string
    - contextPath: AWS.EC2.Images.State
      description: The current state of the AMI.
      type: string
```

### Example 2: Create Command (Execution)

**Command Template**:
```json
{
  "command_name": "aws-ec2-image-create",
  "is_command_exists": true,
  "documentation_url": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/create_image.html"
}
```

**Python Implementation**:
```python
@staticmethod
def create_image_command(client: Any, args: dict[str, Any]) -> CommandResults:
    """Creates an AMI from an EC2 instance."""
    try:
        name = args.get("name")
        if not name:
            raise DemistoException("name parameter is required")
        name = name.strip()
        
        instance_id = args.get("instance_id")
        if not instance_id:
            raise DemistoException("instance_id parameter is required")
        instance_id = instance_id.strip()
        
        api_params = remove_nulls_from_dictionary({
            "Name": name,
            "InstanceId": instance_id,
            "Description": args.get("description"),
            "NoReboot": argToBoolean(args.get("no_reboot", "false")),
        })
        
        response = client.create_image(**api_params)
        
        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != HTTPStatus.OK:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))
        
        image_id = response.get("ImageId")
        if not image_id:
            AWSErrorHandler.handle_response_error(response, args.get("account_id"))
        
        outputs = {
            "ImageId": image_id,
            "Name": name,
            "InstanceId": instance_id,
            "Region": args.get("region")
        }
        
        readable_output = f"Successfully created AMI '{name}' with ID: {image_id}"
        
        return CommandResults(
            outputs_prefix="AWS.EC2.Images",
            outputs_key_field="ImageId",
            outputs=outputs,
            readable_output=readable_output,
            raw_response=response
        )
        
    except ClientError as e:
        AWSErrorHandler.handle_client_error(e, args.get("account_id"))
```

**YAML Definition**:
```yaml
  - name: aws-ec2-image-create
    description: Creates an Amazon Machine Image (AMI) from an Amazon EBS-backed instance.
    execution: true
    arguments:
    - name: account_id
      description: The AWS account ID.
      required: true
    - name: region
      description: The AWS region.
      required: true
      auto: PREDEFINED
      predefined:
      - us-east-1
      # ... all regions
    - name: name
      description: A name for the new image.
      required: true
    - name: instance_id
      description: The ID of the instance.
      required: true
    - name: description
      description: A description for the new image.
      required: false
    - name: no_reboot
      description: By default, Amazon EC2 attempts to shut down and reboot the instance before creating the image.
      required: false
      auto: PREDEFINED
      predefined:
      - 'true'
      - 'false'
    outputs:
    - contextPath: AWS.EC2.Images.ImageId
      description: The ID of the new AMI.
      type: string
    - contextPath: AWS.EC2.Images.Name
      description: The name of the new AMI.
      type: string
```

### Example 3: Waiter Command

**Command Template**:
```json
{
  "command_name": "aws-ec2-image-available-waiter",
  "is_command_exists": true,
  "documentation_url": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/waiter/ImageAvailable.html"
}
```

**Python Implementation**:
```python
@staticmethod
def image_available_waiter_command(client: Any, args: dict[str, Any]) -> CommandResults:
    """Waits until an AMI is available."""
    try:
        filters = parse_filter_field(args.get("filters"))
        image_ids = parse_resource_ids(args.get("image_ids")) if args.get("image_ids") else None
        
        waiter_config = {
            "Delay": int(args.get("waiter_delay", "15")),
            "MaxAttempts": int(args.get("waiter_max_attempts", "40"))
        }
        
        api_params = remove_nulls_from_dictionary({
            "Filters": filters,
            "ImageIds": image_ids,
            "WaiterConfig": waiter_config
        })
        
        waiter = client.get_waiter("image_available")
        waiter.wait(**api_params)
        
        return CommandResults(
            readable_output="Image is now available."
        )
        
    except WaiterError as e:
        raise DemistoException(f"Waiter error occurred: {str(e)}")
    except ClientError as e:
        AWSErrorHandler.handle_client_error(e, args.get("account_id"))
```

**YAML Definition**:
```yaml
  - name: aws-ec2-image-available-waiter
    description: Waits until an AMI is in the 'available' state.
    arguments:
    - name: account_id
      description: The AWS account ID.
      required: true
    - name: region
      description: The AWS region.
      required: true
      auto: PREDEFINED
      predefined:
      - us-east-1
      # ... all regions
    - name: image_ids
      description: "A comma-separated list of image IDs to wait for."
      required: false
      isArray: true
    - name: waiter_delay
      description: "The amount of time in seconds to wait between attempts. Default is 15 seconds."
      required: false
      defaultValue: "15"
    - name: waiter_max_attempts
      description: "The maximum number of attempts. Default is 40 attempts."
      required: false
      defaultValue: "40"
```

**Note**: Waiter commands typically have NO outputs section (they return simple success messages).

---

## ADDITIONAL NOTES

### When Legacy Implementation Doesn't Exist

IF `is_command_exists: false`:

1. **MUST read documentation_url** to understand the API
2. **MUST ask user for clarification** on:
   - Required vs optional parameters
   - Expected output structure
   - Special handling requirements
   - Error scenarios to handle

3. **MUST design from scratch** following these principles:
   - Mirror AWS API parameter names (convert to snake_case)
   - Include standard parameters: account_id, region
   - Add pagination support for list commands (limit, next_token)
   - Include proper error messages
   - Design output context paths logically

4. **MUST validate design with user** before implementation

### Multi-Command Implementation

IF implementing multiple commands in one session:

1. **MUST use same version number** for all commands in the release
2. **MUST list all commands** in the release notes
3. **MUST implement commands sequentially** (one at a time)
4. **MUST update todo list** after each command completion

### Command Categories

1. **Describe/List Commands**:
   - Read-only operations
   - NO `execution: true` in YAML
   - Support pagination (limit, next_token)
   - Return arrays of resources

2. **Create/Modify/Delete Commands**:
   - Modify resources
   - MUST have `execution: true` in YAML
   - Return single resource or confirmation
   - Require explicit user action

3. **Waiter Commands**:
   - Poll for resource state changes
   - NO outputs section in YAML
   - Support waiter_delay and waiter_max_attempts
   - Return simple success message

4. **Get Commands**:
   - Retrieve single resource
   - NO `execution: true` in YAML
   - Return single resource object
   - Require resource identifier

### Integration-Specific Patterns

**AWS**:
- Service classes: EC2, S3, IAM, EKS, RDS, CloudTrail, ECS, Lambda, KMS, ELB, ACM, CostExplorer, Budgets
- Error handler: `AWSErrorHandler.handle_client_error()`
- Response serialization: `serialize_response_with_datetime_encoding()`
- Standard parameters: account_id, region

**GCP** (if implementing):
- Service classes: Compute, Storage, IAM
- Error handler: Similar pattern to AWS
- Standard parameters: project_id, zone/region

**Azure** (if implementing):
- Service classes: Compute, Storage, Network
- Error handler: Similar pattern to AWS
- Standard parameters: subscription_id, resource_group

**OCI** (if implementing):
- Service classes: Compute, ObjectStorage, Identity
- Error handler: Similar pattern to AWS
- Standard parameters: compartment_id, region

---

## WORKFLOW SUMMARY

**Complete Implementation Flow**:

1. ✅ Read COMMAND_TEMPLATE.json
2. ✅ Find legacy implementation (if exists) OR design from documentation
3. ✅ Implement Python command function
4. ✅ Add to COMMANDS_MAPPING
5. ✅ Verify/add IAM permission to REQUIRED_ACTIONS
6. ✅ Add YAML definition with correct indentation
7. ✅ Generate 15-20 comprehensive unit tests
8. ✅ Create release notes file
9. ✅ Update pack version in pack_metadata.json
10. ✅ Validate all components

**Success Criteria**:
- All files modified successfully
- No syntax or formatting errors
- Tests cover all scenarios
- Documentation complete
- Version numbers consistent