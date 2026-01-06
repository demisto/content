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
3. **Legacy Pack Access** (if needed):
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

### Command Template Structure

The comprehensive command template MUST follow this JSON structure:

```json
{
  "pack": "AWS|GCP|Azure|OCI",
  "command_name": "csp-service-resource-action",
  "api_url": "https://docs.cloud.provider/api/reference",
  "potentially_harmful": true|false,
  "permission": "service:Action",
  "description": "Brief description of what the command does",
  "inputs": [
    {
      "name": "parameter_name",
      "type": "string|number|boolean|array",
      "required": true|false,
      "description": "Parameter description",
      "default": "default_value",
      "options": ["option1", "option2"]
    }
  ],
  "human_readable_output": "Template for success message with {placeholders}",
  "command_example": "!command-name param1=\"value1\" param2=\"value2\"",
  "context_output_base_path": "CSP.ServiceName.ResourceType",
  "outputs": [
    {
      "path": "Field1",
      "type": "string|number|boolean|date|array|object",
      "description": "Description of field1"
    }
  ]
}
```

### Special Template Values

**"-" (Unknown/Auto-detect)**:
- Mode MUST attempt to infer the value from:
  - Legacy implementation (if exists)
  - API documentation
  - Similar commands in the pack
  - Standard patterns
- IF unable to infer: MUST ask user for clarification

**"*" (Everything/All)**:
- For `inputs`: Include ALL parameters from API documentation
- For `outputs`: Include ALL fields from API response
- For `permission`: Include ALL required IAM/RBAC permissions

**Examples**:
```json
{
  "inputs": "*",           // Auto-generate all inputs from API docs
  "outputs": "*",          // Auto-generate all outputs from API response
  "description": "-",      // Infer from API docs or legacy implementation
  "permission": "-"        // Infer from command name (e.g., ec2:DescribeImages)
}
```

### User Interaction Flow

**Scenario 1: Complete Template (No Questions Needed)**
```json
{
  "pack": "AWS",
  "command_name": "aws-ec2-image-copy",
  "api_url": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/copy_image.html",
  "potentially_harmful": true,
  "permission": "ec2:CopyImage",
  "description": "Copies an AMI from one region to another",
  "inputs": "*",
  "human_readable_output": "Successfully copied AMI {source_image_id} to {region}",
  "command_example": "!aws-ec2-image-copy name=\"my-ami\" source_image_id=\"ami-123\" source_region=\"us-east-1\"",
  "context_output_base_path": "AWS.EC2.Images",
  "outputs": "*"
}
```

User says: **"Implement aws-ec2-image-copy"**

Mode behavior:
1. Reads template
2. Expands "*" by reading API documentation
3. Implements all components
4. No questions asked

**Scenario 2: Minimal Template with Auto-detect**
```json
{
  "pack": "GCP",
  "command_name": "gcp-compute-instance-stop",
  "api_url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances/stop",
  "potentially_harmful": true,
  "permission": "-",
  "description": "-",
  "inputs": "-",
  "human_readable_output": "-",
  "command_example": "-",
  "context_output_base_path": "-",
  "outputs": "-"
}
```

User says: **"Implement gcp-compute-instance-stop"**

Mode behavior:
1. Reads template
2. Searches for legacy implementation in GCP-Compute pack
3. Infers all "-" values from legacy implementation
4. Implements all components
5. No questions asked (legacy provides all context)

**Scenario 3: New Command Without Legacy**
```json
{
  "pack": "AWS",
  "command_name": "aws-ec2-new-feature",
  "api_url": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/new_feature.html",
  "potentially_harmful": false,
  "permission": "-",
  "description": "-",
  "inputs": "*",
  "human_readable_output": "-",
  "command_example": "-",
  "context_output_base_path": "-",
  "outputs": "*"
}
```

User says: **"Implement aws-ec2-new-feature"**

Mode behavior:
1. Reads template
2. Reads API documentation from api_url
3. Infers permission from command name: "ec2:NewFeature"
4. Generates description from API docs
5. Expands "*" for inputs and outputs from API docs
6. Creates human_readable_output template
7. Generates command_example
8. Infers context_output_base_path: "AWS.EC2.NewFeature"
9. Implements all components
10. No questions asked (API docs provide all context)

**Scenario 4: Missing Critical Information**
```json
{
  "pack": "AWS",
  "command_name": "aws-custom-operation",
  "api_url": "-",
  "potentially_harmful": "-",
  "permission": "-",
  "description": "-",
  "inputs": "-",
  "human_readable_output": "-",
  "command_example": "-",
  "context_output_base_path": "-",
  "outputs": "-"
}
```

User says: **"Implement aws-custom-operation"**

Mode behavior:
1. Reads template
2. Detects missing api_url (critical for inference)
3. MUST ask: "What is the API documentation URL for this command?"
4. User provides URL
5. Reads API documentation
6. Infers all other "-" values
7. Implements all components

### Workflow 1: Parse and Validate Template

1. **Read Template Entry**:
   - Search `Packs/COMMAND_TEMPLATE.json` for command matching user's request
   - IF not found: MUST ask user to create template entry first

2. **Validate Required Fields**:
   - `pack`: MUST be one of: AWS, GCP, Azure, OCI
   - `command_name`: MUST follow pattern: `csp-service-resource-action`
   - `api_url`: MUST be valid URL OR "-" (will ask user if needed)
   - All other fields: Can be "-" or "*" (will be inferred)

3. **Expand Special Values**:
   - Process "*" values: Read API docs and extract all parameters/outputs
   - Process "-" values: Attempt inference from legacy/docs/patterns
   - IF inference fails for critical fields: Ask user

### Workflow 2: Infer Missing Information

**For `permission` field**:
- IF "-": Extract from command name
  - `aws-ec2-image-copy` → `ec2:CopyImage`
  - `gcp-compute-instance-stop` → `compute.instances.stop`
  - Pattern: `service:PascalCaseAction`

**For `description` field**:
- IF "-": Extract from API documentation summary
- IF API docs unavailable: Use command name pattern
  - `aws-ec2-image-copy` → "Copies an Amazon Machine Image (AMI) from one region to another"

**For `inputs` field**:
- IF "*": Read API docs and extract ALL parameters
- IF "-": 
  - Search legacy implementation
  - OR read API docs for required/optional parameters
  - Always include: account_id/project_id, region/zone

**For `outputs` field**:
- IF "*": Read API docs and extract ALL response fields
- IF "-":
  - Search legacy implementation
  - OR read API docs for response structure
  - Create hierarchical context paths

**For `human_readable_output` field**:
- IF "-": Generate template based on command type
  - Describe: "AWS EC2 Images" (table)
  - Create: "Successfully created {resource_type} {identifier}"
  - Modify: "Successfully modified {resource_type} {identifier}"
  - Delete: "Successfully deleted {resource_type} {identifier}"
  - Waiter: "{Resource} is now {desired_state}."

**For `command_example` field**:
- IF "-": Generate from inputs
  - Include all required parameters
  - Include 1-2 optional parameters as examples
  - Use realistic values

**For `context_output_base_path` field**:
- IF "-": Infer from command name
  - `aws-ec2-image-copy` → `AWS.EC2.Images`
  - `gcp-compute-instance-stop` → `GCP.Compute.Instances`
  - Pattern: `CSP.ServiceName.ResourceTypePlural`

**For `potentially_harmful` field**:
- IF "-": Infer from command action
  - create, modify, delete, terminate, stop, revoke → `true`
  - describe, list, get, wait → `false`

### Workflow 3: Find Legacy Implementation (if available)

1. **Determine Legacy Pack Location**:
   - AWS: `Packs/AWS-EC2/Integrations/AWS-EC2/`
   - GCP: `Packs/GCP-Compute/Integrations/GCP-Compute/`
   - Azure: `Packs/Azure-Compute/Integrations/Azure-Compute/`
   - OCI: `Packs/OCI-Compute/Integrations/OCI-Compute/`

2. **Search for Implementation**:
   - Use `search_files` to find command name in Python files
   - Read legacy Python implementation
   - Read legacy YAML definition
   - Extract all implementation details

3. **Use Legacy to Fill Template**:
   - IF template field is "-": Use value from legacy
   - IF template field is "*": Expand using legacy as reference
   - IF template field has value: Use template value (override legacy)

### Workflow 4: Read API Documentation (if needed)

1. **When to Read API Docs**:
   - `inputs: "*"` → Need to extract all parameters
   - `outputs: "*"` → Need to extract all response fields
   - `description: "-"` AND no legacy → Need API summary
   - `api_url: "-"` → MUST ask user for URL first

2. **Extract from API Docs**:
   - Required parameters
   - Optional parameters with defaults
   - Parameter types and constraints
   - Response structure
   - Error scenarios

3. **Transform to Template Format**:
   - Convert API parameter names to snake_case
   - Map API types to template types
   - Extract descriptions
   - Identify arrays and objects

### Workflow 5: Implement Python Command

1. **Locate Target File**: `Packs/<PackName>/Integrations/<PackName>/<PackName>.py`

2. **Identify Service Class**:
   - AWS: EC2, S3, IAM, EKS, RDS, CloudTrail, ECS, Lambda, KMS, ELB, ACM, CostExplorer, Budgets
   - GCP: Compute, Storage, IAM
   - Azure: Compute, Storage, Network
   - OCI: Compute, ObjectStorage, Identity

3. **Generate Function from Template**:
   - Use `inputs` to create parameter extraction code
   - Use `potentially_harmful` to determine validation strictness
   - Use `outputs` to create output formatting code
   - Use `human_readable_output` to create success message
   - Use `permission` to verify IAM/RBAC requirements

4. **Add to COMMANDS_MAPPING**:
   - Add entry: `"command-name": ServiceClass.command_name_command`

5. **Verify Permissions**:
   - Check if `permission` exists in REQUIRED_ACTIONS list
   - Add if missing

### Workflow 6: Generate YAML Definition

1. **Locate Target File**: `Packs/<PackName>/Integrations/<PackName>/<PackName>.yml`

2. **Generate from Template**:
   - Use `command_name` for name field
   - Use `description` for description field
   - Use `potentially_harmful` to add `execution: true` if needed
   - Use `inputs` to generate arguments section
   - Use `outputs` to generate outputs section

3. **Apply Formatting Rules**:
   - Correct indentation (2/4/6 space pattern)
   - Include all regions in predefined list
   - Mark required parameters
   - Add isArray for list parameters

### Workflow 7: Generate Unit Tests

1. **Determine Test Count**:
   - Count inputs: Simple (1-3) → 15 tests, Moderate (4-6) → 18 tests, Complex (7+) → 20 tests

2. **Generate Test Categories**:
   - Success cases (40%): Minimal params, all params, combinations
   - Parameter validation (25%): Missing required, empty, None values
   - Error handling (25%): ClientError, WaiterError, unexpected responses
   - Edge cases (10%): Whitespace, boundaries, special characters

3. **Use Template Fields**:
   - `inputs` → Generate parameter validation tests
   - `outputs` → Verify output structure in assertions
   - `potentially_harmful` → Add execution permission tests
   - `command_example` → Use as basis for success test

### Workflow 8: Create Release Notes and Update Version

1. **Determine Version**:
   - Read current version from pack_metadata.json
   - Increment patch version (e.g., 2.1.8 → 2.1.9)

2. **Create Release Notes**:
   - Use `description` field for changelog entry
   - Format: `- Added the **command-name** command to {description}.`

3. **Update Pack Version**:
   - Update `currentVersion` in pack_metadata.json

---

## BEHAVIOR

### Template Field Processing Rules

**pack** (REQUIRED):
- MUST be one of: "AWS", "GCP", "Azure", "OCI"
- Determines target integration and file locations
- Cannot be "-" or "*"

**command_name** (REQUIRED):
- MUST follow pattern: `csp-service-resource-action`
- Examples: `aws-ec2-image-copy`, `gcp-compute-instance-stop`
- Cannot be "-" or "*"

**api_url** (REQUIRED for new commands):
- Valid URL to official API documentation
- IF "-": MUST ask user for URL
- IF "*": Invalid (must be specific URL)
- Used to extract parameters, outputs, and descriptions

**potentially_harmful** (REQUIRED):
- `true`: Command modifies/deletes resources → adds `execution: true` in YAML
- `false`: Command is read-only → no execution flag
- IF "-": Infer from command action verb
  - create, modify, delete, terminate, stop, revoke, update, put → `true`
  - describe, list, get, wait, show → `false`

**permission** (REQUIRED):
- IAM/RBAC permission string
- AWS format: `service:Action` (e.g., `ec2:CopyImage`)
- GCP format: `service.resource.action` (e.g., `compute.instances.stop`)
- IF "-": Infer from command_name
  - `aws-ec2-image-copy` → `ec2:CopyImage`
  - `gcp-compute-instance-stop` → `compute.instances.stop`
- IF "*": Extract ALL required permissions from API docs

**description** (REQUIRED):
- Brief description of command functionality
- IF "-": Extract from API documentation summary OR legacy implementation
- IF "*": Invalid (must be specific description)
- Used in YAML definition and release notes

**inputs** (REQUIRED):
- Array of input parameter objects
- IF "*": Extract ALL parameters from API documentation
- IF "-": Extract from legacy implementation OR API docs
- IF array: Use as-is
- Always includes standard params: account_id/project_id, region/zone

**human_readable_output** (REQUIRED):
- Template string for success message
- Can include {placeholder} for dynamic values
- IF "-": Generate based on command type
  - Describe/List: Table with resource data
  - Create: "Successfully created {resource_type} {identifier}"
  - Modify: "Successfully modified {resource_type} {identifier}"
  - Delete: "Successfully deleted {resource_type} {identifier}"
  - Waiter: "{Resource} is now {state}."
- IF "*": Invalid (must be specific template)

**command_example** (REQUIRED):
- Example command invocation with realistic values
- IF "-": Generate from inputs (required params + 1-2 optional)
- IF "*": Invalid (must be specific example)
- Format: `!command-name param1="value1" param2="value2"`

**context_output_base_path** (REQUIRED):
- Base path for output context
- Pattern: `CSP.ServiceName.ResourceType`
- IF "-": Infer from command_name
  - `aws-ec2-image-copy` → `AWS.EC2.Images`
  - `gcp-compute-instance-list` → `GCP.Compute.Instances`
- IF "*": Invalid (must be specific path)

**outputs** (REQUIRED):
- Array of output field objects
- IF "*": Extract ALL fields from API response documentation
- IF "-": Extract from legacy implementation OR API docs
- IF array: Use as-is
- Each output has: path, type, description

### Input Parameter Structure

Each input object MUST have:
```json
{
  "name": "parameter_name",           // REQUIRED: snake_case
  "type": "string",                   // REQUIRED: string|number|boolean|array|object
  "required": true,                   // REQUIRED: true|false
  "description": "Parameter desc",    // REQUIRED: Clear description
  "default": "default_value",         // OPTIONAL: Default value if not required
  "options": ["opt1", "opt2"]         // OPTIONAL: Predefined values (creates PREDEFINED in YAML)
}
```

**Special Input Handling**:
- IF `type: "array"`: Add `isArray: true` in YAML, parse with `parse_resource_ids()` or `argToList()`
- IF `options` provided: Add `auto: PREDEFINED` and `predefined:` list in YAML
- IF `type: "boolean"`: Parse with `argToBoolean()` in Python
- IF `type: "object"`: Parse JSON string with `json.loads()` in Python

### Output Field Structure

Each output object MUST have:
```json
{
  "path": "FieldName",                // REQUIRED: PascalCase field name (appended to base path)
  "type": "string",                   // REQUIRED: string|number|boolean|date|array|object
  "description": "Field description"  // REQUIRED: Clear description
}
```

**Full Context Path**: `{context_output_base_path}.{path}`
- Example: Base path `AWS.EC2.Images` + path `ImageId` = `AWS.EC2.Images.ImageId`

### Naming Conventions (STRICT)

**Command Names**: `csp-service-resource-action`
- CSP: aws, gcp, azure, oci (lowercase)
- Service: ec2, s3, compute, storage (lowercase)
- Resource: image, instance, bucket (lowercase, singular)
- Action: create, delete, modify, describe, list, copy, wait (lowercase, verb)

**Python Functions**: `action_resource_command`
- snake_case
- Verb first: `copy_image_command`, `stop_instance_command`
- Suffix with `_command`

**Python/YAML Arguments**: `snake_case`
- `source_image_id`, `waiter_max_attempts`, `instance_type`
- MUST match between Python and YAML

**Output Context Paths**: `CSP.ServiceName.ResourceType.Field`
- PascalCase for all components
- `AWS.EC2.Images.ImageId`, `GCP.Compute.Instances.Name`

### Error Handling Patterns

**Standard Pattern**:
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

**Waiter Pattern**:
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
    execution: true                 # 4 spaces (if potentially_harmful: true)
    arguments:                      # 4 spaces
    - name: param1                  # 4 spaces (dash counts as 2)
      description: Description.     # 6 spaces
      required: true                # 6 spaces
    - name: param2                  # 4 spaces
      description: Description.     # 6 spaces
      required: false               # 6 spaces
      auto: PREDEFINED              # 6 spaces (if options provided)
      predefined:                   # 6 spaces
      - value1                      # 6 spaces (dash counts as 2)
      - value2                      # 6 spaces
    outputs:                        # 4 spaces
    - contextPath: CSP.Service.Field  # 4 spaces
      description: Description.     # 6 spaces
      type: string                  # 6 spaces
```

### Autonomous Operation Mode

The mode SHOULD operate autonomously when possible:

1. **Read template** → Extract all fields
2. **Expand "*" values** → Read API docs automatically
3. **Infer "-" values** → Use legacy/docs/patterns
4. **Implement all components** → Python, YAML, tests, release notes, version
5. **Present for review** → Show what was implemented

**ONLY ask questions when**:
- Critical field is "-" AND cannot be inferred (e.g., api_url missing and no legacy)
- Ambiguous design decision (e.g., multiple valid output structures)
- User confirmation needed for potentially harmful operations

**Goal**: Minimize user interaction. Template should provide enough context for autonomous implementation.

---

## FORMAT

### Complete Template Example

```json
{
  "pack": "AWS",
  "command_name": "aws-ec2-image-copy",
  "api_url": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/copy_image.html",
  "potentially_harmful": true,
  "permission": "ec2:CopyImage",
  "description": "Initiates the copy of an AMI from the specified source region to the current region",
  "inputs": [
    {
      "name": "name",
      "type": "string",
      "required": true,
      "description": "A name for the new AMI in the destination region"
    },
    {
      "name": "source_image_id",
      "type": "string",
      "required": true,
      "description": "The ID of the AMI to copy"
    },
    {
      "name": "source_region",
      "type": "string",
      "required": true,
      "description": "The name of the region that contains the AMI to copy"
    },
    {
      "name": "description",
      "type": "string",
      "required": false,
      "description": "A description for the new AMI in the destination region"
    },
    {
      "name": "encrypted",
      "type": "boolean",
      "required": false,
      "description": "Specifies whether the destination snapshots should be encrypted",
      "options": ["true", "false"]
    },
    {
      "name": "kms_key_id",
      "type": "string",
      "required": false,
      "description": "The identifier of the symmetric AWS KMS key to use when creating encrypted volumes"
    }
  ],
  "human_readable_output": "Successfully initiated copy of AMI {source_image_id} from {source_region} to {region}. New AMI ID: {ImageId}",
  "command_example": "!aws-ec2-image-copy name=\"my-copied-ami\" source_image_id=\"ami-12345\" source_region=\"us-east-1\"",
  "context_output_base_path": "AWS.EC2.Images",
  "outputs": [
    {
      "path": "ImageId",
      "type": "string",
      "description": "The ID of the new AMI"
    },
    {
      "path": "Name",
      "type": "string",
      "description": "The name of the new AMI"
    },
    {
      "path": "SourceImageId",
      "type": "string",
      "description": "The ID of the source AMI"
    },
    {
      "path": "SourceRegion",
      "type": "string",
      "description": "The source region from which the AMI was copied"
    },
    {
      "path": "Region",
      "type": "string",
      "description": "The destination region where the AMI was copied to"
    }
  ]
}
```

### Minimal Template with Auto-Inference

```json
{
  "pack": "AWS",
  "command_name": "aws-ec2-image-available-waiter",
  "api_url": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/waiter/ImageAvailable.html",
  "potentially_harmful": false,
  "permission": "-",
  "description": "-",
  "inputs": "-",
  "human_readable_output": "-",
  "command_example": "-",
  "context_output_base_path": "-",
  "outputs": []
}
```

Mode will infer:
- `permission`: "ec2:DescribeImages" (waiters use describe permissions)
- `description`: "Waits until an AMI is in the 'available' state" (from API docs)
- `inputs`: Standard waiter params (filters, image_ids, owners, executable_users, waiter_delay, waiter_max_attempts)
- `human_readable_output`: "Image is now available."
- `command_example`: `!aws-ec2-image-available-waiter image_ids="ami-123"`
- `context_output_base_path`: N/A (waiters have no outputs)
- `outputs`: [] (waiters return simple messages, no context outputs)

### Python Code Style

- **Imports**: Group by standard library, third-party, local
- **Type Hints**: Use `Any` from typing for clients
- **Docstrings**: Clear, concise function descriptions
- **Line Length**: Maximum 120 characters
- **Spacing**: Two blank lines between functions

### YAML Style

- **Indentation**: Spaces only (no tabs)
- **Quoting**: Use single quotes for string values with special characters
- **Line Length**: Maximum 120 characters for descriptions
- **Boolean Values**: Use `true`/`false` (lowercase)

### Test Code Style

- **Mocking**: Use `mocker.Mock()` for clients
- **Assertions**: One assertion per logical check
- **Setup**: Clear arrange-act-assert pattern
- **Docstrings**: Given-When-Then format

---

## VALIDATION

### Template Validation

Before processing template:
- [ ] `pack` is valid CSP name
- [ ] `command_name` follows naming pattern
- [ ] `api_url` is valid URL OR "-"
- [ ] `potentially_harmful` is boolean OR "-"
- [ ] `permission` is string OR "-" OR "*"
- [ ] `description` is string OR "-"
- [ ] `inputs` is array OR "-" OR "*"
- [ ] `human_readable_output` is string OR "-"
- [ ] `command_example` is string OR "-"
- [ ] `context_output_base_path` is string OR "-"
- [ ] `outputs` is array OR "-" OR "*"

### Pre-Implementation Checklist

Before starting implementation:
- [ ] Template entry exists and validated
- [ ] All "-" values inferred OR user provided clarification
- [ ] All "*" values expanded from API docs
- [ ] Legacy implementation found (if needed)
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
- [ ] Permission in REQUIRED_ACTIONS (if needed)
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
- [ ] All template placeholders replaced with actual values

---

## EXAMPLES

### Example 1: Complete Template (No Inference Needed)

**Template Entry**:
```json
{
  "pack": "AWS",
  "command_name": "aws-s3-bucket-versioning-put",
  "api_url": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/put_bucket_versioning.html",
  "potentially_harmful": true,
  "permission": "s3:PutBucketVersioning",
  "description": "Sets the versioning state of an existing bucket",
  "inputs": [
    {
      "name": "bucket",
      "type": "string",
      "required": true,
      "description": "The name of the bucket"
    },
    {
      "name": "status",
      "type": "string",
      "required": true,
      "description": "The versioning state of the bucket",
      "options": ["Enabled", "Suspended"]
    },
    {
      "name": "mfa_delete",
      "type": "string",
      "required": false,
      "description": "Whether MFA delete is enabled"
    }
  ],
  "human_readable_output": "Successfully updated versioning for bucket {bucket} to {status}",
  "command_example": "!aws-s3-bucket-versioning-put bucket=\"my-bucket\" status=\"Enabled\"",
  "context_output_base_path": "AWS.S3.Buckets",
  "outputs": []
}
```

**User Request**: "Implement aws-s3-bucket-versioning-put"

**Mode Actions** (No questions asked):
1. ✅ Read template
2. ✅ Implement Python function with 3 parameters
3. ✅ Add to COMMANDS_MAPPING
4. ✅ Add s3:PutBucketVersioning to REQUIRED_ACTIONS
5. ✅ Generate YAML with execution: true
6. ✅ Generate 15 unit tests
7. ✅ Create release notes
8. ✅ Update pack version

### Example 2: Minimal Template with Auto-Inference

**Template Entry**:
```json
{
  "pack": "GCP",
  "command_name": "gcp-compute-instance-stop",
  "api_url": "-",
  "potentially_harmful": "-",
  "permission": "-",
  "description": "-",
  "inputs": "-",
  "human_readable_output": "-",
  "command_example": "-",
  "context_output_base_path": "-",
  "outputs": "-"
}
```

**User Request**: "Implement gcp-compute-instance-stop"

**Mode Actions**:
1. ✅ Read template
2. ✅ Search for legacy in `Packs/GCP-Compute/`
3. ✅ Find legacy implementation
4. ✅ Infer all "-" values from legacy:
   - `api_url`: Extract from legacy comments or use standard GCP docs
   - `potentially_harmful`: true (stop is harmful)
   - `permission`: "compute.instances.stop"
   - `description`: "Stops a running instance"
   - `inputs`: Extract from legacy function parameters
   - `human_readable_output`: "Successfully stopped instance {instance_name}"
   - `command_example`: Generate from legacy usage
   - `context_output_base_path`: "GCP.Compute.Instances"
   - `outputs`: Extract from legacy return values
5. ✅ Implement all components
6. ✅ No questions asked (legacy provides all context)

### Example 3: Wildcard Expansion

**Template Entry**:
```json
{
  "pack": "AWS",
  "command_name": "aws-ec2-instances-describe",
  "api_url": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/describe_instances.html",
  "potentially_harmful": false,
  "permission": "ec2:DescribeInstances",
  "description": "Describes specified instances or all instances",
  "inputs": "*",
  "human_readable_output": "-",
  "command_example": "-",
  "context_output_base_path": "AWS.EC2.Instances",
  "outputs": "*"
}
```

**User Request**: "Implement aws-ec2-instances-describe"

**Mode Actions**:
1. ✅ Read template
2. ✅ Read API documentation from api_url
3. ✅ Expand `inputs: "*"`:
   - Extract ALL parameters from API docs
   - Generate input objects for: instance_ids, filters, next_token, limit, etc.
4. ✅ Expand `outputs: "*"`:
   - Extract ALL response fields from API docs
   - Generate output objects for: InstanceId, State, ImageId, InstanceType, etc.
5. ✅ Infer `human_readable_output`: "AWS EC2 Instances" (table format)
6. ✅ Infer `command_example`: `!aws-ec2-instances-describe instance_ids="i-123"`
7. ✅ Implement all components
8. ✅ No questions asked (API docs provide all context)

### Example 4: Missing Critical Information

**Template Entry**:
```json
{
  "pack": "AWS",
  "command_name": "aws-custom-new-feature",
  "api_url": "-",
  "potentially_harmful": "-",
  "permission": "-",
  "description": "-",
  "inputs": "-",
  "human_readable_output": "-",
  "command_example": "-",
  "context_output_base_path": "-",
  "outputs": "-"
}
```

**User Request**: "Implement aws-custom-new-feature"

**Mode Actions**:
1. ✅ Read template
2. ❌ Cannot find legacy (new feature)
3. ❌ Cannot read API docs (api_url is "-")
4. ⚠️ MUST ask: "What is the API documentation URL for aws-custom-new-feature?"
5. ✅ User provides: "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/new_feature.html"
6. ✅ Read API documentation
7. ✅ Infer all other "-" values from API docs
8. ✅ Implement all components

---

## ADDITIONAL NOTES

### Template Creation Guidance

**For Users Creating Templates**:

**Minimal Template** (Let mode infer everything):
```json
{
  "pack": "AWS",
  "command_name": "aws-service-resource-action",
  "api_url": "https://docs.aws.amazon.com/...",
  "potentially_harmful": "-",
  "permission": "-",
  "description": "-",
  "inputs": "*",
  "human_readable_output": "-",
  "command_example": "-",
  "context_output_base_path": "-",
  "outputs": "*"
}
```

**Complete Template** (Full control):
```json
{
  "pack": "AWS",
  "command_name": "aws-service-resource-action",
  "api_url": "https://docs.aws.amazon.com/...",
  "potentially_harmful": true,
  "permission": "service:Action",
  "description": "Detailed description",
  "inputs": [/* full input array */],
  "human_readable_output": "Custom message with {placeholders}",
  "command_example": "!command param=\"value\"",
  "context_output_base_path": "AWS.Service.Resource",
  "outputs": [/* full output array */]
}
```

**Recommended Approach**:
- Start with minimal template using "*" and "-"
- Let mode infer from API docs and legacy
- Review generated implementation
- Refine template if needed for next command

### Multi-Command Implementation

IF implementing multiple commands:

1. **Create multiple template entries** in COMMAND_TEMPLATE.json
2. **Request implementation one at a time**: "Implement command-1", then "Implement command-2"
3. **Use same version number** for all commands in the release
4. **Consolidate release notes**: List all commands in single release notes file

### Command Categories and Patterns

**Describe/List Commands**:
- `potentially_harmful`: false
- `inputs`: Include filters, pagination (limit, next_token)
- `outputs`: Array of resources
- `human_readable_output`: Table format

**Create Commands**:
- `potentially_harmful`: true
- `inputs`: Resource configuration parameters
- `outputs`: Created resource details
- `human_readable_output`: "Successfully created {resource}"

**Modify/Update Commands**:
- `potentially_harmful`: true
- `inputs`: Resource identifier + modification parameters
- `outputs`: Updated resource details OR empty
- `human_readable_output`: "Successfully modified {resource}"

**Delete Commands**:
- `potentially_harmful`: true
- `inputs`: Resource identifier
- `outputs`: Usually empty
- `human_readable_output`: "Successfully deleted {resource}"

**Waiter Commands**:
- `potentially_harmful`: false
- `inputs`: Resource filters + waiter_delay + waiter_max_attempts
- `outputs`: [] (empty - waiters don't return data)
- `human_readable_output`: "{Resource} is now {state}."

### Integration-Specific Patterns

**AWS**:
- Standard inputs: account_id (required), region (required)
- Error handler: `AWSErrorHandler.handle_client_error()`
- Response serialization: `serialize_response_with_datetime_encoding()`
- Permissions format: `service:Action`

**GCP**:
- Standard inputs: project_id (required), zone/region (required)
- Error handler: Similar to AWS pattern
- Permissions format: `service.resource.action`

**Azure**:
- Standard inputs: subscription_id (required), resource_group (required)
- Error handler: Similar to AWS pattern
- Permissions format: `Microsoft.Service/resourceType/action`

**OCI**:
- Standard inputs: compartment_id (required), region (required)
- Error handler: Similar to AWS pattern
- Permissions format: `service.resource.action`

---

## WORKFLOW SUMMARY

**Complete Autonomous Flow** (Ideal):

1. ✅ User creates template entry with "*" and "-" values
2. ✅ User says: "Implement command-name"
3. ✅ Mode reads template
4. ✅ Mode expands "*" from API docs
5. ✅ Mode infers "-" from legacy/docs/patterns
6. ✅ Mode implements: Python + YAML + Tests + Release Notes + Version
7. ✅ Mode presents complete implementation
8. ✅ User reviews and approves

**Minimal Interaction Flow** (When inference possible):

1. ✅ User says: "Implement command-name"
2. ✅ Mode finds template OR asks for template creation
3. ✅ Mode infers missing values
4. ✅ Mode implements all components
5. ✅ Mode presents for review

**Maximum Interaction Flow** (When critical info missing):

1. ✅ User says: "Implement command-name"
2. ❌ Template missing or has critical "-" that can't be inferred
3. ⚠️ Mode asks 1-4 questions (api_url, harmful, outputs, etc.)
4. ✅ User provides answers
5. ✅ Mode implements all components
6. ✅ Mode presents for review

**Success Criteria**:
- All components implemented correctly
- No syntax or formatting errors
- Tests pass (if run)
- Documentation complete
- Version numbers consistent
- User approval obtained