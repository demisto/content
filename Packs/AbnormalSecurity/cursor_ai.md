# Abnormal Security Pack - AI Agent Instructions

## Overview

The Abnormal Security pack for Cortex XSOAR integrates with Abnormal Security's email security platform, which detects and protects against the whole spectrum of email attacks, including vendor email compromise, spear-phishing, spam, and graymail. This integration allows security teams to respond to incidents with greater speed and efficiency, reducing mean time to respond.

## Pack Structure

The pack consists of the following components:

- **Integrations/**: Contains the integration code that connects XSOAR with Abnormal Security
  - **AbnormalSecurity/**: The main integration for interacting with Abnormal Security's API
    - `AbnormalSecurity.py`: Core Python implementation containing all client logic and commands
    - `AbnormalSecurity.yml`: YAML definition of the integration (parameters, commands, inputs, outputs)
    - `AbnormalSecurity_test.py`: Unit tests for the integration
    - `AbnormalSecurity_description.md`: Brief description of the integration
    - `AbnormalSecurity_image.png`: Icon displayed in the XSOAR marketplace
    - `README.md`: Documentation for the integration
    - `command_examples.txt`: Examples of command usage
    - `test_data/`: Contains mock data for testing
  - **AbnormalSecurityEventCollector/**: Integration for collecting events from Abnormal Security
    - Similar structure to the main integration

- **IncidentTypes/**: Custom incident types for Abnormal Security alerts
  - `Abnormal_Security_Custom_Incident_types.json`: Defines custom incident types like email threats and anomaly cases
  
- **IncidentFields/**: Custom fields for Abnormal Security incidents
  - JSON files defining fields specific to Abnormal Security incidents
  - Fields include sender information, threat types, and email metadata
  
- **ModelingRules/**: Rules for modeling and processing Abnormal Security data
  - Contains rules that map incoming data to XSOAR's data model
  - Enables automation of incident classification and handling
  
- **Classifiers/**: Content classifiers for Abnormal Security alerts
  - Maps incoming events to incident types
  - Controls how incidents are created and mapped to fields
  
- **ReleaseNotes/**: Version history and release notes for the pack
  - Contains Markdown files named with version numbers (e.g., `1_0_0.md`)
  - Documents changes, improvements, and fixes in each release

- **pack_metadata.json**: Contains metadata about the pack, including version, support type, and author
  
- **README.md**: Main documentation for the pack

- **.pack-ignore**: Configuration for files to be ignored during pack validation
  
- **.secrets-ignore**: Configuration for excluding false positives from secrets detection

## Main Features

The integration enables security teams to:

1. **Retrieve Email Threat Campaign Data**: Access and analyze email threat campaigns detected by Abnormal Security
2. **Retrieve Email Anomaly Cases**: Get information about email anomaly cases for investigation
3. **Manage Threat Reports**: Handle false positive/negative reports and submit inquiries
4. **Monitor Vendor Security**: View vendor-related security information and cases
5. **Employee Analysis**: Access identity and login information for employee security analysis
6. **Incident Response**: Manage and respond to security incidents identified by Abnormal Security

## Development Environment Setup

### Prerequisites

1. **Python**: The integration uses Python 3.7+ with standard packages from the XSOAR environment
2. **Dependencies**: Uses built-in XSOAR libraries like `demistomock` and `CommonServerPython`
3. **API Access**: Requires an Abnormal Security API key for testing

### Development Tools

- **Poetry**: For dependency management instead of pip (if working locally)
  - Initialize with `poetry init` and add dependencies with `poetry add`
  - Create a `pyproject.toml` file for dependency management
- **pytest**: For unit testing (with mocking capabilities)
  - Uses fixtures for mocking API responses in `test_data/`
- **mypy**: For type checking
  - Add type annotations to all functions and classes
- **flake8**: For linting
  - Enforce code style and formatting rules

### Setting Up Local Development

1. **Create Virtual Environment**:
   ```bash
   poetry install
   poetry shell
   ```

2. **Install Dev Dependencies**:
   ```bash
   poetry add --dev pytest pytest-mock mypy flake8
   ```

3. **Install demistomock**:
   For local testing without XSOAR, install demistomock package

## How to Contribute

### Development Workflow

1. **Clone the Repository**: Start with a fresh clone of the repository
2. **Create a Feature Branch**: Create a branch for your changes
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Install Dependencies**: Use Poetry to install dependencies if working locally
4. **Make Changes**: Update the integration code, tests, or documentation
5. **Test Your Changes**:
   - Run unit tests: `pytest -xvs Packs/AbnormalSecurity/Integrations/AbnormalSecurity/AbnormalSecurity_test.py`
   - Test the integration in a development XSOAR instance
   - Run static type checking: `mypy Packs/AbnormalSecurity/Integrations/AbnormalSecurity/AbnormalSecurity.py`
   - Run linting: `flake8 Packs/AbnormalSecurity/Integrations/AbnormalSecurity/AbnormalSecurity.py`
6. **Update Documentation**: Update README.md and other documentation as needed
7. **Increment Version**: Update the version in pack_metadata.json
8. **Add Release Notes**: Create a new file in the ReleaseNotes directory for your changes
   - Name format: `<version>.md` (e.g., `1_2_1.md`)
   - Include all changes, fixes, and improvements
9. **Submit Changes**: Create a pull request for review

### File Modification Guidelines

1. **Integration Code**:
   - Keep methods small and focused on a single task
   - Use descriptive method names that reflect the Abnormal Security API endpoints
   - Implement proper error handling for all API calls
   - Respect rate limits in the Abnormal Security API

2. **YAML Configuration**:
   - Follow XSOAR schema for command inputs and outputs
   - Document all parameters with clear descriptions
   - Use consistent naming for command arguments

3. **Tests**:
   - Create test cases for normal operation and error conditions
   - Mock all external API calls using fixtures
   - Ensure high test coverage for new features
   - Example test structure:
     ```python
     def test_get_a_list_of_threats_command(mocker):
         """Test for get_a_list_of_threats_command."""
         from AbnormalSecurity import Client, get_a_list_of_threats_command
         
         mock_response = load_json('test_data/threats_response.json')
         client = Client(BASE_URL, False, False, headers, None)
         mocker.patch.object(client, '_http_request', return_value=mock_response)
         
         result = get_a_list_of_threats_command(client, {'limit': '10'})
         assert result.outputs_prefix == 'AbnormalSecurity.Threats'
         assert len(result.outputs) == len(mock_response['threats'])
     ```

4. **Documentation**:
   - Update README.md with new commands and features
   - Add examples to command_examples.txt
   - Include screenshots for complex workflows
   - Document any breaking changes prominently

### Best Practices

1. **Follow XSOAR Guidelines**:
   - Use the standard XSOAR integration structure
   - Follow XSOAR naming conventions
   - Include proper error handling and logging
   
2. **Code Quality**:
   - Include type hints (`typing` module)
   - Write comprehensive unit tests
   - Keep functions small and focused
   - Use descriptive variable and function names
   
3. **Security Considerations**:
   - Never hardcode sensitive data (API keys, passwords)
   - Use proper authentication and authorization
   - Handle errors gracefully without exposing sensitive information

4. **Documentation**:
   - Document all commands, arguments, and outputs
   - Provide clear instructions for users
   - Include examples in command_examples.txt

### Important Rules

1. **Scope**: Only modify files within the `Packs/AbnormalSecurity/` directory
2. **Testing**: Always include tests for new functionality
3. **Backward Compatibility**: Maintain backward compatibility with existing implementations
4. **Versioning**: Follow semantic versioning for releases
5. **Documentation**: Keep documentation up-to-date with changes

## Common Tasks

### Adding a New Command

1. Add the command method to the `Client` class in `AbnormalSecurity.py`
   ```python
   def new_api_method(self, param1, param2, subtenant=None):
       params = assign_params(subtenant=subtenant, param1=param1)
       headers = self._headers
       response = self._http_request('get', 'endpoint/path', params=params, headers=headers)
       return response
   ```

2. Implement the command function that uses the client method
   ```python
   def new_command_function(client, args):
       param1 = args.get('param1')
       param2 = args.get('param2')
       subtenant = args.get('subtenant')
       
       response = client.new_api_method(param1, param2, subtenant)
       
       readable_output = tableToMarkdown('Title', response)
       outputs = {'AbnormalSecurity.OutputKey': response}
       
       return CommandResults(
           readable_output=readable_output,
           outputs=outputs,
           outputs_prefix='AbnormalSecurity.OutputKey',
           raw_response=response
       )
   ```

3. Register the command in the `main()` function
   ```python
   def main():
       # existing code...
       elif command == 'abnormal-new-command':
           return new_command_function(client, args)
       # existing code...
   ```

4. Add command details to `AbnormalSecurity.yml`
   ```yaml
   - name: abnormal-new-command
     description: Description of the new command
     arguments:
     - name: param1
       description: First parameter
       required: true
     - name: param2
       description: Second parameter
       required: false
     outputs:
     - contextPath: AbnormalSecurity.OutputKey
       description: Description of the output
       type: string
   ```

5. Update documentation in `README.md` and `command_examples.txt`
6. Add tests in `AbnormalSecurity_test.py`
   ```python
   def test_new_command_function(mocker):
       """Test for new_command_function."""
       mock_response = {'key': 'value'}
       client = Client(BASE_URL, False, False, headers, None)
       mocker.patch.object(client, 'new_api_method', return_value=mock_response)
       
       args = {'param1': 'value1', 'param2': 'value2'}
       result = new_command_function(client, args)
       
       assert result.outputs == mock_response
       assert result.outputs_prefix == 'AbnormalSecurity.OutputKey'
   ```

### Fixing a Bug

1. Create a test that reproduces the bug
2. Fix the issue in the relevant files
3. Verify the test passes
4. Update documentation if needed
5. Add a release note describing the fix

### Updating Dependencies

1. Update dependency versions in pack configuration
2. Test thoroughly to ensure compatibility
3. Document any breaking changes or new requirements

## Testing Guidelines

1. **Unit Tests**: Use pytest with mocks for API responses
   - Isolate each component for testing
   - Use fixtures to provide mock data and responses
   - Test both success and error cases

2. **Integration Tests**: Test against a development instance of Abnormal Security
   - Create test cases for all common operations
   - Verify actual API responses match expected formats
   - Test end-to-end workflows

3. **Edge Cases**: Test for error conditions, empty responses, and pagination
   - Test rate limiting behavior
   - Test with malformed inputs
   - Test with large response payloads
   - Test pagination logic

4. **Performance**: Test with realistic data volumes
   - Verify response times under load
   - Check memory usage with large datasets
   - Test batched operations

5. **Test Automation**:
   - Create scripts for common test scenarios
   - Implement CI/CD pipeline integration
   - Use test coverage reports

### Testing Commands Locally

For testing commands without a XSOAR instance:

```python
# Test script
from AbnormalSecurity import Client, get_a_list_of_threats_command

# Mock client
client = Client('https://api.abnormalplatform.com/v1', False, False, {'Authorization': 'Bearer test_key'}, None)

# Mock args
args = {'limit': '10'}

# Run command
result = get_a_list_of_threats_command(client, args)
print(result.readable_output)
```

## Validation and CI/CD

1. **Pack Validation**:
   - Run `demisto-sdk validate -i Packs/AbnormalSecurity`
   - Check for schema compliance and best practices

2. **Integration Validation**:
   - Test all commands with sample inputs
   - Verify outputs match expected formats
   - Check for proper error handling

3. **Documentation Validation**:
   - Ensure README.md is up-to-date
   - Verify command examples are accurate
   - Check for clear installation and usage instructions

4. **Security Validation**:
   - Scan for hardcoded secrets
   - Verify proper handling of sensitive data
   - Check for secure API usage patterns

## Additional Resources

- **Abnormal Security API Documentation**: Available at [Abnormal Security Developer Portal](https://www.abnormalsecurity.com/)
- **XSOAR Developer Documentation**: [Cortex XSOAR Developer Hub](https://xsoar.pan.dev/)
- **Support**: Contact support@abnormalsecurity.com for assistance
