Use Microsoft Defender for Endpoint (previously Microsoft Defender Advanced Threat Protection (ATP)) to deliver industry-leading endpoint security for Windows, macOS, Linux, Android, iOS, and network devices. It helps to rapidly stop attacks, scale your security resources, and evolve your defenses. Microsoft Defender for Endpoint is an enterprise endpoint security platform designed to help enterprise networks prevent, detect, investigate, and respond to advanced threats.

## Integration capabilities:
Microsoft Defender for Endpoint allows you to perform preventative protection, post-breach detection, automated investigation, and response.
Microsoft Defender for Endpoint delivers continuous asset visibility, intelligent risk-based assessments, and built-in remediation tools to help your security and IT teams prioritize and address critical vulnerabilities and misconfigurations across your organization.

## What does this pack do?
- Receives alerts from Microsoft Defender for Endpoint as XSOAR incidents
- Enriches IOCs from XSOAR to Microsoft Defender for Endpoint and vice versa
- Allows remediation actions for connected endpoints
- Provides investigation capabilities on connected assets
- Allows asset visibility, status, and health (vulnerability assessment) 

## Content Pack components
- The Microsoft Defender for Endpoint integration imports events as XSOAR incidents.
- The Microsoft Defender Advanced Threat Protection Get Machine Action Status playbook uses generic polling to get machine action information (relevant for Cortex XSOAR v6.2 and earlier).
- The Microsoft Defender for Endpoint - Isolate Endpoint playbook accepts an endpoint ID, IP address, or hostname and isolates it using the Microsoft Defender for Endpoint integration (relevant for Cortex XSOAR v6.2 and earlier).
- The Microsoft Defender for Endpoint - Unisolate Endpoint playbook accepts an endpoint ID, IP address, or hostname and unisolates it using the Microsoft Defender for Endpoint integration (relevant for Cortex XSOAR v6.2 and earlier).

## Authentication
For more details about the authentication used for components in this content pack, see [Microsoft Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication).
