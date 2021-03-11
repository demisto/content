BitSight for Security Performance Management (SPM) enables CISOs to use an external view of security performance to measure, monitor, manage, and report on their cybersecurity program performance over time, and to facilitate a universal understanding of cyber risk across their organization. This improved understanding enables security leaders to make more informed decisions about their cybersecurity program, including where to focus their limited resources in order to achieve the greatest impact, where to spend money, and how to manage their cyber risk more effectively. 
The data-driven metrics within BitSight indicate if the cybersecurity program is performing up to the expectations set by internal goals and objectives, industry best practices, regulators, customers, and other internal or external stakeholders. The BitSight Security Rating, the industry’s original cybersecurity rating score, provides a trusted metric that reflects the organization’s cybersecurity program performance over time. By combining the insights gained from BitSight SPM with the BitSight Security Rating, security leaders provide a more complete view of their cybersecurity program performance over time and help to bring about a universal understanding of cyber risk to the Board of Directors and other stakeholders. 
Bring BitSight findings event information into your security program and leverage Cortex XSOAR's incident management workflows for automation of managing security incidents. This visibility enables you to pinpoint and control the sources of infections in your company infrastructure, seamlessly going from awareness to rapid remediation. The findings information reveals associated IP addresses, destination ports, and more, to assist your company in connecting the security and IT teams to respond faster and more effectively to threats. 

### Community Contributed Integration
Support and maintenance for this integration are provided by the author.
- **URL**: [https://api.bitsighttech.com/]
***
##BitSight
- This section explains how to configure the instance of BitSight  for Security Performance Management in Cortex XSOAR
API Key: You can use the API Key Provided to you
Company's GUID: You can use the Guid of the company for which incidents needs to be fetched, suppose if you are not aware of GUID. Please execute the command 'bitsight-get-companies-guid' it will list the companies and corresponding GUID.
First fetch Days: This integration will fetch incident once in a day, but when fetch incident is  running for first time, it will take input from this parameter and fetch incidents for given number of days.
Incident Daily Fetch time: Parameter gives input to integration at what time incidents needs to be fetched. We can specify here time in 24 hours format ('HH:MM').
Minimum Severity for Findings: Parameter helps to filter the record based on minimum severity entered here. You can choose one of the severity listed.
Findings minimum asset category: Parameter helps to filter the record based on minimum asset category entered here. You can choose one of the asset category listed.
Findings Grade: Parameter helps to filter the record based on Grade. You can choose multiple grades listed.
Risk Vector: Parameter  helps to filter the record based on Risk Vector.  By default 'All' will be selected, if you need only particular values you can unselect 'All' and select the required values Listed.
