Use the Workday IAM integration to fetch Workday reports and create corresponding incidents in Cortex XSOAR. This integration is meant to be used as part of the IAM premium pack.

## Initial Fetch
After you configure an integration instance, the first fetch will sychronize all Workday users (employees) in XSOAR by creating a User Profile indicator for each employee. The User Profile indicators store all employee profiles data, such as the employee's name, street address, phone number, email address, etc.

## Workday Reports
HR use Workday to manage CRUD operations for employees in the organization. It is standard practice for HR to generate reports for these CRUD operations. For example, running a weekly report that captures all new employees and terminated employees, or a daily report that captures updates to existing employee profiles (e.g., new mailing address or phone number).

Cortex XSOAR uses the Workday integration to fetch reports and create XSOAR incidents that correspond to the CRUD operation(s) in the report. For example, if you run a full report that includes 5 new employees, 3 terminated employees, and 10 employee profiles that were updated, 18 unique incidents would be created in XSOAR.

Each report has a unique URL, which you enter as one of the integration instance parameters. If you want to fetch multiple reports, each report will require its own integration instance.

