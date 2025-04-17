
### remedy-get-ticket

***
Get ticket details.

#### Base Command

`remedy-get-ticket`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_request_id | Service request ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Remedy.Ticket.RequesterEmail | string | Email of requester. | 
| Remedy.Ticket.RequesterName | string | Name of requester. | 
| Remedy.Ticket.RequesterPhone | string | Phone of requester. | 
| Remedy.Ticket.RequesterNTID | string | NTID of requester. | 
| Remedy.Ticket.RequesterWorkLocation | string | Work location of requester. | 
| Remedy.Ticket.RequesterWorkCity | string | Work city of requester. | 
| Remedy.Ticket.RequesterWorkStreet | string | Work street of requester. | 
| Remedy.Ticket.Details | string | Ticket details. | 
| Remedy.Ticket.Priority | string | Ticket priority. | 
| Remedy.Ticket.ServiceRequestId | string | Ticket Service request ID. | 
| Remedy.Ticket.Details | string | Ticket Details. | 
| Remedy.Ticket.SourceReference | string | Source reference of the ticket. | 
| Remedy.Ticket.Date | string | Date the ticket was created. | 
| Remedy.Ticket.Time | string | Time the ticket was created. | 
| Remedy.Ticket.ContactEmail | string | Contact Email. | 
| Remedy.Ticket.ContactName | string | Contact Name. | 
| Remedy.Ticket.ContactPhone | string | Contact Phone. | 
| Remedy.Ticket.RequesterPERNR | string | Requester PERNR. | 
### remedy-create-ticket

***
Create a ticket.

#### Base Command

`remedy-create-ticket`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| details | Ticket details. | Required | 
| requester_ntid | Requester NTID. | Required | 
| requester_pernr | Requester PERNR. | Optional | 
| contact_email | Contact Email. | Optional | 
| contact_name | Contact Name. | Optional | 
| contact_phone | Contact Phone. | Optional | 
| requester_email | Email of User. | Required | 
| requester_name | Requester First/Last Name. | Required | 
| requester_phone | User Phone. | Required | 
| requester_work_city | Requester City. | Required | 
| requester_work_location | Requester Office. | Required | 
| requester_work_street | Requester Street. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Remedy.Ticket.RequesterEmail | string | Email of requester. | 
| Remedy.Ticket.RequesterName | string | Name of requester. | 
| Remedy.Ticket.RequesterPhone | string | Phone of requester. | 
| Remedy.Ticket.RequesterNTID | string | NTID of requester. | 
| Remedy.Ticket.RequesterWorkLocation | string | Work location of requester. | 
| Remedy.Ticket.RequesterWorkCity | string | Work city of requester. | 
| Remedy.Ticket.RequesterWorkStreet | string | Work street of requester. | 
| Remedy.Ticket.Details | string | Ticket details. | 
| Remedy.Ticket.Priority | string | Ticket priority. | 
| Remedy.Ticket.ServiceRequestId | string | Ticket Service request ID. | 
| Remedy.Ticket.RequesterPERNR | string | Requester PERNR. | 
| Remedy.Ticket.ContactEmail | string | Contact Email. | 
| Remedy.Ticket.ContactName | string | Contact Name. | 
| Remedy.Ticket.ContactPhone | string | Contact Phone. | 
