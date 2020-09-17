 ## Login to Quest Kace
 Please enter your organization's common user name and password to login.
 
### There are 3 types of users who can access API actions:
- Administrator: All API actions are available. In queries, matching data for all users is returned.
- Read-only administrator: All API queries are available. Matching data for all users is returned.
- Standard user: All API queries are available. Matching data is returned only for the current user

### Shaping:
The shaping query parameter limits the amount of returned data is specified. The returned fields for each
associated entity is controlled by two query values. The first is the name of the entity, while the second half of the
pair is the associated level. Name/value pairs are separated by a comma.
The definition of each shaping level is specific to the entity in question. You can use the following shaping levels:
- LIMITED: ID and name.
- STANDARD: The expected set of fields that a typical user consumer requires. This is the default for any
entity if shaping parameters are not specified.
- EXTENDED: Most data.
- ALL: All data, including foreign keys and similar information.
e.g. machine all,software limited,status limited

### Filtering:
Filtering is accomplished using the filtering query parameter. A comma is used to separate multiple filters.
All filters are matched in the returned data set. Each filter is specified by an optional entity name, a field name, an
operator, and a value.


Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.