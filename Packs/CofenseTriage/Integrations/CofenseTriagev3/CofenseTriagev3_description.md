## Cofense Triage Help


- Cofense Triage provides an API that superuser and operator accounts can use to extract data programmatically from Cofense Triage in JSON format.
- This integration is tested with Cofense Triage version 1.22.0.
- [Contact Us](https://cofense.com/contact-support/) if you don't have a Cofense account.



## Integration Settings Preferences

If Inbox or Reconnaissance is provided as a filter for Report Location:
- Category ID filter cannot be used. 
- Categorization Tags filter cannot be used.

If only Processed is provided as a filter for Report Location:
- Tags filter cannot be used.
 
If Category ID is used as a filter for fetch incidents:
- The Report Location cannot be Inbox or Reconnaissance.
- Tags filter cannot be used.

If Categorization tags are provided in fetch incident parameters:
- The Report Location must be Processed.

If Tags are provided in fetch incident parameters:
- The Report Location must be Reconnaissance. 
