## Mandiant Feed
Use the Mandiant Feed integration to fetch indicators from Mandiant.

### Login
- To log in, use the **Public Key** and **Secret Key** that was given to you by Mandiant.
- **X-App-Name** is a mandatory field. This value is typically a combination of the customer's or partner's organization name, application name, and version. 
### Note
- Checking the *Retrieve Indicator Metadata* and *Create Relationships* boxes will cause additional API calls to retrieve additional data. Palo Alto recommends limiting the number of indicators in order to prevent system overload.
- Creating relationships could create additional indicators.
