### Authentication

The **Username** and **Password** integration parameters can be used to access server that require basic authentication.

These fields also support the use of API key headers. To use API key headers, specify the header name and value in the following format:
`_header:<header_name>` in the **Username** field, and the header value in the **Password** field.

For example, in order to use [GitHub GraphQL API](https://docs.github.com/en/graphql), the parameters should be set as follows:
- ***Username*** : `_header:Authorization`
- ***Password*** : `bearer <PERSONAL-ACCESS-TOKEN>`
