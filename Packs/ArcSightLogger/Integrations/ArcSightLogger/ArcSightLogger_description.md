To use the integration, start a search session using as-search command, both session id and search session id will be returned from the command. 
Use these arguments to preform further filter on the search (e.g. as-drilldown) or to request desired data (e.g. as-events). Eventually use as-close to close the search session and clean data from the server.  

Date/time format for as-search command
Use the following compliant date/time format in as-search parameters: 
yyyy-MM-dd'T'HH:mm:ss.SSSXXX
For example, May 26 2014 at 21:49:46 PM could have a format like one of the following:
Format in PDT: 2014-05-26T21:49:46.000-07:00
Format in UTC: 2014-05-26T21:49:46.000Z