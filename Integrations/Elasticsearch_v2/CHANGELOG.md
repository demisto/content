##[Unreleased]
 - Updated Elasticsearch integration - now supports versions 6 and up.
 
 - command  - search (alias: elastic-search):
    -  index - The index in which the search will be made
    - query - Query string to search (Lucene style, see: https://www.elastic.co/guide/en/elasticsearch/reference/7.3/query-dsl-query-string-query.html#query-string-syntax)
    - page - Page number to start search from, default 0
    - size - Page size, 1 - 10000, default 100
    - sort-field -  field to sort the results table by.
        - Note: The list of fields used to sort the index. Only boolean, numeric, date and keyword fields with doc_values are allowed here.
    - sort-direction - Order in which to sort the results table, if a sort-field is selected. Default: asc
    - explain - Computes a score explanation for a query and a specific document, default false