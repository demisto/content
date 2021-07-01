# WhiteListDomainGlob

## Description
This short automation takes a query that returns Domain and DomainGlob indicators, and compares one to the other using
wildcard match logic.

The purpose of this is to use the domainglob indicators as a whitelist.
You can then use `-tags:whitelisted` to remove any Domain indicators that matched the wildcard logic.

## Example
Given the following indicator data:

**Domain**
```json
{
  "value": "www.google.com",
  "type": "Domain"
}
```

**DomainGlob**
```json
{
  "value": "*.google.com",
  "type": "DomainGlob"
}
```

and the command

`!WhiteListDomainGlob indicator_query=type:Domain glob_whitelist_query=type:DomainGlob add_tag=Whitelisted`

The Domain indicator will be tagged with the value of the *add_tag* argument (`whitelisted`).

uses `findIndicators`, `setIndicator` and `removeIndicatorField`.
