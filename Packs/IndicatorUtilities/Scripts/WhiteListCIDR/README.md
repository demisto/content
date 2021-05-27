# WhiteListCIDR

## Description
This short automation takes a query that returns CIDR indicator objects, and another that returns IP indicator
objects, and compares one to the other using CIDR match logic.

The purpose of this is to use one CIDR list as a whitelist - in your indicator query for an EDL, you can then use 
`-tags:whitelisted` to remove any IP indicators that fell within the CIDR blocks.

## Example
Given the following IP indicator data:

**IP**
```json
{
  "value": "10.10.10.10",
  "type": "IP"
}
```

**CIDR**
```json
{
  "value": "10.0.0.0/8",
  "type": "CIDR"
}
```

The IP indicator will be tagged with the value of the *add_tag* argument.

uses `findIndicators`, `setIndicator` and `removeIndicatorField`.
