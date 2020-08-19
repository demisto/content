## [Unreleased]
- You can now search for for similar incidents using numeric and boolean fields.
- Added support for sorting by ID of similar incidents with identical timestamp.


## [20.5.2] - 2020-05-26
-

## [20.4.1] - 2020-04-29
Fixed an issue where list values in context were not compared correctly while using the "similarContextKeys" argument.

## [20.3.4] - 2020-03-30
Deprecated arguments: similarCustomFields, similarIncidentKeys. Use ***similarIncidentFields*** instead.

## [20.3.3] - 2020-03-18
Added support for the "\\" character in incident fields.

## [20.1.2] - 2020-01-22
Shortened the query time range to improve index usage.

## [19.9.1] - 2019-09-18
Added support for list values in context keys and incident fields.

## [19.9.0] - 2019-09-04
  - Added support for the "\n" character in incident fields.
  - Fixed an issue where duplicate incidents were created at the same time.
  - Added support for list values in the context key value.
  
