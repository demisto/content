## [Unreleased]
  - Added the `max` parameter to the `securonix-list-incidents` command.
  - Added the `max_fetch` parameter to the integration configuration, where the default and maximum value is 50.
  - Fixed an issue where duplicate incidents where fetched.

## [20.4.1] - 2020-04-29
  - Added the *action_parameters* argument to the ***securonix-perform-action-on-incident*** command.
  - Improved the name of the fetched incidents to reflect the incident reason.
  - Fixed an issue where the *Incidents to fetch* parameter was not taken in to account when fetching incidents.

## [20.2.3] - 2020-02-18
Fixed an issue where the integration failed to fetch incidents.

## [20.2.0] - 2020-02-04
  - Added the *Host* parameter, which if supplied overrides the default hostname.
  - Added 4 commands.
    - ***securonix-create-incident***
    - ***securonix-create-watchlist***
    - ***securonix-check-entity-in-watchlist***
    - ***securonix-add-entity-to-watchlist***

## [20.1.2] - 2020-01-22
**Securonix**
Use the Securonix integration to manage, update and fetch incidents and manage watchlists.
