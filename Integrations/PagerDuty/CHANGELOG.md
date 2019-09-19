## [Unreleased]
  - added new arguments to ***PagerDuty-get-users-on-call-now*** command:
    - escalation_policy_ids: Filters the results, showing only on-calls for the specified escalation
        policy IDs.
    - schedule_ids: Filters the results, showing only on-calls for the specified schedule
        IDs. If null is provided, it includes permanent on-calls due to direct user
        escalation targets.