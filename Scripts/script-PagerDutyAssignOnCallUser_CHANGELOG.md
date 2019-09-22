## [Unreleased]
  - added new arguments to ***PagerDutyAssignOnCallUser*** script:
    - escalation_policy_ids: Filters the results, showing only on-calls for the specified escalation
        policy IDs.
    - schedule_ids: Filters the results, showing only on-calls for the specified schedule
        IDs. If null is provided, it includes permanent on-calls due to direct user
        escalation targets.
  - fix TypeError exception