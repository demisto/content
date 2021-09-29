## Grafana Integration

Panel ID can be found in one of those ways:
1. In Grafana's interface, when viewing a dashboard:
    1. Inspect a panel (click `i` when your mouse is on the panel).
    2. Go to the JSON category.
    3. Choose to view `Panel JSON`, the panel ID is the first field shown.
2. In XSOAR's playground:
   1. Run the `grafana-alerts-list` command.
   2. See what panel the alert rules you are interested are in, and choose that panel ID.
         