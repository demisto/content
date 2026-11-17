
_Creators of the Continuous Compromise Assessment™ model.
Our vision? To measure the world’s cyber-compromise by enabling any organization to continuously and intentionally measure and understand compromise to close the breach detection gap from months to minutes._

Cortex XSOAR interfaces with [LUMU](https://lumu.io/) to help streamline security-related service management and visibility from any of both sides.

The data in Lumu Incidents can be mirrored to Cortex XSOAR so that you can track the status and information in the task.
You can also provide comments, change of status like mute, unmute and close in XSOAR which will appear and reflect in Lumu Platform.

# What does this pack do?

- This pack includes **two integrations**: **Lumu** (legacy) and **Lumu SecOps**.
- As of 2026, for new installations, use **Lumu SecOps** because it is the newer service and includes the latest incident types.
- The legacy Lumu integration remains available for backward compatibility with existing deployments.
- Commands in the legacy integration start with `lumu-`.
- Commands in the Lumu SecOps integration start with `lumusecops-`.
- Monitor and poll Lumu incidents from Cortex XSOAR using the [Lumu API specification](https://docs.lumu.io/portal/en/kb/articles/core-concepts-api#Consult_incidents_updates_Available_for_Insights).
- Use the Cortex mirroring process to keep incidents synchronized between Lumu and Cortex XSOAR.
- Operate incidents from Cortex XSOAR with actions such as muting, unmuting, and closing incidents, and submit changes through the Lumu API to sync both platforms.
- Manual interaction to operate Lumu incidents with commands, with more than 15 commands available for automated or analyst-driven workflows.

As part of this pack, you will also get 1 additional out-of-the-box layout named either `lumu` or `lumusecops` regarding the integration deployed so that you can visualize Lumu incident information in Cortex XSOAR.
