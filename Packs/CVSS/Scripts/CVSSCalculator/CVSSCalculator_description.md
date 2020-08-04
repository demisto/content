## CVSSCalculator
This script uses the calculations provided by [first.org](https://www.first.org/cvss/). The script can calculate the CVSS score using CVSS score calculators for
versions 3.0 and 3.1.

The script requires several inputs that are required for CVSS calculations. Optional inputs can also be defined and help calculate environmental and temporal scores.
Please see the references at [first.org](https://www.first.org/cvss/) for all definitions.

As described by [here](https://www.first.org/cvss/v3.1/specification-document), scores have an acceptable deviation:

*"By consensus, and as was done with CVSS v2.0, the acceptable deviation was a value of 0.5. That is, all the metric value combinations used to derive the weights and calculation will produce a numeric score within its assigned severity level, or within 0.5 of that assigned level."*

Deviations occure due to variance in arithmatic carried out by varying interpreters and CPUs. See [Appendix A](https://www.first.org/cvss/v3.1/specification-document) for a full explanation.
