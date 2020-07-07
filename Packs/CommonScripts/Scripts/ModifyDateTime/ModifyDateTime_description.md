## ModifyDateTime
This is a transformer script that will take in a date / time and apply a human readable variation to it. This uses the Python library **dateparser** and the syntax assiciated with it as outlined [here](https://dateparser.readthedocs.io/en/latest/)

The required input is named *"variation"* and is the human readable variation the is applied to the default input value. This can be expressed, for example, as:

`1 day ago`

`3 months ago`

`in 2 years`

`in 20 minutes`

The time variation is applied to the default input date / time and an ISO formatted date is returned.