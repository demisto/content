## PrometheusClient Help

### Authentication

Information about basic authentication configuration on your Prometheus server can be found here: https://prometheus.io/docs/prometheus/latest/configuration/https/

### Query fields

The fields you'd like to query are added to a string separated by a `|` pipe character. e.g. `co2|solar|load` will return your co2 sensor value, solar panel production, and your home energy use.

If you're more interested in `node-exporter` metrics, you might like to query things like `go_info|node_hwmon_temp_celsius`.

### Prometheus Query API

More information about the Prometheus query API can be found here: https://prometheus.io/docs/prometheus/latest/querying/api/