import yaml
d = yaml.safe_load(open("Packs/Akamai_SIEM/Integrations/Akamai_SIEM/Akamai_SIEM.yml"))
watch = ("page_size", "beta_page_size", "max_concurrent_tasks",
         "should_skip_decode_events", "isFetchEvents", "eventFetchInterval",
         "configIds", "fetchTime", "fetchLimit", "isFetch")
for c in d.get("configuration", []):
    n = c.get("name")
    if n in watch:
        print("%-26s type=%s required=%s hidden=%r" % (
            n, c.get("type"), c.get("required"), c.get("hidden")))
