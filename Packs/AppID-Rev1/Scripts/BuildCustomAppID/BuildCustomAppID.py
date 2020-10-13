import demistomock as demisto  # noqa: F401
import jinja2
from CommonServerPython import *  # noqa: F401
from jinja2 import Template


def clean_input(answer):
    lines = answer.split('\n', 1)
    if len(lines) != 2:
        demisto.results("ERROR: Doesn't seem to be formatted properly", answer)
        return('')
    else:
        lines[0] = lines[0].replace(" ", "")
        lines[0] = lines[0].replace(":", "")
        return(lines)


def main():
    app = {}

    fields = {
        'custom_app_name': 'appidname',
        'category': 'appidcategory',
        'sub_category': 'appidsubcategory',
        'technology': 'appidtechnology',
        'risk': 'appidrisk',
        'description': 'appiddescription',
        'risk': 'appidrisk',
    }

    proto = {
        'protocol_selected': 'captureprotocol',
        'port_number': 'capturedstport'
    }

    # getting incident fields
    inc_id = demisto.args().get('incident_id', demisto.incidents()[0]['id'])
    res = demisto.executeCommand("getIncidents", {'id': inc_id})
    incident_data = res[0].get('Contents').get('data')

    for field in fields:
        key = demisto.get(incident_data[0]['CustomFields'], fields[field])
        if key:
            app[field] = key

    app['protocols'] = []

    appidprotocols = {}
    dynport = demisto.get(incident_data[0]['CustomFields'], 'appiddynamicport')
    for field in proto:
        key = demisto.get(incident_data[0]['CustomFields'], proto[field])
        if key:
            if field == 'port_number' and dynport == True:
                appidprotocols[field] = 'dynamic'
            else:
                appidprotocols[field] = key
    app['protocols'].append(appidprotocols)

    app['signatures'] = []

    ascii_answers = demisto.get(demisto.context(), 'Select Ascii Results:')
    for item in ascii_answers['Answers']['0']:
        sig = {}
        result = clean_input(item)
        sig['signature_name'] = result[0]
        sig['selected_string'] = result[1]
        if len(sig['selected_string']) > 127 or len(sig['selected_string']) < 7:
            myErrorText = "ASCII Signatures must be between 7 and 127 bytes.  Please correct this before running playbook again."
            demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"], "Contents": myErrorText})
            pass
        key = demisto.get(incident_data[0]['CustomFields'], 'patternmatchcontext')
        if key:
            sig['context'] = key
        key = demisto.get(incident_data[0]['CustomFields'], 'appidsignaturescope')
        if key:
            sig['scope'] = key
        app['signatures'].append(sig)

    hex_answers = demisto.get(demisto.context(), 'Select Hex Results:')
    for item in hex_answers['Answers']['0']:
        sig = {}
        result = clean_input(item)
        sig['signature_name'] = result[0]
        sig['selected_hex_string'] = result[1].replace(" ", "")
        if len(sig['selected_hex_string']) > 124 or len(sig['selected_hex_string']) < 7:
            myErrorText = "HEX Signatures must be between 7 and 124 bytes.  Please correct this before running playbook again."
            demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"], "Contents": myErrorText})
            pass
        key = demisto.get(incident_data[0]['CustomFields'], 'patternmatchcontext')
        if key:
            sig['context'] = key
        key = demisto.get(incident_data[0]['CustomFields'], 'appidsignaturescope')
        if key:
            sig['scope'] = key
        app['signatures'].append(sig)

    app['flags'] = []
    flags = demisto.get(incident_data[0]['CustomFields'], 'appidcharacteristics')
    if flags:
        for flag in flags:
            if flag:
                app['flags'].append(flag)

    demisto.results(app)
    template = get_template()
    tm = Template(template)
    app_xml = tm.render(apps=[app])

    app_xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"

#    ResultEntries = demisto.executeCommand('panorama', { "action" : "set", "type": "config", "element" : app_xml, 'xpath': app_xpath, 'using': 'rlemm_labfw' })
#    demisto.results(ResultEntries)
    demisto.setContext('appidxml', app_xml)
    demisto.setContext('appidxpath', app_xpath)

# Simply returns the current jinja template


def get_template():
    template = '''
{%- for app in apps %}
<application>
  <entry name="{{ app.custom_app_name }}">
  <default>
    <port>
{%- for protocol in app.protocols %}
      <member>{{ protocol.protocol_selected }}/{{ protocol.port_number }}</member>
{%- endfor %}
    </port>
  </default>
  <signature>
{%- for signature in app.signatures %}
    <entry name="{{ signature.signature_name }}">
      <and-condition>
        <entry name="And Condition 1">
           <or-condition>
              <entry name="Or Condition 1">
                <operator>
                  <pattern-match>
{%- if signature.selected_string is defined %}
                    <pattern>{{ signature.selected_string }}</pattern>
{%- endif %}
{%- if signature.selected_hex_string is defined %}
                    <pattern>\\x{{ signature.selected_hex_string }}\\x</pattern>
{%- endif %}
                    <context>{{ signature.context }}</context>
                  </pattern-match>
                </operator>
              </entry>
           </or-condition>
        </entry>
      </and-condition>
      <scope>{{ signature.scope }}</scope>
      <order-free>no</order-free>
    </entry>
{%- endfor %}
  </signature>
  <subcategory>{{ app.sub_category }}</subcategory>
  <category>{{ app.category }}</category>
  <technology>{{ app.technology }}</technology>
  <risk>{{ app.risk }}</risk>
{%- if app.description is defined %}
  <description>{{ app.description }}</description>
{%- endif %}
{%- if app.timeout is defined %}
  <timeout>{{ app.timeout }}</timeout>
{%- endif %}
{%- if app.tcp_timeout is defined %}
  <tcp-timeout>{{ app.tcp_timeout }}</tcp-timeout>
{%- endif %}
{%- if app.udp_timeout is defined %}
  <udp-timeout>{{ app.udp_timeout }}</udp-timeout>
{%- endif %}
{%- if app.tcp_half_closed_timeout is defined %}
  <tcp-half-closed-timeout>{{ app.tcp_half_closed_timeout }}</tcp-half-closed-timeout>
{%- endif %}
{%- if app.tcp_time_wait_timeout is defined %}
  <tcp-time-wait-timeout>{{ app.tcp_time_wait_timeout }}</tcp-time-wait-timeout>
{%- endif %}
{%- if app.parent_app is defined %}
  <parent-app>{{ app.parent_app }}</parent-app>
{%- endif %}
{%- for flag in app.flags %}
  <{{ flag }}>yes</{{ flag }}>
{%- endfor %}
  </entry>
</application>
{%- endfor %}
'''
    return(template)


main()
