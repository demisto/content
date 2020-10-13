import demistomock as demisto  # noqa: F401
import jinja2
from CommonServerPython import *  # noqa: F401
from jinja2 import Template


def main():

    apps = []

    # getting incident fields
    inc_id = demisto.args().get('incident_id', demisto.incidents()[0]['id'])
    res = demisto.executeCommand("getIncidents", {'id': inc_id})
    incident_data = res[0].get('Contents').get('data')
    app_name = key = demisto.get(incident_data[0]['CustomFields'], 'urlappidname')
    app_sig = key = demisto.get(incident_data[0]['CustomFields'], 'website')

    app = {}
    app['category'] = 'networking'
    app['sub_category'] = 'encrypted-tunnel'
    app['technology'] = 'browser-based'
    app['risk'] = '4'
    app['protocols'] = [{'protocol_selected': 'tcp', 'port_number': 'dynamic'}]
    sig_ssl = {}

    app['signatures'] = []
    app['custom_app_name'] = app_name
    sig_ssl['signature_name'] = 'ssl'
    sig_ssl['selected_string'] = app_sig.replace(".", "\.")
    sig_ssl['context'] = 'ssl-req-client-hello'
    sig_ssl['scope'] = 'session'
    app['signatures'].append(sig_ssl)

    sig_http = {}
    sig_http['signature_name'] = 'http'
    sig_http['selected_string'] = app_sig.replace(".", "\.")
    sig_http['context'] = 'http-req-host-header'
    sig_http['scope'] = 'session'
    app['signatures'].append(sig_http)
    app['flags'] = ['used-by-malware', 'able-to-transfer-file', 'has-known-vulnerability', 'tunnel-other-application']

    apps.append(app)

    template = get_template()
    tm = Template(template)
    app_xml = tm.render(apps=apps)

    app_xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"

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
