<p>
A Google API cloud based translation service.

This integration was integrated and tested with version 2.0.0 of the Python Client of Google Cloud Translate API.
</p>
<h2>Use Cases</h2>
<ul>
<li>Translate text from spam emails</li>
<li>Translate strings found in malware analysis</li>
</ul>
<h2>Detailed Description</h2>
In order to use this integration you need the following:
<ol>
<li><a href="https://console.cloud.google.com/project">Select or create a Cloud Platform project on GCP</a></li>
<li><a href="https://cloud.google.com/billing/docs/how-to/modify-project#enable_billing_for_a_project">Enable billing for the project</a></li>
<li><a href="https://cloud.google.com/translate">Enable the Google Cloud Translate API</a></li>
<li><a href="#create-a-service-account">Create a Service Account</a> with access to Google Translate API</li>
<li>Use the Service Account Private Key in JSON format and the GCP project ID to configure a new instance of Google Cloud Translate integration in Cortex XSOAR</li>
</ol>

<h3>Create a Service Account</h3>
<ol>
<li>Go to: <a href="https://console.developers.google.com">https://console.developers.google.com</a></li>
<li>Select your project</li>
<li>From the side-menu go to <b>IAM & admin > Service accounts > CREATE SERVICE ACCOUNT</b></li>
<li>Type an account name and description and click <b>CREATE</b></li>
<li>From  the drop down list Select a role select <b>Cloud Translation API User</b></li>
<li>Click <b>CONTINUE</b> and then click <b>CREATE KEY</b></li>
<li>Select <b>JSON</b> and click <b>CREATE</b>. The .json file downloads.</li>
</ol>

<h2>Configure GoogleCloudTranslate on Cortex XSOAR</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for GoogleCloudTranslate.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
   <li><strong>Service Account Private Key file contents (JSON)</strong></li>
   <li><strong>Project in Google Cloud Translate</strong></li>
   <li><strong>Trust any certificate (not secure)</strong></li>
   <li><strong>Use system proxy settings</strong></li>
    </ul>
  </li>
  <li>
    Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance.
  </li>
</ol>
<h2>Commands</h2>
<p>
  You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
  After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
  <li><a href="#gct-supported-languages" target="_self">Returns the list of supported two-letter ISO language codes: gct-supported-languages</a></li>
  <li><a href="#gct-translate-text" target="_self">Returns the translated text: gct-translate-text</a></li>
</ol>
<h3 id="gct-supported-languages">1. gct-supported-languages</h3>
<hr>
<p>Returns the list of supported two-letter ISO language codes.</p>
<h5>Base Command</h5>
<p>
  <code>gct-supported-languages</code>
</p>

<h5>Input</h5>
There are no input arguments for this command.
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>GoogleCloudTranslate.SupportedLanguages</td>
      <td>Unknown</td>
      <td>The list of supported two-letter ISO language codes.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!gct-supported-languages</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "GoogleCloudTranslate": {
        "SupportedLanguages": [
            {
                "language_code": "af",
                "support_source": true,
                "support_target": true
            },
            {
                "language_code": "am",
                "support_source": true,
                "support_target": true
            },
            {
                "language_code": "ar",
                "support_source": true,
                "support_target": true
            },
            ...
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<pre>
Languages: af, am, ar, az, be, bg, bn, bs, ca, ceb, co, cs, cy, da, de, el, en, eo, es, et, eu, fa, fi, fr, fy, ga, gd, gl, gu, ha, haw, hi, hmn, hr, ht, hu, hy, id, ig, is, it, iw, ja, jw, ka, kk, km, kn, ko, ku, ky, la, lb, lo, lt, lv, mg, mi, mk, ml, mn, mr, ms, mt, my, ne, nl, no, ny, pa, pl, ps, pt, ro, ru, sd, si, sk, sl, sm, sn, so, sq, sr, st, su, sv, sw, ta, te, tg, th, tl, tr, uk, ur, uz, vi, xh, yi, yo, zh-CN, zh-TW, zu
</pre>
</p>

<h3 id="gct-translate-text">2. gct-translate-text</h3>
<hr>
<p>Returns the translated text.</p>
<h5>Base Command</h5>
<p>
  <code>gct-translate-text text="hello world" target="hr"</code>
</p>

<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>text</td>
      <td>The text to translate.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>target</td>
      <td>The two-letter ISO language code of the target language. Default is "en" (English).</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>source</td>
      <td>The two-letter ISO language code of the source language. Default is "autodetect".</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>GoogleCloudTranslate.TranslateText.ID</td>
      <td>String</td>
      <td>The ID of the request.</td>
    </tr>
    <tr>
      <td>GoogleCloudTranslate.TranslateText.detected_language_code</td>
      <td>String</td>
      <td>The detected two-letter ISO language code of the source language. Null, if no source argument is defined.</td>
    </tr>
    <tr>
      <td>GoogleCloudTranslate.TranslateText.source_language_code</td>
      <td>String</td>
      <td>The source language as specified in the source argument. Null, if no source argument is defined.</td>
    </tr>
    <tr>
      <td>GoogleCloudTranslate.TranslateText.target_language_code</td>
      <td>String</td>
      <td>The two letter ISO language code to which the text was translated.</td>
    </tr>
    <tr>
      <td>GoogleCloudTranslate.TranslateText.text</td>
      <td>String</td>
      <td>The source (original) text that was translated.</td>
    </tr>
    <tr>
      <td>GoogleCloudTranslate.TranslateText.translated_text</td>
      <td>String</td>
      <td>The translated text.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!gct-translate-text text="ciao" target="iw"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "GoogleCloudTranslate.TranslateText": {
        "ID": &lt;ID&gt;,
        "detected_language_code": "it",
        "source_language_code": null,
        "target_language_code": "iw",
        "text": "ciao",
        "translated_text": "\u05e9\u05dc\u05d5\u05dd"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<pre>
Translation: שלום
Source Language Detected: it
</pre>
</p>
</p>
<h2>Additional Information</h2>
<h2>Known Limitations</h2>
The following features are not supported yet:
<ul>
<li>AutoML models
<li>Glossaries
<li>Labels
<li>Batch requests
<li>Multple target language codes
</ul>
<h2>Troubleshooting</h2>
