<!-- HTML_DOC -->
<p>Secure, store and tightly control access to tokens, passwords, certificates, encryption keys for protecting secrets and other sensitive data using HashiCorp Vault. This integration fetches credentials. For more information, see <a href="https://xsoar.pan.dev/docs/reference/articles/managing-credentials">Managing Credentials</a>.</p>
<p>This integration was integrated and tested with version 0.11.5 of HashiCorp Vault.</p>
<h2>Authentication</h2>
The integration supports the following auth methods:
<h3>Userpass Auth Method</h3>
It is required to fill in only the <strong>Username / Role ID</strong> parameter with the username and <strong>Password / Secret ID</strong> parameter with the password.
For more details, see the <a href="https://www.vaultproject.io/docs/auth/userpass">HashiCorp Vault documentation</a>.
<h3>Token Auth Method</h3>
It is required to fill in only the <strong>Authentication token</stronng> parameter.
For more details, see the <a href="https://www.vaultproject.io/docs/auth/token">HashiCorp Vault documentation</a>.
<h3>AppRole Auth Method</h3>
It is required to fill in only the <strong>Username / Role ID</strong> parameter with the role ID and <strong>Password / Secret ID</strong> parameter with the secret ID, and tick the <strong>Use AppRole Auth Method</strong> checkbox.
For more details, see the <a href="https://www.vaultproject.io/docs/auth/approle">HashiCorp Vault documentation</a>.
<h2>Configure HashiCorp Vault on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for HashiCorp Vault.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>HashiCorps server URL (e.g., <a href="https://192.168.0.1:8200/" rel="nofollow">https://192.168.0.1:8200</a>)</strong></li>
<li><strong>Use AppRole Auth Method</strong></li>
<li><strong>Username / Role ID</strong></li>
<li><strong>Password / Role Secret</strong></li>
<li><strong>Authentication token</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li>
<strong>Fetches credentials</strong> - If set, the integration will fetch credentials from Vault to Cortex XSOAR.</li>
<li><strong>CSV list of secrets engine types to fetch secrets from</strong></li>
<li><strong>Concat username to credential object name</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2>Commands</h2>
<hr>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_1647383491061545843063404">List all secrets engines: hashicorp-list-secrets-engines</a></li>
<li><a href="#h_7807319543131545843069087">List secrets for a KV V2 engine: hashicorp-list-secrets</a></li>
<li><a href="#h_9094679395181545843076917">Get information for a secret: hashicorp-get-secret-metadata</a></li>
<li><a href="#h_4218549458191545849743395">Delete data for a secret: hashicorp-delete-secret</a></li>
<li><a href="#h_3474402989221545849794072">Undelete (restore) a secret: hashicorp-undelete-secret</a></li>
<li><a href="#h_27794963210241545849897093">Permanently delete a secret: hashicorp-destroy-secret</a></li>
<li><a href="#h_46699327213151545850066012">Disable a secrets engine: hashicorp-disable-engine</a></li>
<li><a href="#h_74140658616031545850173534">Enable a new secrets engine: hashicorp-enable-engine</a></li>
<li><a href="#h_99103347218881545850224370">List all configured policies: hashicorp-list-policies</a></li>
<li><a href="#h_60360222929071545850296339">Get information for a policy: hashicorp-get-policy</a></li>
<li><a href="#h_97508506437331545850383612">Seal a vault: hashicorp-seal-vault</a></li>
<li><a href="#h_24467581039191545850479673">Unseal a vault: hashicorp-unseal-vault</a></li>
<li><a href="#h_91640933340141545850516512">Configure a secrets engine: hashicorp-configure-engine</a></li>
<li><a href="#h_15700209342841545850664433">Reset the engines configuration: hashicorp-reset-configuration</a></li>
<li><a href="#h_97438551044641545850773245%5C">Create a new authentication token: hashicorp-create-token</a></li>
</ol>
<h3 id="h_1647383491061545843063404">1. List all secrets engines</h3>
<hr>
<p>List all secrets engines that exist in HashiCorp Vault.</p>
<h5>Base Command</h5>
<p><code>hashicorp-list-secrets-engines</code></p>
<h5>Input</h5>
<p>There are no input arguments for this command.</p>
<h5>Context Output</h5>
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 244px;"><strong>Path</strong></th>
<th style="width: 10px;"><strong>Type</strong></th>
<th style="width: 276px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 244px;">HashiCorp.Engine.Type</td>
<td style="width: 10px;">string</td>
<td style="width: 276px;">Secrets engine type</td>
</tr>
<tr>
<td style="width: 244px;">HashiCorp.Engine.Path</td>
<td style="width: 10px;">string</td>
<td style="width: 276px;">Secrets engine path in HashiCorp</td>
</tr>
<tr>
<td style="width: 244px;">HashiCorp.Engine.Description</td>
<td style="width: 10px;">string</td>
<td style="width: 276px;">Secrets engine description</td>
</tr>
<tr>
<td style="width: 244px;">HashiCorp.Engine.Accessor</td>
<td style="width: 10px;">string</td>
<td style="width: 276px;">Secrets engine accessor</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!hashicorp-list-secrets-engines
</pre>
<h5>Context Example</h5>
<pre>{
    "HashiCorp": {
        "Engine": [
            {
                "Accessor": "transit_b0c1c4aa",
                "Path": "transit/",
                "Type": "transit"
            },
            {
                "Accessor": "identity_adef7422",
                "Description": "identity store",
                "Path": "identity/",
                "Type": "identity"
            },
            {
                "Accessor": "aws_32f92054",
                "Path": "aws/",
                "Type": "aws"
            },
            {
                "Accessor": "kv_7d59edbc",
                "Path": "kv/",
                "Type": "kv"
            },
            {
                "Accessor": "database_04257645",
                "Path": "database/",
                "Type": "database"
            },
            {
                "Accessor": "kv_bef123ed",
                "Path": "test_1545739691984 /",
                "Type": "kv"
            },
            {
                "Accessor": "kv_80cff632",
                "Path": "kv2/",
                "Type": "kv"
            },
            {
                "Accessor": "kv_9078f614",
                "Path": "test_1545739444652 /",
                "Type": "kv"
            },
            {
                "Accessor": "system_324bc58d",
                "Description": "system endpoints used for control, policy and debugging",
                "Path": "sys/",
                "Type": "system"
            },
            {
                "Accessor": "kv_871d4cd3",
                "Description": "key/value secret storage",
                "Path": "secret/",
                "Type": "kv"
            },
            {
                "Accessor": "kv_5c21978b",
                "Description": "hmm",
                "Path": "shtut/",
                "Type": "kv"
            },
            {
                "Accessor": "ssh_6048cf80",
                "Path": "ssh/",
                "Type": "ssh"
            },
            {
                "Accessor": "cubbyhole_6094de88",
                "Description": "per-token private secret storage",
                "Path": "cubbyhole/",
                "Type": "cubbyhole"
            },
            {
                "Accessor": "totp_f0eb21f3",
                "Path": "totp/",
                "Type": "totp"
            },
            {
                "Accessor": "azure_0216cdab",
                "Path": "azure/",
                "Type": "azure"
            },
            {
                "Accessor": "kv_86acaa5f",
                "Path": "test_1545739510810 /",
                "Type": "kv"
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/50423205-1f331b80-085b-11e9-920d-7b6971440658.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/50423205-1f331b80-085b-11e9-920d-7b6971440658.png" alt="image"></a></p>
<h3 id="h_7807319543131545843069087">2. List secrets for a KV V2 engine</h3>
<hr>
<p>List secrets (names) for a specified KV engine.</p>
<h5>Base Command</h5>
<p><code>hashicorp-list-secrets</code></p>
<h5>Input</h5>
<table style="width: 750px;">
<thead>
<tr>
<th style="width: 135px;"><strong>Argument Name</strong></th>
<th style="width: 434px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 135px;">engine</td>
<td style="width: 434px;">Engine path, e.g.,"secret/". Use the list-secrets-engines command to retrieve the engine path. command.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 135px;">version</td>
<td style="width: 434px;">The version of the KV engine.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 743px;">
<thead>
<tr>
<th style="width: 164px;"><strong>Path</strong></th>
<th style="width: 10px;"><strong>Type</strong></th>
<th style="width: 197px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 164px;">HashiCorp.Secret.Path</td>
<td style="width: 10px;">string</td>
<td style="width: 197px;">Secret path</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!hashicorp-list-secrets engine=secret/ version=2
</pre>
<h5>Context Example</h5>
<pre>{
    "HashiCorp": {
        "Secret": [
            {
                "Path": "key2"
            },
            {
                "Path": "test_secret"
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/50423245-9a94cd00-085b-11e9-8eed-dd3c53ec67aa.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/50423245-9a94cd00-085b-11e9-8eed-dd3c53ec67aa.png" alt="image"></a></p>
<h3 id="h_9094679395181545843076917">3. Get information for a secret</h3>
<hr>
<p>Returns information about a specified secret in a specified KV V2 engine.</p>
<h5>Base Command</h5>
<p><code>hashicorp-get-secret-metadata</code></p>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 238px;"><strong>Argument Name</strong></th>
<th style="width: 444px;"><strong>Description</strong></th>
<th style="width: 58px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 238px;">engine_path</td>
<td style="width: 444px;">KV Engine path, e.g., "kv/"</td>
<td style="width: 58px;">Required</td>
</tr>
<tr>
<td style="width: 238px;">secret_path</td>
<td style="width: 444px;">Secret path, e.g., "secret"</td>
<td style="width: 58px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 742px;">
<thead>
<tr>
<th style="width: 340px;"><strong>Path</strong></th>
<th style="width: 32px;"><strong>Type</strong></th>
<th style="width: 368px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 340px;">HashiCorp.Secret.Created</td>
<td style="width: 32px;">date</td>
<td style="width: 368px;">Secret created time</td>
</tr>
<tr>
<td style="width: 340px;">HashiCorp.Secret.Version.Destroyed</td>
<td style="width: 32px;">boolean</td>
<td style="width: 368px;">Is the version destroyed</td>
</tr>
<tr>
<td style="width: 340px;">HashiCorp.Secret.Version.Created</td>
<td style="width: 32px;">number</td>
<td style="width: 368px;">Version creation time</td>
</tr>
<tr>
<td style="width: 340px;">HashiCorp.Secret.Version.Deleted</td>
<td style="width: 32px;">date</td>
<td style="width: 368px;">Version deletion time</td>
</tr>
<tr>
<td style="width: 340px;">HashiCorp.Secret.Updated</td>
<td style="width: 32px;">date</td>
<td style="width: 368px;">Secret last updated time</td>
</tr>
<tr>
<td style="width: 340px;">HashiCorp.Secret.Engine</td>
<td style="width: 32px;">string</td>
<td style="width: 368px;">Secret engine type</td>
</tr>
<tr>
<td style="width: 340px;">HashiCorp.Secret.CurrentVersion</td>
<td style="width: 32px;">number</td>
<td style="width: 368px;">Secret current version</td>
</tr>
<tr>
<td style="width: 340px;">HashiCorp.Secret.Path</td>
<td style="width: 32px;">string</td>
<td style="width: 368px;">Secret path</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!hashicorp-get-secret-metadata engine_path=secret/ secret_path=test_secret
</pre>
<h5>Context Example</h5>
<pre>{
    "HashiCorp": {
        "Secret": {
            "Created": "2018-12-23T13:36:43.441882322Z",
            "CurrentVersion": 2,
            "Engine": "secret/",
            "Path": "test_secret",
            "Updated": "2018-12-24T11:50:52.803923598Z",
            "Version": [
                {
                    "Created": "2018-12-23T13:36:43.441882322Z",
                    "Deleted": "",
                    "Destroyed": true,
                    "Number": "1"
                },
                {
                    "Created": "2018-12-24T11:50:52.803923598Z",
                    "Deleted": "",
                    "Destroyed": false,
                    "Number": "2"
                }
            ]
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/50423221-51dd1400-085b-11e9-9e60-26d45298a922.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/50423221-51dd1400-085b-11e9-9e60-26d45298a922.png" alt="image"></a></p>
<h3 id="h_4218549458191545849743395">4. Delete data for a secret</h3>
<hr>
<p>Deletes the data under a specified secret given the secret path. Performs a soft delete that allows you to run the <a href="#h_3474402989221545849794072">hashicorp-undelete-secret</a> command if necessary (for KV V2 engine).</p>
<h5>Base Command</h5>
<p><code>hashicorp-delete-secret</code></p>
<h5>Input</h5>
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 208px;"><strong>Argument Name</strong></th>
<th style="width: 469px;"><strong>Description</strong></th>
<th style="width: 63px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 208px;">secret_path</td>
<td style="width: 469px;">Secret path, e.g., "secret"</td>
<td style="width: 63px;">Required</td>
</tr>
<tr>
<td style="width: 208px;">engine_path</td>
<td style="width: 469px;">Engine path, e.g.,"secret/"</td>
<td style="width: 63px;">Required</td>
</tr>
<tr>
<td style="width: 208px;">versions</td>
<td style="width: 469px;">CSV list of secret versions to delete</td>
<td style="width: 63px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!hashicorp-delete-secret engine_path=secret/ secret_path=test_secret versions=2
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/50423289-1d1d8c80-085c-11e9-9502-4db2650942dc.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/50423289-1d1d8c80-085c-11e9-9502-4db2650942dc.png" alt="image"></a></p>
<h3 id="h_3474402989221545849794072">5. Undelete (restore) a secret</h3>
<hr>
<p>Undeletes (restores) a secret on HashiCorp (for KV V2 engine).</p>
<h5>Base Command</h5>
<p><code>hashicorp-undelete-secret</code></p>
<h5>Input</h5>
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 174px;"><strong>Argument Name</strong></th>
<th style="width: 505px;"><strong>Description</strong></th>
<th style="width: 61px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 174px;">secret_path</td>
<td style="width: 505px;">Secret path, e.g., "secret"</td>
<td style="width: 61px;">Required</td>
</tr>
<tr>
<td style="width: 174px;">engine_path</td>
<td style="width: 505px;">Engine path, e.g.,"secret/"</td>
<td style="width: 61px;">Required</td>
</tr>
<tr>
<td style="width: 174px;">versions</td>
<td style="width: 505px;">CSV list of secret versions to undelete (restore)</td>
<td style="width: 61px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!hashicorp-undelete-secret engine_path=secret/ secret_path=test_secret versions=2
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/50423302-43432c80-085c-11e9-9e67-1f34fb7031c5.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/50423302-43432c80-085c-11e9-9e67-1f34fb7031c5.png" alt="image"></a></p>
<h3 id="h_27794963210241545849897093">6. Permanently delete a secret</h3>
<hr>
<p>Permanently deletes a secret (for KV V2 engine).</p>
<h5>Base Command</h5>
<p><code>hashicorp-destroy-secret</code></p>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 173px;"><strong>Argument Name</strong></th>
<th style="width: 507px;"><strong>Description</strong></th>
<th style="width: 60px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 173px;">secret_path</td>
<td style="width: 507px;">Secret path, .e.g., "secret"</td>
<td style="width: 60px;">Required</td>
</tr>
<tr>
<td style="width: 173px;">engine_path</td>
<td style="width: 507px;">Engine path, e.g.,"secret/"</td>
<td style="width: 60px;">Required</td>
</tr>
<tr>
<td style="width: 173px;">versions</td>
<td style="width: 507px;">CSV list of secret versions to permanently delete</td>
<td style="width: 60px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!hashicorp-destroy-secret engine_path=secret/ secret_path=test_secret versions=1
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/50423339-9d43f200-085c-11e9-9ce6-2e24599402ba.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/50423339-9d43f200-085c-11e9-9ce6-2e24599402ba.png" alt="image"></a></p>
<h3 id="h_46699327213151545850066012">7. Disable a secrets engine</h3>
<hr>
<p>When a secrets engine is no longer needed, it can be disabled. All secrets under the engine are revoked and the corresponding vault data and configurations are removed.</p>
<h5>Base Command</h5>
<p><code>hashicorp-disable-engine</code></p>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 205px;"><strong>Argument Name</strong></th>
<th style="width: 472px;"><strong>Description</strong></th>
<th style="width: 63px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 205px;">path</td>
<td style="width: 472px;">Path of the secrets engine to disable</td>
<td style="width: 63px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!hashicorp-disable-engine path=engine/
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/50423361-e431e780-085c-11e9-8ab0-849248f72fd9.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/50423361-e431e780-085c-11e9-8ab0-849248f72fd9.png" alt="image"></a></p>
<h3 id="h_74140658616031545850173534">8. Enable a new secrets engine</h3>
<hr>
<p>Enables a new secrets engine at the specified path.</p>
<h5>Base Command</h5>
<p><code>hashicorp-enable-engine</code></p>
<h5>Input</h5>
<table style="width: 744px;">
<thead>
<tr>
<th style="width: 229px;"><strong>Argument Name</strong></th>
<th style="width: 448px;"><strong>Description</strong></th>
<th style="width: 63px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 229px;">path</td>
<td style="width: 448px;">The path where the secrets engine will be mounted.</td>
<td style="width: 63px;">Required</td>
</tr>
<tr>
<td style="width: 229px;">type</td>
<td style="width: 448px;">Type of backend. For example, "aws"</td>
<td style="width: 63px;">Required</td>
</tr>
<tr>
<td style="width: 229px;">description</td>
<td style="width: 448px;">Human-friendly description of the mount.</td>
<td style="width: 63px;">Optional</td>
</tr>
<tr>
<td style="width: 229px;">default_lease_ttl</td>
<td style="width: 448px;">The default lease duration, specified as a string duration.<br>For example, "5s" or "30m"</td>
<td style="width: 63px;">Optional</td>
</tr>
<tr>
<td style="width: 229px;">max_lease_ttl</td>
<td style="width: 448px;">The maximum lease duration, specified as a string duration.<br>For example, "5s" or "30m"</td>
<td style="width: 63px;">Optional</td>
</tr>
<tr>
<td style="width: 229px;">force_no_cache</td>
<td style="width: 448px;">Disable caching</td>
<td style="width: 63px;">Optional</td>
</tr>
<tr>
<td style="width: 229px;">audit_non_hmac_request_keys</td>
<td style="width: 448px;">CSV list of keys that will not be HMAC'd by audit devices in the request data object.</td>
<td style="width: 63px;">Optional</td>
</tr>
<tr>
<td style="width: 229px;">audit_non_hmac_response_keys</td>
<td style="width: 448px;">CSV list of keys that will not be HMAC'd by audit devices in the response data object.</td>
<td style="width: 63px;">Optional</td>
</tr>
<tr>
<td style="width: 229px;">listing_visibility</td>
<td style="width: 448px;">Whether to show this mount in the UI-specific listing endpoint; "unauth" or "hidden", default is "hidden" Default is hidden.</td>
<td style="width: 63px;">Optional</td>
</tr>
<tr>
<td style="width: 229px;">passthrough_request_headers</td>
<td style="width: 448px;">CSV list of headers to whitelist and pass from the request to the backend.</td>
<td style="width: 63px;">Optional</td>
</tr>
<tr>
<td style="width: 229px;">kv_version</td>
<td style="width: 448px;">KV version to mount. Set to "2" for mount KV V2.</td>
<td style="width: 63px;">Optional</td>
</tr>
<tr>
<td style="width: 229px;">local</td>
<td style="width: 448px;">Specifies if the secrets engine is a local mount only. Local mounts are not replicated, nor (if a secondary) removed by replication. Supported only in Vault Enterprise.</td>
<td style="width: 63px;">Optional</td>
</tr>
<tr>
<td style="width: 229px;">seal_wrap</td>
<td style="width: 448px;">Enable seal wrapping for the mount. Supported only in Vault Enterprise.</td>
<td style="width: 63px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!hashicorp-enable-engine path=test_path type=kv description="this is a test"
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/50423382-193e3a00-085d-11e9-86d3-6deb037c53d0.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/50423382-193e3a00-085d-11e9-86d3-6deb037c53d0.png" alt="image"></a></p>
<h3 id="h_99103347218881545850224370">9. List all configured policies</h3>
<hr>
<p>Lists all configured policies.</p>
<h5>Base Command</h5>
<p><code>hashicorp-list-policies</code></p>
<h5>Input</h5>
<p>There are no input arguments for this command.</p>
<h5>Context Output</h5>
<table style="width: 743px;">
<thead>
<tr>
<th style="width: 322px;"><strong>Path</strong></th>
<th style="width: 18px;"><strong>Type</strong></th>
<th style="width: 400px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 322px;">HashiCorp.Policy.Name</td>
<td style="width: 18px;">string</td>
<td style="width: 400px;">Policy name</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!hashicorp-list-policies
</pre>
<h5>Context Example</h5>
<pre>{
    "HashiCorp": {
        "Policy": [
            {
                "Name": "default"
            },
            {
                "Name": "root"
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/50423408-83ef7580-085d-11e9-99dc-ee6f4071d07f.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/50423408-83ef7580-085d-11e9-99dc-ee6f4071d07f.png" alt="image"></a></p>
<h3 id="h_60360222929071545850296339">10. Get information for a policy</h3>
<hr>
<p>Get information for a policy.</p>
<h5>Base Command</h5>
<p><code>hashicorp-get-policy</code></p>
<h5>Input</h5>
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 184px;"><strong>Argument Name</strong></th>
<th style="width: 497px;"><strong>Description</strong></th>
<th style="width: 59px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 184px;">name</td>
<td style="width: 497px;">Policy name</td>
<td style="width: 59px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 330px;"><strong>Path</strong></th>
<th style="width: 40px;"><strong>Type</strong></th>
<th style="width: 370px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 330px;">HashiCorp.Policy.Name</td>
<td style="width: 40px;">string</td>
<td style="width: 370px;">Policy name</td>
</tr>
<tr>
<td style="width: 330px;">HashiCorp.Policy.Rule.Path</td>
<td style="width: 40px;">string</td>
<td style="width: 370px;">Policy rule path</td>
</tr>
<tr>
<td style="width: 330px;">HashiCorp.Policy.Rule.Capabilities</td>
<td style="width: 40px;">unknown</td>
<td style="width: 370px;">Policy rule capabilities</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!hashicorp-get-policy name=default
</pre>
<h5>Context Example</h5>
<pre>{
    "HashiCorp": {
        "Policy": {
            "Name": "default",
            "Rule": [
                {
                    "Capabilities": [
                        "update"
                    ],
                    "Path": "sys/control-group/request"
                },
                {
                    "Capabilities": [
                        "update"
                    ],
                    "Path": "auth/token/renew-self"
                },
                {
                    "Capabilities": [
                        "update"
                    ],
                    "Path": "sys/tools/hash"
                },
                {
                    "Capabilities": [
                        "update"
                    ],
                    "Path": "auth/token/revoke-self"
                },
                {
                    "Capabilities": [
                        "read"
                    ],
                    "Path": "sys/internal/ui/resultant-acl"
                },
                {
                    "Capabilities": [
                        "update"
                    ],
                    "Path": "sys/wrapping/lookup"
                },
                {
                    "Capabilities": [
                        "read"
                    ],
                    "Path": "auth/token/lookup-self"
                },
                {
                    "Capabilities": [
                        "update"
                    ],
                    "Path": "sys/leases/renew"
                },
                {
                    "Capabilities": [
                        "read",
                        "list",
                        "delete"
                    ],
                    "Path": "secret/delete/*"
                },
                {
                    "Capabilities": [
                        "update"
                    ],
                    "Path": "sys/renew"
                },
                {
                    "Capabilities": [
                        "update"
                    ],
                    "Path": "sys/tools/random/*"
                },
                {
                    "Capabilities": [
                        "read",
                        "delete"
                    ],
                    "Path": "secret"
                },
                {
                    "Capabilities": [
                        "update"
                    ],
                    "Path": "sys/capabilities-self"
                },
                {
                    "Capabilities": [
                        "create",
                        "read",
                        "update",
                        "delete",
                        "list"
                    ],
                    "Path": "cubbyhole/*"
                },
                {
                    "Capabilities": [
                        "read",
                        "list"
                    ],
                    "Path": "sys/policies"
                },
                {
                    "Capabilities": [
                        "update"
                    ],
                    "Path": "sys/leases/lookup"
                },
                {
                    "Capabilities": [
                        "update"
                    ],
                    "Path": "sys/tools/hash/*"
                },
                {
                    "Capabilities": [
                        "update"
                    ],
                    "Path": "sys/wrapping/wrap"
                },
                {
                    "Capabilities": [
                        "update"
                    ],
                    "Path": "sys/tools/random"
                },
                {
                    "Capabilities": [
                        "read"
                    ],
                    "Path": "sys/mounts"
                },
                {
                    "Capabilities": [
                        "update"
                    ],
                    "Path": "sys/wrapping/unwrap"
                },
                {
                    "Capabilities": [
                        "read",
                        "list"
                    ],
                    "Path": "sys/policy"
                },
                {
                    "Capabilities": [
                        "read",
                        "list"
                    ],
                    "Path": "sys/policy/*"
                },
                {
                    "Capabilities": [
                        "read",
                        "list"
                    ],
                    "Path": "sys/policies/*"
                },
                {
                    "Capabilities": [
                        "read",
                        "delete"
                    ],
                    "Path": "secret/*"
                }
            ]
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/50423429-c3b65d00-085d-11e9-88b3-6a66ac38ee3c.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/50423429-c3b65d00-085d-11e9-88b3-6a66ac38ee3c.png" alt="image"></a></p>
<h3 id="h_97508506437331545850383612">11. Seal a vault</h3>
<hr>
<p>If you suspect your data has been compromised, you can seal your vault to prevent access to your secrets.</p>
<h5>Base Command</h5>
<p><code>hashicorp-seal-vault</code></p>
<h5>Input</h5>
<p>There are no input arguments for this command.</p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!hashicorp-seal-vault
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/50424561-c53c5100-086e-11e9-90f9-54795257b202.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/50424561-c53c5100-086e-11e9-90f9-54795257b202.png" alt="image"></a></p>
<h3 id="h_24467581039191545850479673">12. Unseal a vault</h3>
<hr>
<p>Use a single master key share to unseal the vault. If the master key shares threshold is met, vault will attempt to unseal the vault. Otherwise, this API must be called until the threshold is met.</p>
<h5>Base Command</h5>
<p><code>hashicorp-unseal-vault</code></p>
<h5>Input</h5>
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 216px;"><strong>Argument Name</strong></th>
<th style="width: 470px;"><strong>Description</strong></th>
<th style="width: 54px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 216px;">key</td>
<td style="width: 470px;">Single master key</td>
<td style="width: 54px;">Optional</td>
</tr>
<tr>
<td style="width: 216px;">reset</td>
<td style="width: 470px;">Reset the unseal project</td>
<td style="width: 54px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!hashicorp-unseal-vault key=ABCD
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/50424547-9d4ced80-086e-11e9-9f68-e8f50c4ac000.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/50424547-9d4ced80-086e-11e9-9f68-e8f50c4ac000.png" alt="image"></a><br> <a href="https://user-images.githubusercontent.com/35098543/50424752-33364780-0872-11e9-83e3-2bfe855385f2.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/50424752-33364780-0872-11e9-83e3-2bfe855385f2.png" alt="image"></a><br> <a href="https://user-images.githubusercontent.com/35098543/50424757-46491780-0872-11e9-9917-5b2ec073148d.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/50424757-46491780-0872-11e9-9917-5b2ec073148d.png" alt="image"></a></p>
<h3 id="h_91640933340141545850516512">13. Configure a secrets engine</h3>
<hr>
<p>Configure a secrets engine to fetch secrets from.</p>
<h5>Base Command</h5>
<p><code>hashicorp-configure-engine</code></p>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 175px;"><strong>Argument Name</strong></th>
<th style="width: 532px;"><strong>Description</strong></th>
<th style="width: 33px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 175px;">path</td>
<td style="width: 532px;">The engine path, e.g., "secret/"</td>
<td style="width: 33px;">Required</td>
</tr>
<tr>
<td style="width: 175px;">type</td>
<td style="width: 532px;">The engine type, e.g., "KV"</td>
<td style="width: 33px;">Required</td>
</tr>
<tr>
<td style="width: 175px;">version</td>
<td style="width: 532px;">The engine version (for KV engines); "1" or "2"</td>
<td style="width: 33px;">Optional</td>
</tr>
<tr>
<td style="width: 175px;">folder</td>
<td style="width: 532px;">Specific folder to fetch secrets from, e.g., "secret-folder/". (Supported only for engine type KV2)</td>
<td style="width: 33px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!hashicorp-configure-engine path=secret/ type=KV version=2
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/50423439-f19ba180-085d-11e9-8bd4-b875d3e80e2b.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/50423439-f19ba180-085d-11e9-8bd4-b875d3e80e2b.png" alt="image"></a></p>
<h3 id="h_15700209342841545850664433">14. Reset an engines configuration</h3>
<hr>
<p>Reset the engines configuration.</p>
<h5>Base Command</h5>
<p><code>hashicorp-reset-configuration</code></p>
<h5>Input</h5>
<p>There are no input arguments for this command.</p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!hashicorp-reset-configuration
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/50423445-13952400-085e-11e9-9e98-d8ac936ac0ec.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/50423445-13952400-085e-11e9-9e98-d8ac936ac0ec.png" alt="image"></a></p>
<h3>15. Create a new authentication token</h3>
<hr>
<p>Creates a new authentication token.</p>
<h5>Base Command</h5>
<p><code>hashicorp-create-token</code></p>
<h5>Input</h5>
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 159px;"><strong>Argument Name</strong></th>
<th style="width: 534px;"><strong>Description</strong></th>
<th style="width: 47px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 159px;">role_name</td>
<td style="width: 534px;">The name of the token role.</td>
<td style="width: 47px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">policies</td>
<td style="width: 534px;">CSV list of policies for the token. This must be a subset of the policies belonging to the token making the request, unless root. If policies are not specified, all policies of the calling token are applied to the new token.</td>
<td style="width: 47px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">meta</td>
<td style="width: 534px;">A map of string-to-string valued metadata. This is passed through to the audit devices.</td>
<td style="width: 47px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">no_parent</td>
<td style="width: 534px;">If true and set by a root caller, the token will not have the parent token of the caller. This creates a token with no parent.</td>
<td style="width: 47px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">no_default_policy</td>
<td style="width: 534px;">If true the default policy will not be included in this token's policy set; "true" or "false"</td>
<td style="width: 47px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">renewable</td>
<td style="width: 534px;">If set to false, the token cannot be renewed past its initial TTL. If set to true, the token can be renewed up to the system/mount maximum TTL. "true" or "false"</td>
<td style="width: 47px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">ttl</td>
<td style="width: 534px;">The TTL (lease duration) period of the token, provided as "10m" or "1h", where hour is the largest suffix. If not provided, the token is valid for the default lease TTL, or indefinitely if the root policy is used.</td>
<td style="width: 47px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">explicit_max_ttl</td>
<td style="width: 534px;">If set, the token will have an explicit max TTL applied to it. The maximum token TTL cannot be changed later, and unlike with normal tokens, updates to the system/mount max TTL value will have no effect at renewal time. The token can never be renewed or used past the value set at issue time.</td>
<td style="width: 47px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">display_name</td>
<td style="width: 534px;">The display name of the token.</td>
<td style="width: 47px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">num_uses</td>
<td style="width: 534px;">The maximum number of times the token can be used. Supply this argument to create a one-time-token, or limited use token. The value of 0 has no limit to the number of uses.</td>
<td style="width: 47px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">period</td>
<td style="width: 534px;">If specified, the token will be periodic; it will not have a maximum TTL (unless an "explicit-max-ttl" is also set), but every renewal will use the given period. Requires a root/sudo token to use.</td>
<td style="width: 47px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 261px;"><strong>Path</strong></th>
<th style="width: 42px;"><strong>Type</strong></th>
<th style="width: 437px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 261px;">HashiCorp.Auth.Token</td>
<td style="width: 42px;">string</td>
<td style="width: 437px;">Authentication token</td>
</tr>
<tr>
<td style="width: 261px;">HashiCorp.Auth.Policy</td>
<td style="width: 42px;">unknown</td>
<td style="width: 437px;">Authentication policies</td>
</tr>
<tr>
<td style="width: 261px;">HashiCorp.Auth.LeaseDuration</td>
<td style="width: 42px;">number</td>
<td style="width: 437px;">Authentication lease duration in seconds, 0 if indefinitely</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!hashicorp-create-token display_name=test_token policies=default ttl=40m
</pre>
<h5>Context Example</h5>
<pre>{
    "HashiCorp": {
        "Auth": {
            "LeaseDuration": 2400,
            "Policy": [
                "default"
            ],
            "Token": "84naQ9M9UsbvPdjD72eDD9Ya"
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/50423466-5656fc00-085e-11e9-8264-98fa4e46b4c5.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/50423466-5656fc00-085e-11e9-8264-98fa4e46b4c5.png" alt="image"></a></p>
<h2>Additional Information</h2>
<p>In order to fetch credentials from HashiCorp Vault, the relevant secrets engines must be configured with the integration so it can pull the data from them. To configure an engine with the integration, use the <code>configure-engine</code> command.</p>
<h2>Known Limitations</h2>
<p>Currently the integration is able to fetch credentials from the following engines:<br> K/V Versions 1,2<br> Cubbyhole</p>
<p>More engines will be supported in the future.</p>
<p>The following commands are limited to the K/V V2 engine:</p>
<ol>
<li><a href="#h_1647383491061545843063404">hashicorp-list-secrets</a></li>
<li><a href="#h_9094679395181545843076917">hashicorp-get-secret-metadata</a></li>
<li><a href="#h_4218549458191545849743395">hashicorp-delete-secret</a></li>
<li><a href="#h_3474402989221545849794072">hashicorp-undelete-secret</a></li>
<li><a href="#h_27794963210241545849897093">hashicorp-destroy-secret</a></li>
</ol>
<h2>Troubleshooting</h2>
<p>If you receive an <code>404 Not Found</code> error, please make sure you specified the correct engine and secret paths. If you receive a permissions error, make sure your user is authorized to the relevant policies in HashiCorp Vault. For example, in order to view the list of secrets engines, permissions to the following path are required:</p>
<pre>path "sys/mounts" {
    capabilities = ["read"]
}
</pre>
<p>To view all relevant paths please refer to the <a href="https://www.vaultproject.io/api/">Vault documentation</a>.</p>