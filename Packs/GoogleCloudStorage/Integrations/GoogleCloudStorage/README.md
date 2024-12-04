<!-- HTML_DOC -->
<p>Use the Google Cloud Storage integration to manage files, buckets, bucket objects, and bucket policies.</p>
<p>This integration was integrated and tested with API version v1 of Google Cloud Storage.</p>
<h2>Detailed Description</h2>
<p>Create a Service Account:</p>
<ol>
<li>Go to the <a href="https://developers.google.com/identity/protocols/OAuth2ServiceAccount#creatinganaccount">Google documentation</a> and follow the procedure in the Creating a Service Account section. After you create a service account, a Service Account Private Key file is downloaded. You will need this file in step 3.</li>
<li>Grant the Storage Admin permission to the Service Account to enable the Service Account to perform all Google Storage API commands.</li>
<li>In Cortex XSOAR, configure an instance of the Google Cloud Storage integration. For the Service Account Private Key parameter, copy the JSON contents of the file you downloaded in step 1.</li>
</ol>
<h2>Configure Google Cloud Storage on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong>  &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Google Cloud Storage.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Service Account Private Key file contents (JSON)</strong></li>
<li>Optional: <strong>Use system proxy settings</strong>
</li>
<li>Optional: <strong>Trust any certificate (not secure)</strong>
</li>
</ul>
</li>
</ol>
<ol start="4">
<li>Click <strong>Test</strong> to validate the new instance.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_0b662964-deaa-49ea-9d66-8161b6b81b81" target="_self">Retrieves the list of buckets: gcs-list-buckets</a></li>
<li><a href="#h_3951a5e9-88ad-4f26-b0d4-33bd27beb754" target="_self">Retrieves bucket information: gcs-get-bucket</a></li>
<li><a href="#h_9ea053ca-a54b-4bc1-9ae9-bedb511a7226" target="_self">Creates a new bucket: gcs-create-bucket</a></li>
<li><a href="#h_1bfe01fe-20db-4b4f-a69c-697a67fcbfbf" target="_self">Deletes a bucket: gcs-delete-bucket</a></li>
<li><a href="#h_8e7d5156-479a-43f6-b5a3-67ad5fdcd265" target="_self">Retrieves the list of objects in a bucket: gcs-list-bucket-objects</a></li>
<li><a href="#h_2389134c-1da8-41b4-bd8e-b2b3f333b47b" target="_self">Retrieves object data into a file: gcs-download-file</a></li>
<li><a href="#h_2007679a-1ab4-4384-a713-6450bf33791b" target="_self">Uploads a file (object) into a bucket: gcs-upload-file</a></li>
<li><a href="#h_294b5fe3-5bea-4902-8095-9fe5069ea5c5" target="_self">Retrieves the Access Control List of a bucket: gcs-list-bucket-policy</a></li>
<li><a href="#h_592411ea-b01a-415c-aaeb-8cac6eeb1e20" target="_self">Adds a new entity to a bucket's Access Control List: gcs-create-bucket-policy</a></li>
<li><a href="#h_c84501e3-c95f-4f0a-a088-3b8f4629360c" target="_self">Updates an existing entity in a bucket's Access Control List: gcs-put-bucket-policy</a></li>
<li><a href="#h_fe3feb0d-0b65-4204-9882-df64a5b9011c" target="_self">Removes an entity from a bucket's Access Control List: gcs-delete-bucket-policy</a></li>
<li><a href="#h_183a3c2f-cbe6-40d4-adb0-a5e97a034a22" target="_self">Retrieves the Access Control List of an object: gcs-list-bucket-object-policy</a></li>
<li><a href="#h_4afd8a99-18d7-4728-b00f-7d5a97c6fedc" target="_self">Adds a new entity to an object's Access Control List: gcs-create-bucket-object-policy</a></li>
<li><a href="#h_11258d19-a352-45b7-b6ca-bf1190dec556" target="_self">Updates an existing entity in an object's Access Control List: gcs-put-bucket-object-policy</a></li>
<li><a href="#h_91177d0b-8270-4c60-b9ce-768b023b5123" target="_self">Removes an entity from an object's Access Control List: gcs-delete-bucket-object-policy</a></li>
</ol>
<h3 id="h_0b662964-deaa-49ea-9d66-8161b6b81b81">1. Retrieve the list of buckets</h3>
<hr>
<p>Retrieve the list of buckets.</p>
<h5>Base Command</h5>
<p><code>gcs-list-buckets</code></p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 242px;"><strong>Path</strong></th>
<th style="width: 118px;"><strong>Type</strong></th>
<th style="width: 348px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 242px;">GCS.Bucket.Name</td>
<td style="width: 118px;">String</td>
<td style="width: 348px;">Bucket name (also ID).</td>
</tr>
<tr>
<td style="width: 242px;">GCS.Bucket.TimeCreated</td>
<td style="width: 118px;">Date</td>
<td style="width: 348px;">Bucket creation time.</td>
</tr>
<tr>
<td style="width: 242px;">GCS.Bucket.TimeUpdated</td>
<td style="width: 118px;">Date</td>
<td style="width: 348px;">Last time bucket was modified.</td>
</tr>
<tr>
<td style="width: 242px;">GCS.Bucket.OwnerID</td>
<td style="width: 118px;">String</td>
<td style="width: 348px;">Bucket owner ID.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>gcs-list-buckets</pre>
<h5>Human Readable Output</h5>
<h3>Buckets in project my-project</h3>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 159px;">Name</th>
<th style="width: 209px;">Time Created</th>
<th style="width: 219px;">Time Updated</th>
<th style="width: 108px;">Owner ID</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 159px;">my-bucket</td>
<td style="width: 209px;">2019-08-25T11:14:46</td>
<td style="width: 219px;">2019-08-25T11:14:49</td>
<td style="width: 108px;"> </td>
</tr>
<tr>
<td style="width: 159px;">another-bucket</td>
<td style="width: 209px;">2019-09-01T15:31:45</td>
<td style="width: 219px;">2019-09-01T17:52:23</td>
<td style="width: 108px;"> </td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_3951a5e9-88ad-4f26-b0d4-33bd27beb754">2. Retrieve bucket information</h3>
<hr>
<p>Retrieves bucket information.</p>
<h5>Base Command</h5>
<p><code>gcs-get-bucket</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 225px;"><strong>Argument Name</strong></th>
<th style="width: 359px;"><strong>Description</strong></th>
<th style="width: 124px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 225px;">bucket_name</td>
<td style="width: 359px;">Name of the bucket to retrieve.</td>
<td style="width: 124px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 276px;"><strong>Path</strong></th>
<th style="width: 84px;"><strong>Type</strong></th>
<th style="width: 348px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 276px;">GCS.Bucket.Name</td>
<td style="width: 84px;">String</td>
<td style="width: 348px;">Bucket name (also ID).</td>
</tr>
<tr>
<td style="width: 276px;">GCS.Bucket.TimeCreated</td>
<td style="width: 84px;">Date</td>
<td style="width: 348px;">Bucket creation time.</td>
</tr>
<tr>
<td style="width: 276px;">GCS.Bucket.TimeUpdated</td>
<td style="width: 84px;">Date</td>
<td style="width: 348px;">Last time bucket was modified.</td>
</tr>
<tr>
<td style="width: 276px;">GCS.Bucket.OwnerID</td>
<td style="width: 84px;">String</td>
<td style="width: 348px;">Bucket owner ID.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>gcs-get-bucket bucket_name=my-bucket</pre>
<h5>Human Readable Output</h5>
<h3>Bucket my-bucket</h3>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 120px;">Name</th>
<th style="width: 226px;">Time Created</th>
<th style="width: 233px;">Time Updated</th>
<th style="width: 116px;">Owner ID</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 120px;">my-bucket</td>
<td style="width: 226px;">2019-08-25T11:14:46</td>
<td style="width: 233px;">2019-08-25T11:14:49</td>
<td style="width: 116px;"> </td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_9ea053ca-a54b-4bc1-9ae9-bedb511a7226">3. Create a new bucket</h3>
<hr>
<p>Creates a new bucket.</p>
<h5>Base Command</h5>
<p><code>gcs-create-bucket</code></p>
<h5>Input</h5>
<table style="width: 744px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 185px;"><strong>Argument Name</strong></th>
<th style="width: 417px;"><strong>Description</strong></th>
<th style="width: 106px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 185px;">bucket_name</td>
<td style="width: 417px;">Name of the bucket to create.</td>
<td style="width: 106px;">Required</td>
</tr>
<tr>
<td style="width: 185px;">bucket_acl</td>
<td style="width: 417px;">Access Control List for the bucket.</td>
<td style="width: 106px;">Optional</td>
</tr>
<tr>
<td style="width: 185px;">default_object_acl</td>
<td style="width: 417px;">Default Access Control List for the object.</td>
<td style="width: 106px;">Optional</td>
</tr>
<tr>
<td style="width: 185px;">location</td>
<td style="width: 417px;">The location of the bucket, The default value is US.</td>
<td style="width: 106px;">Optional</td>
</tr>
<tr>
<td style="width: 185px;">uniform_bucket_level_access</td>
<td style="width: 417px;">Whether the bucket is configured to allow only IAM, The default value is false.</td>
<td style="width: 106px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>gcs-create-bucket bucket_name=my-bucket bucket_acl=publicRead default_object_acl=authenticatedRead</pre>
<h5>Human Readable Output</h5>
<p>Bucket my-bucket was created successfully.</p>
<h3 id="h_1bfe01fe-20db-4b4f-a69c-697a67fcbfbf">4. Delete a bucket</h3>
<hr>
<p>Deletes a bucket.</p>
<h5>Base Command</h5>
<p><code>gcs-delete-bucket</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 187px;"><strong>Argument Name</strong></th>
<th style="width: 417px;"><strong>Description</strong></th>
<th style="width: 104px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 187px;">bucket_name</td>
<td style="width: 417px;">Name of the bucket to delete.</td>
<td style="width: 104px;">Required</td>
</tr>
<tr>
<td style="width: 187px;">force</td>
<td style="width: 417px;">Forces the bucket to delete (if not empty).</td>
<td style="width: 104px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>gcs-delete-bucket bucket_name=my-bucket force=true</pre>
<h5>Human Readable Output</h5>
<p>Bucket my-bucket was deleted successfully.</p>
<h3 id="h_8e7d5156-479a-43f6-b5a3-67ad5fdcd265">5. Retrieve a list of objects in a bucket</h3>
<hr>
<p>Retrieves the list of objects in a bucket.</p>
<h5>Base Command</h5>
<p><code>gcs-list-bucket-objects</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 184px;"><strong>Argument Name</strong></th>
<th style="width: 421px;"><strong>Description</strong></th>
<th style="width: 103px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 184px;">bucket_name</td>
<td style="width: 421px;">Name of the bucket in which to list objects.</td>
<td style="width: 103px;">Required</td>
</tr>
<tr>
<td style="width: 184px;">prefix</td>
<td style="width: 421px;">Specify to limit blobs within a "folder" i.e., "folder-1/" if blob is "folder-1/file.txt".</td>
<td style="width: 103px;">Optional</td>
</tr>
<tr>
<td style="width: 184px;">delimiter</td>
<td style="width: 421px;">Use a delimiter if you want to limit results within a specific "folder" and without any nested blobs i.e., "/".</td>
<td style="width: 103px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 280px;"><strong>Path</strong></th>
<th style="width: 67px;"><strong>Type</strong></th>
<th style="width: 361px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 280px;">GCS.BucketObject.Name</td>
<td style="width: 67px;">String</td>
<td style="width: 361px;">Object name.</td>
</tr>
<tr>
<td style="width: 280px;">GCS.BucketObject.Bucket</td>
<td style="width: 67px;">String</td>
<td style="width: 361px;">Name of the bucket containing the object.</td>
</tr>
<tr>
<td style="width: 280px;">GCS.BucketObject.ContentType</td>
<td style="width: 67px;">String</td>
<td style="width: 361px;">Content-Type of the object data.</td>
</tr>
<tr>
<td style="width: 280px;">GCS.BucketObject.TimeCreated</td>
<td style="width: 67px;">Date</td>
<td style="width: 361px;">Object creation time.</td>
</tr>
<tr>
<td style="width: 280px;">GCS.BucketObject.TimeUpdated</td>
<td style="width: 67px;">Date</td>
<td style="width: 361px;">Last time object was modified.</td>
</tr>
<tr>
<td style="width: 280px;">GCS.BucketObject.TimeDeleted</td>
<td style="width: 67px;">Date</td>
<td style="width: 361px;">Object deletion time (available if the object is archived).</td>
</tr>
<tr>
<td style="width: 280px;">GCS.BucketObject.Size</td>
<td style="width: 67px;">Number</td>
<td style="width: 361px;">Object size in bytes.</td>
</tr>
<tr>
<td style="width: 280px;">GCS.BucketObject.MD5</td>
<td style="width: 67px;">String</td>
<td style="width: 361px;">MD5 hash of the data in Base64.</td>
</tr>
<tr>
<td style="width: 280px;">GCS.BucketObject.OwnerID</td>
<td style="width: 67px;">String</td>
<td style="width: 361px;">Object owner ID.</td>
</tr>
<tr>
<td style="width: 280px;">GCS.BucketObject.CRC32c</td>
<td style="width: 67px;">String</td>
<td style="width: 361px;">CRC32c checksum (as described in <a href="https://tools.ietf.org/html/rfc4960#appendix-B">RFC 4960, Appendix B</a>), encoded using Base64 in big-endian byte order.</td>
</tr>
<tr>
<td style="width: 280px;">GCS.BucketObject.EncryptionAlgorithm</td>
<td style="width: 67px;">String</td>
<td style="width: 361px;">The encryption algorithm.</td>
</tr>
<tr>
<td style="width: 280px;">GCS.BucketObject.EncryptionKeySHA256</td>
<td style="width: 67px;">String</td>
<td style="width: 361px;">SHA256 hash value of the encryption key.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>gcs-list-bucket-objects bucket_name=my-bucket prefix=some/path/ delimiter=/</pre>
<h5>Human Readable Output</h5>
<h3>Objects in bucket my-bucket</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th>Name</th>
<th>Bucket</th>
<th>Content Type</th>
<th>Time Created</th>
<th>Time Updated</th>
<th>Time Deleted</th>
<th>Size</th>
<th>MD5</th>
<th>Owner ID</th>
<th>CRC32c</th>
<th>Encryption Algorithm</th>
<th>Encryption Key SHA256</th>
</tr>
</thead>
<tbody>
<tr>
<td>/some/path/file1.txt</td>
<td>my-bucket</td>
<td>text/plain</td>
<td>2019-08-25T11:15:48</td>
<td>2019-08-25T11:15:48</td>
<td> </td>
<td>29</td>
<td>TMPFaqwyxk3L8lVD+4GKXA==</td>
<td> </td>
<td>0B/wfQ==</td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>/some/path/file2.txt</td>
<td>my-bucket</td>
<td>text/plain</td>
<td>2019-09-01T14:08:15</td>
<td>2019-09-01T14:08:15</td>
<td> </td>
<td>29</td>
<td>Ao3wKBgCODPKqSnqx2GGAc==</td>
<td> </td>
<td>xL/6R5==</td>
<td> </td>
<td> </td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_2389134c-1da8-41b4-bd8e-b2b3f333b47b">6. Retrieve object data into a file</h3>
<hr>
<p>Retrieves object data into a file.</p>
<h5>Base Command</h5>
<p><code>gcs-download-file</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 146px;"><strong>Argument Name</strong></th>
<th style="width: 491px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 146px;">bucket_name</td>
<td style="width: 491px;">Name of the bucket in which the object resides.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 146px;">object_name</td>
<td style="width: 491px;">Name of the object to download.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 146px;">saved_file_name</td>
<td style="width: 491px;">Name of the file in which the object is downloaded (if not specified, the name is derived from the object name, but this may fail if the object contains invalid filename characters).</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>gcs-download-file bucket_name=my-bucket object_name=/some/path/file1.txt</pre>
<h5>Human Readable Output</h5>
<p>Link to the retrieved file.</p>
<h3 id="h_2007679a-1ab4-4384-a713-6450bf33791b">7. Upload a file (object) into a bucket</h3>
<hr>
<p>Uploads a file (object) into a bucket.</p>
<h5>Base Command</h5>
<p><code>gcs-upload-file</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 180px;"><strong>Argument Name</strong></th>
<th style="width: 435px;"><strong>Description</strong></th>
<th style="width: 93px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 180px;">entry_id</td>
<td style="width: 435px;">ID of a context entry containing the file to upload.</td>
<td style="width: 93px;">Required</td>
</tr>
<tr>
<td style="width: 180px;">bucket_name</td>
<td style="width: 435px;">Name of the bucket in which to upload the object.</td>
<td style="width: 93px;">Required</td>
</tr>
<tr>
<td style="width: 180px;">object_name</td>
<td style="width: 435px;">Name of the uploaded object within the bucket.</td>
<td style="width: 93px;">Required</td>
</tr>
<tr>
<td style="width: 180px;">object_acl</td>
<td style="width: 435px;">Access Control List for the uploaded object.</td>
<td style="width: 93px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>gcs-upload-file entry_id=889@a7c34bf4-a552-49b2-83b6-e95590596286 bucket_name=my-bucket object_name=/some/path/my_file.txt object_acl=bucketOwnerRead</pre>
<h5>Human Readable Output</h5>
<p>File some_source_file.txt was successfully uploaded to bucket my-bucket as /some/path/my_file.txt</p>
<h3 id="h_294b5fe3-5bea-4902-8095-9fe5069ea5c5">8. Retrieve the Access Control List of a bucket</h3>
<hr>
<p>Retrieves the Access Control List of a bucket.</p>
<h5>Base Command</h5>
<p><code>gcs-list-bucket-policy</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 178px;"><strong>Argument Name</strong></th>
<th style="width: 432px;"><strong>Description</strong></th>
<th style="width: 98px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 178px;">bucket_name</td>
<td style="width: 432px;">Name of the bucket for the Access Control List.</td>
<td style="width: 98px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 220px;"><strong>Path</strong></th>
<th style="width: 46px;"><strong>Type</strong></th>
<th style="width: 442px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 220px;">GCS.BucketPolicy.Bucket</td>
<td style="width: 46px;">String</td>
<td style="width: 442px;">Name of the bucket holding the Access Control List.</td>
</tr>
<tr>
<td style="width: 220px;">GCS.BucketPolicy.Entity</td>
<td style="width: 46px;">String</td>
<td style="width: 442px;">The entity holding the permission.</td>
</tr>
<tr>
<td style="width: 220px;">GCS.BucketPolicy.Email</td>
<td style="width: 46px;">String</td>
<td style="width: 442px;">Email address associated with the entity (if any).</td>
</tr>
<tr>
<td style="width: 220px;">GCS.BucketPolicy.Role</td>
<td style="width: 46px;">String</td>
<td style="width: 442px;">The access permission for the entity.</td>
</tr>
<tr>
<td style="width: 220px;">GCS.BucketPolicy.Team</td>
<td style="width: 46px;">String</td>
<td style="width: 442px;">Project team associated with the entity (if any).</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>gcs-list-bucket-policy bucket_name=my-bucket</pre>
<h5>Human Readable Output</h5>
<h3>ACL policy for bucket my-bucket</h3>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 109px;">Bucket</th>
<th style="width: 232px;">Entity</th>
<th style="width: 191px;">Email</th>
<th style="width: 78px;">Role</th>
<th style="width: 72px;">Team</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 109px;">my-bucket</td>
<td style="width: 232px;">project-owners-12345</td>
<td style="width: 191px;"> </td>
<td style="width: 78px;">OWNER</td>
<td style="width: 72px;">owners</td>
</tr>
<tr>
<td style="width: 109px;">my-bucket</td>
<td style="width: 232px;">user-alice@company.com</td>
<td style="width: 191px;">alice@company.com</td>
<td style="width: 78px;">WRITER</td>
<td style="width: 72px;">writers</td>
</tr>
<tr>
<td style="width: 109px;">my-bucket</td>
<td style="width: 232px;">allUsers</td>
<td style="width: 191px;"> </td>
<td style="width: 78px;">WRITER</td>
<td style="width: 72px;"> </td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_592411ea-b01a-415c-aaeb-8cac6eeb1e20">9. Add a new entity to a bucket's Access Control List</h3>
<hr>
<p>Adds a new entity to a bucket's Access Control List. Note: use the gcs-put-bucket-policy command to update an existing entry.</p>
<h5>Base Command</h5>
<p><code>gcs-create-bucket-policy</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 138px;"><strong>Argument Name</strong></th>
<th style="width: 497px;"><strong>Description</strong></th>
<th style="width: 73px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 138px;">bucket_name</td>
<td style="width: 497px;">Name of the bucket in which to modify the Access Control List.</td>
<td style="width: 73px;">Required</td>
</tr>
<tr>
<td style="width: 138px;">entity</td>
<td style="width: 497px;">Entity to add into the Access Control List. Common entity formats are:<br> * user-&lt;userId or email&gt;<br> * group-&lt;groupId or email&gt;<br> * allUsers<br> * allAuthenticatedUsers<br> For more options and details, <a href="https://cloud.google.com/storage/docs/json_api/v1/bucketAccessControls#resource">see this reference</a>
</td>
<td style="width: 73px;">Required</td>
</tr>
<tr>
<td style="width: 138px;">role</td>
<td style="width: 497px;">The access permission for the entity.</td>
<td style="width: 73px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>gcs-create-bucket-policy bucket_name=my-bucket entity=user-alice@company.com role=Writer</pre>
<h5>Human Readable Output</h5>
<p>Added entity user-alice@company.com to ACL of bucket my-bucket with role Writer</p>
<h3 id="h_c84501e3-c95f-4f0a-a088-3b8f4629360c">10. Updates an existing entity in a bucket's Access Control List</h3>
<hr>
<p>Updates an existing entity in a bucket's Access Control List. Note: use the gcs-create-bucket-policy command to create a new entry.</p>
<h5>Base Command</h5>
<p><code>gcs-put-bucket-policy</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 153px;"><strong>Argument Name</strong></th>
<th style="width: 476px;"><strong>Description</strong></th>
<th style="width: 79px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 153px;">bucket_name</td>
<td style="width: 476px;">Name of the bucket in which to modify the Access Control List.</td>
<td style="width: 79px;">Required</td>
</tr>
<tr>
<td style="width: 153px;">entity</td>
<td style="width: 476px;">The entity to update in the Access Control List.<br> Common entity formats are:<br> * user-&lt;userId or email&gt;<br> * group-&lt;groupId or email&gt;<br> * allUsers<br> * allAuthenticatedUsers<br> For more options and details, <a href="https://cloud.google.com/storage/docs/json_api/v1/bucketAccessControls#resource">see this reference</a>
</td>
<td style="width: 79px;">Required</td>
</tr>
<tr>
<td style="width: 153px;">role</td>
<td style="width: 476px;">The access permissions for the entity.</td>
<td style="width: 79px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>gcs-put-bucket-policy bucket_name=my-bucket entity=user-alice@company.com role=Reader</pre>
<h5>Human Readable Output</h5>
<p>Updated ACL entity user-alice@company.com in bucket my-bucket to role Reader</p>
<h3 id="h_fe3feb0d-0b65-4204-9882-df64a5b9011c">11. Removes an entity from a bucket's Access Control List</h3>
<hr>
<p>Removes an entity from a bucket's Access Control List.</p>
<h5>Base Command</h5>
<p><code>gcs-delete-bucket-policy</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 140px;"><strong>Argument Name</strong></th>
<th style="width: 497px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 140px;">bucket_name</td>
<td style="width: 497px;">Name of the bucket in which to modify the Access Control List.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 140px;">entity</td>
<td style="width: 497px;">Entity to remove from the Access Control List. Common entity formats are:<br> * user-&lt;userId or email&gt;<br> * group-&lt;groupId or email&gt;<br> * allUsers<br> * allAuthenticatedUsers<br> For more options and details, <a href="https://cloud.google.com/storage/docs/json_api/v1/bucketAccessControls#resource">see this reference</a>
</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>gcs-delete-bucket-policy bucket_name=my-bucket entity=user-alice@company.com</pre>
<h5>Human Readable Output</h5>
<p>Removed entity user-alice@company.com from ACL of bucket my-bucket</p>
<h3 id="h_183a3c2f-cbe6-40d4-adb0-a5e97a034a22">12. Retrieves the Access Control List of an object</h3>
<hr>
<p>Retrieves the Access Control List of an object.</p>
<h5>Base Command</h5>
<p><code>gcs-list-bucket-object-policy</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 172px;"><strong>Argument Name</strong></th>
<th style="width: 443px;"><strong>Description</strong></th>
<th style="width: 93px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 172px;">bucket_name</td>
<td style="width: 443px;">Name of the bucket in which the object resides.</td>
<td style="width: 93px;">Required</td>
</tr>
<tr>
<td style="width: 172px;">object_name</td>
<td style="width: 443px;">Name of the object in which to list access controls.</td>
<td style="width: 93px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 254px;"><strong>Path</strong></th>
<th style="width: 45px;"><strong>Type</strong></th>
<th style="width: 409px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 254px;">GCS.BucketObjectPolicy.Bucket</td>
<td style="width: 45px;">String</td>
<td style="width: 409px;">Name of the bucket in which the object resides.</td>
</tr>
<tr>
<td style="width: 254px;">GCS.BucketObjectPolicy.Object</td>
<td style="width: 45px;">String</td>
<td style="width: 409px;">Name of the object holding the Access Control List.</td>
</tr>
<tr>
<td style="width: 254px;">GCS.BucketObjectPolicy.Entity</td>
<td style="width: 45px;">String</td>
<td style="width: 409px;">The entity holding the permission.</td>
</tr>
<tr>
<td style="width: 254px;">GCS.BucketObjectPolicy.Email</td>
<td style="width: 45px;">String</td>
<td style="width: 409px;">Email address associated with the entity (if any).</td>
</tr>
<tr>
<td style="width: 254px;">GCS.BucketObjectPolicy.Role</td>
<td style="width: 45px;">String</td>
<td style="width: 409px;">The access permission for the entity.</td>
</tr>
<tr>
<td style="width: 254px;">GCS.BucketObjectPolicy.Team</td>
<td style="width: 45px;">String</td>
<td style="width: 409px;">Project team associated with the entity (if any).</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>gcs-list-bucket-object-policy bucket_name=my-bucket object_name=/some/path/my_file.txt</pre>
<h5>Human Readable Output</h5>
<h3>ACL policy for object foo/bar/moshe.txt</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th>Bucket</th>
<th>Object</th>
<th>Entity</th>
<th>Email</th>
<th>Role</th>
<th>Team</th>
</tr>
</thead>
<tbody>
<tr>
<td>my-bucket</td>
<td>/some/path/my_file.txt</td>
<td>allAuthenticatedUsers</td>
<td> </td>
<td>READER</td>
<td> </td>
</tr>
<tr>
<td>my-bucket</td>
<td>/some/path/my_file.txt</td>
<td>user-alice@company.com</td>
<td>alice@company.com</td>
<td>OWNER</td>
<td>owners</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_4afd8a99-18d7-4728-b00f-7d5a97c6fedc">13. Adds a new entity to an object's Access Control List</h3>
<hr>
<p>Adds a new entity to an object's Access Control List. Note: use the gcs-put-bucket-object-policy command to update an existing entry.</p>
<h5>Base Command</h5>
<p><code>gcs-create-bucket-object-policy</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 136px;"><strong>Argument Name</strong></th>
<th style="width: 499px;"><strong>Description</strong></th>
<th style="width: 73px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 136px;">bucket_name</td>
<td style="width: 499px;">Name of the bucket in which the object resides.</td>
<td style="width: 73px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">object_name</td>
<td style="width: 499px;">Name of the object in which to modify the Access control List.</td>
<td style="width: 73px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">entity</td>
<td style="width: 499px;">Entity to add into the Access Control List. Common entity formats are:<br> * user-&lt;userId or email&gt;<br> * group-&lt;groupId or email&gt;<br> * allUsers<br> * allAuthenticatedUsers<br> For more options and details, <a href="https://cloud.google.com/storage/docs/json_api/v1/bucketAccessControls#resource">see this reference</a>
</td>
<td style="width: 73px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">role</td>
<td style="width: 499px;">The access permission for the entity.</td>
<td style="width: 73px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>gcs-create-bucket-object-policy bucket_name=my-bucket object_name=/some/path/my_file.txt entity=allUsers role=Reader</pre>
<h5>Human Readable Output</h5>
<p>Added entity allUsers to ACL of object /some/path/my_file.txt with role Reader</p>
<h3 id="h_11258d19-a352-45b7-b6ca-bf1190dec556">14. Update an existing entity in an object's Access Control List</h3>
<hr>
<p>Updates an existing entity in an object's Access Control List. Note: use gcs-create-bucket-object-policy command to create a new entry.</p>
<h5>Base Command</h5>
<p><code>gcs-put-bucket-object-policy</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 147px;"><strong>Argument Name</strong></th>
<th style="width: 490px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 147px;">bucket_name</td>
<td style="width: 490px;">Name of the bucket in which the object resides.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 147px;">object_name</td>
<td style="width: 490px;">Name of the object in which to modify access controls.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 147px;">entity</td>
<td style="width: 490px;">The entity to update in the Access Control List. Common entity formats are:<br> * user-&lt;userId or email&gt;<br> * group-&lt;groupId or email&gt;<br> * allUsers<br> * allAuthenticatedUsers<br> For more options and details, <a href="https://cloud.google.com/storage/docs/json_api/v1/bucketAccessControls#resource">see this reference</a>
</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 147px;">role</td>
<td style="width: 490px;">The access permissions for the entity.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>gcs-put-bucket-object-policy bucket_name=my-bucket object_name=/some/path/my_file.txt entity=allUsers role=Owner</pre>
<h5>Human Readable Output</h5>
<p>Updated ACL entity allUsers in object /some/path/my_file.txt to role Owner</p>
<h3 id="h_91177d0b-8270-4c60-b9ce-768b023b5123">15. Remove an entity from an object's Access Control List</h3>
<hr>
<p>Removes an entity from an object's Access Control List.</p>
<h5>Base Command</h5>
<p><code>gcs-delete-bucket-object-policy</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 169px;"><strong>Argument Name</strong></th>
<th style="width: 451px;"><strong>Description</strong></th>
<th style="width: 88px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 169px;">bucket_name</td>
<td style="width: 451px;">Name of the bucket in which the object resides.</td>
<td style="width: 88px;">Required</td>
</tr>
<tr>
<td style="width: 169px;">object_name</td>
<td style="width: 451px;">Name of the object in which to modify access controls.</td>
<td style="width: 88px;">Required</td>
</tr>
<tr>
<td style="width: 169px;">entity</td>
<td style="width: 451px;">Entity to remove from the Access Control List.<br> Common entity formats are:<br> * user-&lt;userId or email&gt;<br> * group-&lt;groupId or email&gt;<br> * allUsers<br> * allAuthenticatedUsers<br> For more options and details, <a href="https://cloud.google.com/storage/docs/json_api/v1/bucketAccessControls#resource">see this reference</a>
</td>
<td style="width: 88px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>gcs-delete-bucket-object-policy bucket_name=my-bucket object_name=/some/path/my_file.txt entity=allUsers</pre>
<h5>Human Readable Output</h5>
<p>Removed entity allUsers from ACL of object /some/path/my_file.txt</p>

<h3>16. Copy an object from one bucket to another</h3>
<hr>
<p>Copies an object from one bucket to another.</h3>
<h5>Base Command</h5>
<p><code>gcs-copy-file</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 169px;"><strong>Argument Name</strong></th>
<th style="width: 451px;"><strong>Description</strong></th>
<th style="width: 88px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 169px;">source_bucket_name</td>
<td style="width: 451px;">Name of the Bucket to copy the object from. If not specified, operation will be performed on the default bucket parameter.</td>
<td style="width: 88px;">Optional</td>
</tr>
<tr>
<td style="width: 169px;">destination_bucket_name</td>
<td style="width: 451px;">Name of the Bucket to copy the object to</td>
<td style="width: 88px;">Required</td>
</tr>
<tr>
<td style="width: 169px;">source_object_name</td>
<td style="width: 451px;">Name of the object to copy</td>
<td style="width: 88px;">Required</td>
</tr>
<tr>
<td style="width: 169px;">destination_object_name</td>
<td style="width: 451px;">Name of the object in the destination bucket. If not specified, operation will be performed with the source_object_name parameter.</td>
<td style="width: 88px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>gcs-copy-file source_bucket_name="my-bucket" destination_bucket_name="another-bucket" source_object_name="/some/path/my_file.txt"</pre>
<h5>Human Readable Output</h5>
<p>File was successfully copied to bucket "another-bucket" as /some/path/my_file.txt</p>


<h3>17. Use public access prevention</h3>
<hr>
<p>Blocks public access to a specified Google Cloud Storage bucket by enabling public access prevention, ensuring only authorized users can access the bucket.</h3>
<h5>Base Command</h5>
<p><code>gcs-block-public-access-bucket</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 169px;"><strong>Argument Name</strong></th>
<th style="width: 451px;"><strong>Description</strong></th>
<th style="width: 88px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 169px;">bucket_name</td>
<td style="width: 451px;">Name of the bucket to which public access policy is to be applied.</td>
<td style="width: 88px;">Optional</td>
</tr>
<tr>
<td style="width: 169px;">public_access_prevention</td>
<td style="width: 451px;">Defines the public access prevention mode for the bucket.
        - enforced: Completely blocks public access to the bucket, ensuring only authorized users can access it.
        - inherited: The bucket will inherit the public access prevention setting from its parent project.</td>
<td style="width: 88px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>gcs-block-public-access-bucket source_bucket_name="my-bucket" public_access_prevention="enforced"</pre>
<h5>Human Readable Output</h5>
<p>Public access prevention is set to enforced for my-bucket.</p>
