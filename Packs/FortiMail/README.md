<!-- HTML_DOC -->
<h2>Overview</h2>
<p>Use the Fortinet FortiMail integration to manage MailGateway settings and groups.</p>
<p>We recommend that users have API Service enabled on the box and the accountorder to access commands.</p>
<p>This integration was integrated and tested with FortiMail latest Version and is under development</p>
<h2>Configure FortiGate on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for FortiGate.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g. 192.168.0.1)</strong></li>
<li><strong>Account Username</strong></li>
<li><strong>Account Password</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, username + password, and connection.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_90934042941543315010414">get_domains</a></li>
<li><a href="#h_251291621171543315015519">get_antispam_domains</a></li>
<li><a href="#h_2511153492291543315020336">get_recipient_policies</a></li>
<li><a href="#h_549888813401543315025030">grey_list</a></li>
<li><a href="#h_2658967384501543315029859">get_session_safe_list</a></li>
<li><a href="#h_4649504885591543315036188">get_session_block_list</a></li>
<li><a href="#h_6602236946671543315041059">update_block_list</a></li>
<li><a href="#h_8412979427741543315053679">update_safe_list</a></li>
<li><a href="#h_1422688068801543315066050">block_sender_address</a></li>
<li><a href="#h_4085733299851543315074230">block_recipient_address</a></li>
<li><a href="#h_24259910811861543315086356">unblock_sender_address</a></li>
<li><a href="#h_2455845312891543315091313">unblock_recipient_address</a></li>
<li><a href="#h_71275394613911543315098969">display_quarantine_mail_list</a></li>
<li><a href="#h_90703567814921543315103725">quarantine_release</a></li>
<li><a href="#h_57698000216851543315108111">view_mail_in_quarantine</a></li>
<li><a href="#h_57698000216851543315108144">system_quarantine_batch_release</a></li>
</ol>
<h3 id="h_90934042941543315010414">1. get_domains</h3>
<h3 id="h_251291621171543315015519">2. get_antispam_domains</h3>
<h3 id="h_2511153492291543315020336">3. get_recipient_policies</h3>
<h3 id="h_549888813401543315025030">4. grey_list</h3>
<h3 id="h_2658967384501543315029859">5. get_session_safe_list</h3>
<h3 id="h_4649504885591543315036188">6. get_session_block_list</h3>
<h3 id="h_6602236946671543315041059">7. update_block_list</h3>
<h3 id="h_8412979427741543315053679">8. update_safe_list</h3>
<h3 id="h_1422688068801543315066050">9. block_sender_address</h3>
<h3 id="h_4085733299851543315074230">10. block_recipient_address</h3>
<h3 id="h_24259910811861543315086356">11. unblock_sender_address</h3>
<h3 id="h_2455845312891543315091313">12. unblock_recipient_address</h3>
<h3 id="h_71275394613911543315098969">13. display_quarantine_mail_list</h3>
<h3 id="h_90703567814921543315103725">14. quarantine_release</h3>
<h3 id="h_57698000216851543315108111">15. view_mail_in_quarantine</h3>
<h3 id="#h_57698000216851543315108144">16. system_quarantine_batch_release</h3>
