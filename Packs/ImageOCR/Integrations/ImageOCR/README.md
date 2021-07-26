<!-- HTML_DOC -->
<div class="cl-preview-section">
<p>Use the Image OCR integration to extract text from images. The integration utilizes the open-source<span> </span><a href="https://github.com/tesseract-ocr/tesseract/"><strong>tesseract</strong></a><span> </span>OCR engine.</p>
</div>
<div class="cl-preview-section">
<h2 id="use-cases">Use Cases</h2>
</div>
<div class="cl-preview-section">
<ul>
<li>Extract text from images included in emails during a phishing investigation.</li>
<li>Extract text from images included in an html page.</li>
</ul>
</div>
<div class="cl-preview-section">
<h2 id="configure-image-ocr-on-demisto">Configure Image OCR on Cortex XSOAR</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for Image OCR.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li>
<strong>A CSV of language codes of the language to use for OCR (leave empty to use defaults).</strong><span> </span>Default language is English.</li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate that the configuration is valid.</li>
</ol>
</div>
<div class="cl-preview-section">
<p><strong>Note</strong>: The default language used for OCR is English. To configure additional languages, in the<span> </span><strong>Languages</strong><span> </span>option specify a CSV list of language codes. For example, to set the integration for English and French, set this value:<span> </span><em>eng,fra</em>. To see all supported language codes, use the following command:</p>
</div>
<div class="cl-preview-section">
<pre><code>!image-ocr-list-languages
</code></pre>
</div>
<div class="cl-preview-section">
<h2 id="commands">Commands</h2>
</div>
<div class="cl-preview-section">
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
</div>
<div class="cl-preview-section">
<ol>
<li>Get a list of supported OCR languages: image-ocr-list-languages</li>
<li>Extract text from an image: image-ocr-extract-text</li>
</ol>
</div>
<div class="cl-preview-section">
<h3 id="get-a-list-of-supported-ocr-languages">1. Get a list of supported OCR languages</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Lists supported languages for which the integration can extract text.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>image-ocr-list-languages</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<p>There are no input arguments for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="context-output">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>image-ocr-list-languages</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h2 id="image-ocr-supported-languages">Image OCR Supported Languages</h2>
</div>
<div class="cl-preview-section">
<ul>
<li>ara</li>
<li>chi_sim</li>
<li>chi_sim_vert</li>
<li>chi_tra</li>
<li>chi_tra_vert</li>
<li>deu</li>
<li>eng</li>
<li>fra</li>
<li>heb</li>
<li>ita</li>
<li>jpn</li>
<li>jpn_vert</li>
<li>osd</li>
<li>rus</li>
<li>spa</li>
<li>tur</li>
</ul>
</div>
<div class="cl-preview-section">
<h3 id="extract-text-from-an-image">2. Extract text from an image</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Extracts text from an image.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>image-ocr-extract-text</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-1">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 162.333px;"><strong>Argument Name</strong></th>
<th style="width: 506.667px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 162.333px;">entryid</td>
<td style="width: 506.667px;">Entry ID of the image file to process.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 162.333px;">langs</td>
<td style="width: 506.667px;">A CSV of language codes of the language to use for OCR. Overrides default language. languages.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-1">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 102.667px;"><strong>Path</strong></th>
<th style="width: 87.3333px;"><strong>Type</strong></th>
<th style="width: 550px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 102.667px;">File.Text</td>
<td style="width: 87.3333px;">String</td>
<td style="width: 550px;">Extracted text from the passed image file.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-1">Command Example</h5>
</div>
<div class="cl-preview-section">
<p><code>image-ocr-extract-text entryid="922@e84104f7-b235-4d82-860a-ea09f5dc0559"</code></p>
</div>
<div class="cl-preview-section">
<h5 id="context-example">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre><code>{
    "File": {
        "Text": "The quick brown fox\njumped over the 5\nlazy dogs!\n\f", 
        "EntryID": "922@e84104f7-b235-4d82-860a-ea09f5dc0559"
    }
}
</code></pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h2 id="image-ocr-extracted-text">Image OCR Extracted Text</h2>
</div>
<div class="cl-preview-section">
<p>The quick brown fox<br> jumped over the 5<br> lazy dogs!</p>
</div>