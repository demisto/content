const { createReadStream } = require('fs');
const { once } = require('events');
const mdx = require('@mdx-js/mdx');

const NO_HTML = "<!-- NOT_HTML_DOC -->";
const YES_HTML = "<!-- HTML_DOC -->";

function isHtmlDoc(content) {
    return content.startsWith(YES_HTML) ||
        (!content.startsWith(NO_HTML) && (
            content.startsWith("<p>") ||
            content.startsWith("<!DOCTYPE html>") ||
            (content.includes("<thead>") && content.includes("<tbody>"))
        ));
}

function fixMdx(content) {
    let txt = content;
    const replaceTuples = [
        [/<br>(?!<\/br>)/gi, "<br/>"],
        [/<hr>(?!<\/hr>)/gi, "<hr/>"],
        [/<pre>/gi, "<pre>{`"],
        [/<\/pre>/gi, "`}</pre>"]
    ];
    replaceTuples.forEach(([oldPattern, newValue]) => {
        txt = txt.replace(oldPattern, newValue);
    });
    txt = txt.replace(/<!--.*?-->/gs, "");
    return txt;
}

async function readInitialChunk(file, length = 1024) {
    return new Promise((resolve, reject) => {
        const stream = createReadStream(file, { encoding: 'utf8', highWaterMark: length });
        let data = '';
        stream.on('data', chunk => {
            data += chunk;
            stream.destroy(); // stop reading more
        });
        stream.on('close', () => resolve(data));
        stream.on('error', reject);
    });
}

const { readFile } = require('fs-extra');

async function parseMDX(file) {
    try {
        // Read first 1KB to check if HTML
        const initialContent = await readInitialChunk(file);
        if (isHtmlDoc(initialContent)) {
            return true; // Skip MDX parsing for HTML docs
        }

        // Read full file content (now that we know it's MDX)
        let contents = await readFile(file, 'utf8');
        contents = fixMdx(contents);
        await mdx(contents);
        return true;
    } catch (error) {
        console.error(`Validation failed in ${file}:`, error.message);
        return false;
    }
}

// For concurrency limiting
const pLimit = require('p-limit');
const limit = pLimit(4);

const files = process.argv.slice(2);
(async () => {
    const promises = files.map(file => limit(() => parseMDX(file)));
    const results = await Promise.all(promises);

    if (results.includes(false)) {
        process.exit(1);
    }
})();
