const { createReadStream } = require('fs');
const { pipeline } = require('stream');
const mdx = require('@mdx-js/mdx');
const { promisify } = require('util');
const pipelineAsync = promisify(pipeline);


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
    // copied from: https://github.com/demisto/content-docs/blob/2402bd1ab1a71f5bf1a23e1028df6ce3b2729cbb/content-repo/mdx_utils.py#L11
    // to use the same logic as we have in the content-docs build
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

async function parseMDX(file) {
    try {
        let isHtml = false;
        let initialContent = '';
        await pipelineAsync(
            createReadStream(file, { encoding: 'utf8', highWaterMark: 1024 }), // Adjust highWaterMark as needed
            {
                objectMode: false,
                transform(chunk, encoding, callback) {
                  initialContent += chunk;
                  if (initialContent.length > 1024 && !isHtml) { // Check early for HTML to avoid unnecessary processing
                    isHtml = isHtmlDoc(initialContent);
                  }
                  callback(null, chunk);
                },
                flush(callback) {
                  if (!isHtml) {
                    const processedContent = fixMdx(initialContent);
                    pipelineAsync(
                      processedContent,
                      mdx(),
                      process.stdout,
                      callback
                    );
                  } else {
                    callback(null);
                  }
                }
              }
        );

        if (isHtml) {
          return true;
        }
        return true;

    } catch (error) {
        console.error(`Validation failed in ${file}:`, error.message);
        return false;
    }
}


const files = process.argv.slice(2);
(async () => {
    const promises = [];

    for (let i = 0; i < files.length; i++) {
        const promise = parseMDX(files[i]);
        promises.push(promise);
    }

    const results = await Promise.all(promises);

    if (results.includes(false)) {
        process.exit(1);
    }
})();
