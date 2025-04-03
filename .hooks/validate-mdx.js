const { readFile } = require('fs-extra');
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


function fixMdx(readmeContent) {
    // copied from: https://github.com/demisto/content-docs/blob/2402bd1ab1a71f5bf1a23e1028df6ce3b2729cbb/content-repo/mdx_utils.py#L11
    // to use the same logic as we have in the content-docs build
    let txt = readmeContent;

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

        let contents = await readFile(file, 'utf8');

        if (isHtmlDoc(contents)) {
            return true;
        }
        contents = fixMdx(contents);
        await mdx(contents);
        return true;
    } catch (error) {
        console.error(`Validation failed in ${file}:`, error.message);
        return false;
    }
}

const files = process.argv.slice(2);
(async () => {
    let hasErrors = false;

    const promises = [];

    // For loop calling parseMDX without await
    for (let i = 0; i < files.length; i++) {
        const promise = parseMDX(files[i]); // Call async function that returns boolean
        promises.push(promise); // Store the promise
    }

    // Wait for all promises to resolve and get boolean results
    const results = await Promise.all(promises);

    if (results.includes(false)) {
        process.exit(1);
    }
})();
