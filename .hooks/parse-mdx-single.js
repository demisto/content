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
            process.exit(0);
        }

        contents = fixMdx(contents);
        await mdx(contents);
        process.exit(0);
    } catch (err) {
        console.error(`Validation failed in ${file}: ${err.message}`);
        process.exit(1);
    }
}

const file = process.argv[2];
if (!file) {
    console.error("No file provided to parse.");
    process.exit(1);
}

parseMDX(file);
