#!/usr/bin/env node

const { readFile } = require('fs-extra');
const mdx = require('@mdx-js/mdx');
const path = require('path');


// Constants to define explicit NO_HTML and YES_HTML indicators
const NO_HTML = "<!-- NOT_HTML_DOC -->";
const YES_HTML = "<!-- HTML_DOC -->";

// Function to determine if content is HTML
function isHtmlDoc(content) {
    return content.startsWith(YES_HTML) ||
        (!content.startsWith(NO_HTML) && (
            content.startsWith("<p>") ||
            content.startsWith("<!DOCTYPE html>") ||
            (content.includes("<thead>") && content.includes("<tbody>"))
        ));
}

// Function to apply MDX fixes
function fixMdx(readmeContent) {
    let txt = readmeContent;

    // Define replacement rules
    const replaceTuples = [
        [/<br>(?!<\/br>)/gi, "<br/>"],
        [/<hr>(?!<\/hr>)/gi, "<hr/>"],
        [/<pre>/gi, "<pre>{`"],
        [/<\/pre>/gi, "`}</pre>"]
    ];

    // Apply replacements
    replaceTuples.forEach(([oldPattern, newValue]) => {
        txt = txt.replace(oldPattern, newValue);
    });

    // Remove HTML comments
    txt = txt.replace(/<!--.*?-->/gs, "");

    return txt;
}

// Function to parse and process MDX
async function parseMDX(file) {
    try {

        let contents = await readFile(file, 'utf8');

        // Ensure the file is not an HTML document
        if (isHtmlDoc(contents)) {
            return null; // Skip this file
        }

        contents = fixMdx(contents); // Apply MDX fixes
        await mdx(contents);
        return true;
    } catch (error) {
        console.error(`❌ Validation failed in ${file}:`, error.message);
        return false; // Mark as failed
    }
}

// Extract files from command-line arguments
const files = process.argv.slice(2);

if (files.length === 0) {
    console.error("❌ No files provided for validation.");
    process.exit(0);
}

console.log(`🔎 Found ${files.length} files to validate. Processing...`);

(async () => {
    let hasErrors = false;

    for (const file of files) {
        const success = await parseMDX(file);
        if (!success) {
            hasErrors = true;
        }
    }

    if (hasErrors) {
        console.error("❌ Some files failed validation. Commit aborted.");
        process.exit(1);
    }

    console.log("🎉 All provided files have been successfully validated!");
})();
