const { spawn } = require('child_process');
const path = require('path');

const files = process.argv.slice(2);

async function runValidator(file, heapLimit = 2048) {
    return new Promise((resolve, reject) => {
        const child = spawn(
            'node',
            [`--max-old-space-size=${heapLimit}`, path.join(__dirname, 'parse-mdx-single.js'), file],
            { stdio: 'inherit' }
        );

        child.on('exit', (code) => {
            if (code === 0) {
                return resolve(true);
            }
            if (heapLimit < 4096) {
                console.warn(`\n[${file}] Retrying with more memory (${heapLimit * 2} MB)...\n`);
                return resolve(runValidator(file, heapLimit * 2));
            }
            console.error(`\n❌ [${file}] Failed after retrying with 4096 MB heap.\n`);
            return resolve(false);
        });
    });
}

(async () => {
    let allPassed = true;

    for (const file of files) {
        console.log(`\n🔍 Validating: ${file}`);
        const result = await runValidator(file);
        if (!result) allPassed = false;
    }

    if (!allPassed) {
        console.error("\n🚫 Some README files failed MDX validation.");
        process.exit(1);
    } else {
        console.log("\n✅ All README files passed MDX validation.");
    }
})();
