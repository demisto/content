const { spawn } = require('child_process');
const path = require('path');

const files = process.argv.slice(2);
const MAX_HEAP_MB = 4096;

async function runValidator(file, heapLimit = 2048) {
    return new Promise((resolve, reject) => {
        let stderrData = '';

        const child = spawn(
            'node',
            [`--max-old-space-size=${heapLimit}`, path.join(__dirname, 'parse-mdx-single.js'), file],
            { stdio: ['ignore', 'inherit', 'pipe'] }
        );

        child.stderr.on('data', (data) => {
            stderrData += data.toString();
        });

        child.on('exit', (code, signal) => {
            const oomExitCodes = [134, 137];
            const oomSignals = ['SIGKILL', 'SIGABRT'];
            const isOOM =
                oomExitCodes.includes(code) ||
                oomSignals.includes(signal) ||
                stderrData.includes('JavaScript heap out of memory');

            if (code === 0) {
                return resolve(true);
            }

            if (isOOM && heapLimit < MAX_HEAP_MB) {
                console.warn(`\n[${file}] OOM detected. Retrying with more memory (${heapLimit * 2} MB)...\n`);
                return resolve(runValidator(file, heapLimit * 2));
            }

            if (isOOM) {
                console.error(`\n❌ [${file}] Failed due to OOM after retrying with ${MAX_HEAP_MB} MB heap.\n`);
            } else {
                console.error(`\n❌ [${file}] Failed with exit code ${code}, signal ${signal}.\n`);
            }

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
