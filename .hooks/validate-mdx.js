const { spawn } = require('child_process');
const path = require('path');

async function runValidator(file, heapLimit = 2048) {
    return new Promise((resolve, reject) => {
        let stderrData = '';

        console.log(`[${file}] Starting validation with heap limit: ${heapLimit} MB`);

        const child = spawn(
            'node',
            [`--max-old-space-size=${heapLimit}`, path.join(__dirname, 'parse-mdx-single.js'), file],
            { stdio: ['ignore', 'inherit', 'pipe'] }  // capture stderr
        );

        child.stderr.on('data', (data) => {
            const text = data.toString();
            stderrData += text;
            console.log(`[${file}] STDERR: ${text.trim()}`);
        });

        child.on('exit', (code, signal) => {
            console.log(`[${file}] Process exited with code: ${code}, signal: ${signal}`);

            if (code === 0) {
                console.log(`[${file}] Validation succeeded.`);
                return resolve(true);
            }

            const oomExitCodes = [134, 137];
            const oomSignals = ['SIGKILL', 'SIGABRT'];

            const isOOMExitCode = oomExitCodes.includes(code);
            const isOOMSignal = oomSignals.includes(signal);
            const isOOMStderr = stderrData.includes('JavaScript heap out of memory') || stderrData.includes('Allocation failed - JavaScript heap out of memory');

            console.log(`[${file}] OOM detected by exit code: ${isOOMExitCode}`);
            console.log(`[${file}] OOM detected by signal: ${isOOMSignal}`);
            console.log(`[${file}] OOM detected by stderr: ${isOOMStderr}`);

            if ((isOOMExitCode || isOOMSignal || isOOMStderr) && heapLimit < 4096) {
                console.warn(`\n[${file}] OOM detected. Retrying with more memory (${heapLimit * 2} MB)...\n`);
                return resolve(runValidator(file, heapLimit * 2));
            }

            if (isOOMExitCode || isOOMSignal || isOOMStderr) {
                console.error(`\n❌ [${file}] Failed due to OOM after retrying with 4096 MB heap.\n`);
            } else {
                console.error(`\n❌ [${file}] Failed with exit code ${code}, signal ${signal}.\n`);
            }
            return resolve(false);
        });
    });
}
