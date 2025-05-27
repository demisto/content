const { spawn } = require('child_process');
const path = require('path');

const files = process.argv.slice(2);

(async () => {
    for (const file of files) {
        await new Promise((resolve, reject) => {
            const child = spawn(
                'node',
                ['--max-old-space-size=2048', path.join(__dirname, 'parse-mdx-single.js'), file],
                { stdio: 'inherit' } // pass output to parent console
            );

            child.on('exit', (code) => {
                if (code === 0) return resolve();
                reject(new Error(`MDX validation failed for ${file}`));
            });
        }).catch((err) => {
            console.error(err.message);
            process.exit(1); // fail fast
        });
    }
})();
