/**
 * Stress test script for the Headless Browser Renderer.
 * Sends multiple batches of URLs to test concurrency and memory handling.
 *
 * Usage: npx tsx scripts/stress-test.ts [baseUrl] [batchSize] [numBatches]
 *
 * Example: npx tsx scripts/stress-test.ts http://localhost:3000 50 5
 */

const BASE_URL = process.argv[2] || 'http://localhost:3000';
const BATCH_SIZE = parseInt(process.argv[3] || '10', 10);
const NUM_BATCHES = parseInt(process.argv[4] || '3', 10);

/** Sample URLs for testing */
const SAMPLE_URLS = [
  'https://example.com',
  'https://httpbin.org/html',
  'https://httpbin.org/delay/2',
  'https://www.wikipedia.org',
  'https://jsonplaceholder.typicode.com',
  'https://httpbin.org/status/404',
  'https://httpbin.org/status/500',
  'https://httpbin.org/redirect/3',
  'https://httpbin.org/bytes/1024',
  'https://example.org',
];

interface BatchResult {
  batch_id: string;
  total: number;
  succeeded: number;
  failed: number;
  partial: number;
  system_stats: {
    peak_memory_percent: number;
    processing_time_ms: number;
  };
}

async function sendBatch(batchNum: number, urls: string[]): Promise<BatchResult> {
  console.log(`\n📦 Sending batch ${batchNum + 1}/${NUM_BATCHES} (${urls.length} URLs)...`);

  const startTime = Date.now();

  const response = await fetch(`${BASE_URL}/render`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      urls,
      locale: 'en-US',
      options: {
        viewport: { width: 1280, height: 720 },
        timeout_ms: 15000,
        full_page: false,
        block_resources: ['media', 'font'],
      },
    }),
  });

  const elapsed = Date.now() - startTime;

  if (!response.ok) {
    const errorText = await response.text();
    console.error(`  ❌ Batch ${batchNum + 1} failed: ${response.status} ${errorText}`);
    throw new Error(`Batch failed: ${response.status}`);
  }

  const result = (await response.json()) as BatchResult;

  console.log(`  ✅ Batch ${batchNum + 1} complete in ${elapsed}ms`);
  console.log(`     Success: ${result.succeeded} | Partial: ${result.partial} | Failed: ${result.failed}`);
  console.log(`     Peak memory: ${result.system_stats.peak_memory_percent}%`);
  console.log(`     Server processing: ${result.system_stats.processing_time_ms}ms`);

  return result;
}

async function checkHealth(): Promise<void> {
  console.log('\n🏥 Checking health...');
  const response = await fetch(`${BASE_URL}/health`);
  const health = await response.json();
  console.log('   Health:', JSON.stringify(health, null, 2));
}

async function getMetrics(): Promise<void> {
  console.log('\n📊 Fetching metrics...');
  const response = await fetch(`${BASE_URL}/metrics`);
  const metrics = await response.text();

  // Extract key metrics
  const lines = metrics.split('\n').filter((l) =>
    l.startsWith('renderer_') && !l.startsWith('#'),
  );
  console.log('   Key metrics:');
  for (const line of lines) {
    console.log(`     ${line}`);
  }
}

async function main(): Promise<void> {
  console.log('🚀 Headless Browser Renderer Stress Test');
  console.log(`   Target: ${BASE_URL}`);
  console.log(`   Batch size: ${BATCH_SIZE}`);
  console.log(`   Number of batches: ${NUM_BATCHES}`);
  console.log(`   Total URLs: ${BATCH_SIZE * NUM_BATCHES}`);

  // Check health first
  try {
    await checkHealth();
  } catch (err) {
    console.error('❌ Server is not reachable. Make sure it is running.');
    process.exit(1);
  }

  const allResults: BatchResult[] = [];
  const overallStart = Date.now();

  // Send batches sequentially
  for (let i = 0; i < NUM_BATCHES; i++) {
    // Generate URLs for this batch
    const urls: string[] = [];
    for (let j = 0; j < BATCH_SIZE; j++) {
      urls.push(SAMPLE_URLS[j % SAMPLE_URLS.length]);
    }

    try {
      const result = await sendBatch(i, urls);
      allResults.push(result);
    } catch (err) {
      console.error(`  ❌ Batch ${i + 1} error:`, err);
    }

    // Small delay between batches
    if (i < NUM_BATCHES - 1) {
      console.log('   ⏳ Waiting 2s before next batch...');
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
  }

  // Summary
  const overallElapsed = Date.now() - overallStart;
  const totalUrls = allResults.reduce((sum, r) => sum + r.total, 0);
  const totalSuccess = allResults.reduce((sum, r) => sum + r.succeeded, 0);
  const totalPartial = allResults.reduce((sum, r) => sum + r.partial, 0);
  const totalFailed = allResults.reduce((sum, r) => sum + r.failed, 0);
  const peakMemory = Math.max(...allResults.map((r) => r.system_stats.peak_memory_percent));
  const avgProcessingTime =
    allResults.reduce((sum, r) => sum + r.system_stats.processing_time_ms, 0) / allResults.length;

  console.log('\n' + '='.repeat(60));
  console.log('📋 STRESS TEST SUMMARY');
  console.log('='.repeat(60));
  console.log(`   Total batches:      ${allResults.length}/${NUM_BATCHES}`);
  console.log(`   Total URLs:         ${totalUrls}`);
  console.log(`   Succeeded:          ${totalSuccess} (${((totalSuccess / totalUrls) * 100).toFixed(1)}%)`);
  console.log(`   Partial:            ${totalPartial} (${((totalPartial / totalUrls) * 100).toFixed(1)}%)`);
  console.log(`   Failed:             ${totalFailed} (${((totalFailed / totalUrls) * 100).toFixed(1)}%)`);
  console.log(`   Peak memory:        ${peakMemory}%`);
  console.log(`   Avg processing:     ${avgProcessingTime.toFixed(0)}ms per batch`);
  console.log(`   Total elapsed:      ${overallElapsed}ms`);
  console.log(`   Throughput:         ${((totalUrls / overallElapsed) * 1000).toFixed(1)} URLs/sec`);
  console.log('='.repeat(60));

  // Final health check
  await checkHealth();
  await getMetrics();
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
