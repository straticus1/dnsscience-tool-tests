const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox'] });
  const page = await browser.newPage();

  try {
    console.log('=== DNS Science Stats Verification ===\n');

    // Test Homepage
    console.log('1. Homepage...');
    await page.goto('https://www.dnsscience.io/', { waitUntil: 'networkidle0', timeout: 30000 });
    await new Promise(r => setTimeout(r, 2000));
    const homeContent = await page.content();
    console.log(homeContent.includes('domain') ? '   ✓ Stats visible' : '   ✗ No stats');

    // Test Explorer
    console.log('\n2. Explorer...');
    await page.goto('https://www.dnsscience.io/explorer', { waitUntil: 'networkidle0', timeout: 30000 });
    await new Promise(r => setTimeout(r, 2000));
    const explorerContent = await page.content();
    console.log(explorerContent.includes('Total') ? '   ✓ Stats visible' : '   ✗ No stats');

    // Test API
    console.log('\n3. API /api/stats...');
    const apiResp = await page.goto('https://www.dnsscience.io/api/stats', { waitUntil: 'networkidle0' });
    if (apiResp.ok()) {
      const stats = await apiResp.json();
      console.log('   ✓ API working');
      if (stats.total_domains) console.log('   - Domains:', stats.total_domains);
      if (stats.total_valuations) console.log('   - Valuations:', stats.total_valuations);
    } else {
      console.log('   ✗ API failed');
    }

  } catch (error) {
    console.error('Error:', error.message);
  } finally {
    await browser.close();
  }
})();
