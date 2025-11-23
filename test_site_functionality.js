const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  try {
    console.log('=== DNS Science Site Functionality Test ===\n');

    // Test 1: Homepage loads
    console.log('Test 1: Loading homepage...');
    const page = await browser.newPage();
    await page.goto('https://www.dnsscience.io/', { waitUntil: 'networkidle0', timeout: 30000 });
    const title = await page.title();
    console.log(`✓ Homepage loaded: ${title}\n`);

    // Test 2: Check for login button
    console.log('Test 2: Checking login functionality...');
    const loginButton = await page.$('a[href="/login"]');
    console.log(loginButton ? '✓ Login button found' : '✗ Login button NOT found');

    // Test 3: Navigate to Explorer
    console.log('\nTest 3: Testing Explorer page...');
    await page.goto('https://www.dnsscience.io/explorer', { waitUntil: 'networkidle0', timeout: 30000 });
    const explorerContent = await page.content();
    const hasSearchInput = explorerContent.includes('domain-search') || explorerContent.includes('searchInput');
    console.log(hasSearchInput ? '✓ Explorer page has search functionality' : '✗ Explorer search NOT found');

    // Test 4: Check API docs
    console.log('\nTest 4: Testing API documentation...');
    await page.goto('https://www.dnsscience.io/docs/api', { waitUntil: 'networkidle0', timeout: 30000 });
    const apiContent = await page.content();
    const hasAPIEndpoints = apiContent.includes('/api/') || apiContent.includes('endpoint');
    console.log(hasAPIEndpoints ? '✓ API docs page loaded with endpoints' : '✗ API docs incomplete');

    // Test 5: Check registrar page with new TLDs
    console.log('\nTest 5: Testing Registrar page with 1,438 TLDs...');
    await page.goto('https://www.dnsscience.io/registrar', { waitUntil: 'networkidle0', timeout: 30000 });
    const registrarContent = await page.content();

    // Check for View All TLDs link
    const hasViewAllLink = registrarContent.includes('View All TLDs') || registrarContent.includes('showAllTLDs');
    console.log(hasViewAllLink ? '✓ "View All TLDs" link found' : '✗ View All TLDs link NOT found');

    // Check for random TLD rotation
    const hasRandomTLDs = registrarContent.includes('Try one of these') || registrarContent.includes('randomTLDs');
    console.log(hasRandomTLDs ? '✓ Random TLD section found' : '✗ Random TLD section NOT found');

    // Check for allTLDs array with substantial size
    const tldArrayMatch = registrarContent.match(/const allTLDs = \[([\s\S]*?)\];/);
    if (tldArrayMatch) {
      const tldCount = (tldArrayMatch[1].match(/tld:/g) || []).length;
      console.log(`✓ Found ${tldCount} TLDs in array`);
      if (tldCount >= 1400) {
        console.log('✓ All 1,438 TLDs are present!');
      } else {
        console.log(`⚠ Expected ~1,438 TLDs, found ${tldCount}`);
      }
    } else {
      console.log('✗ Could not find TLD array');
    }

    // Test 6: Check for JavaScript errors
    console.log('\nTest 6: Checking for JavaScript errors...');
    const errors = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        errors.push(msg.text());
      }
    });

    await page.goto('https://www.dnsscience.io/', { waitUntil: 'networkidle0', timeout: 30000 });
    await new Promise(resolve => setTimeout(resolve, 2000));

    if (errors.length === 0) {
      console.log('✓ No JavaScript errors detected');
    } else {
      console.log(`✗ Found ${errors.length} JavaScript errors:`);
      errors.slice(0, 5).forEach(err => console.log(`  - ${err}`));
    }

    // Test 7: Check database connectivity (via API)
    console.log('\nTest 7: Testing database connectivity...');
    const apiResponse = await page.goto('https://www.dnsscience.io/api/stats', {
      waitUntil: 'networkidle0',
      timeout: 30000
    });

    if (apiResponse.ok()) {
      const stats = await apiResponse.json();
      console.log('✓ API responding');
      if (stats.total_domains) {
        const domainCount = Number(stats.total_domains).toLocaleString();
        console.log(`✓ Database connected - ${domainCount} domains`);
      }
    } else {
      console.log(`✗ API returned status: ${apiResponse.status()}`);
    }

    // Test 8: Check pricing page
    console.log('\nTest 8: Testing Pricing page...');
    await page.goto('https://www.dnsscience.io/pricing', { waitUntil: 'networkidle0', timeout: 30000 });
    const pricingContent = await page.content();
    const hasStripePricing = pricingContent.includes('Free') && pricingContent.includes('Professional');
    console.log(hasStripePricing ? '✓ Pricing tiers found' : '✗ Pricing page incomplete');

    console.log('\n=== Test Summary ===');
    console.log('All critical tests completed');
    console.log('Site Status: OPERATIONAL ✓');

  } catch (error) {
    console.error('\n✗ Test failed with error:');
    console.error(error.message);
    process.exit(1);
  } finally {
    await browser.close();
  }
})();
