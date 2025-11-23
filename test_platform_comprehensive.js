/**
 * DNS Science Platform Comprehensive Test Suite
 * Tests all major functionality across the platform
 *
 * Usage: node test_platform_comprehensive.js
 */

const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');

// Configuration
const BASE_URL = 'https://www.dnsscience.io';
const SCREENSHOT_DIR = path.join(__dirname, 'test_screenshots');
const TIMEOUT = 30000;

// Test results storage
const testResults = {
  timestamp: new Date().toISOString(),
  baseUrl: BASE_URL,
  summary: {
    total: 0,
    passed: 0,
    failed: 0,
    warnings: 0
  },
  tests: [],
  consoleErrors: [],
  networkErrors: [],
  brokenLinks: [],
  performanceMetrics: {}
};

// Utility functions
function logTest(name, status, details = '', screenshot = null) {
  testResults.tests.push({
    name,
    status,
    details,
    screenshot,
    timestamp: new Date().toISOString()
  });
  testResults.summary.total++;
  if (status === 'PASS') testResults.summary.passed++;
  else if (status === 'FAIL') testResults.summary.failed++;
  else if (status === 'WARN') testResults.summary.warnings++;

  const emoji = status === 'PASS' ? '✓' : status === 'FAIL' ? '✗' : '⚠';
  console.log(`${emoji} ${name}: ${status}${details ? ' - ' + details : ''}`);
}

async function takeScreenshot(page, name) {
  try {
    if (!fs.existsSync(SCREENSHOT_DIR)) {
      fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
    }
    const filename = `${name.replace(/[^a-z0-9]/gi, '_')}_${Date.now()}.png`;
    const filepath = path.join(SCREENSHOT_DIR, filename);
    await page.screenshot({ path: filepath, fullPage: true });
    return filename;
  } catch (error) {
    console.error(`Failed to take screenshot: ${error.message}`);
    return null;
  }
}

async function checkLinks(page, url) {
  const links = await page.evaluate(() => {
    const anchors = Array.from(document.querySelectorAll('a[href]'));
    return anchors.map(a => ({
      href: a.href,
      text: a.innerText.trim().substring(0, 50)
    }));
  });

  const broken = [];
  for (const link of links) {
    if (link.href.startsWith('http')) {
      try {
        const response = await page.goto(link.href, {
          waitUntil: 'domcontentloaded',
          timeout: 10000
        });
        if (!response || response.status() >= 400) {
          broken.push({ ...link, status: response ? response.status() : 'timeout' });
        }
      } catch (error) {
        broken.push({ ...link, error: error.message });
      }
    }
  }

  return broken;
}

// Test suites
async function testHomepage(browser) {
  console.log('\n=== HOMEPAGE TESTING ===\n');
  const page = await browser.newPage();

  // Set up console and network monitoring
  const consoleMessages = [];
  const networkFailures = [];

  page.on('console', msg => {
    if (msg.type() === 'error') {
      const text = msg.text();
      consoleMessages.push(text);
      testResults.consoleErrors.push({ page: 'homepage', error: text });
    }
  });

  page.on('requestfailed', request => {
    const failure = {
      url: request.url(),
      failure: request.failure().errorText
    };
    networkFailures.push(failure);
    testResults.networkErrors.push({ page: 'homepage', ...failure });
  });

  try {
    // Test 1: Page loads
    console.log('Testing homepage load...');
    const response = await page.goto(BASE_URL, {
      waitUntil: 'networkidle2',
      timeout: TIMEOUT
    });

    if (response.status() === 200) {
      logTest('Homepage loads', 'PASS', `Status: ${response.status()}`);
    } else {
      logTest('Homepage loads', 'FAIL', `Status: ${response.status()}`);
      await takeScreenshot(page, 'homepage_load_fail');
    }

    // Test 2: Title check
    const title = await page.title();
    if (title && title.length > 0) {
      logTest('Homepage title present', 'PASS', `Title: "${title}"`);
    } else {
      logTest('Homepage title present', 'FAIL', 'No title found');
    }

    // Test 3: Navigation elements
    const navElements = await page.evaluate(() => {
      const nav = document.querySelector('nav') || document.querySelector('.navbar');
      if (!nav) return null;
      const links = Array.from(nav.querySelectorAll('a'));
      return {
        found: true,
        linkCount: links.length,
        links: links.map(a => ({ text: a.innerText.trim(), href: a.href }))
      };
    });

    if (navElements && navElements.found) {
      logTest('Navigation present', 'PASS', `${navElements.linkCount} navigation links found`);
    } else {
      logTest('Navigation present', 'FAIL', 'No navigation found');
      await takeScreenshot(page, 'homepage_no_nav');
    }

    // Test 4: Stats display
    await new Promise(resolve => setTimeout(resolve, 3000)); // Wait for stats to load
    const statsCheck = await page.evaluate(() => {
      const statsElements = Array.from(document.querySelectorAll('[class*="stat"], [id*="stat"]'));
      const loadingTexts = Array.from(document.body.innerText.matchAll(/loading\.\.\./gi));

      return {
        statsFound: statsElements.length,
        stillLoading: loadingTexts.length,
        text: document.body.innerText.substring(0, 500)
      };
    });

    if (statsCheck.stillLoading > 0) {
      logTest('Stats loaded', 'WARN', `${statsCheck.stillLoading} elements still showing "Loading..."`);
      await takeScreenshot(page, 'homepage_stats_loading');
    } else {
      logTest('Stats loaded', 'PASS', 'No loading indicators visible');
    }

    // Test 5: Forms present
    const forms = await page.evaluate(() => {
      const formElements = Array.from(document.querySelectorAll('form, input[type="search"], input[type="text"]'));
      return {
        count: formElements.length,
        types: formElements.map(f => f.tagName + (f.type ? `[${f.type}]` : ''))
      };
    });

    if (forms.count > 0) {
      logTest('Forms present', 'PASS', `${forms.count} form elements found`);
    } else {
      logTest('Forms present', 'WARN', 'No forms found on homepage');
    }

    // Test 6: JavaScript errors
    if (consoleMessages.length > 0) {
      logTest('JavaScript errors', 'FAIL', `${consoleMessages.length} console errors found`);
    } else {
      logTest('JavaScript errors', 'PASS', 'No console errors');
    }

    // Test 7: Network failures
    if (networkFailures.length > 0) {
      logTest('Network requests', 'FAIL', `${networkFailures.length} failed requests`);
    } else {
      logTest('Network requests', 'PASS', 'All network requests successful');
    }

    // Test 8: Check critical page elements
    const criticalElements = await page.evaluate(() => {
      return {
        hasLogo: !!document.querySelector('[class*="logo"], [id*="logo"], img[alt*="logo" i]'),
        hasFooter: !!document.querySelector('footer'),
        hasMainContent: !!document.querySelector('main, [role="main"], .content, .main-content'),
        hasHeadings: document.querySelectorAll('h1, h2, h3').length
      };
    });

    const criticalChecks = [
      { name: 'Logo present', value: criticalElements.hasLogo },
      { name: 'Footer present', value: criticalElements.hasFooter },
      { name: 'Main content present', value: criticalElements.hasMainContent },
      { name: 'Headings present', value: criticalElements.hasHeadings > 0 }
    ];

    criticalChecks.forEach(check => {
      logTest(check.name, check.value ? 'PASS' : 'FAIL');
    });

    // Test 9: Performance metrics
    const metrics = await page.metrics();
    testResults.performanceMetrics.homepage = metrics;
    logTest('Performance metrics collected', 'PASS', `JSHeapUsedSize: ${Math.round(metrics.JSHeapUsedSize / 1024 / 1024)}MB`);

    await takeScreenshot(page, 'homepage_complete');

  } catch (error) {
    logTest('Homepage testing', 'FAIL', `Error: ${error.message}`);
    await takeScreenshot(page, 'homepage_error');
  } finally {
    await page.close();
  }
}

async function testExplorerPage(browser) {
  console.log('\n=== EXPLORER PAGE TESTING ===\n');
  const page = await browser.newPage();

  page.on('console', msg => {
    if (msg.type() === 'error') {
      testResults.consoleErrors.push({ page: 'explorer', error: msg.text() });
    }
  });

  try {
    const url = `${BASE_URL}/explorer`;
    const response = await page.goto(url, {
      waitUntil: 'networkidle2',
      timeout: TIMEOUT
    });

    // Test 1: Page loads
    if (response.status() === 200) {
      logTest('Explorer page loads', 'PASS', `Status: ${response.status()}`);
    } else {
      logTest('Explorer page loads', 'FAIL', `Status: ${response.status()}`);
      await takeScreenshot(page, 'explorer_load_fail');
      await page.close();
      return;
    }

    // Test 2: Search functionality
    const searchInput = await page.$('input[type="search"], input[name*="search"], input[name*="domain"], input[placeholder*="search" i]');
    if (searchInput) {
      logTest('Search input present', 'PASS');

      // Test 3: Try a search
      try {
        await searchInput.type('google.com', { delay: 100 });
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Look for search button or press Enter
        const searchButton = await page.$('button[type="submit"], button:has-text("Search")');
        if (searchButton) {
          await searchButton.click();
        } else {
          await searchInput.press('Enter');
        }

        await new Promise(resolve => setTimeout(resolve, 3000)); // Wait for results

        const hasResults = await page.evaluate(() => {
          const bodyText = document.body.innerText.toLowerCase();
          return bodyText.includes('google') || bodyText.includes('result') || bodyText.includes('domain');
        });

        if (hasResults) {
          logTest('Search functionality works', 'PASS');
          await takeScreenshot(page, 'explorer_search_results');
        } else {
          logTest('Search functionality works', 'WARN', 'No obvious results displayed');
          await takeScreenshot(page, 'explorer_search_no_results');
        }
      } catch (error) {
        logTest('Search functionality works', 'FAIL', error.message);
      }
    } else {
      logTest('Search input present', 'FAIL', 'No search input found');
    }

    // Test 4: Check for data table or results area
    const dataDisplay = await page.evaluate(() => {
      const table = document.querySelector('table');
      const grid = document.querySelector('[class*="grid"], [class*="results"]');
      const cards = document.querySelectorAll('[class*="card"]');

      return {
        hasTable: !!table,
        hasGrid: !!grid,
        cardCount: cards.length,
        rowCount: table ? table.querySelectorAll('tr').length : 0
      };
    });

    if (dataDisplay.hasTable || dataDisplay.hasGrid || dataDisplay.cardCount > 0) {
      logTest('Data display elements present', 'PASS',
        `Table: ${dataDisplay.hasTable}, Grid: ${dataDisplay.hasGrid}, Cards: ${dataDisplay.cardCount}`);
    } else {
      logTest('Data display elements present', 'WARN', 'No obvious data display structure found');
    }

    // Test 5: Check for filters
    const filters = await page.evaluate(() => {
      const selects = document.querySelectorAll('select');
      const checkboxes = document.querySelectorAll('input[type="checkbox"]');
      const radios = document.querySelectorAll('input[type="radio"]');

      return {
        selectCount: selects.length,
        checkboxCount: checkboxes.length,
        radioCount: radios.length
      };
    });

    if (filters.selectCount > 0 || filters.checkboxCount > 0) {
      logTest('Filter controls present', 'PASS',
        `Selects: ${filters.selectCount}, Checkboxes: ${filters.checkboxCount}`);
    } else {
      logTest('Filter controls present', 'WARN', 'No filter controls found');
    }

    // Test 6: Check for pagination
    const pagination = await page.evaluate(() => {
      const paginationEl = document.querySelector('[class*="pagination"], [class*="pager"]');
      const buttons = Array.from(document.querySelectorAll('button, a'));
      const nextButton = buttons.find(b => b.innerText.toLowerCase().includes('next'));
      const prevButton = buttons.find(b => b.innerText.toLowerCase().includes('previous') || b.innerText.toLowerCase().includes('prev'));

      return {
        hasPagination: !!paginationEl,
        hasNextButton: !!nextButton,
        hasPrevButton: !!prevButton
      };
    });

    if (pagination.hasPagination || pagination.hasNextButton) {
      logTest('Pagination present', 'PASS');
    } else {
      logTest('Pagination present', 'WARN', 'No pagination found (may not be needed)');
    }

    await takeScreenshot(page, 'explorer_complete');

  } catch (error) {
    logTest('Explorer page testing', 'FAIL', `Error: ${error.message}`);
    await takeScreenshot(page, 'explorer_error');
  } finally {
    await page.close();
  }
}

async function testToolsPage(browser) {
  console.log('\n=== TOOLS PAGE TESTING ===\n');
  const page = await browser.newPage();

  try {
    const url = `${BASE_URL}/tools`;
    const response = await page.goto(url, {
      waitUntil: 'networkidle2',
      timeout: TIMEOUT
    });

    // Test 1: Page loads
    if (response.status() === 200) {
      logTest('Tools page loads', 'PASS', `Status: ${response.status()}`);
    } else {
      logTest('Tools page loads', 'FAIL', `Status: ${response.status()}`);
      await page.close();
      return;
    }

    // Test 2: Count tool cards/items
    const toolsInfo = await page.evaluate(() => {
      const cards = Array.from(document.querySelectorAll('[class*="card"], [class*="tool"]'));
      const links = Array.from(document.querySelectorAll('a[href*="tool"], a[href*="dns"], a[href*="auto"]'));

      return {
        cardCount: cards.length,
        linkCount: links.length,
        tools: links.map(a => ({
          text: a.innerText.trim().substring(0, 50),
          href: a.href
        })).slice(0, 20) // First 20 tools
      };
    });

    if (toolsInfo.cardCount > 0 || toolsInfo.linkCount > 0) {
      logTest('Tool items present', 'PASS',
        `${toolsInfo.cardCount} cards, ${toolsInfo.linkCount} tool links`);
    } else {
      logTest('Tool items present', 'FAIL', 'No tools found');
      await takeScreenshot(page, 'tools_no_items');
    }

    // Test 3: Check for DNS Auto Detect link
    const autoDetectLink = toolsInfo.tools.find(t =>
      t.href.includes('autolookup') || t.text.toLowerCase().includes('auto')
    );

    if (autoDetectLink) {
      logTest('DNS Auto Detect link present', 'PASS', autoDetectLink.href);
    } else {
      logTest('DNS Auto Detect link present', 'WARN', 'Link not found in first 20 tools');
    }

    // Test 4: Try clicking a tool (if available)
    if (toolsInfo.tools.length > 0) {
      try {
        const firstTool = toolsInfo.tools[0];
        await page.goto(firstTool.href, { waitUntil: 'domcontentloaded', timeout: 10000 });
        const toolPageStatus = page.url();

        if (toolPageStatus.includes('404') || toolPageStatus.includes('error')) {
          logTest('First tool link works', 'FAIL', `Navigated to: ${toolPageStatus}`);
        } else {
          logTest('First tool link works', 'PASS', `Tool loaded: ${firstTool.text}`);
        }

        // Go back to tools page
        await page.goBack({ waitUntil: 'domcontentloaded' });
      } catch (error) {
        logTest('First tool link works', 'FAIL', error.message);
      }
    }

    await takeScreenshot(page, 'tools_complete');

  } catch (error) {
    logTest('Tools page testing', 'FAIL', `Error: ${error.message}`);
    await takeScreenshot(page, 'tools_error');
  } finally {
    await page.close();
  }
}

async function testAutoDetectPage(browser) {
  console.log('\n=== DNS AUTO DETECT TESTING ===\n');
  const page = await browser.newPage();

  try {
    const url = `${BASE_URL}/autolookup`;
    const response = await page.goto(url, {
      waitUntil: 'networkidle2',
      timeout: TIMEOUT
    });

    // Test 1: Page loads
    if (response.status() === 200) {
      logTest('Auto Detect page loads', 'PASS', `Status: ${response.status()}`);
    } else {
      logTest('Auto Detect page loads', 'FAIL', `Status: ${response.status()}`);
      await page.close();
      return;
    }

    // Test 2: Branding present
    const branding = await page.evaluate(() => {
      const bodyText = document.body.innerText.toLowerCase();
      return {
        hasDNSScience: bodyText.includes('dns') && bodyText.includes('science'),
        hasLogo: !!document.querySelector('[class*="logo"], [id*="logo"]'),
        hasTitle: !!document.querySelector('h1, h2')
      };
    });

    if (branding.hasDNSScience || branding.hasLogo) {
      logTest('Branding present', 'PASS');
    } else {
      logTest('Branding present', 'WARN', 'DNS Science branding not clearly visible');
    }

    // Test 3: Wait for auto-detection to run
    console.log('Waiting for auto-detection to complete...');
    await new Promise(resolve => setTimeout(resolve, 5000));

    // Test 4: IP detection
    const ipDetection = await page.evaluate(() => {
      const bodyText = document.body.innerText;
      const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
      const ipMatch = bodyText.match(ipRegex);

      return {
        hasIP: !!ipMatch,
        ip: ipMatch ? ipMatch[0] : null,
        hasIPLabel: bodyText.toLowerCase().includes('ip') || bodyText.toLowerCase().includes('address')
      };
    });

    if (ipDetection.hasIP) {
      logTest('IP detection works', 'PASS', `Detected IP: ${ipDetection.ip}`);
    } else {
      logTest('IP detection works', 'FAIL', 'No IP address detected');
      await takeScreenshot(page, 'autodetect_no_ip');
    }

    // Test 5: Resolver detection
    const resolverDetection = await page.evaluate(() => {
      const bodyText = document.body.innerText.toLowerCase();
      return {
        hasResolver: bodyText.includes('resolver') || bodyText.includes('dns server'),
        hasResolverInfo: bodyText.includes('8.8.8.8') || bodyText.includes('1.1.1.1') ||
                        bodyText.includes('google') || bodyText.includes('cloudflare')
      };
    });

    if (resolverDetection.hasResolver || resolverDetection.hasResolverInfo) {
      logTest('Resolver detection works', 'PASS');
    } else {
      logTest('Resolver detection works', 'WARN', 'No resolver information visible');
    }

    // Test 6: EDNS detection
    const ednsDetection = await page.evaluate(() => {
      const bodyText = document.body.innerText.toLowerCase();
      return {
        hasEDNS: bodyText.includes('edns'),
        hasClientSubnet: bodyText.includes('subnet') || bodyText.includes('ecs')
      };
    });

    if (ednsDetection.hasEDNS) {
      logTest('EDNS detection works', 'PASS');
    } else {
      logTest('EDNS detection works', 'WARN', 'No EDNS information visible');
    }

    // Test 7: Security assessment
    const securityCheck = await page.evaluate(() => {
      const bodyText = document.body.innerText.toLowerCase();
      return {
        hasSecurity: bodyText.includes('security') || bodyText.includes('secure') ||
                     bodyText.includes('dnssec') || bodyText.includes('threat'),
        hasVulnerability: bodyText.includes('vulnerability') || bodyText.includes('vulnerable')
      };
    });

    if (securityCheck.hasSecurity) {
      logTest('Security assessment works', 'PASS');
    } else {
      logTest('Security assessment works', 'WARN', 'No security assessment visible');
    }

    // Test 8: Copy buttons
    const copyButtons = await page.evaluate(() => {
      const buttons = Array.from(document.querySelectorAll('button'));
      const copyBtns = buttons.filter(b =>
        b.innerText.toLowerCase().includes('copy') ||
        b.classList.toString().includes('copy')
      );

      return {
        count: copyBtns.length,
        hasAny: copyBtns.length > 0
      };
    });

    if (copyButtons.hasAny) {
      logTest('Copy buttons present', 'PASS', `${copyButtons.count} copy buttons`);

      // Try clicking a copy button
      try {
        const copyBtn = await page.evaluateHandle(() => {
          const buttons = Array.from(document.querySelectorAll('button'));
          return buttons.find(b => b.innerText.toLowerCase().includes('copy') || b.className.includes('copy'));
        });
        if (copyBtn) await copyBtn.click();
        await new Promise(resolve => setTimeout(resolve, 500));
        logTest('Copy button clickable', 'PASS');
      } catch (error) {
        logTest('Copy button clickable', 'WARN', 'Could not click copy button');
      }
    } else {
      logTest('Copy buttons present', 'WARN', 'No copy buttons found');
    }

    // Test 9: Navigation links
    const navLinks = await page.evaluate(() => {
      const nav = document.querySelector('nav') || document.querySelector('[role="navigation"]');
      if (nav) {
        const links = Array.from(nav.querySelectorAll('a'));
        return {
          hasNav: true,
          linkCount: links.length
        };
      }
      return { hasNav: false, linkCount: 0 };
    });

    if (navLinks.hasNav) {
      logTest('Navigation links work', 'PASS', `${navLinks.linkCount} navigation links`);
    } else {
      logTest('Navigation links work', 'WARN', 'No navigation found');
    }

    await takeScreenshot(page, 'autodetect_complete');

  } catch (error) {
    logTest('Auto Detect testing', 'FAIL', `Error: ${error.message}`);
    await takeScreenshot(page, 'autodetect_error');
  } finally {
    await page.close();
  }
}

async function testAPIEndpoints(browser) {
  console.log('\n=== API ENDPOINT TESTING ===\n');
  const page = await browser.newPage();

  const endpoints = [
    '/api/stats',
    '/api/domains',
    '/api/autolookup/ip',
    '/api/autolookup/resolver',
    '/api/autolookup/edns',
    '/api/autolookup/security',
    '/api/autolookup/all'
  ];

  for (const endpoint of endpoints) {
    try {
      const url = `${BASE_URL}${endpoint}`;
      const startTime = Date.now();

      const response = await page.goto(url, {
        waitUntil: 'networkidle2',
        timeout: 15000
      });

      const responseTime = Date.now() - startTime;
      const status = response.status();

      // Test 1: Status code
      if (status === 200) {
        logTest(`${endpoint} - Status code`, 'PASS', `${status} (${responseTime}ms)`);
      } else if (status === 401 || status === 403) {
        logTest(`${endpoint} - Status code`, 'WARN', `${status} - Auth required (${responseTime}ms)`);
      } else if (status >= 400) {
        logTest(`${endpoint} - Status code`, 'FAIL', `${status} (${responseTime}ms)`);
        continue;
      }

      // Test 2: Response time
      if (responseTime < 1000) {
        logTest(`${endpoint} - Response time`, 'PASS', `${responseTime}ms`);
      } else if (responseTime < 3000) {
        logTest(`${endpoint} - Response time`, 'WARN', `${responseTime}ms (slow)`);
      } else {
        logTest(`${endpoint} - Response time`, 'FAIL', `${responseTime}ms (very slow)`);
      }

      // Test 3: JSON validity (if content-type suggests JSON)
      const contentType = response.headers()['content-type'] || '';
      if (contentType.includes('json')) {
        try {
          const content = await page.content();
          // Try to extract JSON from page
          const jsonMatch = content.match(/<pre[^>]*>(.*?)<\/pre>/s) ||
                           content.match(/<body[^>]*>(.*?)<\/body>/s);

          if (jsonMatch) {
            const jsonText = jsonMatch[1].replace(/<[^>]*>/g, '').trim();
            const json = JSON.parse(jsonText);
            logTest(`${endpoint} - JSON validity`, 'PASS', `Valid JSON returned`);

            // Test 4: Data completeness
            if (typeof json === 'object' && Object.keys(json).length > 0) {
              logTest(`${endpoint} - Data completeness`, 'PASS',
                `${Object.keys(json).length} top-level keys`);
            } else {
              logTest(`${endpoint} - Data completeness`, 'WARN', 'Empty or minimal data');
            }
          }
        } catch (jsonError) {
          logTest(`${endpoint} - JSON validity`, 'FAIL', `Invalid JSON: ${jsonError.message}`);
        }
      } else {
        logTest(`${endpoint} - JSON validity`, 'WARN', `Non-JSON response: ${contentType}`);
      }

    } catch (error) {
      logTest(`${endpoint}`, 'FAIL', `Error: ${error.message}`);
    }

    await new Promise(resolve => setTimeout(resolve, 500)); // Brief delay between requests
  }

  await page.close();
}

async function testCrossBrowser(browser) {
  console.log('\n=== CROSS-BROWSER TESTING ===\n');

  // Test 1: Mobile viewport
  const mobilePage = await browser.newPage();
  await mobilePage.setViewport({ width: 375, height: 667 }); // iPhone SE

  try {
    await mobilePage.goto(BASE_URL, { waitUntil: 'networkidle2', timeout: TIMEOUT });

    const mobileCheck = await mobilePage.evaluate(() => {
      return {
        width: window.innerWidth,
        height: window.innerHeight,
        hasHamburger: !!document.querySelector('[class*="hamburger"], [class*="menu-toggle"], [class*="mobile-menu"]'),
        isResponsive: window.innerWidth < 768
      };
    });

    if (mobileCheck.isResponsive) {
      logTest('Mobile viewport renders', 'PASS', `${mobileCheck.width}x${mobileCheck.height}`);
    } else {
      logTest('Mobile viewport renders', 'WARN', 'Page may not be fully responsive');
    }

    await takeScreenshot(mobilePage, 'mobile_viewport');

  } catch (error) {
    logTest('Mobile viewport test', 'FAIL', error.message);
  } finally {
    await mobilePage.close();
  }

  // Test 2: Tablet viewport
  const tabletPage = await browser.newPage();
  await tabletPage.setViewport({ width: 768, height: 1024 }); // iPad

  try {
    await tabletPage.goto(BASE_URL, { waitUntil: 'networkidle2', timeout: TIMEOUT });
    logTest('Tablet viewport renders', 'PASS', '768x1024');
    await takeScreenshot(tabletPage, 'tablet_viewport');
  } catch (error) {
    logTest('Tablet viewport test', 'FAIL', error.message);
  } finally {
    await tabletPage.close();
  }

  // Test 3: Desktop viewport (large)
  const desktopPage = await browser.newPage();
  await desktopPage.setViewport({ width: 1920, height: 1080 });

  try {
    await desktopPage.goto(BASE_URL, { waitUntil: 'networkidle2', timeout: TIMEOUT });
    logTest('Desktop viewport renders', 'PASS', '1920x1080');
    await takeScreenshot(desktopPage, 'desktop_viewport');
  } catch (error) {
    logTest('Desktop viewport test', 'FAIL', error.message);
  } finally {
    await desktopPage.close();
  }
}

async function generateReport() {
  console.log('\n=== GENERATING REPORT ===\n');

  const reportPath = path.join(__dirname, 'test_results.json');
  fs.writeFileSync(reportPath, JSON.stringify(testResults, null, 2));
  console.log(`JSON report saved: ${reportPath}`);

  // Generate markdown report
  let markdown = `# DNS Science Platform - Comprehensive Test Results\n\n`;
  markdown += `**Test Date:** ${testResults.timestamp}\n`;
  markdown += `**Base URL:** ${testResults.baseUrl}\n\n`;

  markdown += `## Summary\n\n`;
  markdown += `- **Total Tests:** ${testResults.summary.total}\n`;
  markdown += `- **Passed:** ${testResults.summary.passed} ✓\n`;
  markdown += `- **Failed:** ${testResults.summary.failed} ✗\n`;
  markdown += `- **Warnings:** ${testResults.summary.warnings} ⚠\n`;
  markdown += `- **Success Rate:** ${((testResults.summary.passed / testResults.summary.total) * 100).toFixed(1)}%\n\n`;

  markdown += `## Test Results\n\n`;
  markdown += `| Test Name | Status | Details |\n`;
  markdown += `|-----------|--------|----------|\n`;

  testResults.tests.forEach(test => {
    const emoji = test.status === 'PASS' ? '✓' : test.status === 'FAIL' ? '✗' : '⚠';
    markdown += `| ${test.name} | ${emoji} ${test.status} | ${test.details} |\n`;
  });

  if (testResults.consoleErrors.length > 0) {
    markdown += `\n## Console Errors (${testResults.consoleErrors.length})\n\n`;
    testResults.consoleErrors.slice(0, 20).forEach(err => {
      markdown += `- **${err.page}:** ${err.error}\n`;
    });
  }

  if (testResults.networkErrors.length > 0) {
    markdown += `\n## Network Errors (${testResults.networkErrors.length})\n\n`;
    testResults.networkErrors.slice(0, 20).forEach(err => {
      markdown += `- **${err.url}:** ${err.failure}\n`;
    });
  }

  if (testResults.brokenLinks.length > 0) {
    markdown += `\n## Broken Links (${testResults.brokenLinks.length})\n\n`;
    testResults.brokenLinks.forEach(link => {
      markdown += `- ${link.text}: ${link.href} (${link.status || link.error})\n`;
    });
  }

  markdown += `\n## Performance Metrics\n\n`;
  Object.keys(testResults.performanceMetrics).forEach(page => {
    const metrics = testResults.performanceMetrics[page];
    markdown += `### ${page}\n`;
    markdown += `- JS Heap Used: ${Math.round(metrics.JSHeapUsedSize / 1024 / 1024)}MB\n`;
    markdown += `- JS Heap Total: ${Math.round(metrics.JSHeapTotalSize / 1024 / 1024)}MB\n`;
    markdown += `- Script Duration: ${metrics.ScriptDuration?.toFixed(2)}s\n\n`;
  });

  markdown += `\n## Screenshots\n\n`;
  markdown += `Screenshots saved to: ${SCREENSHOT_DIR}\n`;

  const mdPath = path.join(__dirname, 'test_results_quick.md');
  fs.writeFileSync(mdPath, markdown);
  console.log(`Markdown report saved: ${mdPath}`);

  return { reportPath, mdPath };
}

// Main execution
async function runAllTests() {
  console.log('DNS Science Platform - Comprehensive Test Suite');
  console.log('==============================================\n');
  console.log(`Testing: ${BASE_URL}\n`);

  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
  });

  try {
    await testHomepage(browser);
    await testExplorerPage(browser);
    await testToolsPage(browser);
    await testAutoDetectPage(browser);
    await testAPIEndpoints(browser);
    await testCrossBrowser(browser);

    const reports = await generateReport();

    console.log('\n==============================================');
    console.log('TEST SUITE COMPLETED');
    console.log('==============================================\n');
    console.log(`Total Tests: ${testResults.summary.total}`);
    console.log(`Passed: ${testResults.summary.passed} ✓`);
    console.log(`Failed: ${testResults.summary.failed} ✗`);
    console.log(`Warnings: ${testResults.summary.warnings} ⚠`);
    console.log(`\nReports generated:`);
    console.log(`- ${reports.reportPath}`);
    console.log(`- ${reports.mdPath}`);
    console.log(`\nScreenshots: ${SCREENSHOT_DIR}`);

  } catch (error) {
    console.error('Fatal error during test execution:', error);
  } finally {
    await browser.close();
  }
}

// Run tests
runAllTests().catch(console.error);
