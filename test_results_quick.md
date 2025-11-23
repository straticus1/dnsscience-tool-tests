# DNS Science Platform - Comprehensive Test Results

**Test Date:** 2025-11-15T13:13:40.965Z
**Base URL:** https://www.dnsscience.io

## Summary

- **Total Tests:** 62
- **Passed:** 48 ✓
- **Failed:** 6 ✗
- **Warnings:** 8 ⚠
- **Success Rate:** 77.4%

## Test Results

| Test Name | Status | Details |
|-----------|--------|----------|
| Homepage loads | ✓ PASS | Status: 200 |
| Homepage title present | ✓ PASS | Title: "DNS Science - Email Security & DNS Tracker" |
| Navigation present | ✗ FAIL | No navigation found |
| Stats loaded | ⚠ WARN | 3 elements still showing "Loading..." |
| Forms present | ✓ PASS | 29 form elements found |
| JavaScript errors | ✗ FAIL | 4 console errors found |
| Network requests | ✓ PASS | All network requests successful |
| Logo present | ✗ FAIL |  |
| Footer present | ✓ PASS |  |
| Main content present | ✗ FAIL |  |
| Headings present | ✓ PASS |  |
| Performance metrics collected | ✓ PASS | JSHeapUsedSize: 3MB |
| Explorer page loads | ✓ PASS | Status: 200 |
| Search input present | ✓ PASS |  |
| Search functionality works | ✗ FAIL | SyntaxError: Failed to execute 'querySelector' on 'Document': 'button[type="submit"], button:has-text("Search")' is not a valid selector. |
| Data display elements present | ✓ PASS | Table: true, Grid: true, Cards: 4 |
| Filter controls present | ⚠ WARN | No filter controls found |
| Pagination present | ✓ PASS |  |
| Tools page loads | ✓ PASS | Status: 200 |
| Tool items present | ✓ PASS | 9 cards, 2 tool links |
| DNS Auto Detect link present | ✓ PASS | https://www.dnsscience.io/autolookup |
| First tool link works | ✓ PASS | Tool loaded: 🔧 Tools |
| Auto Detect page loads | ✓ PASS | Status: 200 |
| Branding present | ✓ PASS |  |
| IP detection works | ✓ PASS | Detected IP: 24.187.53.33 |
| Resolver detection works | ✓ PASS |  |
| EDNS detection works | ✓ PASS |  |
| Security assessment works | ✓ PASS |  |
| Copy buttons present | ✓ PASS | 4 copy buttons |
| Copy button clickable | ✓ PASS |  |
| Navigation links work | ✓ PASS | 4 navigation links |
| /api/stats - Status code | ✓ PASS | 200 (3647ms) |
| /api/stats - Response time | ✗ FAIL | 3647ms (very slow) |
| /api/stats - JSON validity | ✓ PASS | Valid JSON returned |
| /api/stats - Data completeness | ✓ PASS | 7 top-level keys |
| /api/domains - Status code | ✓ PASS | 200 (1254ms) |
| /api/domains - Response time | ⚠ WARN | 1254ms (slow) |
| /api/domains - JSON validity | ✓ PASS | Valid JSON returned |
| /api/domains - Data completeness | ✓ PASS | 2 top-level keys |
| /api/autolookup/ip - Status code | ✓ PASS | 200 (1215ms) |
| /api/autolookup/ip - Response time | ⚠ WARN | 1215ms (slow) |
| /api/autolookup/ip - JSON validity | ✓ PASS | Valid JSON returned |
| /api/autolookup/ip - Data completeness | ✓ PASS | 4 top-level keys |
| /api/autolookup/resolver - Status code | ✓ PASS | 200 (1219ms) |
| /api/autolookup/resolver - Response time | ⚠ WARN | 1219ms (slow) |
| /api/autolookup/resolver - JSON validity | ✓ PASS | Valid JSON returned |
| /api/autolookup/resolver - Data completeness | ✓ PASS | 5 top-level keys |
| /api/autolookup/edns - Status code | ✓ PASS | 200 (1219ms) |
| /api/autolookup/edns - Response time | ⚠ WARN | 1219ms (slow) |
| /api/autolookup/edns - JSON validity | ✓ PASS | Valid JSON returned |
| /api/autolookup/edns - Data completeness | ✓ PASS | 4 top-level keys |
| /api/autolookup/security - Status code | ✓ PASS | 200 (1213ms) |
| /api/autolookup/security - Response time | ⚠ WARN | 1213ms (slow) |
| /api/autolookup/security - JSON validity | ✓ PASS | Valid JSON returned |
| /api/autolookup/security - Data completeness | ✓ PASS | 6 top-level keys |
| /api/autolookup/all - Status code | ✓ PASS | 200 (1229ms) |
| /api/autolookup/all - Response time | ⚠ WARN | 1229ms (slow) |
| /api/autolookup/all - JSON validity | ✓ PASS | Valid JSON returned |
| /api/autolookup/all - Data completeness | ✓ PASS | 5 top-level keys |
| Mobile viewport renders | ✓ PASS | 375x667 |
| Tablet viewport renders | ✓ PASS | 768x1024 |
| Desktop viewport renders | ✓ PASS | 1920x1080 |

## Console Errors (4)

- **homepage:** Failed to load resource: the server responded with a status of 401 ()
- **homepage:** Failed to load resource: the server responded with a status of 404 ()
- **homepage:** Failed to load resource: the server responded with a status of 500 ()
- **homepage:** Failed to load dashboard stats: JSHandle@error

## Performance Metrics

### homepage
- JS Heap Used: 3MB
- JS Heap Total: 6MB
- Script Duration: 0.04s


## Screenshots

Screenshots saved to: /Users/ryan/development/dnsscience-tool-tests/test_screenshots
