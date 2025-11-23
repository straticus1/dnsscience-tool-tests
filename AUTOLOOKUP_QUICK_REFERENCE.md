# DNS Auto Lookup - Quick Reference Card

## Access
**URL:** https://www.dnsscience.io/autolookup

---

## What It Does
Automatically detects and displays:
- Your public IP address (IPv4/IPv6)
- DNS resolver you're using
- EDNS Client Subnet information
- DNS security configuration
- Overall security score

---

## API Endpoints

| Endpoint | Purpose | Example Response |
|----------|---------|------------------|
| `/api/autolookup/ip` | Get client IP | `{"ipv4": "1.2.3.4", "ipv6": null}` |
| `/api/autolookup/resolver` | Detect DNS resolver | `{"resolver_ip": "8.8.8.8", "provider": "Google"}` |
| `/api/autolookup/edns` | Check EDNS subnet | `{"enabled": true, "subnet": "1.2.3.0/24"}` |
| `/api/autolookup/security` | Assess security | `{"dnssec": true, "score": 85}` |
| `/api/autolookup/all` | Get everything | Combined response from all above |

---

## Files

| File | Location | Size |
|------|----------|------|
| HTML | `/var/www/dnsscience/templates/autolookup.html` | 12 KB |
| CSS | `/var/www/dnsscience/static/css/autolookup.css` | 8 KB |
| JS | `/var/www/dnsscience/static/js/autolookup.js` | 12 KB |
| API | `/var/www/dnsscience/autolookup_api.py` | 13 KB |

---

## Quick Commands

### Test Deployment
```bash
python3 test_autolookup.py
```

### Redeploy
```bash
python3 deploy_autolookup.py
```

### Check Logs
```bash
sudo tail -f /var/log/apache2/error.log
```

### Test API
```bash
curl https://www.dnsscience.io/api/autolookup/all | jq
```

### Restart Apache
```bash
sudo systemctl restart apache2
```

---

## Security Score Breakdown

| Feature | Points | Total |
|---------|--------|-------|
| DNSSEC Validation | 40 | 40 |
| DNS-over-HTTPS | 30 | 70 |
| DNS-over-TLS | 30 | 100 |

**Ratings:**
- 80-100: Excellent
- 60-79: Good
- 0-59: Needs improvement

---

## Privacy Levels (EDNS)

| Level | Description | Example |
|-------|-------------|---------|
| **Low** | No subnet exposed | ECS disabled |
| **Medium** | Network exposed | 1.2.3.0/24 |
| **High** | Full IP exposed | 1.2.3.4/32 |

---

## Recognized DNS Providers

- Google Public DNS (8.8.8.8)
- Cloudflare DNS (1.1.1.1)
- Quad9 (9.9.9.9)
- OpenDNS (208.67.222.222)
- Level3 (4.2.2.x)

---

## Integration Code

Add to `app.py`:
```python
from autolookup_api import register_autolookup_routes
register_autolookup_routes(app)
```

---

## Status Check

```bash
# All should return 200
curl -I https://www.dnsscience.io/autolookup
curl -I https://www.dnsscience.io/api/autolookup/ip
curl -I https://www.dnsscience.io/static/css/autolookup.css
curl -I https://www.dnsscience.io/static/js/autolookup.js
```

---

## Test Results

**Latest:** November 15, 2025
**Status:** ✓ All tests passed (8/8)
- Main page: ✓
- IP API: ✓
- Resolver API: ✓
- EDNS API: ✓
- Security API: ✓
- Combined API: ✓
- CSS: ✓
- JavaScript: ✓

---

## Features vs. dnscheck.tools

| Feature | dnscheck.tools | DNS Auto Lookup |
|---------|----------------|-----------------|
| IP Detection | ✓ | ✓ |
| DNS Resolver | ✓ | ✓ + Provider ID |
| EDNS Detection | ✓ | ✓ + Privacy Rating |
| Security Check | ✓ | ✓ + Score (0-100) |
| API Endpoints | Basic | 5 comprehensive |
| Copy Buttons | - | ✓ |
| Dark Mode | - | ✓ |
| Mobile Friendly | ✓ | ✓ |
| Response Time | - | ✓ |

---

## One-Line Tests

```bash
# IP detection
curl -s https://www.dnsscience.io/api/autolookup/ip | jq .ipv4

# Your DNS resolver
curl -s https://www.dnsscience.io/api/autolookup/resolver | jq .provider

# Security score
curl -s https://www.dnsscience.io/api/autolookup/security | jq .score
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Page not loading | Check Apache: `systemctl status apache2` |
| API returns 404 | Restart Apache: `systemctl restart apache2` |
| Wrong IP detected | Check X-Forwarded-For header |
| DNSSEC always false | Normal for some server configs |
| Unknown resolver | Normal for ISP/custom DNS |

---

## Performance

- Page load: ~500ms
- API response: 50-200ms
- Total detection: 1-2 seconds
- Page weight: 32 KB

---

**Created:** November 15, 2025
**Version:** 1.0.0
**Status:** Production Ready ✓
