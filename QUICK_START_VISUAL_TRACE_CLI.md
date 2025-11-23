# Quick Start Guide - Visual Traceroute & CLI

## Visual Traceroute - 5 Minute Deploy

### Step 1: Copy Files

```bash
# Navigate to project directory
cd /path/to/dnsscience

# Copy all Visual Traceroute files
cp visual_traceroute.py ./
cp templates/visualtrace.html templates/
cp static/js/visualtrace.js static/js/
cp static/css/visualtrace.css static/css/
cp static/data/root_servers.json static/data/
cp static/data/dns_resolvers.json static/data/
```

### Step 2: Integrate with Flask App

Add to your main Flask app (e.g., `app.py`):

```python
from visual_traceroute import visual_trace_bp

app.register_blueprint(visual_trace_bp)

@app.route('/visualtrace')
def visualtrace():
    return render_template('visualtrace.html')
```

### Step 3: Install System Dependencies

```bash
# Install traceroute (if not already installed)
# Ubuntu/Debian:
sudo apt-get install traceroute

# macOS (usually pre-installed):
which traceroute

# Verify
traceroute google.com
```

### Step 4: Restart Flask App

```bash
# If using systemd:
sudo systemctl restart your-flask-app

# If using Gunicorn:
sudo systemctl restart gunicorn

# Or kill and restart manually
```

### Step 5: Test

```bash
# Test the page
curl http://localhost:5000/visualtrace

# Test the API
curl -X POST http://localhost:5000/api/traceroute \
  -H "Content-Type: application/json" \
  -d '{"target": "google.com", "source": "local", "max_hops": 15}'
```

### Step 6: Add to Navigation

Add link to your site navigation:

```html
<a href="/visualtrace">Visual Traceroute</a>
```

**Done!** Access at: `https://your-domain.com/visualtrace`

---

## CLI Tool - 2 Minute Install

### Method 1: Quick Install (Recommended)

```bash
cd cli
chmod +x install.sh
./install.sh
```

Follow the prompts. Choose option 2 (user install) for quickest setup.

### Method 2: Manual Install

```bash
cd cli
pip3 install --user -r requirements.txt
pip3 install --user -e .
```

### Method 3: Virtual Environment

```bash
cd cli
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

### Test Installation

```bash
dnsscience --version
dnsscience --help
dnsscience autodetect
```

### Configure API Key (Optional)

```bash
dnsscience config --api-key YOUR_API_KEY
dnsscience config --show
```

**Done!** Start using:

```bash
dnsscience email example.com
dnsscience ssl example.com
dnsscience trace example.com
```

---

## Quick Test Commands

### Visual Traceroute

```bash
# From browser:
https://your-domain.com/visualtrace

# Enter in the input box:
google.com

# Click "Run Traceroute"
# Watch the animated path draw on the map!
```

### CLI Tool

```bash
# Auto-detect your DNS
dnsscience autodetect

# Check email security
dnsscience email gmail.com

# Check SSL certificate
dnsscience ssl google.com

# Run traceroute
dnsscience trace google.com

# Batch processing
echo -e "google.com\ncloudflare.com\namazon.com" > domains.txt
dnsscience batch domains.txt --checks email,ssl --output results.json
```

---

## Common Issues & Solutions

### Visual Traceroute

**Issue**: "Traceroute command not found"
```bash
# Install traceroute
sudo apt-get install traceroute  # Ubuntu/Debian
brew install traceroute          # macOS (if missing)
```

**Issue**: "GeoIP lookup failed"
```bash
# Check internet connectivity
curl https://ipinfo.io/8.8.8.8

# If rate limited, wait a minute and try again
# Or sign up for ipinfo.io API key
```

**Issue**: "Map tiles not loading"
```bash
# Check if CDN is accessible
curl https://unpkg.com/leaflet@1.9.4/dist/leaflet.css

# Check browser console for errors
# May need to adjust CSP headers
```

### CLI Tool

**Issue**: "dnsscience command not found"
```bash
# Add ~/.local/bin to PATH
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Or use full path
~/.local/bin/dnsscience --help
```

**Issue**: "Connection refused"
```bash
# Check API URL
dnsscience config --show

# Set correct API URL
dnsscience config --api-url https://dnsscience.io
```

**Issue**: "Module not found"
```bash
# Reinstall dependencies
pip3 install --user -r requirements.txt
```

---

## File Locations

### Visual Traceroute

```
Visual Traceroute Files:
├── visual_traceroute.py          → Backend API
├── templates/visualtrace.html    → Frontend HTML
├── static/js/visualtrace.js      → Frontend JavaScript
├── static/css/visualtrace.css    → Styles
├── static/data/root_servers.json → DNS root servers
└── static/data/dns_resolvers.json→ DNS resolvers
```

### CLI Tool

```
CLI Tool Files:
├── cli/dnsscience.py     → Main CLI application
├── cli/setup.py          → Package setup
├── cli/requirements.txt  → Dependencies
├── cli/install.sh        → Installer
└── cli/README.md         → Documentation
```

---

## Next Steps

### After Visual Traceroute Deploy:

1. ✓ Test with multiple domains
2. ✓ Check mobile responsiveness
3. ✓ Set up rate limiting (5 req/min recommended)
4. ✓ Configure monitoring
5. ✓ Add to site navigation
6. ✓ Create demo video (optional)
7. ✓ Announce to users

### After CLI Install:

1. ✓ Test all commands
2. ✓ Configure API key
3. ✓ Create example scripts
4. ✓ Add to documentation site
5. ✓ Share installation instructions
6. ✓ Collect user feedback
7. ✓ Plan enhancements

---

## Support

**Documentation**:
- Visual Traceroute: `VISUAL_TRACEROUTE_README.md`
- Deployment: `DEPLOYMENT_GUIDE_VISUAL_TRACE.md`
- CLI Guide: `cli/README.md`
- Complete Report: `IMPLEMENTATION_COMPLETE_VISUAL_TRACEROUTE_CLI.md`

**Get Help**:
- Email: support@dnsscience.io
- GitHub: https://github.com/dnsscience
- Docs: https://dnsscience.io/docs

---

## Quick Command Reference

### Visual Traceroute API

```bash
# Traceroute
POST /api/traceroute
{
  "target": "example.com",
  "source": "local",
  "max_hops": 30
}

# Remote locations
GET /api/remote-locations

# DNS resolvers
GET /api/dns-resolvers
```

### CLI Commands

```bash
dnsscience autodetect                    # DNS auto-detect
dnsscience email <domain>                # Email security
dnsscience value <domain>                # Domain valuation
dnsscience ssl <domain>                  # SSL analysis
dnsscience rdap <domain>                 # RDAP lookup
dnsscience threat <ip>                   # Threat intel
dnsscience trace <target>                # Traceroute
dnsscience batch <file> [options]        # Batch processing
dnsscience config [options]              # Configuration

# All commands support:
--format table|json|yaml|csv             # Output format
```

---

**Version**: 1.0.0
**Last Updated**: 2025-11-15
**Status**: PRODUCTION READY
