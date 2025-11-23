# Visual Traceroute - Complete Feature Guide

## Overview

The Visual Traceroute tool provides an interactive, map-based network path visualization with comprehensive DNS infrastructure mapping. It combines traditional traceroute functionality with geographic visualization, DNS root server locations, and global resolver mapping.

## Features

### 1. Interactive World Map

- **Technology**: Leaflet.js with dark theme
- **Base Layer**: CartoDB Dark Matter tiles
- **Controls**: Pan, zoom, and reset functionality
- **Responsive**: Mobile-friendly design

### 2. DNS Root Servers (RED Markers)

Display all 13 DNS root servers with detailed information:

- **A-Root** (VeriSign, Dulles, VA)
- **B-Root** (USC-ISI, Marina del Rey, CA)
- **C-Root** (Cogent Communications, Herndon, VA)
- **D-Root** (University of Maryland, College Park, MD)
- **E-Root** (NASA Ames, Mountain View, CA)
- **F-Root** (ISC, Palo Alto, CA) - 85 anycast sites
- **G-Root** (US DOD, Columbus, OH)
- **H-Root** (US Army, Aberdeen, MD)
- **I-Root** (Netnod, Stockholm, Sweden) - 65 anycast sites
- **J-Root** (VeriSign, Dulles, VA) - 127 anycast sites
- **K-Root** (RIPE NCC, Amsterdam, Netherlands) - 69 anycast sites
- **L-Root** (ICANN, Los Angeles, CA) - 167 anycast sites
- **M-Root** (WIDE Project, Tokyo, Japan)

Each marker shows:
- Server name and letter
- Operating organization
- Primary location
- IPv4 and IPv6 addresses
- Number of anycast sites

### 3. DNS Resolvers (BLUE Markers)

- **Data Source**: `/static/data/dns_resolvers.json`
- **Total Resolvers**: 500+ global DNS resolvers
- **Clustering**: Automatic marker clustering by geographic area
- **Tiers**: Visual distinction between Tier 1 and other resolvers

Resolver information includes:
- Provider name
- IP address
- City and country
- Tier classification
- Tags (public, global, commercial, etc.)

### 4. Remote Traceroute Locations (ORANGE Markers)

Available remote traceroute sources:

- **US East** (Virginia) - Hurricane Electric
- **US West** (California) - Hurricane Electric
- **Europe** (London) - LINX
- **Asia** (Tokyo) - JPIX
- **Oceania** (Sydney) - Vocus

Features:
- Click to select as traceroute source
- Integration with Looking Glass servers
- Future: API-based remote traceroute

### 5. Traceroute Execution

**Backend**: Python-based traceroute with GeoIP lookup

**Process**:
1. User enters target domain or IP
2. Backend executes `traceroute` command
3. Parse hop-by-hop results
4. GeoIP lookup for each hop (ipinfo.io API)
5. Return structured data with locations

**API Endpoint**: `POST /api/traceroute`

Request:
```json
{
  "target": "example.com",
  "source": "local",
  "max_hops": 30
}
```

Response:
```json
{
  "success": true,
  "target": "example.com",
  "source": "local",
  "hops": [
    {
      "hop": 1,
      "ip": "192.168.1.1",
      "hostname": "gateway.local",
      "latency": 2.34,
      "location": {
        "ip": "192.168.1.1",
        "city": "San Francisco",
        "country": "US",
        "lat": 37.7749,
        "lon": -122.4194,
        "org": "Comcast Cable"
      }
    }
  ],
  "stats": {
    "total_hops": 12,
    "valid_hops": 10,
    "countries_traversed": 3,
    "total_latency_ms": 145.67
  }
}
```

### 6. Visual Path Drawing

**Animation**:
- Animated polyline drawing (200ms per hop)
- Color: Lime green (#00ff88)
- Weight: 3px with opacity
- Smooth curves between points

**Hop Markers**:
- Small circular markers at each hop
- Click for detailed popup
- Shows IP, hostname, latency, location

**Auto-fit**:
- Map automatically zooms to show entire path
- 50px padding around bounds

### 7. Side Panel Results

**Statistics Cards**:
- Total Hops
- Total Latency (ms)
- Valid Hops
- Countries Traversed

**Hop Table**:
- Hop number
- IP address
- Hostname
- Latency
- Geographic location
- ISP/Organization

**Export Options**:
- Copy to clipboard (formatted text)
- Export as JSON
- Download results

### 8. User Interface

**Controls Panel**:
- Target input (domain or IP)
- Max hops selector (1-64)
- Run Traceroute button
- Reset Map button

**Legend**:
- RED: DNS Root Servers
- BLUE: DNS Resolvers
- ORANGE: Remote Traceroute Points
- GREEN: Traceroute Path

**Loading States**:
- Spinner animation during execution
- Progress messages
- Estimated time display

## Technical Architecture

### Frontend Stack

```
/templates/visualtrace.html
├── Leaflet.js 1.9.4 (map library)
├── Leaflet.markercluster (clustering)
├── Custom CSS (dark theme)
└── Custom JavaScript (interactions)

/static/js/visualtrace.js
├── Map initialization
├── Layer management
├── API communication
├── Path animation
└── Export functionality

/static/css/visualtrace.css
├── Dark theme styling
├── Responsive design
├── Animations
└── Custom markers

/static/data/
├── root_servers.json (13 root servers)
└── dns_resolvers.json (500+ resolvers)
```

### Backend Stack

```
/visual_traceroute.py
├── Flask Blueprint
├── Traceroute execution
├── GeoIP lookup (ipinfo.io)
├── Result parsing
└── API endpoints
```

### API Endpoints

1. **POST /api/traceroute**
   - Execute traceroute
   - GeoIP lookup for hops
   - Return path data

2. **GET /api/remote-locations**
   - List available remote sources
   - Return location data

3. **POST /api/dns-path**
   - DNS resolution path tracing
   - (Future implementation)

4. **GET /api/dns-resolvers**
   - Load resolver data
   - Filter and optimize payload

## Installation

### Requirements

```bash
pip install flask requests
```

### File Structure

```
/Users/ryan/development/dnsscience-tool-tests/
├── visual_traceroute.py           # Backend API
├── templates/
│   └── visualtrace.html           # Frontend HTML
├── static/
│   ├── js/
│   │   └── visualtrace.js        # Frontend JavaScript
│   ├── css/
│   │   └── visualtrace.css       # Frontend CSS
│   └── data/
│       ├── root_servers.json     # DNS root servers
│       └── dns_resolvers.json    # DNS resolvers
```

### Integration with Main App

Add to your Flask app:

```python
from visual_traceroute import visual_trace_bp

app.register_blueprint(visual_trace_bp)

@app.route('/visualtrace')
def visualtrace_page():
    return render_template('visualtrace.html')
```

## Usage

### Access the Tool

Navigate to: `https://dnsscience.io/visualtrace`

### Run a Traceroute

1. Enter target domain or IP in input field
2. Adjust max hops if needed (default: 30)
3. Click "Run Traceroute"
4. Wait for execution (up to 60 seconds)
5. View results on map and in side panel

### Explore DNS Infrastructure

- **Root Servers**: Click RED markers to see details
- **Resolvers**: Click BLUE markers (clustered by location)
- **Remote Points**: Click ORANGE markers to select source

### Export Results

- **Copy**: Copy formatted text to clipboard
- **JSON**: Download complete data as JSON
- **Print**: Browser print (hides controls)

## Advanced Features

### GeoIP Rate Limiting

The tool uses ipinfo.io free tier:
- 50,000 requests/month
- No API key required
- 0.1s delay between lookups to avoid rate limits

### Remote Traceroute (Coming Soon)

Future implementation will support:
- Looking Glass API integration
- RIPE Atlas measurements
- Cloudflare Radar API
- Custom remote points

### DNS Path Tracing (Coming Soon)

Visualize DNS resolution:
1. Client → Recursive Resolver
2. Recursive → Root Server
3. Root → TLD Server
4. TLD → Authoritative NS
5. Authoritative → Client

## Performance Optimization

### Clustering

DNS resolvers use marker clustering:
- Reduces visual clutter
- Shows count in cluster
- Automatic zoom adaptation

### Data Loading

Lazy loading strategy:
- Root servers: Load on page init
- Resolvers: Load on demand
- Remote locations: API call

### Map Tiles

Using CartoDB Dark tiles:
- CDN-delivered
- Cached by browser
- Fast worldwide delivery

## Mobile Responsiveness

Responsive breakpoints:

**Desktop** (>768px):
- Side panel: 400px fixed
- Controls: Absolute positioned
- Full map view

**Mobile** (<768px):
- Side panel: 100% width, 300px height
- Controls: Full width
- Stacked layout

## Browser Support

Tested on:
- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+
- Mobile Safari (iOS 14+)
- Chrome Mobile (Android 10+)

## Security Considerations

### Input Validation

- Domain/IP format validation
- Max hops limit (1-64)
- Timeout protection (60s)

### Rate Limiting

Backend should implement:
- Per-IP rate limiting
- Per-user limits (if authenticated)
- Concurrent request limits

### GeoIP Privacy

- No user location tracking
- Only traceroute target IPs geolocated
- No logs of user queries

## Troubleshooting

### Traceroute Fails

**Issue**: "Error running traceroute"

**Solutions**:
1. Check traceroute is installed: `which traceroute`
2. May require sudo privileges
3. Try ICMP vs UDP mode
4. Check firewall rules

### GeoIP Lookup Fails

**Issue**: "GeoIP lookup failed"

**Solutions**:
1. Check ipinfo.io API status
2. Verify network connectivity
3. Check rate limits
4. Use fallback to no location

### Map Not Loading

**Issue**: Blank map or tiles not showing

**Solutions**:
1. Check browser console for errors
2. Verify Leaflet.js CDN accessible
3. Check CSP headers
4. Try different tile provider

### No Markers Showing

**Issue**: Map loads but no markers

**Solutions**:
1. Check JSON data files exist
2. Verify file paths in JavaScript
3. Check browser console for 404s
4. Confirm data format is valid JSON

## Future Enhancements

### Phase 1 (Q1 2025)
- Remote traceroute via Looking Glass APIs
- DNS path visualization
- Historical traceroute comparison
- Save/share traceroute results

### Phase 2 (Q2 2025)
- MTR (My Traceroute) integration
- Packet loss visualization
- Latency heatmaps
- ASN path analysis

### Phase 3 (Q3 2025)
- Real-time monitoring
- Alert on path changes
- BGP route analysis
- Network topology mapping

## Support

For issues or questions:
- GitHub: https://github.com/dnsscience/visual-traceroute
- Email: support@dnsscience.io
- Docs: https://dnsscience.io/docs/visual-traceroute

## License

MIT License - See LICENSE file

## Credits

- Map Library: Leaflet.js
- GeoIP Data: ipinfo.io
- Tile Provider: CartoDB
- Root Server Data: IANA
- DNS Resolver Data: Public DNS Project

Version: 1.0.0
Last Updated: 2025-11-15
