/**
 * Visual Traceroute - Interactive Map Script
 * DNSScience.io
 */

// Global variables
let map;
let rootServersLayer;
let resolversLayer;
let remoteLocationsLayer;
let tracePathLayer;
let currentTraceData = null;

// Custom marker icons
const rootServerIcon = L.divIcon({
    className: 'custom-marker',
    html: '<div style="background: #ff4444; width: 16px; height: 16px; border-radius: 50%; border: 2px solid white; box-shadow: 0 0 10px rgba(255, 68, 68, 0.6);"></div>',
    iconSize: [20, 20],
    iconAnchor: [10, 10]
});

const resolverIcon = L.divIcon({
    className: 'custom-marker',
    html: '<div style="background: #4444ff; width: 12px; height: 12px; border-radius: 50%; border: 2px solid white;"></div>',
    iconSize: [16, 16],
    iconAnchor: [8, 8]
});

const remoteLocationIcon = L.divIcon({
    className: 'custom-marker',
    html: '<div style="background: #ff9944; width: 14px; height: 14px; border-radius: 50%; border: 2px solid white; box-shadow: 0 0 8px rgba(255, 153, 68, 0.6);"></div>',
    iconSize: [18, 18],
    iconAnchor: [9, 9]
});

const hopIcon = L.divIcon({
    className: 'custom-marker',
    html: '<div style="background: #00ff88; width: 10px; height: 10px; border-radius: 50%; border: 2px solid white;"></div>',
    iconSize: [14, 14],
    iconAnchor: [7, 7]
});

// Router icon for traceroute hops - will be colored dynamically
function createRouterIcon(color) {
    return L.divIcon({
        className: 'router-marker',
        html: `<div style="font-size: 24px; text-shadow: 0 0 4px rgba(0,0,0,0.8), 0 0 8px ${color}; filter: drop-shadow(0 0 2px white);" title="Router">🔀</div>`,
        iconSize: [30, 30],
        iconAnchor: [15, 15]
    });
}

// Firewall/Packet filter icon for timeout hops
const firewallIcon = L.divIcon({
    className: 'firewall-marker',
    html: '<div style="font-size: 28px; text-shadow: 0 0 4px rgba(0,0,0,0.8); filter: drop-shadow(0 0 2px white);" title="Packet Filter / Firewall">🧱</div>',
    iconSize: [32, 32],
    iconAnchor: [16, 16]
});

// Initialize map
function initMap() {
    // Create dark-themed map
    map = L.map('map', {
        center: [20, 0],
        zoom: 2,
        minZoom: 2,
        maxZoom: 18,
        worldCopyJump: true
    });

    // Dark tile layer
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
        subdomains: 'abcd',
        maxZoom: 20
    }).addTo(map);

    // Initialize layers
    rootServersLayer = L.layerGroup().addTo(map);
    resolversLayer = L.markerClusterGroup({
        maxClusterRadius: 50,
        iconCreateFunction: function(cluster) {
            const count = cluster.getChildCount();
            return L.divIcon({
                html: '<div style="background: rgba(68, 68, 255, 0.8); color: white; border-radius: 50%; width: 40px; height: 40px; display: flex; align-items: center; justify-content: center; font-weight: bold; border: 2px solid white;">' + count + '</div>',
                className: 'custom-cluster',
                iconSize: [40, 40]
            });
        }
    }).addTo(map);
    remoteLocationsLayer = L.layerGroup().addTo(map);
    tracePathLayer = L.layerGroup().addTo(map);

    // Load initial data
    loadRootServers();
    loadRemoteLocations();
}

// Load DNS root servers
async function loadRootServers() {
    try {
        const response = await fetch('/static/data/root_servers.json');
        const data = await response.json();

        data.root_servers.forEach(server => {
            const marker = L.marker([server.lat, server.lon], { icon: rootServerIcon })
                .bindPopup(`
                    <div style="padding: 10px;">
                        <h4 style="color: #00d4ff; margin-bottom: 8px;">${server.name}</h4>
                        <p><strong>Operator:</strong> ${server.operator}</p>
                        <p><strong>Location:</strong> ${server.primary_location}</p>
                        <p><strong>IPv4:</strong> ${server.ip_v4}</p>
                        <p><strong>IPv6:</strong> ${server.ip_v6}</p>
                        <p><strong>Anycast Sites:</strong> ${server.sites}</p>
                    </div>
                `);
            rootServersLayer.addLayer(marker);
        });
    } catch (error) {
        console.error('Error loading root servers:', error);
    }
}

// Load remote traceroute locations
async function loadRemoteLocations() {
    try {
        const response = await fetch('/api/remote-locations');
        const data = await response.json();

        if (data.success) {
            data.locations.forEach(location => {
                const marker = L.marker([location.lat, location.lon], { icon: remoteLocationIcon })
                    .bindPopup(`
                        <div style="padding: 10px;">
                            <h4 style="color: #00d4ff; margin-bottom: 8px;">${location.name}</h4>
                            <p><strong>Provider:</strong> ${location.provider}</p>
                            <p style="margin-top: 10px; color: #00ff88; cursor: pointer;" onclick="setSourceLocation('${location.id}')">
                                Click to use as traceroute source
                            </p>
                        </div>
                    `);
                remoteLocationsLayer.addLayer(marker);
            });
        }
    } catch (error) {
        console.error('Error loading remote locations:', error);
    }
}

// Set source location for traceroute
function setSourceLocation(locationId) {
    console.log('Source location set to:', locationId);
    // TODO: Implement remote traceroute
    alert('Remote traceroute source selection coming soon!');
}

// Run traceroute
async function runTraceroute() {
    const target = document.getElementById('target-input').value.trim();
    const maxHops = parseInt(document.getElementById('max-hops').value) || 30;

    if (!target) {
        alert('Please enter a target domain or IP address');
        return;
    }

    // Clear previous results
    clearTrace();

    // Show loading
    const resultsContainer = document.getElementById('results-container');
    resultsContainer.innerHTML = `
        <div class="loading">
            <div class="spinner"></div>
            <p>Running traceroute to ${target}...</p>
            <p style="font-size: 12px; color: #a0a0a0; margin-top: 10px;">
                This may take up to 60 seconds
            </p>
        </div>
    `;

    // Disable button
    const btn = document.getElementById('run-trace-btn');
    btn.disabled = true;
    btn.textContent = 'Running...';

    try {
        const response = await fetch('/api/traceroute', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                target: target,
                source: 'local',
                max_hops: maxHops
            })
        });

        const data = await response.json();

        if (data.success) {
            currentTraceData = data;
            displayTraceResults(data);
            drawTracePath(data.hops);
        } else {
            resultsContainer.innerHTML = `
                <div style="padding: 20px; text-align: center; color: #ff4444;">
                    <p>Error: ${data.error || 'Traceroute failed'}</p>
                </div>
            `;
        }
    } catch (error) {
        console.error('Traceroute error:', error);
        resultsContainer.innerHTML = `
            <div style="padding: 20px; text-align: center; color: #ff4444;">
                <p>Error: ${error.message}</p>
                <p style="font-size: 12px; margin-top: 10px;">
                    Make sure the backend server is running
                </p>
            </div>
        `;
    } finally {
        btn.disabled = false;
        btn.textContent = 'Run Traceroute';
    }
}

// Display trace results in side panel
function displayTraceResults(data) {
    // Show stats
    document.getElementById('stats-section').style.display = 'grid';
    document.getElementById('export-section').style.display = 'flex';

    document.getElementById('stat-total-hops').textContent = data.stats.total_hops;
    document.getElementById('stat-valid-hops').textContent = data.stats.valid_hops;
    document.getElementById('stat-countries').textContent = data.stats.countries_traversed;
    document.getElementById('stat-total-latency').textContent = data.stats.total_latency_ms.toFixed(2) + 'ms';

    // Display hops
    const resultsContainer = document.getElementById('results-container');
    resultsContainer.innerHTML = '<div class="hops-table"></div>';
    const hopsTable = resultsContainer.querySelector('.hops-table');

    data.hops.forEach(hop => {
        const hopRow = document.createElement('div');
        hopRow.className = 'hop-row';

        const latencyText = hop.latency ? `${hop.latency.toFixed(2)}ms` : 'N/A';
        const hostnameText = hop.hostname || hop.ip || 'Timeout';
        const locationText = hop.location
            ? `${hop.location.city}, ${hop.location.country}`
            : 'Unknown location';

        hopRow.innerHTML = `
            <div class="hop-header">
                <span class="hop-num">Hop ${hop.hop}</span>
                <span class="hop-latency">${latencyText}</span>
            </div>
            <div class="hop-details">
                <div>${hostnameText}</div>
                ${hop.ip ? `<div style="color: #6c757d;">${hop.ip}</div>` : ''}
            </div>
            ${hop.location ? `<div class="hop-location">${hop.location.org}</div>` : ''}
            ${hop.location ? `<div class="hop-location">${locationText}</div>` : ''}
        `;

        hopsTable.appendChild(hopRow);
    });
}

// Calculate gradient color from green to red based on position
function getHopColor(index, totalHops) {
    if (totalHops <= 1) return '#00ff88'; // Green for single hop

    // Gradient: Green (#00ff88) -> Yellow (#ffff00) -> Red (#ff4444)
    const ratio = index / (totalHops - 1);

    if (ratio < 0.5) {
        // Green to Yellow (0.0 to 0.5)
        const localRatio = ratio * 2;
        const r = Math.round(0 + (255 - 0) * localRatio);
        const g = 255;
        const b = Math.round(136 - 136 * localRatio);
        return `rgb(${r}, ${g}, ${b})`;
    } else {
        // Yellow to Red (0.5 to 1.0)
        const localRatio = (ratio - 0.5) * 2;
        const r = 255;
        const g = Math.round(255 - (255 - 68) * localRatio);
        const b = Math.round(0 + (68 - 0) * localRatio);
        return `rgb(${r}, ${g}, ${b})`;
    }
}

// Draw trace path on map
function drawTracePath(hops) {
    tracePathLayer.clearLayers();

    // Separate timeout hops from valid hops
    const timeoutHops = hops.filter(h => !h.ip || h.ip === '*' || !h.location);
    const validHops = hops.filter(h => h.location && h.location.lat && h.location.lon);

    if (validHops.length === 0) {
        // Even if no valid hops, show firewall icons for timeouts
        if (timeoutHops.length > 0) {
            console.log(`No geolocatable hops, but ${timeoutHops.length} timeout(s) detected`);
        }
        return;
    }

    // Create polyline points
    const points = validHops.map(h => [h.location.lat, h.location.lon]);

    // Draw animated polyline
    const polyline = L.polyline(points, {
        color: '#00ff88',
        weight: 3,
        opacity: 0.8,
        smoothFactor: 1
    }).addTo(tracePathLayer);

    // Add router markers for each valid hop with gradient colors
    validHops.forEach((hop, index) => {
        const hopColor = getHopColor(index, validHops.length);
        const routerIcon = createRouterIcon(hopColor);

        const marker = L.marker([hop.location.lat, hop.location.lon], { icon: routerIcon })
            .bindPopup(`
                <div style="padding: 10px;">
                    <h4 style="color: ${hopColor};">🔀 Hop ${hop.hop}</h4>
                    <p><strong>IP:</strong> ${hop.ip}</p>
                    ${hop.hostname ? `<p><strong>Hostname:</strong> ${hop.hostname}</p>` : ''}
                    <p><strong>Latency:</strong> ${hop.latency ? hop.latency.toFixed(2) + 'ms' : 'N/A'}</p>
                    <p><strong>Location:</strong> ${hop.location.city}, ${hop.location.country}</p>
                    <p><strong>Organization:</strong> ${hop.location.org}</p>
                    <p style="color: ${hopColor}; margin-top: 10px; font-size: 12px;">
                        <strong>Color code:</strong> ${index === 0 ? 'Source' : (index === validHops.length - 1 ? 'Destination' : 'Intermediate')}
                    </p>
                </div>
            `);
        tracePathLayer.addLayer(marker);
    });

    // Add firewall icons for timeout hops (if we can estimate location)
    // For timeouts, try to place them between the last known and next known hop
    hops.forEach((hop, index) => {
        if (!hop.ip || hop.ip === '*' || hop.ip === 'timeout') {
            // Try to find surrounding valid hops for approximate location
            const prevValidHop = hops.slice(0, index).reverse().find(h => h.location && h.location.lat);
            const nextValidHop = hops.slice(index + 1).find(h => h.location && h.location.lat);

            if (prevValidHop && prevValidHop.location && nextValidHop && nextValidHop.location) {
                // Place firewall between previous and next hop
                const lat = (prevValidHop.location.lat + nextValidHop.location.lat) / 2;
                const lon = (prevValidHop.location.lon + nextValidHop.location.lon) / 2;

                const marker = L.marker([lat, lon], { icon: firewallIcon })
                    .bindPopup(`
                        <div style="padding: 10px;">
                            <h4 style="color: #ff6b6b;">🧱 Hop ${hop.hop} - Packet Filter</h4>
                            <p><strong>Status:</strong> Request timed out or filtered</p>
                            <p style="margin-top: 10px; color: #ff6b6b;">
                                This hop did not respond to traceroute probes, likely due to:<br>
                                • Firewall filtering ICMP/UDP<br>
                                • Router configured not to respond<br>
                                • Packet prioritization/rate limiting
                            </p>
                            <p style="margin-top: 10px; font-size: 11px; color: #aaa;">
                                Location is approximate (midpoint between known hops)
                            </p>
                        </div>
                    `);
                tracePathLayer.addLayer(marker);
            } else if (prevValidHop && prevValidHop.location) {
                // Only previous hop known - place slightly ahead
                const marker = L.marker(
                    [prevValidHop.location.lat + 0.5, prevValidHop.location.lon + 0.5],
                    { icon: firewallIcon }
                ).bindPopup(`
                    <div style="padding: 10px;">
                        <h4 style="color: #ff6b6b;">🧱 Hop ${hop.hop} - Packet Filter</h4>
                        <p><strong>Status:</strong> Request timed out (*)</p>
                        <p style="margin-top: 10px; font-size: 11px; color: #aaa;">
                            Approximate location (after last known hop)
                        </p>
                    </div>
                `);
                tracePathLayer.addLayer(marker);
            }
        }
    });

    // Fit map to show entire path
    map.fitBounds(polyline.getBounds(), { padding: [50, 50] });

    // Animate path drawing
    animatePolyline(polyline);
}

// Animate polyline drawing
function animatePolyline(polyline) {
    const originalLatLngs = polyline.getLatLngs();
    polyline.setLatLngs([]);

    let index = 0;
    const interval = setInterval(() => {
        if (index < originalLatLngs.length) {
            polyline.addLatLng(originalLatLngs[index]);
            index++;
        } else {
            clearInterval(interval);
        }
    }, 200);
}

// Clear trace path
function clearTrace() {
    tracePathLayer.clearLayers();
    currentTraceData = null;
    document.getElementById('stats-section').style.display = 'none';
    document.getElementById('export-section').style.display = 'none';
}

// Reset map
function resetMap() {
    clearTrace();
    map.setView([20, 0], 2);
    document.getElementById('target-input').value = '';
    document.getElementById('results-container').innerHTML = `
        <p style="color: #a0a0a0; text-align: center; padding: 40px 20px;">
            Enter a target domain or IP address and click "Run Traceroute" to begin.
        </p>
    `;
}

// Export results as JSON
function exportJSON() {
    if (!currentTraceData) {
        alert('No traceroute data to export');
        return;
    }

    const dataStr = JSON.stringify(currentTraceData, null, 2);
    const blob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `traceroute-${currentTraceData.target}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
}

// Copy results to clipboard
function copyResults() {
    if (!currentTraceData) {
        alert('No traceroute data to copy');
        return;
    }

    let text = `Traceroute to ${currentTraceData.target}\n\n`;
    text += `Total Hops: ${currentTraceData.stats.total_hops}\n`;
    text += `Total Latency: ${currentTraceData.stats.total_latency_ms.toFixed(2)}ms\n`;
    text += `Countries Traversed: ${currentTraceData.stats.countries_traversed}\n\n`;
    text += 'Hop | IP | Hostname | Latency | Location\n';
    text += '----+----+----------+---------+---------\n';

    currentTraceData.hops.forEach(hop => {
        const ip = hop.ip || 'N/A';
        const hostname = hop.hostname || 'N/A';
        const latency = hop.latency ? `${hop.latency.toFixed(2)}ms` : 'N/A';
        const location = hop.location
            ? `${hop.location.city}, ${hop.location.country}`
            : 'Unknown';

        text += `${hop.hop} | ${ip} | ${hostname} | ${latency} | ${location}\n`;
    });

    navigator.clipboard.writeText(text).then(() => {
        alert('Results copied to clipboard!');
    }).catch(err => {
        console.error('Failed to copy:', err);
    });
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    initMap();

    document.getElementById('run-trace-btn').addEventListener('click', runTraceroute);
    document.getElementById('reset-btn').addEventListener('click', resetMap);
    document.getElementById('export-json').addEventListener('click', exportJSON);
    document.getElementById('copy-results').addEventListener('click', copyResults);

    // Allow Enter key to run traceroute
    document.getElementById('target-input').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            runTraceroute();
        }
    });
});
