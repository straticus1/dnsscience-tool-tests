/**
 * DNS Auto Lookup - Client-side Detection Script
 * Performs real-time detection of IP, DNS resolver, EDNS, and security settings
 */

// Global state
let queryCount = 0;
let detectionResults = {
    ip: null,
    resolver: null,
    edns: null,
    security: null
};

// Update query counter
function updateQueryCounter() {
    queryCount++;
    const counterElement = document.getElementById('query-counter');
    if (counterElement) {
        counterElement.textContent = queryCount;
    }
}

// Copy to clipboard functionality
function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    if (!element) return;

    const text = element.textContent.trim();

    navigator.clipboard.writeText(text).then(() => {
        // Visual feedback
        const button = element.parentElement.querySelector('.copy-btn');
        if (button) {
            const originalText = button.textContent;
            button.textContent = '✓ Copied!';
            button.classList.add('copied');

            setTimeout(() => {
                button.textContent = originalText;
                button.classList.remove('copied');
            }, 2000);
        }
    }).catch(err => {
        console.error('Failed to copy:', err);
        alert('Failed to copy to clipboard');
    });
}

// Update status badge
function updateStatus(statusId, text, className = '') {
    const statusElement = document.getElementById(statusId);
    if (statusElement) {
        statusElement.textContent = text;
        statusElement.className = 'status-badge ' + className;
    }
}

// Show/hide copy button
function toggleCopyButton(buttonId, show) {
    const button = document.getElementById(buttonId);
    if (button) {
        button.style.display = show ? 'inline-block' : 'none';
    }
}

// IP Address Detection
async function detectIP() {
    try {
        updateStatus('ip-status', 'detecting...', 'detecting');

        const response = await fetch('/api/autolookup/ip');
        const data = await response.json();

        updateQueryCounter();

        if (data.error) {
            throw new Error(data.error);
        }

        // Update IPv4
        const ipv4Element = document.getElementById('ipv4-result');
        if (data.ipv4) {
            ipv4Element.textContent = data.ipv4;
            ipv4Element.className = 'result-value success';
            toggleCopyButton('ipv4-copy', true);
        } else {
            ipv4Element.textContent = 'Not available';
            ipv4Element.className = 'result-value';
        }

        // Update IPv6
        const ipv6Element = document.getElementById('ipv6-result');
        if (data.ipv6) {
            ipv6Element.textContent = data.ipv6;
            ipv6Element.className = 'result-value success';
            toggleCopyButton('ipv6-copy', true);
        } else {
            ipv6Element.textContent = 'Not available';
            ipv6Element.className = 'result-value';
        }

        detectionResults.ip = data;
        updateStatus('ip-status', 'complete', 'complete');

    } catch (error) {
        console.error('IP detection failed:', error);
        document.getElementById('ipv4-result').textContent = 'Detection failed';
        document.getElementById('ipv6-result').textContent = 'Detection failed';
        updateStatus('ip-status', 'error', 'error');
    }
}

// DNS Resolver Detection
async function detectResolver() {
    try {
        updateStatus('resolver-status', 'detecting...', 'detecting');

        const startTime = performance.now();
        const response = await fetch('/api/autolookup/resolver');
        const data = await response.json();
        const responseTime = Math.round(performance.now() - startTime);

        updateQueryCounter();

        if (data.error) {
            throw new Error(data.error);
        }

        // Update provider
        const providerElement = document.getElementById('resolver-provider');
        providerElement.textContent = data.provider || 'Unknown';
        providerElement.className = 'result-value';

        // Update resolver IP
        const ipElement = document.getElementById('resolver-ip');
        if (data.resolver_ip) {
            ipElement.textContent = data.resolver_ip;
            ipElement.className = 'result-value success';
            toggleCopyButton('resolver-copy', true);
        } else {
            ipElement.textContent = 'Unknown';
            ipElement.className = 'result-value';
        }

        // Update speed
        const speedElement = document.getElementById('resolver-speed');
        speedElement.textContent = `${responseTime}ms`;
        speedElement.className = responseTime < 50 ? 'result-value success' :
                                 responseTime < 200 ? 'result-value warning' :
                                 'result-value error';

        detectionResults.resolver = data;
        updateStatus('resolver-status', 'complete', 'complete');

    } catch (error) {
        console.error('Resolver detection failed:', error);
        document.getElementById('resolver-provider').textContent = 'Detection failed';
        document.getElementById('resolver-ip').textContent = 'Detection failed';
        document.getElementById('resolver-speed').textContent = 'N/A';
        updateStatus('resolver-status', 'error', 'error');
    }
}

// EDNS Client Subnet Detection
async function detectEDNS() {
    try {
        updateStatus('edns-status', 'detecting...', 'detecting');

        const response = await fetch('/api/autolookup/edns');
        const data = await response.json();

        updateQueryCounter();

        if (data.error) {
            throw new Error(data.error);
        }

        // Update enabled status
        const enabledElement = document.getElementById('edns-enabled');
        if (data.enabled) {
            enabledElement.innerHTML = '<span class="status-icon good"></span>Enabled';
            enabledElement.className = 'result-value success';
        } else {
            enabledElement.innerHTML = '<span class="status-icon bad"></span>Disabled';
            enabledElement.className = 'result-value';
        }

        // Update subnet
        const subnetElement = document.getElementById('edns-subnet');
        if (data.subnet) {
            subnetElement.textContent = data.subnet;
            subnetElement.className = 'result-value';
            toggleCopyButton('edns-copy', true);
        } else {
            subnetElement.textContent = 'Not exposed';
            subnetElement.className = 'result-value success';
        }

        // Update privacy impact
        const privacyElement = document.getElementById('edns-privacy');
        if (data.privacy_impact) {
            privacyElement.textContent = data.privacy_impact;
            privacyElement.className = data.privacy_impact.includes('High') ? 'result-value error' :
                                      data.privacy_impact.includes('Medium') ? 'result-value warning' :
                                      'result-value success';
        } else {
            privacyElement.textContent = 'Good';
            privacyElement.className = 'result-value success';
        }

        detectionResults.edns = data;
        updateStatus('edns-status', 'complete', 'complete');

    } catch (error) {
        console.error('EDNS detection failed:', error);
        document.getElementById('edns-enabled').textContent = 'Detection failed';
        document.getElementById('edns-subnet').textContent = 'Detection failed';
        document.getElementById('edns-privacy').textContent = 'N/A';
        updateStatus('edns-status', 'error', 'error');
    }
}

// DNS Security Assessment
async function detectSecurity() {
    try {
        updateStatus('security-status', 'analyzing...', 'detecting');

        const response = await fetch('/api/autolookup/security');
        const data = await response.json();

        updateQueryCounter();

        if (data.error) {
            throw new Error(data.error);
        }

        // Update DNSSEC
        const dnssecElement = document.getElementById('security-dnssec');
        if (data.dnssec) {
            dnssecElement.innerHTML = '<span class="status-icon good"></span>Validated';
            dnssecElement.className = 'result-value success';
        } else {
            dnssecElement.innerHTML = '<span class="status-icon warning"></span>Not validated';
            dnssecElement.className = 'result-value warning';
        }

        // Update DoH
        const dohElement = document.getElementById('security-doh');
        if (data.doh === true) {
            dohElement.innerHTML = '<span class="status-icon good"></span>Available';
            dohElement.className = 'result-value success';
        } else if (data.doh === false) {
            dohElement.innerHTML = '<span class="status-icon bad"></span>Not available';
            dohElement.className = 'result-value error';
        } else {
            dohElement.innerHTML = '<span class="status-icon warning"></span>Unknown';
            dohElement.className = 'result-value warning';
        }

        // Update DoT
        const dotElement = document.getElementById('security-dot');
        if (data.dot === true) {
            dotElement.innerHTML = '<span class="status-icon good"></span>Available';
            dotElement.className = 'result-value success';
        } else if (data.dot === false) {
            dotElement.innerHTML = '<span class="status-icon bad"></span>Not available';
            dotElement.className = 'result-value error';
        } else {
            dotElement.innerHTML = '<span class="status-icon warning"></span>Unknown';
            dotElement.className = 'result-value warning';
        }

        // Update security score
        const scoreElement = document.getElementById('security-score');
        const score = data.score || 0;
        const scoreText = `${score}/100`;

        if (score >= 80) {
            scoreElement.innerHTML = `<span class="status-icon good"></span>${scoreText} - Excellent`;
            scoreElement.className = 'result-value success';
        } else if (score >= 60) {
            scoreElement.innerHTML = `<span class="status-icon warning"></span>${scoreText} - Good`;
            scoreElement.className = 'result-value warning';
        } else {
            scoreElement.innerHTML = `<span class="status-icon bad"></span>${scoreText} - Needs improvement`;
            scoreElement.className = 'result-value error';
        }

        detectionResults.security = data;
        updateStatus('security-status', 'complete', 'complete');

    } catch (error) {
        console.error('Security detection failed:', error);
        document.getElementById('security-dnssec').textContent = 'Detection failed';
        document.getElementById('security-doh').textContent = 'Detection failed';
        document.getElementById('security-dot').textContent = 'Detection failed';
        document.getElementById('security-score').textContent = 'N/A';
        updateStatus('security-status', 'error', 'error');
    }
}

// Run all detections
async function runAllDetections() {
    console.log('Starting DNS Auto Lookup detections...');

    // Run detections in parallel for speed
    await Promise.all([
        detectIP(),
        detectResolver(),
        detectEDNS(),
        detectSecurity()
    ]);

    console.log('All detections complete:', detectionResults);
}

// Initialize on page load
window.addEventListener('DOMContentLoaded', () => {
    console.log('DNS Auto Lookup initialized');
    runAllDetections();
});

// Refresh functionality (can be triggered by button if needed)
function refreshDetections() {
    console.log('Refreshing detections...');
    runAllDetections();
}

// Export for global access
window.copyToClipboard = copyToClipboard;
window.refreshDetections = refreshDetections;
