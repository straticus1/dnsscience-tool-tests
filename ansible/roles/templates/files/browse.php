<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Data Browser - DNS Science</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
        }

        header {
            background: white;
            padding: 20px 30px;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        h1 {
            color: #667eea;
            font-size: 28px;
        }

        .nav-links a {
            color: #667eea;
            text-decoration: none;
            margin-left: 20px;
            font-weight: 500;
        }

        .nav-links a:hover {
            color: #764ba2;
        }

        .tabs {
            background: white;
            padding: 0;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 30px;
            overflow: hidden;
        }

        .tab-buttons {
            display: flex;
            border-bottom: 2px solid #f0f0f0;
        }

        .tab-button {
            flex: 1;
            padding: 20px;
            background: white;
            border: none;
            cursor: pointer;
            font-size: 16px;
            font-weight: 500;
            color: #666;
            transition: all 0.3s;
        }

        .tab-button:hover {
            background: #f8f8f8;
        }

        .tab-button.active {
            color: #667eea;
            border-bottom: 3px solid #667eea;
            margin-bottom: -2px;
        }

        .tab-content {
            display: none;
            padding: 30px;
        }

        .tab-content.active {
            display: block;
        }

        .filters {
            background: #f8f8f8;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }

        .filter-row {
            display: flex;
            gap: 15px;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }

        .filter-row:last-child {
            margin-bottom: 0;
        }

        .filter-group {
            flex: 1;
            min-width: 200px;
        }

        .filter-group label {
            display: block;
            margin-bottom: 5px;
            color: #666;
            font-size: 14px;
            font-weight: 500;
        }

        .filter-group select,
        .filter-group input {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
        }

        .data-table {
            width: 100%;
            background: white;
            border-radius: 8px;
            overflow: hidden;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        thead {
            background: #667eea;
            color: white;
        }

        th {
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }

        td {
            padding: 15px;
            border-bottom: 1px solid #f0f0f0;
        }

        tr:hover {
            background: #f8f8f8;
        }

        .badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }

        .badge-success {
            background: #d4edda;
            color: #155724;
        }

        .badge-danger {
            background: #f8d7da;
            color: #721c24;
        }

        .badge-warning {
            background: #fff3cd;
            color: #856404;
        }

        .badge-info {
            background: #d1ecf1;
            color: #0c5460;
        }

        .ssl-grade {
            font-weight: bold;
            font-size: 16px;
        }

        .ssl-A-plus { color: #28a745; }
        .ssl-A { color: #5cb85c; }
        .ssl-A-minus { color: #91cf91; }
        .ssl-B { color: #ffc107; }
        .ssl-C { color: #fd7e14; }
        .ssl-D { color: #dc3545; }
        .ssl-F { color: #c82333; }

        .pagination {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 10px;
            margin-top: 20px;
        }

        .pagination button {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 500;
        }

        .pagination button:disabled {
            background: #ccc;
            cursor: not-allowed;
        }

        .pagination button:hover:not(:disabled) {
            background: #764ba2;
        }

        .pagination .page-info {
            color: #666;
            font-size: 14px;
        }

        .loading {
            text-align: center;
            padding: 40px;
            color: #666;
        }

        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }

        .stat-card {
            background: #f8f8f8;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }

        .stat-value {
            font-size: 32px;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 5px;
        }

        .stat-label {
            color: #666;
            font-size: 14px;
        }

        .domain-link {
            color: #667eea;
            text-decoration: none;
            font-weight: 500;
        }

        .domain-link:hover {
            text-decoration: underline;
        }

        .threat-severity-critical { color: #dc3545; font-weight: bold; }
        .threat-severity-high { color: #fd7e14; font-weight: bold; }
        .threat-severity-medium { color: #ffc107; }
        .threat-severity-low { color: #28a745; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>DNS Science - Data Browser</h1>
            <div class="nav-links">
                <a href="/">Home</a>
                <a href="/scanners">Scanners</a>
                <a href="/settings">Settings</a>
            </div>
        </header>

        <div class="tabs">
            <div class="tab-buttons">
                <button class="tab-button active" onclick="switchTab('tlds')">TLDs</button>
                <button class="tab-button" onclick="switchTab('ssl-status')">SSL Status</button>
                <button class="tab-button" onclick="switchTab('threats')">Threat Intel</button>
                <button class="tab-button" onclick="switchTab('blacklists')">Blacklists</button>
            </div>

            <!-- TLDs Tab -->
            <div id="tlds-tab" class="tab-content active">
                <div class="stats-grid" id="tld-stats"></div>
                <div class="data-table">
                    <table>
                        <thead>
                            <tr>
                                <th>TLD</th>
                                <th>Total Domains</th>
                                <th>DNSSEC Enabled</th>
                                <th>SPF Valid</th>
                                <th>Avg Security Score</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="tlds-tbody"></tbody>
                    </table>
                </div>
                <div class="pagination" id="tlds-pagination"></div>
            </div>

            <!-- SSL Status Tab -->
            <div id="ssl-status-tab" class="tab-content">
                <div class="filters">
                    <div class="filter-row">
                        <div class="filter-group">
                            <label>SSL Grade:</label>
                            <select id="ssl-grade-filter" onchange="loadSSLStatus()">
                                <option value="A+">A+</option>
                                <option value="A">A</option>
                                <option value="A-">A-</option>
                                <option value="B">B</option>
                                <option value="C">C</option>
                                <option value="D">D</option>
                                <option value="F">F</option>
                                <option value="none">No SSL</option>
                            </select>
                        </div>
                    </div>
                </div>
                <div class="data-table">
                    <table>
                        <thead>
                            <tr>
                                <th>Domain</th>
                                <th>SSL Grade</th>
                                <th>Certificate Issuer</th>
                                <th>Expires</th>
                                <th>Security Score</th>
                                <th>Last Checked</th>
                            </tr>
                        </thead>
                        <tbody id="ssl-status-tbody"></tbody>
                    </table>
                </div>
                <div class="pagination" id="ssl-status-pagination"></div>
            </div>

            <!-- Threats Tab -->
            <div id="threats-tab" class="tab-content">
                <div class="filters">
                    <div class="filter-row">
                        <div class="filter-group">
                            <label>Severity:</label>
                            <select id="threat-severity-filter" onchange="loadThreats()">
                                <option value="">All Severities</option>
                                <option value="critical">Critical</option>
                                <option value="high">High</option>
                                <option value="medium">Medium</option>
                                <option value="low">Low</option>
                            </select>
                        </div>
                    </div>
                </div>
                <div class="data-table">
                    <table>
                        <thead>
                            <tr>
                                <th>Domain</th>
                                <th>Threat Type</th>
                                <th>Severity</th>
                                <th>Source</th>
                                <th>Description</th>
                                <th>First Seen</th>
                                <th>Last Seen</th>
                            </tr>
                        </thead>
                        <tbody id="threats-tbody"></tbody>
                    </table>
                </div>
                <div class="pagination" id="threats-pagination"></div>
            </div>

            <!-- Blacklists Tab -->
            <div id="blacklists-tab" class="tab-content">
                <div class="filters">
                    <div class="filter-row">
                        <div class="filter-group">
                            <label>Blacklist:</label>
                            <select id="blacklist-filter" onchange="loadBlacklists()">
                                <option value="">All Blacklists</option>
                                <option value="spamhaus">Spamhaus</option>
                                <option value="barracuda">Barracuda</option>
                                <option value="sorbs">SORBS</option>
                                <option value="spamcop">SpamCop</option>
                            </select>
                        </div>
                    </div>
                </div>
                <div class="data-table">
                    <table>
                        <thead>
                            <tr>
                                <th>Domain</th>
                                <th>Blacklist</th>
                                <th>Reason</th>
                                <th>Severity</th>
                                <th>Listed Since</th>
                                <th>Last Checked</th>
                            </tr>
                        </thead>
                        <tbody id="blacklists-tbody"></tbody>
                    </table>
                </div>
                <div class="pagination" id="blacklists-pagination"></div>
            </div>
        </div>
    </div>

    <script src="/static/js/browser.js"></script>
</body>
</html>
