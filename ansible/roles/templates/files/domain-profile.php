<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ domain }} - DNS Science</title>
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
        }

        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        h1 {
            color: #667eea;
            font-size: 32px;
            margin-bottom: 5px;
        }

        .domain-name {
            font-weight: normal;
            color: #333;
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

        .overview-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }

        .card h2 {
            color: #667eea;
            margin-bottom: 15px;
            font-size: 20px;
        }

        .stat-item {
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px solid #f0f0f0;
        }

        .stat-item:last-child {
            border-bottom: none;
        }

        .stat-label {
            color: #666;
            font-weight: 500;
        }

        .stat-value {
            color: #333;
            font-weight: 600;
        }

        .badge {
            display: inline-block;
            padding: 5px 12px;
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

        .score-circle {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 36px;
            font-weight: bold;
            margin: 0 auto 15px;
        }

        .score-A { background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); color: white; }
        .score-B { background: linear-gradient(135deg, #fdbb2d 0%, #22c1c3 100%); color: white; }
        .score-C { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; }
        .score-D { background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); color: white; }
        .score-F { background: linear-gradient(135deg, #eb3349 0%, #f45c43 100%); color: white; }

        .timeline {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 30px;
        }

        .timeline h2 {
            color: #667eea;
            margin-bottom: 20px;
        }

        .timeline-item {
            display: flex;
            padding: 15px 0;
            border-left: 3px solid #667eea;
            padding-left: 20px;
            margin-left: 10px;
            position: relative;
        }

        .timeline-item::before {
            content: '';
            position: absolute;
            left: -8px;
            top: 20px;
            width: 13px;
            height: 13px;
            border-radius: 50%;
            background: #667eea;
        }

        .timeline-date {
            min-width: 150px;
            color: #666;
            font-size: 14px;
        }

        .timeline-content {
            flex: 1;
        }

        .timeline-title {
            font-weight: 600;
            color: #333;
            margin-bottom: 5px;
        }

        .timeline-desc {
            color: #666;
            font-size: 14px;
        }

        .table-responsive {
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        thead {
            background: #f8f8f8;
        }

        th {
            padding: 12px;
            text-align: left;
            color: #666;
            font-weight: 600;
            font-size: 14px;
        }

        td {
            padding: 12px;
            border-bottom: 1px solid #f0f0f0;
        }

        tr:hover {
            background: #f8f8f8;
        }

        .loading {
            text-align: center;
            padding: 60px;
            color: #666;
        }

        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .threat-alert {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 5px;
        }

        .threat-alert-critical {
            background: #f8d7da;
            border-left-color: #dc3545;
        }

        .threat-alert-high {
            background: #fff3cd;
            border-left-color: #fd7e14;
        }

        .threat-title {
            font-weight: 600;
            margin-bottom: 5px;
            color: #333;
        }

        .threat-desc {
            font-size: 14px;
            color: #666;
        }

        .dns-record {
            display: grid;
            grid-template-columns: 80px 1fr;
            padding: 10px;
            background: #f8f8f8;
            margin-bottom: 8px;
            border-radius: 5px;
        }

        .dns-type {
            font-weight: 600;
            color: #667eea;
        }

        .dns-value {
            color: #333;
            word-break: break-all;
        }

        .cert-info {
            background: #f8f8f8;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 15px;
        }

        .cert-subject {
            font-weight: 600;
            color: #333;
            margin-bottom: 8px;
        }

        .cert-details {
            font-size: 14px;
            color: #666;
        }

        .tabs-secondary {
            display: flex;
            border-bottom: 2px solid #f0f0f0;
            margin-bottom: 20px;
        }

        .tab-btn {
            padding: 12px 24px;
            background: none;
            border: none;
            cursor: pointer;
            color: #666;
            font-weight: 500;
            transition: all 0.3s;
        }

        .tab-btn:hover {
            color: #667eea;
        }

        .tab-btn.active {
            color: #667eea;
            border-bottom: 3px solid #667eea;
            margin-bottom: -2px;
        }

        .tab-panel {
            display: none;
        }

        .tab-panel.active {
            display: block;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-content">
                <div>
                    <h1><span class="domain-name">{{ domain }}</span></h1>
                    <p style="color: #666; margin-top: 5px;">Complete Domain Profile</p>
                </div>
                <div class="nav-links">
                    <a href="/">Home</a>
                    <a href="/browse">Browse</a>
                    <a href="/scanners">Scanners</a>
                </div>
            </div>
        </header>

        <div id="loading" class="card loading">
            <div class="spinner"></div>
            <p>Loading domain profile...</p>
        </div>

        <div id="content" style="display: none;">
            <!-- Overview Cards -->
            <div class="overview-grid">
                <div class="card" id="security-score-card">
                    <h2>Security Score</h2>
                    <div id="security-score-display"></div>
                </div>

                <div class="card">
                    <h2>DNSSEC</h2>
                    <div id="dnssec-info"></div>
                </div>

                <div class="card">
                    <h2>Email Security</h2>
                    <div id="email-security-info"></div>
                </div>

                <div class="card">
                    <h2>SSL Certificate</h2>
                    <div id="ssl-info"></div>
                </div>
            </div>

            <!-- Threats Section -->
            <div class="card" id="threats-section" style="display: none; margin-bottom: 30px;">
                <h2>Active Threats</h2>
                <div id="threats-list"></div>
            </div>

            <!-- Blacklists Section -->
            <div class="card" id="blacklists-section" style="display: none; margin-bottom: 30px;">
                <h2>Blacklist Status</h2>
                <div id="blacklists-list"></div>
            </div>

            <!-- Detailed Information Tabs -->
            <div class="card">
                <div class="tabs-secondary">
                    <button class="tab-btn active" onclick="switchDetailTab('certificates')">Certificates</button>
                    <button class="tab-btn" onclick="switchDetailTab('dns-records')">DNS Records</button>
                    <button class="tab-btn" onclick="switchDetailTab('scan-history')">Scan History</button>
                    <button class="tab-btn" onclick="switchDetailTab('timeline')">Timeline</button>
                </div>

                <div id="certificates-panel" class="tab-panel active">
                    <h2>SSL Certificates</h2>
                    <div id="certificates-list"></div>
                </div>

                <div id="dns-records-panel" class="tab-panel">
                    <h2>DNS Records</h2>
                    <div id="dns-records-list"></div>
                </div>

                <div id="scan-history-panel" class="tab-panel">
                    <h2>Scan History</h2>
                    <div class="table-responsive">
                        <table>
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>Status</th>
                                    <th>Security Score</th>
                                    <th>DNSSEC</th>
                                    <th>SPF</th>
                                    <th>DKIM</th>
                                    <th>DMARC</th>
                                </tr>
                            </thead>
                            <tbody id="scan-history-tbody"></tbody>
                        </table>
                    </div>
                </div>

                <div id="timeline-panel" class="tab-panel">
                    <h2>Change Timeline</h2>
                    <div id="timeline-list"></div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const domainName = "{{ domain }}";
    </script>
    <script src="/static/js/domain-profile.js"></script>
</body>
</html>
