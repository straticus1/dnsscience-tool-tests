<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNS Science - Email Security & DNS Tracker</title>
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
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 30px;
        }

        h1 {
            color: #667eea;
            margin-bottom: 10px;
        }

        .subtitle {
            color: #666;
            font-size: 14px;
        }

        .search-section {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 30px;
        }

        .search-form {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }

        input[type="text"] {
            flex: 1;
            padding: 12px 20px;
            border: 2px solid #e0e0e0;
            border-radius: 5px;
            font-size: 16px;
        }

        input[type="text"]:focus {
            outline: none;
            border-color: #667eea;
        }

        button {
            padding: 12px 30px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            transition: background 0.3s;
        }

        button:hover {
            background: #5568d3;
        }

        button:disabled {
            background: #ccc;
            cursor: not-allowed;
        }

        .status {
            padding: 10px;
            border-radius: 5px;
            margin-top: 10px;
            display: none;
        }

        .status.success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        .status.error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }

        .status.loading {
            background: #d1ecf1;
            color: #0c5460;
            border: 1px solid #bee5eb;
        }

        .results-section {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            display: none;
        }

        .security-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .security-card {
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            padding: 20px;
        }

        .security-card h3 {
            color: #333;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .status-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
        }

        .status-badge.enabled {
            background: #d4edda;
            color: #155724;
        }

        .status-badge.disabled {
            background: #f8d7da;
            color: #721c24;
        }

        .status-badge.partial {
            background: #fff3cd;
            color: #856404;
        }

        .detail-item {
            margin: 10px 0;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
            font-size: 14px;
        }

        .detail-label {
            font-weight: bold;
            color: #666;
            display: block;
            margin-bottom: 5px;
        }

        .history-section {
            margin-top: 30px;
            padding-top: 30px;
            border-top: 2px solid #e0e0e0;
        }

        .history-item {
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
            margin-bottom: 10px;
        }

        .timestamp {
            color: #666;
            font-size: 14px;
            font-weight: bold;
        }

        .search-results {
            margin-top: 20px;
        }

        .domain-list-item {
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
            margin-bottom: 10px;
            cursor: pointer;
            transition: background 0.2s;
        }

        .domain-list-item:hover {
            background: #e9ecef;
        }

        .domain-name {
            font-weight: bold;
            color: #667eea;
            font-size: 18px;
        }

        .last-checked {
            color: #666;
            font-size: 14px;
            margin-top: 5px;
        }

        .pagination {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #e9ecef;
        }

        .pagination-info {
            text-align: center;
            color: #666;
            margin-bottom: 15px;
            font-size: 14px;
        }

        .pagination-buttons {
            display: flex;
            justify-content: center;
            gap: 8px;
            flex-wrap: wrap;
            align-items: center;
        }

        .pagination-buttons button {
            padding: 8px 12px;
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 14px;
            color: #495057;
        }

        .pagination-buttons button:hover {
            background: #e9ecef;
            border-color: #667eea;
        }

        .pagination-buttons button.active {
            background: #667eea;
            color: white;
            border-color: #667eea;
            font-weight: bold;
        }

        .pagination-dots {
            color: #666;
            padding: 0 5px;
        }

        .status-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 12px;
            margin-left: 10px;
            font-weight: normal;
        }

        .status-badge.scanning {
            background: #ffc107;
            color: #000;
        }

        .status-badge.failed {
            background: #dc3545;
            color: white;
        }

        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }

        .tab {
            padding: 10px 20px;
            background: #f8f9fa;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            transition: background 0.2s;
        }

        .tab.active {
            background: #667eea;
            color: white;
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        .loading-spinner {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(255,255,255,.3);
            border-radius: 50%;
            border-top-color: #fff;
            animation: spin 1s ease-in-out infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        @keyframes progress {
            0% { transform: translateX(-100%); }
            50% { transform: translateX(100%); }
            100% { transform: translateX(-100%); }
        }

        code {
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 13px;
        }

        /* Theme Toggle */
        .theme-toggle {
            position: fixed;
            top: 20px;
            right: 20px;
            background: white;
            border-radius: 50px;
            padding: 10px 15px;
            cursor: pointer;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
            display: flex;
            align-items: center;
            gap: 8px;
            z-index: 1000;
            transition: background 0.3s;
        }

        .theme-toggle:hover {
            transform: scale(1.05);
        }

        .theme-toggle .sun {
            font-size: 20px;
        }

        .theme-toggle .moon {
            font-size: 20px;
            display: none;
        }

        /* Dark Mode Styles */
        body.dark-mode {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        }

        body.dark-mode .theme-toggle {
            background: #2d2d2d;
        }

        body.dark-mode .theme-toggle .sun {
            display: none;
        }

        body.dark-mode .theme-toggle .moon {
            display: block;
        }

        body.dark-mode header,
        body.dark-mode .search-section,
        body.dark-mode .results-section {
            background: #2d2d2d;
            color: #e0e0e0;
        }

        body.dark-mode h1,
        body.dark-mode h2,
        body.dark-mode h3 {
            color: #8b9cff;
        }

        body.dark-mode .subtitle {
            color: #b0b0b0;
        }

        body.dark-mode input[type="text"] {
            background: #1a1a1a;
            border-color: #444;
            color: #e0e0e0;
        }

        body.dark-mode .security-card,
        body.dark-mode .detail-item,
        body.dark-mode .history-item,
        body.dark-mode .domain-list-item {
            background: #1a1a1a;
            border-color: #444;
            color: #e0e0e0;
        }

        body.dark-mode .tab {
            background: #1a1a1a;
            color: #e0e0e0;
        }

        body.dark-mode code {
            background: #1a1a1a;
            color: #8b9cff;
        }

        /* Dashboard Cards Dark Mode */
        body.dark-mode .dashboard-card-gradient {
            background: #2d2d2d !important;
            border: 1px solid #444;
        }

        body.dark-mode .dashboard-card-chart {
            background: #1a1a1a !important;
            border-color: #444;
        }

        /* Quick Glance Cards */
        .glance-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
            border-color: #667eea;
        }

        body.dark-mode .glance-card {
            background: #2d2d2d !important;
            border-color: #444 !important;
            color: #e0e0e0 !important;
        }

        body.dark-mode .glance-card div[style*="color: #333"] {
            color: #e0e0e0 !important;
        }

        /* Navigation Bar */
        .nav-bar {
            display: flex;
            justify-content: flex-end;
            gap: 15px;
            padding: 15px 30px;
            background: rgba(255,255,255,0.95);
            border-radius: 10px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }

        body.dark-mode .nav-bar {
            background: rgba(45,45,45,0.95);
        }

        .nav-button {
            padding: 8px 20px;
            background: transparent;
            color: #667eea;
            border: 2px solid #667eea;
            border-radius: 5px;
            font-size: 14px;
            cursor: pointer;
            transition: all 0.3s;
            text-decoration: none;
            display: inline-block;
        }

        .nav-button:hover {
            background: #667eea;
            color: white;
        }

        .nav-button.primary {
            background: #667eea;
            color: white;
        }

        .nav-button.primary:hover {
            background: #5568d3;
            border-color: #5568d3;
        }

        body.dark-mode .nav-button {
            color: #8b9cff;
            border-color: #8b9cff;
        }

        body.dark-mode .nav-button:hover {
            background: #8b9cff;
            color: #1a1a1a;
        }

        body.dark-mode .nav-button.primary {
            background: #8b9cff;
            color: #1a1a1a;
        }

        /* Dropdown Menu */
        .nav-dropdown {
            position: relative;
            display: inline-block;
        }

        .nav-dropdown-content {
            display: none;
            position: absolute;
            background: white;
            min-width: 160px;
            box-shadow: 0 8px 16px rgba(0,0,0,0.2);
            border-radius: 5px;
            z-index: 1000;
            top: 100%;
            margin-top: 2px;
            padding: 5px 0;
        }

        .nav-dropdown:hover .nav-dropdown-content,
        .nav-dropdown-content:hover {
            display: block;
        }

        .nav-dropdown-content a {
            color: #667eea !important;
            padding: 12px 16px;
            text-decoration: none;
            display: block;
            border: none !important;
            background: transparent !important;
            transition: background 0.3s;
            border-radius: 0 !important;
        }

        .nav-dropdown-content a:hover {
            background: #f0f0f0 !important;
            color: #667eea !important;
        }

        .nav-dropdown .nav-button::after {
            content: ' ▼';
            font-size: 10px;
        }

        body.dark-mode .nav-dropdown-content {
            background: #2d2d2d;
        }

        body.dark-mode .nav-dropdown-content a {
            color: #8b9cff !important;
        }

        body.dark-mode .nav-dropdown-content a:hover {
            background: #3d3d3d !important;
            color: #8b9cff !important;
        }

        /* Expert Mode Option Cards */
        .expert-option-card {
            background: white;
            padding: 12px;
            border-radius: 6px;
            border: 2px solid #e0e0e0;
        }

        body.dark-mode .expert-option-card {
            background: #1a1a1a;
            border-color: #444;
        }

        .expert-option-card h4 {
            margin: 0 0 10px 0;
            color: #667eea;
            font-size: 14px;
        }

        body.dark-mode .expert-option-card h4 {
            color: #8b9cff;
        }

        .expert-option-card label {
            display: flex;
            align-items: center;
            margin: 6px 0;
            cursor: pointer;
        }

        .expert-option-card label span {
            font-size: 13px;
            color: #333;
        }

        body.dark-mode .expert-option-card label span {
            color: #e0e0e0;
        }

        .expert-options-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-bottom: 15px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
        }

        body.dark-mode .expert-options-grid {
            background: #2d2d2d;
        }

        @media (max-width: 768px) {
            .nav-bar {
                flex-wrap: wrap;
                gap: 10px;
            }

            .nav-button {
                font-size: 12px;
                padding: 6px 12px;
            }
        }

        .user-section {
            display: flex;
            justify-content: flex-end;
            margin-top: 15px;
        }

        .user-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        #user-email {
            color: #666;
            font-size: 14px;
        }

        .user-plan {
            background: #667eea;
            color: white;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
        }

        .account-btn, .logout-btn, .login-btn, .register-btn {
            padding: 8px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.2s;
        }

        .account-btn {
            background: #667eea;
            color: white;
        }

        .account-btn:hover {
            background: #5568d3;
        }

        .logout-btn {
            background: #f0f0f0;
            color: #666;
        }

        .logout-btn:hover {
            background: #e0e0e0;
        }

        .login-btn {
            background: transparent;
            border: 2px solid #667eea;
            color: #667eea;
        }

        .login-btn:hover {
            background: #667eea;
            color: white;
        }

        .register-btn {
            background: #667eea;
            color: white;
        }

        .register-btn:hover {
            background: #5568d3;
        }

        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.7);
            align-items: center;
            justify-content: center;
        }

        .modal.active {
            display: flex;
        }

        .modal-content {
            background: white;
            padding: 40px;
            border-radius: 10px;
            max-width: 450px;
            width: 90%;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }

        .modal-content h2 {
            color: #667eea;
            margin-bottom: 20px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: #333;
            font-weight: 500;
        }

        .form-group input {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 5px;
            font-size: 14px;
        }

        .form-group input:focus {
            outline: none;
            border-color: #667eea;
        }

        .form-actions {
            display: flex;
            gap: 10px;
            margin-top: 25px;
        }

        .form-actions button {
            flex: 1;
            padding: 12px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.2s;
        }

        .btn-primary {
            background: #667eea;
            color: white;
        }

        .btn-primary:hover {
            background: #5568d3;
        }

        .btn-secondary {
            background: #f0f0f0;
            color: #666;
        }

        .btn-secondary:hover {
            background: #e0e0e0;
        }

        .error-message {
            background: #fee;
            color: #c33;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 15px;
            font-size: 14px;
        }

        .success-message {
            background: #efe;
            color: #3c3;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 15px;
            font-size: 14px;
        }

        .dashboard {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 30px;
        }

        .dashboard h2 {
            color: #667eea;
            margin-bottom: 20px;
        }

        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .dashboard-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }

        .dashboard-card h3 {
            color: #333;
            font-size: 14px;
            margin-bottom: 10px;
        }

        .dashboard-card .value {
            font-size: 32px;
            font-weight: bold;
            color: #667eea;
        }

        .dashboard-card .label {
            color: #666;
            font-size: 12px;
            margin-top: 5px;
        }

        .api-keys-section {
            margin-top: 30px;
        }

        .api-key-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .api-key-info {
            flex: 1;
        }

        .api-key-info strong {
            color: #333;
        }

        .api-key-info .key-prefix {
            font-family: monospace;
            color: #666;
            font-size: 12px;
        }

        .api-key-actions button {
            padding: 6px 12px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            margin-left: 5px;
        }

        .btn-danger {
            background: #dc3545;
            color: white;
        }

        .btn-danger:hover {
            background: #c82333;
        }

        /* Footer */
        .footer {
            background: white;
            padding: 40px 30px;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-top: 30px;
        }

        body.dark-mode .footer {
            background: #2d2d2d;
        }

        .footer-content {
            max-width: 1200px;
            margin: 0 auto;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 40px;
        }

        .footer-column {
            color: #666;
        }

        body.dark-mode .footer-column {
            color: #aaa;
        }

        .footer-title {
            color: #667eea;
            margin-bottom: 15px;
            font-size: 1.3em;
        }

        body.dark-mode .footer-title {
            color: #8b9cff;
        }

        .footer-heading {
            color: #667eea;
            margin-bottom: 15px;
            font-size: 1.1em;
        }

        body.dark-mode .footer-heading {
            color: #8b9cff;
        }

        .footer-text {
            line-height: 1.8;
            font-size: 0.9em;
            color: #666;
        }

        body.dark-mode .footer-text {
            color: #aaa;
        }

        .footer-copyright {
            color: #999;
            margin-top: 15px;
            font-size: 0.85em;
        }

        body.dark-mode .footer-copyright {
            color: #666;
        }

        .footer-links {
            list-style: none;
            padding: 0;
            margin: 0;
        }

        .footer-links li {
            margin: 8px 0;
        }

        .footer-links a {
            color: #666;
            text-decoration: none;
            transition: color 0.3s;
        }

        .footer-links a:hover {
            color: #667eea;
        }

        body.dark-mode .footer-links a {
            color: #aaa;
        }

        body.dark-mode .footer-links a:hover {
            color: #8b9cff;
        }

        .footer-links span {
            color: #666;
        }

        body.dark-mode .footer-links span {
            color: #888;
        }

        .footer-bottom {
            border-top: 1px solid #e0e0e0;
            margin-top: 30px;
            padding-top: 20px;
            text-align: center;
            color: #999;
            font-size: 0.85em;
        }

        body.dark-mode .footer-bottom {
            border-top-color: #444;
            color: #666;
        }

        .footer-company-link {
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
            transition: color 0.3s;
        }

        .footer-company-link:hover {
            color: #764ba2;
        }

        body.dark-mode .footer-company-link {
            color: #8b9cff;
        }

        body.dark-mode .footer-company-link:hover {
            color: #a78bfa;
        }

        /* Valuation and Result Cards */
        .valuation-stat-card {
            text-align: center;
            padding: 15px;
            background: white;
            border-radius: 8px;
        }

        body.dark-mode .valuation-stat-card {
            background: #2d2d2d;
        }

        .valuation-stat-label {
            color: #666;
            font-size: 12px;
        }

        body.dark-mode .valuation-stat-label {
            color: #aaa;
        }

        .valuation-stat-value {
            font-size: 20px;
            font-weight: bold;
            margin-top: 5px;
            color: #667eea;
        }

        body.dark-mode .valuation-stat-value {
            color: #8b9cff;
        }

        .valuation-stat-subvalue {
            color: #888;
            font-size: 14px;
            margin-top: 5px;
        }

        body.dark-mode .valuation-stat-subvalue {
            color: #aaa;
        }

        .valuation-score-card {
            text-align: center;
            padding: 15px;
            background: white;
            border-radius: 8px;
        }

        body.dark-mode .valuation-score-card {
            background: #2d2d2d;
        }

        .valuation-breakdown-summary {
            cursor: pointer;
            font-weight: bold;
            padding: 10px;
            background: white;
            border-radius: 5px;
        }

        body.dark-mode .valuation-breakdown-summary {
            background: #2d2d2d;
            color: #e0e0e0;
        }

        .valuation-breakdown-content {
            margin-top: 10px;
            padding: 15px;
            background: white;
            border-radius: 5px;
        }

        body.dark-mode .valuation-breakdown-content {
            background: #1a1a1a;
            color: #e0e0e0;
        }

        .valuation-score-row {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #eee;
        }

        body.dark-mode .valuation-score-row {
            border-bottom-color: #444;
        }

        .valuation-score-label {
            color: #333;
        }

        body.dark-mode .valuation-score-label {
            color: #e0e0e0;
        }

        .valuation-score-value {
            font-weight: bold;
        }

    </style>
    <link rel="stylesheet" href="/static/css/live-stats.css?v={{ cache_bust.css.live_stats }}">
    <script src="/static/js/live-stats.js?v={{ cache_bust.js.live_stats }}" defer></script>
    <script src="/static/js/threat-feed.js?v={{ cache_bust.js.threat_feed }}" defer></script>
</head>
<body>
    <!-- Theme Toggle -->
    <div id="themeToggle" class="theme-toggle">
        <span class="sun">☀️</span>
        <span class="moon">🌙</span>
    </div>
    <div class="container">
        <!-- Navigation Bar -->
        <div class="nav-bar">
            <a href="/about" class="nav-button">About Us</a>
            <a href="/explorer" class="nav-button">Data Explorer</a>
            <a href="/tools" class="nav-button">🔧 Tools</a>
            <a href="/registrar" class="nav-button">Registrar</a>
            <a href="/pricing" class="nav-button">Pricing</a>
            <div class="nav-dropdown">
                <span class="nav-button">Docs</span>
                <div class="nav-dropdown-content">
                    <a href="/docs/api">API Docs</a>
                    <a href="/docs/cli">CLI Docs</a>
                    <a href="/docs/architecture">Architecture</a>
                </div>
            </div>
            <a href="/login" class="nav-button" id="nav-login">Login</a>
            <a href="/signup" class="nav-button primary" id="nav-signup">Sign Up</a>
            <div id="nav-user-info" style="display: none; margin-left: auto; align-items: center; gap: 10px;">
                <span id="nav-user-email" style="color: white; font-size: 14px;"></span>
                <span class="user-plan" id="nav-user-plan"></span>
                <button onclick="showAccountDashboard()" class="nav-button" style="padding: 6px 12px; font-size: 12px;">Account</button>
                <button onclick="logoutUser()" class="nav-button" style="padding: 6px 12px; font-size: 12px; background: #dc3545;">Logout</button>
            </div>
        </div>

        <header>
            <h1>🔒 DNS Science</h1>
            <p class="subtitle">Email Security, IP, and DNS Research Tool - Track DNSSEC, SPF, SenderID, DMARC, DKIM, MTA-STS, and SMTP STARTTLS</p>
        
            <div class="stats-display" style="text-align: right; color: #667eea; font-weight: bold;">
                Monitoring <span id="total-domains">...</span> domains and <span id="total-ssl-certs">...</span> SSL Certificates
            </div>
        </div>
        </header>

        <div class="search-section">
            <div class="tabs">
                <button class="tab active" onclick="switchTab('scan')">Scan Domain</button>
                <button class="tab" onclick="switchTab('ipscan')">Scan IP</button>
                <button class="tab" onclick="switchTab('globallookup')">Global Lookup</button>
                <button class="tab" onclick="switchTab('register')">Register Domain</button>
                <button class="tab" onclick="switchTab('search')">Scan History</button>
                <button class="tab" onclick="switchTab('myscans')">My Scans</button>
            </div>

            <div id="scan-tab" class="tab-content active">
                <h2>Scan a Domain</h2>

                <!-- Mode Selection Buttons -->
                <div style="margin-bottom: 15px;">
                    <button onclick="toggleDomainScanMode('simple')" id="domain-simple-mode-btn" class="mode-btn active" style="background: #667eea; padding: 8px 16px; margin-right: 10px;">
                        Simple Mode
                    </button>
                    <button onclick="toggleDomainScanMode('advanced')" id="domain-advanced-mode-btn" class="mode-btn" style="background: #764ba2; padding: 8px 16px; margin-right: 10px;">
                        Advanced Mode
                    </button>
                    <button onclick="toggleDomainScanMode('expert')" id="domain-expert-mode-btn" class="mode-btn" style="background: #e74c3c; padding: 8px 16px;">
                        🎯 Expert Mode
                    </button>
                </div>

                <!-- Simple Mode -->
                <div id="simple-domain-mode" class="domain-scan-mode">
                    <form class="search-form" onsubmit="scanDomain(event, 'simple')">
                        <input type="text" id="domain-input-simple" placeholder="Enter domain (e.g., example.com)" required>
                        <button type="submit" id="scan-button-simple">Scan Domain</button>
                    </form>
                    <div style="margin-top: 10px; font-size: 13px; color: #666; padding: 10px; background: #f8f9fa; border-radius: 5px;">
                        <strong>Quick Scan:</strong> DNS records, WHOIS, SSL certificate, basic security checks
                    </div>
                </div>

                <!-- Advanced Mode -->
                <div id="advanced-domain-mode" class="domain-scan-mode" style="display: none;">
                    <form class="search-form" onsubmit="scanDomain(event, 'advanced')">
                        <input type="text" id="domain-input-advanced" placeholder="Enter domain (e.g., example.com)" required>
                        <button type="submit" id="scan-button-advanced">Advanced Scan</button>
                    </form>
                    <div style="margin-top: 10px; font-size: 13px; color: #666; padding: 10px; background: #f8f9fa; border-radius: 5px;">
                        <strong>Advanced Scan:</strong> Full DNS analysis, DNSSEC validation, SSL/TLS deep scan, subdomain enumeration, email security (SPF/DKIM/DMARC), threat intelligence
                    </div>
                </div>

                <!-- Expert Mode -->
                <div id="expert-domain-mode" class="domain-scan-mode" style="display: none;">
                    <form class="search-form" onsubmit="scanDomain(event, 'expert')" style="display: block;">
                        <input type="text" id="domain-input-expert" placeholder="Enter domain (e.g., example.com)" required style="width: 100%; margin-bottom: 15px;">

                        <div class="expert-options-grid">
                            <div class="expert-option-card">
                                <h4>🌐 DNS Analysis</h4>
                                <label>
                                    <input type="checkbox" class="expert-domain-option" data-category="dns" value="records" checked style="margin-right: 8px;">
                                    <span>All DNS Records (A/AAAA/MX/TXT/etc)</span>
                                </label>
                                <label>
                                    <input type="checkbox" class="expert-domain-option" data-category="dns" value="dnssec" checked style="margin-right: 8px;">
                                    <span>DNSSEC Validation (Unbound)</span>
                                </label>
                                <label>
                                    <input type="checkbox" class="expert-domain-option" data-category="dns" value="propagation" checked style="margin-right: 8px;">
                                    <span>Global DNS Propagation Check</span>
                                </label>
                                <label>
                                    <input type="checkbox" class="expert-domain-option" data-category="dns" value="subdomains" style="margin-right: 8px;">
                                    <span>Subdomain Enumeration</span>
                                </label>
                            </div>

                            <div class="expert-option-card">
                                <h4>🔒 Security & SSL</h4>
                                <label>
                                    <input type="checkbox" class="expert-domain-option" data-category="security" value="ssl" checked style="margin-right: 8px;">
                                    <span>SSL/TLS Certificate Analysis</span>
                                </label>
                                <label>
                                    <input type="checkbox" class="expert-domain-option" data-category="security" value="ssl-chain" checked style="margin-right: 8px;">
                                    <span>Certificate Chain Validation</span>
                                </label>
                                <label>
                                    <input type="checkbox" class="expert-domain-option" data-category="security" value="cipher-suites" style="margin-right: 8px;">
                                    <span>Cipher Suite Analysis</span>
                                </label>
                                <label>
                                    <input type="checkbox" class="expert-domain-option" data-category="security" value="cert-transparency" checked style="margin-right: 8px;">
                                    <span>Certificate Transparency Logs</span>
                                </label>
                            </div>

                            <div class="expert-option-card">
                                <h4>📧 Email Security</h4>
                                <label>
                                    <input type="checkbox" class="expert-domain-option" data-category="email" value="spf" checked style="margin-right: 8px;">
                                    <span>SPF Record Analysis</span>
                                </label>
                                <label>
                                    <input type="checkbox" class="expert-domain-option" data-category="email" value="dkim" checked style="margin-right: 8px;">
                                    <span>DKIM Configuration</span>
                                </label>
                                <label>
                                    <input type="checkbox" class="expert-domain-option" data-category="email" value="dmarc" checked style="margin-right: 8px;">
                                    <span>DMARC Policy Check</span>
                                </label>
                                <label>
                                    <input type="checkbox" class="expert-domain-option" data-category="email" value="mx-health" checked style="margin-right: 8px;">
                                    <span>MX Server Health Check</span>
                                </label>
                            </div>

                            <div class="expert-option-card">
                                <h4>🔍 Intelligence & WHOIS</h4>
                                <label>
                                    <input type="checkbox" class="expert-domain-option" data-category="intel" value="whois" checked style="margin-right: 8px;">
                                    <span>WHOIS/RDAP Lookup</span>
                                </label>
                                <label>
                                    <input type="checkbox" class="expert-domain-option" data-category="intel" value="reputation" checked style="margin-right: 8px;">
                                    <span>Domain Reputation Score</span>
                                </label>
                                <label>
                                    <input type="checkbox" class="expert-domain-option" data-category="intel" value="threat" checked style="margin-right: 8px;">
                                    <span>Threat Intelligence Feeds</span>
                                </label>
                                <label>
                                    <input type="checkbox" class="expert-domain-option" data-category="intel" value="blockchain" style="margin-right: 8px;">
                                    <span>Blockchain DNS (.eth/.crypto)</span>
                                </label>
                            </div>
                        </div>

                        <div style="display: flex; gap: 10px; align-items: center;">
                            <button type="submit" id="scan-button-expert" style="flex: 1;">Run Expert Scan</button>
                            <button type="button" onclick="selectAllDomainExpertOptions()" style="background: #95a5a6; padding: 12px 20px;">Select All</button>
                            <button type="button" onclick="deselectAllDomainExpertOptions()" style="background: #95a5a6; padding: 12px 20px;">Clear All</button>
                        </div>
                    </form>
                    <div style="margin-top: 10px; font-size: 12px; color: #999; padding: 10px; background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 5px;">
                        <strong>⚡ Expert Mode:</strong> Full control over DNS analysis with Unbound DNSSEC validation, comprehensive security scans, and threat intelligence.
                        Anonymous users: 5 expert scans per session. <a href="/login" style="color: #667eea; font-weight: 500;">Login</a> for unlimited access.
                    </div>
                </div>

                <div id="status" class="status"></div>
            </div>

            <div id="ipscan-tab" class="tab-content">
                <h2>Scan an IP Address</h2>

                <!-- Mode Selection Buttons -->
                <div style="margin-bottom: 15px;">
                    <button onclick="toggleIPScanMode('simple')" id="ip-simple-mode-btn" class="mode-btn active" style="background: #667eea; padding: 8px 16px; margin-right: 10px;">
                        Simple Mode
                    </button>
                    <button onclick="toggleIPScanMode('advanced')" id="ip-advanced-mode-btn" class="mode-btn" style="background: #764ba2; padding: 8px 16px; margin-right: 10px;">
                        Advanced Mode
                    </button>
                    <button onclick="toggleIPScanMode('expert')" id="ip-expert-mode-btn" class="mode-btn" style="background: #e74c3c; padding: 8px 16px;">
                        🎯 Expert Mode
                    </button>
                </div>

                <!-- Simple Mode -->
                <div id="simple-ip-mode" class="ip-scan-mode">
                    <form class="search-form" onsubmit="scanIP(event, 'simple')">
                        <input type="text" id="ip-input-simple" placeholder="Enter IP address (e.g., 8.8.8.8)" required>
                        <button type="submit" id="ip-scan-button-simple">Scan IP</button>
                    </form>
                    <div style="margin-top: 10px; font-size: 13px; color: #666; padding: 10px; background: #f8f9fa; border-radius: 5px;">
                        <strong>Quick Scan:</strong> Basic geolocation, ASN, and RBL checks
                    </div>
                </div>

                <!-- Advanced Mode -->
                <div id="advanced-ip-mode" class="ip-scan-mode" style="display: none;">
                    <form class="search-form" onsubmit="scanIP(event, 'advanced')">
                        <input type="text" id="ip-input-advanced" placeholder="Enter IP address or CIDR (e.g., 192.168.1.0/24)" required>
                        <button type="submit" id="ip-scan-button-advanced">Advanced Scan</button>
                    </form>
                    <div style="margin-top: 10px; font-size: 13px; color: #666; padding: 10px; background: #f8f9fa; border-radius: 5px;">
                        <strong>Advanced Scan:</strong> Includes Cloudflare DNS intelligence, privacy detection, enhanced BGP analysis, comprehensive RBL checks
                        <br>
                        <strong>Note:</strong> CIDR ranges limited to /24 (256 IPs) for anonymous users. <a href="/login" style="color: #667eea;">Login</a> to scan larger ranges.
                    </div>
                </div>

                <!-- Expert Mode -->
                <div id="expert-ip-mode" class="ip-scan-mode" style="display: none;">
                    <form class="search-form" onsubmit="scanIP(event, 'expert')" style="display: block;">
                        <input type="text" id="ip-input-expert" placeholder="Enter IP address or CIDR range" required style="width: 100%; margin-bottom: 15px;">

                        <div class="expert-options-grid">
                            <div class="expert-option-card">
                                <h4>🌍 Geolocation & Network</h4>
                                <label>
                                    <input type="checkbox" class="expert-option" data-category="geo" value="ipinfo" checked style="margin-right: 8px;">
                                    <span>IPInfo.io (Geo, ASN, Company)</span>
                                </label>
                                <label>
                                    <input type="checkbox" class="expert-option" data-category="geo" value="maxmind" checked style="margin-right: 8px;">
                                    <span>MaxMind GeoIP</span>
                                </label>
                                <label>
                                    <input type="checkbox" class="expert-option" data-category="geo" value="bgp" checked style="margin-right: 8px;">
                                    <span>BGP/ASN Analysis</span>
                                </label>
                                <label>
                                    <input type="checkbox" class="expert-option" data-category="geo" value="ripestat" checked style="margin-right: 8px;">
                                    <span>RIPEstat Intelligence</span>
                                </label>
                            </div>

                            <div class="expert-option-card">
                                <h4>🛡️ Security & Reputation</h4>
                                <label>
                                    <input type="checkbox" class="expert-option" data-category="security" value="abuseipdb" checked style="margin-right: 8px;">
                                    <span>AbuseIPDB</span>
                                </label>
                                <label>
                                    <input type="checkbox" class="expert-option" data-category="security" value="rbl" checked style="margin-right: 8px;">
                                    <span>RBL/DNSBL Checks (60+ lists)</span>
                                </label>
                                <label>
                                    <input type="checkbox" class="expert-option" data-category="security" value="threatintel" checked style="margin-right: 8px;">
                                    <span>Threat Intelligence Feeds</span>
                                </label>
                                <label>
                                    <input type="checkbox" class="expert-option" data-category="security" value="shodan" style="margin-right: 8px;">
                                    <span>Shodan Port Scan</span>
                                </label>
                            </div>

                            <div class="expert-option-card">
                                <h4>🔍 Advanced Analysis</h4>
                                <label>
                                    <input type="checkbox" class="expert-option" data-category="advanced" value="cloudflare" checked style="margin-right: 8px;">
                                    <span>Cloudflare Intelligence</span>
                                </label>
                                <label>
                                    <input type="checkbox" class="expert-option" data-category="advanced" value="privacy" checked style="margin-right: 8px;">
                                    <span>Privacy/VPN/Proxy Detection</span>
                                </label>
                                <label>
                                    <input type="checkbox" class="expert-option" data-category="advanced" value="reverse-dns" checked style="margin-right: 8px;">
                                    <span>Reverse DNS Lookup</span>
                                </label>
                                <label>
                                    <input type="checkbox" class="expert-option" data-category="advanced" value="whois" checked style="margin-right: 8px;">
                                    <span>WHOIS/RDAP Data</span>
                                </label>
                            </div>

                            <div class="expert-option-card">
                                <h4>⚙️ Scan Options</h4>
                                <label>
                                    <input type="checkbox" class="expert-option" data-category="options" value="ports" style="margin-right: 8px;">
                                    <span>Port Scan (Top 100)</span>
                                </label>
                                <label>
                                    <input type="checkbox" class="expert-option" data-category="options" value="traceroute" style="margin-right: 8px;">
                                    <span>Traceroute</span>
                                </label>
                                <label>
                                    <input type="checkbox" class="expert-option" data-category="options" value="ssl-check" style="margin-right: 8px;">
                                    <span>SSL/TLS Certificate Check</span>
                                </label>
                                <label>
                                    <input type="checkbox" class="expert-option" data-category="options" value="deep-scan" style="margin-right: 8px;">
                                    <span>Deep Historical Analysis</span>
                                </label>
                            </div>
                        </div>

                        <div style="display: flex; gap: 10px; align-items: center;">
                            <button type="submit" id="ip-scan-button-expert" style="flex: 1;">Run Expert Scan</button>
                            <button type="button" onclick="selectAllExpertOptions()" style="background: #95a5a6; padding: 12px 20px;">Select All</button>
                            <button type="button" onclick="deselectAllExpertOptions()" style="background: #95a5a6; padding: 12px 20px;">Clear All</button>
                        </div>
                    </form>
                    <div style="margin-top: 10px; font-size: 12px; color: #999; padding: 10px; background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 5px;">
                        <strong>⚡ Expert Mode:</strong> Customize exactly which intelligence sources and scans to run. Some options require login.
                        Anonymous users: 5 expert scans per session. <a href="/login" style="color: #667eea; font-weight: 500;">Login</a> for unlimited access.
                    </div>
                </div>

                <div id="ip-status" class="status"></div>
                <div id="ip-results" class="results-section"></div>
            </div>

            <div id="globallookup-tab" class="tab-content">
                <h2>Global DNS Lookup</h2>
                <div style="margin-bottom: 15px;">
                    <button onclick="toggleGlobalLookupMode('simple')" id="simple-mode-btn" class="mode-btn active" style="background: #667eea; padding: 8px 16px; margin-right: 10px;">
                        Simple Mode
                    </button>
                    <button onclick="toggleGlobalLookupMode('advanced')" id="advanced-mode-btn" class="mode-btn" style="background: #764ba2; padding: 8px 16px;">
                        Advanced Mode
                    </button>
                </div>

                <!-- Simple Mode -->
                <div id="simple-lookup-mode" class="lookup-mode">
                    <form class="search-form" onsubmit="performGlobalLookup(event, 'simple')">
                        <input type="text" id="global-lookup-input" placeholder="Enter domain or IP address (e.g., example.com or 8.8.8.8)" required>
                        <button type="submit" id="global-lookup-button">Lookup</button>
                    </form>
                </div>

                <!-- Advanced Mode -->
                <div id="advanced-lookup-mode" class="lookup-mode" style="display: none;">
                    <form class="search-form" onsubmit="performGlobalLookup(event, 'advanced')" style="display: grid; grid-template-columns: 2fr 1.5fr 1fr auto; gap: 10px;">
                        <input type="text" id="advanced-lookup-input" placeholder="Enter domain or IP address" required>
                        <select id="location-filter" style="padding: 12px; border: 2px solid #ddd; border-radius: 8px; font-size: 16px;">
                            <option value="">All Locations</option>
                            <option value="US">United States</option>
                            <option value="GB">United Kingdom</option>
                            <option value="DE">Germany</option>
                            <option value="FR">France</option>
                            <option value="CA">Canada</option>
                            <option value="AU">Australia</option>
                            <option value="JP">Japan</option>
                            <option value="CN">China</option>
                            <option value="BR">Brazil</option>
                            <option value="IN">India</option>
                            <option value="RU">Russia</option>
                            <option value="KR">South Korea</option>
                            <option value="SG">Singapore</option>
                            <option value="NL">Netherlands</option>
                        </select>
                        <select id="resolver-limit" style="padding: 12px; border: 2px solid #ddd; border-radius: 8px; font-size: 16px;">
                            <option value="10">10 resolvers</option>
                            <option value="25">25 resolvers</option>
                            <option value="50" selected>50 resolvers</option>
                            <option value="100">100 resolvers</option>
                            <option value="250">250 resolvers</option>
                            <option value="0">All resolvers</option>
                        </select>
                        <button type="submit" id="advanced-lookup-button">Lookup</button>
                    </form>
                </div>

                <div id="global-lookup-status" class="status"></div>
                <div id="global-lookup-progress" style="display: none; margin-top: 10px;">
                    <div style="background: #f0f0f0; border-radius: 8px; padding: 15px; margin-bottom: 15px;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                            <span id="progress-text" style="font-weight: bold;">Scanned 0 of 0 resolvers</span>
                            <span id="progress-percent" style="color: #667eea; font-weight: bold;">0%</span>
                        </div>
                        <div style="background: #ddd; border-radius: 10px; height: 20px; overflow: hidden;">
                            <div id="progress-bar" style="background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); height: 100%; width: 0%; transition: width 0.3s;"></div>
                        </div>
                    </div>
                </div>
                <div id="global-lookup-results" class="results-section"></div>
            </div>

            <div id="search-tab" class="tab-content">
                <h2>Scan History - All Platform Scans</h2>
                <div style="margin-bottom: 15px;">
                    <button onclick="toggleAdvancedSearch()" style="background: #764ba2; padding: 8px 16px;">
                        Advanced Search
                    </button>
                </div>
                <div id="advanced-search" style="display: none; background: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 15px;">
                    <h3 style="margin-bottom: 10px; font-size: 16px;">Advanced Filters</h3>
                    <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; margin-bottom: 10px;">
                        <div>
                            <label style="display: block; margin-bottom: 5px; font-size: 14px;">gTLD</label>
                            <select id="gtld-filter" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 5px;">
                                <option value="">All gTLDs</option>
                                <option value="com">com</option>
                                <option value="net">net</option>
                                <option value="org">org</option>
                                <option value="edu">edu</option>
                                <option value="gov">gov</option>
                                <option value="io">io</option>
                                <option value="ai">ai</option>
                                <option value="app">app</option>
                            </select>
                        </div>
                        <div>
                            <label style="display: block; margin-bottom: 5px; font-size: 14px;">ccTLD</label>
                            <select id="cctld-filter" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 5px;">
                                <option value="">All ccTLDs</option>
                                <option value="uk">uk</option>
                                <option value="de">de</option>
                                <option value="fr">fr</option>
                                <option value="ca">ca</option>
                                <option value="au">au</option>
                                <option value="jp">jp</option>
                                <option value="cn">cn</option>
                            </select>
                        </div>
                        <div>
                            <label style="display: block; margin-bottom: 5px; font-size: 14px;">Country</label>
                            <select id="country-filter" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 5px;">
                                <option value="">All Countries</option>
                                <option value="US">United States</option>
                                <option value="GB">United Kingdom</option>
                                <option value="DE">Germany</option>
                                <option value="FR">France</option>
                                <option value="CA">Canada</option>
                                <option value="AU">Australia</option>
                                <option value="JP">Japan</option>
                                <option value="CN">China</option>
                            </select>
                        </div>
                    </div>
                </div>
                <form class="search-form" onsubmit="searchDomains(event)">
                    <input type="text" id="search-input" placeholder="Search all scanned domains...">
                    <button type="submit">Search</button>
                </form>
                <div id="search-results" class="search-results"></div>
                <div id="search-pagination" style="text-align: center; margin-top: 20px;"></div>
            </div>

            <div id="myscans-tab" class="tab-content">
                <h2>My Scans - Domains I've Scanned</h2>
                <form class="search-form" onsubmit="searchMyScans(event)">
                    <input type="text" id="myscans-input" placeholder="Search my scans...">
                    <button type="submit">Search</button>
                </form>
                <div id="myscans-results" class="search-results"></div>
            </div>

            <div id="register-tab" class="tab-content">
                <h2>Register a New Domain</h2>
                <p style="color: #666; margin-bottom: 20px;">Search for and register your perfect domain name through our OpenSRS partnership</p>

                <form class="search-form" onsubmit="searchDomainAvailability(event)">
                    <input type="text" id="domain-register-input" placeholder="Enter domain name (e.g., mycompany.com)" required>
                    <button type="submit" id="domain-search-button">Check Availability</button>
                </form>

                <div id="domain-search-status" class="status"></div>
                <div id="domain-search-results" class="results-section"></div>
            </div>
        </div>

        <!-- Statistics Dashboard Section -->
        <div class="search-section" style="margin-top: 30px;">
            <h2 style="margin-bottom: 20px;">Platform Statistics Dashboard</h2>

            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px;">
                <!-- Total Market Value Card -->
                <div class="dashboard-card-gradient" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 10px; color: white;">
                    <h3 style="font-size: 16px; margin-bottom: 10px; opacity: 0.9;">Total Market Value</h3>
                    <div style="font-size: 32px; font-weight: bold;" id="total-market-value">Loading...</div>
                    <div style="font-size: 12px; margin-top: 5px; opacity: 0.8;" id="valued-domains-count"></div>
                </div>

                <!-- Domains Added Card -->
                <div class="dashboard-card-gradient" style="background: linear-gradient(135deg, #8b9cff 0%, #667eea 100%); padding: 20px; border-radius: 10px; color: white;">
                    <h3 style="font-size: 16px; margin-bottom: 10px; opacity: 0.9;">Domains Added Today</h3>
                    <div style="font-size: 32px; font-weight: bold;" id="domains-added-today">Loading...</div>
                    <div style="font-size: 12px; margin-top: 5px; opacity: 0.8;" id="domains-added-stats">This week: - | This month: -</div>
                </div>

                <!-- Domain Status Card -->
                <div class="dashboard-card-gradient" style="background: linear-gradient(135deg, #764ba2 0%, #667eea 100%); padding: 20px; border-radius: 10px; color: white;">
                    <h3 style="font-size: 16px; margin-bottom: 10px; opacity: 0.9;">Domain Status</h3>
                    <div id="domain-status-chart" style="font-size: 14px;">Loading...</div>
                </div>
            </div>

            <!-- Charts Row -->
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px;">
                <!-- TLD Distribution Chart -->
                <div class="dashboard-card-chart" style="background: white; padding: 20px; border-radius: 10px; border: 1px solid #e0e0e0;">
                    <h3 style="font-size: 18px; margin-bottom: 15px;">Top TLD Distribution</h3>
                    <canvas id="tld-chart" style="max-height: 300px;"></canvas>
                </div>

                <!-- Expiration Timeline Chart -->
                <div class="dashboard-card-chart" style="background: white; padding: 20px; border-radius: 10px; border: 1px solid #e0e0e0;">
                    <h3 style="font-size: 18px; margin-bottom: 15px;">Domains Pending Expiration</h3>
                    <canvas id="expiration-chart" style="max-height: 300px;"></canvas>
                </div>
            </div>
        </div>

        <!-- Quick Glance Security Stats - Draggable -->
        <div class="search-section" style="margin-top: 30px;">
            <h2 style="margin-bottom: 10px;">Security Quick Glance</h2>
            <p style="color: #666; font-size: 14px; margin-bottom: 20px;">
                <span style="opacity: 0.7;">💡 Drag and drop tiles to rearrange</span>
            </p>

            <div id="quick-glance-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                <!-- DNSSEC Card -->
                <div class="glance-card" data-stat="dnssec" style="background: white; padding: 15px; border-radius: 8px; border: 2px solid #e0e0e0; cursor: move; transition: all 0.3s;">
                    <div style="font-size: 12px; color: #667eea; font-weight: bold; margin-bottom: 5px;">🔒 DNSSEC</div>
                    <div style="font-size: 28px; font-weight: bold; color: #333;" id="stat-dnssec">-</div>
                    <div style="font-size: 11px; color: #999; margin-top: 3px;" id="stat-dnssec-pct">-%</div>
                </div>

                <!-- DMARC Card -->
                <div class="glance-card" data-stat="dmarc" style="background: white; padding: 15px; border-radius: 8px; border: 2px solid #e0e0e0; cursor: move; transition: all 0.3s;">
                    <div style="font-size: 12px; color: #667eea; font-weight: bold; margin-bottom: 5px;">📧 DMARC</div>
                    <div style="font-size: 28px; font-weight: bold; color: #333;" id="stat-dmarc">-</div>
                    <div style="font-size: 11px; color: #999; margin-top: 3px;" id="stat-dmarc-pct">-%</div>
                </div>

                <!-- DANE Card -->
                <div class="glance-card" data-stat="dane" style="background: white; padding: 15px; border-radius: 8px; border: 2px solid #e0e0e0; cursor: move; transition: all 0.3s;">
                    <div style="font-size: 12px; color: #667eea; font-weight: bold; margin-bottom: 5px;">🛡️ DANE</div>
                    <div style="font-size: 28px; font-weight: bold; color: #333;" id="stat-dane">-</div>
                    <div style="font-size: 11px; color: #999; margin-top: 3px;" id="stat-dane-pct">-%</div>
                </div>

                <!-- MTA-STS Card -->
                <div class="glance-card" data-stat="mta-sts" style="background: white; padding: 15px; border-radius: 8px; border: 2px solid #e0e0e0; cursor: move; transition: all 0.3s;">
                    <div style="font-size: 12px; color: #667eea; font-weight: bold; margin-bottom: 5px;">📮 MTA-STS</div>
                    <div style="font-size: 28px; font-weight: bold; color: #333;" id="stat-mta-sts">-</div>
                    <div style="font-size: 11px; color: #999; margin-top: 3px;" id="stat-mta-sts-pct">-%</div>
                </div>

                <!-- TLSA Card -->
                <div class="glance-card" data-stat="tlsa" style="background: white; padding: 15px; border-radius: 8px; border: 2px solid #e0e0e0; cursor: move; transition: all 0.3s;">
                    <div style="font-size: 12px; color: #667eea; font-weight: bold; margin-bottom: 5px;">🔐 TLSA</div>
                    <div style="font-size: 28px; font-weight: bold; color: #333;" id="stat-tlsa">-</div>
                    <div style="font-size: 11px; color: #999; margin-top: 3px;" id="stat-tlsa-pct">-%</div>
                </div>

                <!-- IPs by Country Card -->
                <div class="glance-card" data-stat="geoip" style="background: white; padding: 15px; border-radius: 8px; border: 2px solid #e0e0e0; cursor: move; transition: all 0.3s; grid-column: span 2;">
                    <div style="font-size: 12px; color: #667eea; font-weight: bold; margin-bottom: 10px;">🌍 IPs by Country</div>
                    <canvas id="geoip-chart" style="max-height: 150px;"></canvas>
                </div>
            </div>
        </div>

        <div id="results" class="results-section"></div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/sortablejs@1.15.0/Sortable.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script>
        let currentDomain = null;
        let currentSearchPage = 1;
        let tldChart = null;
        let expirationChart = null;
        let geoipChart = null;

        function switchTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

            if (tab === 'scan') {
                document.querySelector('[onclick="switchTab(\'scan\')"]').classList.add('active');
                document.getElementById('scan-tab').classList.add('active');
            } else if (tab === 'ipscan') {
                document.querySelector('[onclick="switchTab(\'ipscan\')"]').classList.add('active');
                document.getElementById('ipscan-tab').classList.add('active');
            } else if (tab === 'globallookup') {
                document.querySelector('[onclick="switchTab(\'globallookup\')"]').classList.add('active');
                document.getElementById('globallookup-tab').classList.add('active');
            } else if (tab === 'register') {
                document.querySelector('[onclick="switchTab(\'register\')"]').classList.add('active');
                document.getElementById('register-tab').classList.add('active');
            } else if (tab === 'search') {
                document.querySelector('[onclick="switchTab(\'search\')"]').classList.add('active');
                document.getElementById('search-tab').classList.add('active');
                loadAllDomains();
            } else if (tab === 'myscans') {
                document.querySelector('[onclick="switchTab(\'myscans\')"]').classList.add('active');
                document.getElementById('myscans-tab').classList.add('active');
                loadMyScans();
            }
        }

        function showStatus(message, type) {
            const statusEl = document.getElementById('status');
            statusEl.textContent = message;
            statusEl.className = `status ${type}`;
            statusEl.style.display = 'block';
        }

        async function scanDomain(event, mode = 'simple') {
            event.preventDefault();

            // Get domain input based on mode
            const domainInputId = mode === 'expert' ? 'domain-input-expert' : (mode === 'advanced' ? 'domain-input-advanced' : 'domain-input-simple');
            const buttonId = mode === 'expert' ? 'scan-button-expert' : (mode === 'advanced' ? 'scan-button-advanced' : 'scan-button-simple');

            const domain = document.getElementById(domainInputId).value.trim().toLowerCase();
            const button = document.getElementById(buttonId);

            // Collect expert options if in expert mode
            const expertOptions = {};
            if (mode === 'expert') {
                document.querySelectorAll('.expert-domain-option:checked').forEach(checkbox => {
                    const category = checkbox.dataset.category;
                    const value = checkbox.value;
                    if (!expertOptions[category]) expertOptions[category] = [];
                    expertOptions[category].push(value);
                });
            }

            button.disabled = true;
            button.innerHTML = '<span class="loading-spinner"></span> Scanning...';
            const scanMessage = mode === 'expert'
                ? `Running expert scan with ${Object.values(expertOptions).flat().length} selected checks...`
                : (mode === 'advanced' ? 'Starting advanced scan with full DNS analysis...' : 'Starting scan...');
            showStatus(scanMessage, 'loading');
            document.getElementById('results').style.display = 'none';

            try {
                // Build request body
                const requestBody = { domain };
                if (mode === 'advanced') {
                    requestBody.advanced = true;
                } else if (mode === 'expert') {
                    requestBody.expert = true;
                    requestBody.options = expertOptions;
                }

                // Queue the scan
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(requestBody)
                });

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.error || 'Scan failed');
                }

                // Poll for results
                const jobId = data.job_id;
                showStatus(`Scan queued. Waiting for results...`, 'loading');

                const result = await pollScanStatus(jobId, domain);

                if (result) {
                    showStatus('Scan completed successfully!', 'success');
                    currentDomain = domain;
                    displayResults(result);
                    loadHistory(domain);
                } else {
                    throw new Error('Scan timed out or failed');
                }

            } catch (error) {
                showStatus(`Error: ${error.message}`, 'error');
            } finally {
                button.disabled = false;
                button.textContent = 'Scan';
            }
        }

        async function pollScanStatus(jobId, domain) {
            const maxAttempts = 60; // Poll for up to 60 seconds
            const pollInterval = 1000; // Poll every 1 second

            for (let attempt = 0; attempt < maxAttempts; attempt++) {
                try {
                    const response = await fetch(`/api/scan/status/${jobId}`);
                    const data = await response.json();

                    if (data.status === 'completed' && data.result) {
                        return data.result;
                    } else if (data.status === 'failed') {
                        throw new Error(data.error || 'Scan failed');
                    } else if (data.status === 'processing') {
                        showStatus(`Scanning ${domain}... (${attempt + 1}s)`, 'loading');
                    }

                    // Wait before next poll
                    await new Promise(resolve => setTimeout(resolve, pollInterval));
                } catch (error) {
                    if (attempt === maxAttempts - 1) {
                        throw error;
                    }
                    // Continue polling on transient errors
                    await new Promise(resolve => setTimeout(resolve, pollInterval));
                }
            }

            return null; // Timeout
        }

        async function scanIP(event, mode = 'simple') {
            event.preventDefault();

            // Get IP input based on mode
            const ipInputId = mode === 'expert' ? 'ip-input-expert' : (mode === 'advanced' ? 'ip-input-advanced' : 'ip-input-simple');
            const buttonId = mode === 'expert' ? 'ip-scan-button-expert' : (mode === 'advanced' ? 'ip-scan-button-advanced' : 'ip-scan-button-simple');

            const ipInput = document.getElementById(ipInputId).value.trim();
            const button = document.getElementById(buttonId);
            const statusEl = document.getElementById('ip-status');
            const resultsEl = document.getElementById('ip-results');

            // Collect expert options if in expert mode
            const expertOptions = {};
            if (mode === 'expert') {
                document.querySelectorAll('.expert-option:checked').forEach(checkbox => {
                    const category = checkbox.dataset.category;
                    const value = checkbox.value;
                    if (!expertOptions[category]) expertOptions[category] = [];
                    expertOptions[category].push(value);
                });
            }

            button.disabled = true;
            button.innerHTML = '<span class="loading-spinner"></span> Scanning...';

            const scanMessage = mode === 'expert'
                ? `Running expert scan with ${Object.values(expertOptions).flat().length} selected intelligence sources...`
                : (mode === 'advanced'
                    ? 'Performing advanced scan with all intelligence sources...'
                    : 'Scanning IP address and gathering intelligence from multiple sources...');

            statusEl.textContent = scanMessage;
            statusEl.className = 'status loading';
            statusEl.style.display = 'block';
            resultsEl.style.display = 'none';

            // Show loading skeleton
            const icon = mode === 'expert' ? '🎯' : (mode === 'advanced' ? '🔬' : '🔍');
            const title = mode === 'expert' ? 'Expert Analysis' : (mode === 'advanced' ? 'Advanced Analysis' : 'Analyzing IP Address');

            resultsEl.innerHTML = `
                <div style="padding: 30px; text-align: center;">
                    <div style="font-size: 48px; margin-bottom: 20px;">${icon}</div>
                    <h3>${title}...</h3>
                    <p style="color: #666; margin-top: 10px;">
                        ${scanMessage}
                    </p>
                    <div style="margin-top: 20px;">
                        <div style="display: inline-block; width: 200px; height: 4px; background: #e0e0e0; border-radius: 2px; overflow: hidden;">
                            <div style="height: 100%; background: linear-gradient(90deg, #667eea, #764ba2); animation: progress 2s ease-in-out infinite;"></div>
                        </div>
                    </div>
                </div>
            `;
            resultsEl.style.display = 'block';

            try {
                // Determine if it's a CIDR range or single IP
                const isCIDR = ipInput.includes('/');
                let endpoint;
                const params = new URLSearchParams();

                if (isCIDR) {
                    endpoint = `/api/range/${encodeURIComponent(ipInput)}/scan`;
                } else {
                    endpoint = `/api/ip/${ipInput}/scan`;
                }

                // Add mode and options as parameters
                if (mode === 'advanced') {
                    params.append('advanced', 'true');
                } else if (mode === 'expert') {
                    params.append('expert', 'true');
                    params.append('options', JSON.stringify(expertOptions));
                }

                const queryString = params.toString();
                if (queryString) {
                    endpoint += '?' + queryString;
                }

                const response = await fetch(endpoint);
                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.error || 'IP scan failed');
                }

                // Check if we have any data
                if (!data || (data.is_private && !isCIDR)) {
                    statusEl.textContent = 'Note: This is a private/special IP address. Limited data available.';
                    statusEl.className = 'status';
                    statusEl.style.background = '#fff3cd';
                    statusEl.style.color = '#856404';
                } else {
                    statusEl.textContent = 'Scan completed successfully!';
                    statusEl.className = 'status success';
                }

                if (isCIDR) {
                    displayIPRangeResults(data);
                } else {
                    displayIPResults(data);
                }

                // Show any errors/warnings from data sources
                if (data.errors && data.errors.length > 0) {
                    const errorSummary = document.createElement('div');
                    errorSummary.style.cssText = 'margin-top: 15px; padding: 10px; background: #fff3cd; border-radius: 5px; border-left: 3px solid #ffc107;';
                    errorSummary.innerHTML = `
                        <strong style="color: #856404;">⚠️ Some data sources encountered errors:</strong><br>
                        <small style="color: #666;">
                            ${data.errors.map(e => `• ${e.source}: ${e.error}`).join('<br>')}
                        </small>
                    `;
                    resultsEl.appendChild(errorSummary);
                }

            } catch (error) {
                statusEl.textContent = `Error: ${error.message}`;
                statusEl.className = 'status error';
                resultsEl.innerHTML = `
                    <div style="padding: 30px; text-align: center;">
                        <div style="font-size: 48px; margin-bottom: 20px; color: #dc3545;">❌</div>
                        <h3 style="color: #dc3545;">Scan Failed</h3>
                        <p style="color: #666; margin-top: 10px;">
                            ${error.message}
                        </p>
                        <p style="color: #999; font-size: 13px; margin-top: 15px;">
                            Please verify the IP address format and try again. For CIDR ranges, use format: 192.168.1.0/24
                        </p>
                    </div>
                `;
                resultsEl.style.display = 'block';
            } finally {
                button.disabled = false;
                button.textContent = 'Scan IP';
            }
        }

        function displayIPResults(data) {
            const resultsEl = document.getElementById('ip-results');
            const geo = data.geolocation || {};
            const net = data.network || {};
            const rep = data.reputation || {};
            const bgp = data.bgp || {};
            const whois = data.whois || {};
            const reverseDns = data.reverse_dns || {};

            // Determine reputation color
            const abuseConf = rep.abuse_confidence || 0;
            let repColor = '#28a745'; // green
            let repLabel = 'Clean';
            if (abuseConf >= 75) {
                repColor = '#dc3545'; // red
                repLabel = 'High Risk';
            } else if (abuseConf >= 50) {
                repColor = '#ff6b35'; // orange
                repLabel = 'Suspicious';
            } else if (abuseConf >= 25) {
                repColor = '#ffc107'; // yellow
                repLabel = 'Low Risk';
            }

            // Check if we have privacy detection data (IPInfo.io)
            const hasPrivacyData = net.is_vpn !== undefined || net.is_proxy !== undefined ||
                                   net.is_tor !== undefined || net.is_hosting !== undefined;

            // Format threat categories
            const threatCategories = rep.threat_categories || [];
            const categoryNames = {
                '3': 'Fraud',
                '4': 'DDoS Attack',
                '9': 'Hacking',
                '10': 'Spam',
                '11': 'Malware',
                '14': 'Port Scan',
                '15': 'Vulnerability Scan',
                '18': 'Brute Force',
                '19': 'Bad Web Bot',
                '20': 'Exploited Host',
                '21': 'Web App Attack',
                '22': 'SSH Attack',
                '23': 'IoT Targeted'
            };

            resultsEl.innerHTML = `
                <div style="margin-bottom: 20px; padding: 15px; background: ${abuseConf >= 50 ? '#fff3cd' : '#d4edda'}; border-radius: 8px; border-left: 4px solid ${repColor};">
                    <h3 style="margin: 0 0 10px 0; color: #333;">
                        IP Security Summary: <strong style="color: ${repColor};">${data.ip}</strong>
                    </h3>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                        <div>
                            <strong>Threat Level:</strong>
                            <span style="color: ${repColor}; font-weight: bold;">${repLabel} (${abuseConf}%)</span>
                        </div>
                        <div>
                            <strong>Total Reports:</strong> ${rep.total_reports || 0}
                        </div>
                        <div>
                            <strong>Blacklist Hits:</strong> ${(rep.blacklists?.hit_count || 0)} / 10
                        </div>
                        <div>
                            <strong>Data Sources:</strong> ${data.data_sources ? data.data_sources.length : 0}
                        </div>
                    </div>
                </div>

                <div class="security-grid">
                    <div class="security-card">
                        <h3>📍 Geolocation (IPInfo.io)</h3>
                        <div class="detail-item">
                            <span class="detail-label">Country:</span>
                            ${geo.country || 'N/A'}
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Region:</span>
                            ${geo.region || 'N/A'}
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">City:</span>
                            ${geo.city || 'N/A'}
                        </div>
                        ${geo.postal_code ? `
                        <div class="detail-item">
                            <span class="detail-label">Postal Code:</span>
                            ${geo.postal_code}
                        </div>
                        ` : ''}
                        <div class="detail-item">
                            <span class="detail-label">Coordinates:</span>
                            ${geo.coordinates ? `${geo.coordinates.latitude}, ${geo.coordinates.longitude}` : 'N/A'}
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Timezone:</span>
                            ${geo.timezone || 'N/A'}
                        </div>
                    </div>

                    <div class="security-card">
                        <h3>🌐 Network Information</h3>
                        <div class="detail-item">
                            <span class="detail-label">ASN:</span>
                            ${net.asn ? `AS${net.asn}` : 'N/A'}
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Organization:</span>
                            ${net.asn_name || net.organization || 'N/A'}
                        </div>
                        ${rep.isp || net.isp ? `
                        <div class="detail-item">
                            <span class="detail-label">ISP:</span>
                            ${rep.isp || net.isp}
                        </div>
                        ` : ''}
                        ${rep.domain || net.domain ? `
                        <div class="detail-item">
                            <span class="detail-label">Domain:</span>
                            ${rep.domain || net.domain}
                        </div>
                        ` : ''}
                        ${net.hostname || reverseDns.ptr_record ? `
                        <div class="detail-item">
                            <span class="detail-label">Hostname:</span>
                            ${net.hostname || reverseDns.ptr_record || 'None'}
                        </div>
                        ` : ''}
                        ${reverseDns.has_ptr !== undefined ? `
                        <div class="detail-item">
                            <span class="detail-label">Reverse DNS:</span>
                            ${reverseDns.has_ptr ? '✅ Valid' : '❌ No PTR'}
                        </div>
                        ` : ''}
                    </div>

                    ${hasPrivacyData ? `
                    <div class="security-card">
                        <h3>🔒 Privacy Detection (IPInfo.io)</h3>
                        <div class="detail-item">
                            <span class="detail-label">VPN:</span>
                            ${net.is_vpn ? '<span style="color: #ffc107;">⚠️ Detected</span>' : '<span style="color: #28a745;">✅ Not Detected</span>'}
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Proxy:</span>
                            ${net.is_proxy ? '<span style="color: #ffc107;">⚠️ Detected</span>' : '<span style="color: #28a745;">✅ Not Detected</span>'}
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Tor:</span>
                            ${net.is_tor ? '<span style="color: #dc3545;">⚠️ Detected</span>' : '<span style="color: #28a745;">✅ Not Detected</span>'}
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Hosting:</span>
                            ${net.is_hosting ? '<span style="color: #ffc107;">⚠️ Datacenter</span>' : '<span style="color: #28a745;">✅ Residential</span>'}
                        </div>
                    </div>
                    ` : ''}

                    <div class="security-card">
                        <h3>⚠️ Threat Intelligence (AbuseIPDB)</h3>
                        <div class="detail-item">
                            <span class="detail-label">Abuse Confidence:</span>
                            <span style="color: ${repColor}; font-weight: bold; font-size: 18px;">${abuseConf}%</span>
                            <span style="margin-left: 10px; color: ${repColor};">(${repLabel})</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Total Reports:</span>
                            ${rep.total_reports || 0}
                        </div>
                        ${rep.num_distinct_users ? `
                        <div class="detail-item">
                            <span class="detail-label">Distinct Reporters:</span>
                            ${rep.num_distinct_users}
                        </div>
                        ` : ''}
                        ${rep.last_reported_at ? `
                        <div class="detail-item">
                            <span class="detail-label">Last Reported:</span>
                            ${new Date(rep.last_reported_at).toLocaleString()}
                        </div>
                        ` : ''}
                        <div class="detail-item">
                            <span class="detail-label">Whitelisted:</span>
                            ${rep.is_whitelisted ? '✅ Yes' : '❌ No'}
                        </div>
                        ${rep.usage_type ? `
                        <div class="detail-item">
                            <span class="detail-label">Usage Type:</span>
                            ${rep.usage_type}
                        </div>
                        ` : ''}
                        ${threatCategories.length > 0 ? `
                        <div class="detail-item">
                            <span class="detail-label">Threat Categories:</span>
                            <div style="margin-top: 5px;">
                                ${threatCategories.map(cat => `
                                    <span style="display: inline-block; background: #f8d7da; color: #721c24; padding: 3px 8px; margin: 2px; border-radius: 12px; font-size: 12px;">
                                        ${categoryNames[cat] || cat}
                                    </span>
                                `).join('')}
                            </div>
                        </div>
                        ` : ''}
                    </div>

                    <div class="security-card">
                        <h3>🔀 BGP Routing (RIPEstat)</h3>
                        <div class="detail-item">
                            <span class="detail-label">Prefix:</span>
                            ${bgp.prefix || 'N/A'}
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Origin ASN:</span>
                            ${bgp.origin_asn ? `AS${bgp.origin_asn}` : 'N/A'}
                        </div>
                        ${bgp.asn_name ? `
                        <div class="detail-item">
                            <span class="detail-label">AS Name:</span>
                            ${bgp.asn_name}
                        </div>
                        ` : ''}
                        ${bgp.asn_country ? `
                        <div class="detail-item">
                            <span class="detail-label">AS Country:</span>
                            ${bgp.asn_country}
                        </div>
                        ` : ''}
                        <div class="detail-item">
                            <span class="detail-label">Announced:</span>
                            ${bgp.is_announced ? '✅ Yes' : '❌ No'}
                        </div>
                        ${bgp.path && bgp.path.length > 0 ? `
                        <div class="detail-item">
                            <span class="detail-label">AS Path Length:</span>
                            ${bgp.path.length} hops
                        </div>
                        ` : ''}
                    </div>

                    ${rep.blacklists && rep.blacklists.hit_count > 0 ? `
                    <div class="security-card" style="border: 2px solid #dc3545;">
                        <h3>🚫 Blacklist Status (${rep.blacklists.hit_count} hits)</h3>
                        ${Object.entries(rep.blacklists.details || {}).map(([name, info]) => `
                            <div class="detail-item">
                                <span class="detail-label">${name.replace(/_/g, ' ').toUpperCase()}:</span>
                                ${info.listed ?
                                    `<span style="color: #dc3545; font-weight: bold;">❌ LISTED</span>` :
                                    info.listed === false ?
                                    `<span style="color: #28a745;">✅ Clean</span>` :
                                    `<span style="color: #999;">⚠️ Error</span>`
                                }
                                ${info.response_codes ? `<br><small style="color: #666;">Response: ${info.response_codes.join(', ')}</small>` : ''}
                            </div>
                        `).join('')}
                        ${rep.blacklists.listed_in && rep.blacklists.listed_in.length > 0 ? `
                        <div style="margin-top: 15px; padding: 10px; background: #f8d7da; border-radius: 5px; border-left: 3px solid #dc3545;">
                            <strong style="color: #721c24;">⚠️ Listed on:</strong><br>
                            ${rep.blacklists.listed_in.map(bl => `<span style="color: #721c24;">• ${bl}</span>`).join('<br>')}
                        </div>
                        ` : ''}
                    </div>
                    ` : rep.blacklists ? `
                    <div class="security-card">
                        <h3>🚫 Blacklist Status</h3>
                        <div style="text-align: center; padding: 20px; color: #28a745;">
                            <div style="font-size: 48px;">✅</div>
                            <div style="font-size: 16px; font-weight: bold; margin-top: 10px;">Not Listed</div>
                            <div style="font-size: 14px; color: #666; margin-top: 5px;">
                                Checked ${Object.keys(rep.blacklists.details || {}).length} RBL databases
                            </div>
                        </div>
                    </div>
                    ` : ''}

                    ${whois.net_name || whois.description || whois.country || whois.abuse_contact ? `
                    <div class="security-card">
                        <h3>📋 WHOIS Information (RIPEstat)</h3>
                        ${whois.net_name ? `
                        <div class="detail-item">
                            <span class="detail-label">Network Name:</span>
                            ${whois.net_name}
                        </div>
                        ` : ''}
                        ${whois.description ? `
                        <div class="detail-item">
                            <span class="detail-label">Description:</span>
                            ${whois.description}
                        </div>
                        ` : ''}
                        ${whois.country ? `
                        <div class="detail-item">
                            <span class="detail-label">Country:</span>
                            ${whois.country}
                        </div>
                        ` : ''}
                        ${whois.net_range ? `
                        <div class="detail-item">
                            <span class="detail-label">Network Range:</span>
                            ${whois.net_range}
                        </div>
                        ` : ''}
                        ${whois.abuse_contact ? `
                        <div class="detail-item">
                            <span class="detail-label">Abuse Contact:</span>
                            <a href="mailto:${whois.abuse_contact}" style="color: #667eea;">${whois.abuse_contact}</a>
                        </div>
                        ` : ''}
                    </div>
                    ` : ''}
                </div>

                ${data.scan_duration_ms ? `
                <div style="margin-top: 20px; padding: 10px; background: #f8f9fa; border-radius: 5px; text-align: center; color: #666; font-size: 13px;">
                    ⚡ Scan completed in ${data.scan_duration_ms}ms |
                    📅 ${new Date(data.scan_timestamp).toLocaleString()}
                    ${data.errors && data.errors.length > 0 ? ` | ⚠️ ${data.errors.length} errors` : ''}
                </div>
                ` : ''}
            `;
        }

        function displayIPRangeResults(data) {
            const resultsEl = document.getElementById('ip-results');
            const ips = data.ips || [];

            resultsEl.innerHTML = `
                <h3>IP Range Scan Results</h3>
                <div class="detail-item">
                    <span class="detail-label">Range:</span>
                    ${data.range}
                </div>
                <div class="detail-item">
                    <span class="detail-label">IPs Scanned:</span>
                    ${data.ips_scanned}
                </div>
                <div class="detail-item">
                    <span class="detail-label">Scan Time:</span>
                    ${data.scan_time}
                </div>

                <h4 style="margin-top: 20px;">Individual IP Results:</h4>
                <div style="max-height: 600px; overflow-y: auto;">
                    ${ips.map(ip => {
                        const abuseConf = ip.reputation?.abuse_confidence || 0;
                        let repColor = '#28a745';
                        if (abuseConf >= 75) repColor = '#dc3545';
                        else if (abuseConf >= 25) repColor = '#ffc107';

                        return `
                            <div class="security-card" style="margin-bottom: 10px;">
                                <h4>${ip.ip}</h4>
                                <div class="detail-item">
                                    <span class="detail-label">Location:</span>
                                    ${ip.geolocation?.city || 'N/A'}, ${ip.geolocation?.country || 'N/A'}
                                </div>
                                <div class="detail-item">
                                    <span class="detail-label">ASN:</span>
                                    ${ip.network?.asn ? `AS${ip.network.asn}` : 'N/A'}
                                </div>
                                <div class="detail-item">
                                    <span class="detail-label">Reputation:</span>
                                    <span style="color: ${repColor}; font-weight: bold;">${abuseConf}%</span>
                                </div>
                            </div>
                        `;
                    }).join('')}
                </div>
            `;
        }

        // IP Scan Mode Toggle
        function toggleIPScanMode(mode) {
            const simpleBtn = document.getElementById('ip-simple-mode-btn');
            const advancedBtn = document.getElementById('ip-advanced-mode-btn');
            const expertBtn = document.getElementById('ip-expert-mode-btn');
            const simpleMode = document.getElementById('simple-ip-mode');
            const advancedMode = document.getElementById('advanced-ip-mode');
            const expertMode = document.getElementById('expert-ip-mode');

            // Remove active class from all buttons
            simpleBtn.classList.remove('active');
            advancedBtn.classList.remove('active');
            expertBtn.classList.remove('active');

            // Hide all modes
            simpleMode.style.display = 'none';
            advancedMode.style.display = 'none';
            expertMode.style.display = 'none';

            // Show selected mode
            if (mode === 'simple') {
                simpleBtn.classList.add('active');
                simpleMode.style.display = 'block';
            } else if (mode === 'advanced') {
                advancedBtn.classList.add('active');
                advancedMode.style.display = 'block';
            } else if (mode === 'expert') {
                expertBtn.classList.add('active');
                expertMode.style.display = 'block';
            }
        }

        // Expert Options - Select/Deselect All
        function selectAllExpertOptions() {
            document.querySelectorAll('.expert-option').forEach(checkbox => {
                checkbox.checked = true;
            });
        }

        function deselectAllExpertOptions() {
            document.querySelectorAll('.expert-option').forEach(checkbox => {
                checkbox.checked = false;
            });
        }

        // Domain Scan Mode Toggle
        function toggleDomainScanMode(mode) {
            const simpleBtn = document.getElementById('domain-simple-mode-btn');
            const advancedBtn = document.getElementById('domain-advanced-mode-btn');
            const expertBtn = document.getElementById('domain-expert-mode-btn');
            const simpleMode = document.getElementById('simple-domain-mode');
            const advancedMode = document.getElementById('advanced-domain-mode');
            const expertMode = document.getElementById('expert-domain-mode');

            // Remove active class from all buttons
            simpleBtn.classList.remove('active');
            advancedBtn.classList.remove('active');
            expertBtn.classList.remove('active');

            // Hide all modes
            simpleMode.style.display = 'none';
            advancedMode.style.display = 'none';
            expertMode.style.display = 'none';

            // Show selected mode
            if (mode === 'simple') {
                simpleBtn.classList.add('active');
                simpleMode.style.display = 'block';
            } else if (mode === 'advanced') {
                advancedBtn.classList.add('active');
                advancedMode.style.display = 'block';
            } else if (mode === 'expert') {
                expertBtn.classList.add('active');
                expertMode.style.display = 'block';
            }
        }

        // Domain Expert Options - Select/Deselect All
        function selectAllDomainExpertOptions() {
            document.querySelectorAll('.expert-domain-option').forEach(checkbox => {
                checkbox.checked = true;
            });
        }

        function deselectAllDomainExpertOptions() {
            document.querySelectorAll('.expert-domain-option').forEach(checkbox => {
                checkbox.checked = false;
            });
        }

        function toggleGlobalLookupMode(mode) {
            const simpleBtn = document.getElementById('simple-mode-btn');
            const advancedBtn = document.getElementById('advanced-mode-btn');
            const simpleMode = document.getElementById('simple-lookup-mode');
            const advancedMode = document.getElementById('advanced-lookup-mode');

            if (mode === 'simple') {
                simpleBtn.classList.add('active');
                advancedBtn.classList.remove('active');
                simpleMode.style.display = 'block';
                advancedMode.style.display = 'none';
            } else {
                simpleBtn.classList.remove('active');
                advancedBtn.classList.add('active');
                simpleMode.style.display = 'none';
                advancedMode.style.display = 'block';
            }
        }

        async function performGlobalLookup(event, mode) {
            event.preventDefault();

            const query = mode === 'simple'
                ? document.getElementById('global-lookup-input').value.trim().toLowerCase()
                : document.getElementById('advanced-lookup-input').value.trim().toLowerCase();
            const location = mode === 'advanced'
                ? document.getElementById('location-filter').value
                : '';
            const limit = mode === 'advanced'
                ? parseInt(document.getElementById('resolver-limit').value)
                : 50;

            const button = mode === 'simple'
                ? document.getElementById('global-lookup-button')
                : document.getElementById('advanced-lookup-button');
            const statusEl = document.getElementById('global-lookup-status');
            const resultsEl = document.getElementById('global-lookup-results');
            const progressEl = document.getElementById('global-lookup-progress');
            const progressText = document.getElementById('progress-text');
            const progressPercent = document.getElementById('progress-percent');
            const progressBar = document.getElementById('progress-bar');

            button.disabled = true;
            button.innerHTML = '<span class="loading-spinner"></span> Looking up...';
            statusEl.textContent = 'Starting global DNS lookup...';
            statusEl.className = 'status loading';
            statusEl.style.display = 'block';
            resultsEl.innerHTML = '';
            progressEl.style.display = 'block';
            progressText.textContent = 'Scanned 0 of ? resolvers';
            progressPercent.textContent = '0%';
            progressBar.style.width = '0%';

            try {
                const endpoint = `/api/global-lookup`;
                const response = await fetch(endpoint, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        query: query,
                        location: location,
                        limit: limit
                    })
                });

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.error || 'Global lookup failed');
                }

                // Update progress to 100%
                const total = data.resolvers_queried || 0;
                progressText.textContent = `Scanned ${total} of ${total} resolvers`;
                progressPercent.textContent = '100%';
                progressBar.style.width = '100%';

                statusEl.textContent = `Lookup completed! Queried ${total} DNS resolvers.`;
                statusEl.className = 'status success';
                displayGlobalLookupResults(data);

            } catch (error) {
                statusEl.textContent = `Error: ${error.message}`;
                statusEl.className = 'status error';
                progressEl.style.display = 'none';
            } finally {
                button.disabled = false;
                button.textContent = 'Lookup';
            }
        }

        function displayGlobalLookupResults(data) {
            const resultsEl = document.getElementById('global-lookup-results');
            const results = data.results || [];

            console.log('Displaying global lookup results:', data);

            if (results.length === 0) {
                resultsEl.innerHTML = '<p>No results found.</p>';
                resultsEl.style.display = 'block';
                return;
            }

            resultsEl.innerHTML = `
                <h3>Global DNS Lookup Results (${results.length} resolvers)</h3>
                <div style="overflow-x: auto;">
                    <table style="width: 100%; border-collapse: collapse; margin-top: 15px;">
                        <thead>
                            <tr style="background: #667eea; color: white;">
                                <th style="padding: 12px; text-align: left; border: 1px solid #ddd;">Country</th>
                                <th style="padding: 12px; text-align: left; border: 1px solid #ddd;">Location</th>
                                <th style="padding: 12px; text-align: left; border: 1px solid #ddd;">Resolver</th>
                                <th style="padding: 12px; text-align: left; border: 1px solid #ddd;">Query</th>
                                <th style="padding: 12px; text-align: left; border: 1px solid #ddd;">Result</th>
                                <th style="padding: 12px; text-align: left; border: 1px solid #ddd;">Response Time</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${results.map(result => `
                                <tr style="border-bottom: 1px solid #ddd;">
                                    <td style="padding: 10px; border: 1px solid #ddd;">${result.country || 'N/A'}</td>
                                    <td style="padding: 10px; border: 1px solid #ddd;">${result.city || 'N/A'}</td>
                                    <td style="padding: 10px; border: 1px solid #ddd;">${result.resolver || 'N/A'}</td>
                                    <td style="padding: 10px; border: 1px solid #ddd;">${result.query || 'N/A'}</td>
                                    <td style="padding: 10px; border: 1px solid #ddd; font-family: monospace;">${result.result || 'No answer'}</td>
                                    <td style="padding: 10px; border: 1px solid #ddd;">${result.response_time || 'N/A'}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>

                <!-- Historical Tracking and Drift Detection Section -->
                <div style="margin-top: 30px; padding: 20px; background: #f8f9fa; border-radius: 10px;">
                    <h3 style="margin-bottom: 15px;">Historical Tracking & Drift Detection</h3>
                    <div style="display: flex; gap: 15px; margin-bottom: 15px;">
                        <button onclick="loadLookupHistory('${data.query}')" style="background: #667eea; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-weight: bold;">
                            View 14-Day History
                        </button>
                        <button onclick="loadDriftAnalysis('${data.query}')" style="background: #764ba2; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-weight: bold;">
                            Check for DNS Drift
                        </button>
                    </div>
                    <div id="history-section" style="display: none; margin-top: 20px; padding: 15px; background: white; border-radius: 8px;">
                        <h4>Lookup History (Last 14 Days)</h4>
                        <div id="history-content" style="margin-top: 15px;"></div>
                    </div>
                    <div id="drift-section" style="display: none; margin-top: 20px; padding: 15px; background: white; border-radius: 8px;">
                        <h4>DNS Drift Analysis</h4>
                        <div id="drift-content" style="margin-top: 15px;"></div>
                    </div>
                </div>
            `;
            resultsEl.style.display = 'block';
        }

        async function loadLookupHistory(query) {
            const historySection = document.getElementById('history-section');
            const historyContent = document.getElementById('history-content');
            const driftSection = document.getElementById('drift-section');

            // Show history section, hide drift section
            historySection.style.display = 'block';
            driftSection.style.display = 'none';
            historyContent.innerHTML = '<p>Loading history...</p>';

            try {
                const response = await fetch(`/api/global-lookup/history/${encodeURIComponent(query)}`);
                const data = await response.json();

                if (data.error) {
                    historyContent.innerHTML = `<p style="color: #dc3545;">Error: ${data.error}</p>`;
                    return;
                }

                if (!data.history || data.history.length === 0) {
                    historyContent.innerHTML = '<p>No historical lookups found for this query.</p>';
                    return;
                }

                // Group history by date
                const historyByDate = {};
                data.history.forEach(record => {
                    const date = new Date(record.lookup_timestamp).toLocaleDateString();
                    if (!historyByDate[date]) {
                        historyByDate[date] = [];
                    }
                    historyByDate[date].push(record);
                });

                // Generate HTML
                let html = '<div style="overflow-x: auto;">';
                html += '<table style="width: 100%; border-collapse: collapse; margin-top: 10px;">';
                html += '<thead><tr style="background: #667eea; color: white;">';
                html += '<th style="padding: 10px; text-align: left;">Date</th>';
                html += '<th style="padding: 10px; text-align: left;">Time</th>';
                html += '<th style="padding: 10px; text-align: left;">Query Type</th>';
                html += '<th style="padding: 10px; text-align: left;">Location</th>';
                html += '<th style="padding: 10px; text-align: left;">Resolvers</th>';
                html += '<th style="padding: 10px; text-align: left;">Sample Results</th>';
                html += '</tr></thead><tbody>';

                data.history.forEach(record => {
                    const timestamp = new Date(record.lookup_timestamp);
                    const results = JSON.parse(record.results);
                    const successResults = results.filter(r => r.result && !r.result.includes('Timeout') && !r.result.includes('Error'));
                    const sampleResult = successResults.length > 0 ? successResults[0].result : 'No valid results';

                    html += '<tr style="border-bottom: 1px solid #ddd;">';
                    html += `<td style="padding: 10px;">${timestamp.toLocaleDateString()}</td>`;
                    html += `<td style="padding: 10px;">${timestamp.toLocaleTimeString()}</td>`;
                    html += `<td style="padding: 10px;">${record.query_type}</td>`;
                    html += `<td style="padding: 10px;">${record.location_filter || 'Global'}</td>`;
                    html += `<td style="padding: 10px;">${record.resolvers_queried}</td>`;
                    html += `<td style="padding: 10px; font-family: monospace; font-size: 12px;">${sampleResult}</td>`;
                    html += '</tr>';
                });

                html += '</tbody></table></div>';

                // Add drift analysis summary if available
                if (data.drift_analysis && data.drift_analysis.length > 0) {
                    html += '<div style="margin-top: 20px; padding: 15px; background: #f0f4ff; border-radius: 8px;">';
                    html += '<h5 style="margin-bottom: 10px;">DNS Drift Summary (by day)</h5>';
                    html += '<table style="width: 100%; border-collapse: collapse;">';
                    html += '<thead><tr style="background: #764ba2; color: white;">';
                    html += '<th style="padding: 8px; text-align: left;">Date</th>';
                    html += '<th style="padding: 8px; text-align: left;">Unique IPs</th>';
                    html += '<th style="padding: 8px; text-align: left;">Resolver Count</th>';
                    html += '</tr></thead><tbody>';

                    data.drift_analysis.forEach(drift => {
                        const uniqueIps = drift.unique_ips ? drift.unique_ips.join(', ') : 'N/A';
                        html += '<tr style="border-bottom: 1px solid #ddd;">';
                        html += `<td style="padding: 8px;">${drift.day}</td>`;
                        html += `<td style="padding: 8px; font-family: monospace; font-size: 11px;">${uniqueIps}</td>`;
                        html += `<td style="padding: 8px;">${drift.resolver_count}</td>`;
                        html += '</tr>';
                    });

                    html += '</tbody></table></div>';
                }

                historyContent.innerHTML = html;

            } catch (error) {
                historyContent.innerHTML = `<p style="color: #dc3545;">Error loading history: ${error.message}</p>`;
            }
        }

        async function loadDriftAnalysis(query) {
            const driftSection = document.getElementById('drift-section');
            const driftContent = document.getElementById('drift-content');
            const historySection = document.getElementById('history-section');

            // Show drift section, hide history section
            driftSection.style.display = 'block';
            historySection.style.display = 'none';
            driftContent.innerHTML = '<p>Analyzing DNS drift...</p>';

            try {
                const response = await fetch(`/api/global-lookup/drift/${encodeURIComponent(query)}`);
                const data = await response.json();

                if (data.error) {
                    driftContent.innerHTML = `<p style="color: #dc3545;">Error: ${data.error}</p>`;
                    return;
                }

                if (data.message) {
                    driftContent.innerHTML = `<p>${data.message}</p>`;
                    return;
                }

                const driftDetected = data.drift_detected;
                const changePercent = data.change_percentage || 0;
                const previousIps = data.previous_ips || [];
                const currentIps = data.current_ips || [];
                const addedIps = data.added_ips || [];
                const removedIps = data.removed_ips || [];

                let html = '<div style="padding: 15px;">';

                // Status banner
                if (driftDetected) {
                    html += `<div style="padding: 15px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 5px; margin-bottom: 20px;">`;
                    html += `<h4 style="margin: 0 0 5px 0; color: #856404;">DNS Drift Detected!</h4>`;
                    html += `<p style="margin: 0; color: #856404;">Detected ${changePercent.toFixed(1)}% change in DNS responses over the past week.</p>`;
                    html += `</div>`;
                } else {
                    html += `<div style="padding: 15px; background: #d4edda; border-left: 4px solid #28a745; border-radius: 5px; margin-bottom: 20px;">`;
                    html += `<h4 style="margin: 0 0 5px 0; color: #155724;">No Significant Drift</h4>`;
                    html += `<p style="margin: 0; color: #155724;">DNS responses are stable (${changePercent.toFixed(1)}% change).</p>`;
                    html += `</div>`;
                }

                // Comparison table
                html += '<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px;">';

                // Previous IPs
                html += '<div style="padding: 15px; background: #f8f9fa; border-radius: 8px;">';
                html += '<h5 style="margin-top: 0; color: #666;">Previous IPs (7 days ago)</h5>';
                if (previousIps.length > 0) {
                    html += '<ul style="margin: 0; padding-left: 20px;">';
                    previousIps.forEach(ip => {
                        const isRemoved = removedIps.includes(ip);
                        html += `<li style="font-family: monospace; color: ${isRemoved ? '#dc3545' : '#333'}; ${isRemoved ? 'text-decoration: line-through;' : ''}">${ip}</li>`;
                    });
                    html += '</ul>';
                } else {
                    html += '<p style="color: #999;">No data available</p>';
                }
                html += '</div>';

                // Current IPs
                html += '<div style="padding: 15px; background: #f8f9fa; border-radius: 8px;">';
                html += '<h5 style="margin-top: 0; color: #666;">Current IPs (latest)</h5>';
                if (currentIps.length > 0) {
                    html += '<ul style="margin: 0; padding-left: 20px;">';
                    currentIps.forEach(ip => {
                        const isAdded = addedIps.includes(ip);
                        html += `<li style="font-family: monospace; color: ${isAdded ? '#28a745' : '#333'}; ${isAdded ? 'font-weight: bold;' : ''}">${ip}${isAdded ? ' (NEW)' : ''}</li>`;
                    });
                    html += '</ul>';
                } else {
                    html += '<p style="color: #999;">No data available</p>';
                }
                html += '</div>';

                html += '</div>';

                // Changes summary
                if (addedIps.length > 0 || removedIps.length > 0) {
                    html += '<div style="padding: 15px; background: #e7f3ff; border-radius: 8px;">';
                    html += '<h5 style="margin-top: 0;">Changes Summary</h5>';

                    if (addedIps.length > 0) {
                        html += `<p style="margin: 5px 0;"><strong style="color: #28a745;">Added IPs (${addedIps.length}):</strong> ${addedIps.join(', ')}</p>`;
                    }

                    if (removedIps.length > 0) {
                        html += `<p style="margin: 5px 0;"><strong style="color: #dc3545;">Removed IPs (${removedIps.length}):</strong> ${removedIps.join(', ')}</p>`;
                    }

                    html += '</div>';
                }

                html += '</div>';
                driftContent.innerHTML = html;

            } catch (error) {
                driftContent.innerHTML = `<p style="color: #dc3545;">Error analyzing drift: ${error.message}</p>`;
            }
        }

        function displayResults(data) {
            const resultsEl = document.getElementById('results');
            resultsEl.style.display = 'block';

            resultsEl.innerHTML = `
                <h2>Results for ${data.domain}</h2>
                <div class="security-grid">
                    ${renderDNSSECCard(data)}
                    ${renderSPFCard(data)}
                    ${renderDKIMCard(data)}
                    ${renderMTASTSCard(data)}
                    ${renderSMTPCard(data)}
                </div>
                <div id="valuation-container" style="margin-top: 20px;">
                    <div class="security-card" style="background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);">
                        <h3>💰 Domain Valuation</h3>
                        <div id="valuation-content">Loading valuation...</div>
                    </div>
                </div>
                <div class="history-section">
                    <h3>Scan History</h3>
                    <div id="history-container">Loading history...</div>
                </div>
            `;

            // Load valuation data
            loadValuation(data.domain);
        }

        function renderDNSSECCard(data) {
            const status = data.dnssec_enabled ?
                (data.dnssec_valid ? 'enabled' : 'partial') : 'disabled';

            return `
                <div class="security-card">
                    <h3>
                        DNSSEC
                        <span class="status-badge ${status}">
                            ${data.dnssec_enabled ? (data.dnssec_valid ? 'VALID' : 'ENABLED') : 'DISABLED'}
                        </span>
                    </h3>
                    <div class="detail-item">
                        <span class="detail-label">Status:</span>
                        ${data.dnssec_details || 'No details available'}
                    </div>
                </div>
            `;
        }

        function renderSPFCard(data) {
            const status = data.spf_valid ? 'enabled' : 'disabled';

            return `
                <div class="security-card">
                    <h3>
                        SPF
                        <span class="status-badge ${status}">
                            ${data.spf_valid ? 'VALID' : 'INVALID/MISSING'}
                        </span>
                    </h3>
                    <div class="detail-item">
                        <span class="detail-label">Record:</span>
                        ${data.spf_record ? `<code>${data.spf_record}</code>` : 'Not found'}
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Details:</span>
                        ${data.spf_details || 'No details available'}
                    </div>
                </div>
            `;
        }

        function renderDKIMCard(data) {
            const status = data.dkim_valid ? 'enabled' : 'disabled';
            const selectors = JSON.parse(data.dkim_selectors || '[]');

            return `
                <div class="security-card">
                    <h3>
                        DKIM
                        <span class="status-badge ${status}">
                            ${data.dkim_valid ? 'FOUND' : 'NOT FOUND'}
                        </span>
                    </h3>
                    <div class="detail-item">
                        <span class="detail-label">Selectors:</span>
                        ${selectors.length > 0 ? selectors.join(', ') : 'None found'}
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Details:</span>
                        ${data.dkim_details || 'No details available'}
                    </div>
                </div>
            `;
        }

        function renderMTASTSCard(data) {
            const status = data.mta_sts_enabled ? 'enabled' : 'disabled';

            return `
                <div class="security-card">
                    <h3>
                        MTA-STS
                        <span class="status-badge ${status}">
                            ${data.mta_sts_enabled ? 'ENABLED' : 'DISABLED'}
                        </span>
                    </h3>
                    <div class="detail-item">
                        <span class="detail-label">Details:</span>
                        ${data.mta_sts_details || 'No details available'}
                    </div>
                    ${data.mta_sts_policy ? `
                        <div class="detail-item">
                            <span class="detail-label">Policy:</span>
                            <pre><code>${data.mta_sts_policy}</code></pre>
                        </div>
                    ` : ''}
                </div>
            `;
        }

        function renderSMTPCard(data) {
            const port25 = data.smtp_starttls_25;
            const port587 = data.smtp_starttls_587;
            const status = (port25 || port587) ? 'enabled' : 'disabled';

            return `
                <div class="security-card">
                    <h3>
                        SMTP STARTTLS
                        <span class="status-badge ${status}">
                            ${(port25 && port587) ? 'BOTH PORTS' :
                              (port25 || port587) ? 'PARTIAL' : 'DISABLED'}
                        </span>
                    </h3>
                    <div class="detail-item">
                        <span class="detail-label">Port 25:</span>
                        ${port25 ? '✅ STARTTLS Available' : '❌ Not Available'}
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Port 587:</span>
                        ${port587 ? '✅ STARTTLS Available' : '❌ Not Available'}
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Details:</span>
                        ${data.smtp_details || 'No details available'}
                    </div>
                </div>
            `;
        }

        async function loadValuation(domain) {
            try {
                const response = await fetch(`/api/domain/${domain}/valuation`);
                const data = await response.json();

                const valuationContent = document.getElementById('valuation-content');

                if (data.error) {
                    valuationContent.innerHTML = '<p>Valuation not available</p>';
                    return;
                }

                const formatCurrency = (value) => {
                    return new Intl.NumberFormat('en-US', {
                        style: 'currency',
                        currency: 'USD',
                        minimumFractionDigits: 0,
                        maximumFractionDigits: 0
                    }).format(value);
                };

                const getScoreColor = (score) => {
                    if (score >= 80) return '#28a745';
                    if (score >= 60) return '#ffc107';
                    return '#dc3545';
                };

                valuationContent.innerHTML = `
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 15px;">
                        <div class="valuation-stat-card">
                            <div class="valuation-stat-label">Estimated Value Range</div>
                            <div class="valuation-stat-value">
                                ${formatCurrency(data.estimated_value_low)} - ${formatCurrency(data.estimated_value_high)}
                            </div>
                            <div class="valuation-stat-subvalue">
                                Mid: ${formatCurrency(data.estimated_value_mid)}
                            </div>
                        </div>
                        <div class="valuation-score-card">
                            <div class="valuation-stat-label">Overall Score</div>
                            <div style="font-size: 32px; font-weight: bold; margin-top: 5px; color: ${getScoreColor(data.overall_score)};">
                                ${data.overall_score}/100
                            </div>
                        </div>
                    </div>

                    <details style="margin-top: 15px;">
                        <summary class="valuation-breakdown-summary">
                            Score Breakdown
                        </summary>
                        <div class="valuation-breakdown-content">
                            <div style="display: grid; gap: 10px;">
                                <div class="valuation-score-row">
                                    <span class="valuation-score-label">Length Quality:</span>
                                    <span class="valuation-score-value" style="color: ${getScoreColor(data.length_score)};">
                                        ${data.length_score}/100
                                    </span>
                                </div>
                                <div class="valuation-score-row">
                                    <span class="valuation-score-label">TLD Premium:</span>
                                    <span class="valuation-score-value" style="color: ${getScoreColor(data.tld_score)};">
                                        ${data.tld_score}/100
                                    </span>
                                </div>
                                <div class="valuation-score-row">
                                    <span class="valuation-score-label">Domain Age:</span>
                                    <span class="valuation-score-value" style="color: ${getScoreColor(data.age_score)};">
                                        ${data.age_score}/100
                                    </span>
                                </div>
                                <div class="valuation-score-row">
                                    <span class="valuation-score-label">Activity Level:</span>
                                    <span class="valuation-score-value" style="color: ${getScoreColor(data.activity_score)};">
                                        ${data.activity_score}/100
                                    </span>
                                </div>
                                <div class="valuation-score-row">
                                    <span class="valuation-score-label">Keyword Quality:</span>
                                    <span class="valuation-score-value" style="color: ${getScoreColor(data.keyword_score)};">
                                        ${data.keyword_score}/100
                                    </span>
                                </div>
                            </div>
                        </div>
                    </details>

                    <div class="valuation-stat-subvalue" style="margin-top: 10px; font-size: 11px; text-align: center;">
                        Valuation Method: ${data.valuation_method || 'internal_algorithm_v1'}
                        ${data.created_at ? '• Updated: ' + new Date(data.created_at).toLocaleDateString() : ''}
                    </div>
                `;

            } catch (error) {
                console.error('Error loading valuation:', error);
                document.getElementById('valuation-content').innerHTML =
                    '<p style="color: #666;">Valuation data unavailable</p>';
            }
        }

        async function loadHistory(domain) {
            try {
                const response = await fetch(`/api/domain/${domain}/history?limit=10`);
                const data = await response.json();

                const historyContainer = document.getElementById('history-container');

                if (data.history.length === 0) {
                    historyContainer.innerHTML = '<p>No previous scans found.</p>';
                    return;
                }

                historyContainer.innerHTML = data.history.map(scan => `
                    <div class="history-item">
                        <div class="timestamp">${new Date(scan.scan_timestamp).toLocaleString()}</div>
                        <div style="margin-top: 10px; display: flex; gap: 10px; flex-wrap: wrap;">
                            <span class="status-badge ${scan.dnssec_enabled ? 'enabled' : 'disabled'}">
                                DNSSEC: ${scan.dnssec_enabled ? 'ON' : 'OFF'}
                            </span>
                            <span class="status-badge ${scan.spf_valid ? 'enabled' : 'disabled'}">
                                SPF: ${scan.spf_valid ? 'YES' : 'NO'}
                            </span>
                            <span class="status-badge ${scan.dkim_valid ? 'enabled' : 'disabled'}">
                                DKIM: ${scan.dkim_valid ? 'YES' : 'NO'}
                            </span>
                            <span class="status-badge ${scan.mta_sts_enabled ? 'enabled' : 'disabled'}">
                                MTA-STS: ${scan.mta_sts_enabled ? 'YES' : 'NO'}
                            </span>
                            <span class="status-badge ${scan.smtp_starttls_25 || scan.smtp_starttls_587 ? 'enabled' : 'disabled'}">
                                STARTTLS: ${scan.smtp_starttls_25 && scan.smtp_starttls_587 ? 'BOTH' :
                                           scan.smtp_starttls_25 || scan.smtp_starttls_587 ? 'PARTIAL' : 'NO'}
                            </span>
                        </div>
                    </div>
                `).join('');

            } catch (error) {
                console.error('Error loading history:', error);
            }
        }

        async function searchDomains(event) {
            event.preventDefault();
            loadAllDomains();
        }

        async function loadAllDomains() {
            const query = document.getElementById('search-input').value.trim();
            const resultsEl = document.getElementById('search-results');

            resultsEl.innerHTML = '<p>Loading...</p>';

            try {
                const url = query ? `/api/search?q=${encodeURIComponent(query)}` : '/api/domains';
                const response = await fetch(url);
                const data = await response.json();

                if (data.domains.length === 0) {
                    resultsEl.innerHTML = '<p>No domains found.</p>';
                    return;
                }

                resultsEl.innerHTML = data.domains.map(domain => `
                    <div class="domain-list-item" onclick="loadDomainDetails('${domain.domain_name}')">
                        <div class="domain-name">${domain.domain_name}</div>
                        <div class="last-checked">
                            Last checked: ${domain.last_checked ?
                                new Date(domain.last_checked).toLocaleString() : 'Never'}
                        </div>
                    </div>
                `).join('');

            } catch (error) {
                resultsEl.innerHTML = `<p>Error: ${error.message}</p>`;
            }
        }

        async function loadDomainDetails(domain) {
            document.getElementById('domain-input').value = domain;
            switchTab('scan');

            try {
                const response = await fetch(`/api/domain/${domain}`);

                if (!response.ok) {
                    if (response.status === 404) {
                        showStatus(`Domain "${domain}" not found in database. Try scanning it first.`, 'error');
                    } else {
                        showStatus(`Error loading domain: HTTP ${response.status}`, 'error');
                    }
                    return;
                }

                const data = await response.json();
                currentDomain = domain;
                displayResults(data);
                loadHistory(domain);
                showStatus('Loaded from history', 'success');
            } catch (error) {
                showStatus(`Error loading domain: ${error.message}`, 'error');
            }
        }

        let currentPage = 1;
        const perPage = 20;

        async function searchMyScans(event) {
            event.preventDefault();
            currentPage = 1; // Reset to page 1 on new search
            loadMyScans();
        }

        async function loadMyScans(page = currentPage) {
            const query = document.getElementById('myscans-input').value.trim();
            const resultsEl = document.getElementById('myscans-results');

            resultsEl.innerHTML = '<p>Loading...</p>';

            try {
                // Build URL with pagination
                let url = `/api/my-scans?page=${page}&limit=${perPage}`;
                if (query) {
                    url += `&q=${encodeURIComponent(query)}`;
                }

                const response = await fetch(url);
                const data = await response.json();

                if (data.domains && data.domains.length === 0) {
                    resultsEl.innerHTML = '<p>No scans found. Start scanning domains to see them here!</p>';
                    return;
                }

                if (data.domains) {
                    // Build domain list
                    let html = data.domains.map(domain => {
                        const statusClass = domain.status || 'completed';
                        const statusText = {
                            'scanning': '⏳ Scanning...',
                            'completed': domain.last_checked ?
                                `Scanned: ${new Date(domain.last_checked).toLocaleString()}` : 'Pending...',
                            'failed': '❌ Scan failed'
                        }[statusClass] || 'Unknown';

                        const clickable = statusClass === 'completed' ?
                            `onclick="loadDomainDetails('${domain.domain_name}')"` :
                            `style="cursor: not-allowed; opacity: 0.7"`;

                        return `
                            <div class="domain-list-item" ${clickable}>
                                <div class="domain-name">
                                    ${domain.domain_name}
                                    ${statusClass === 'scanning' ? '<span class="status-badge scanning">Scanning</span>' : ''}
                                    ${statusClass === 'failed' ? '<span class="status-badge failed">Failed</span>' : ''}
                                </div>
                                <div class="last-checked">${statusText}</div>
                            </div>
                        `;
                    }).join('');

                    // Add pagination controls
                    if (data.total_pages > 1) {
                        html += '<div class="pagination">';
                        html += `<div class="pagination-info">Page ${data.page} of ${data.total_pages} (${data.count} total)</div>`;
                        html += '<div class="pagination-buttons">';

                        // Previous button
                        if (data.page > 1) {
                            html += `<button onclick="currentPage = ${data.page - 1}; loadMyScans(${data.page - 1}); return false;">‹ Previous</button>`;
                        }

                        // Page numbers
                        const startPage = Math.max(1, data.page - 2);
                        const endPage = Math.min(data.total_pages, data.page + 2);

                        if (startPage > 1) {
                            html += `<button onclick="currentPage = 1; loadMyScans(1); return false;">1</button>`;
                            if (startPage > 2) html += '<span class="pagination-dots">...</span>';
                        }

                        for (let i = startPage; i <= endPage; i++) {
                            if (i === data.page) {
                                html += `<button class="active">${i}</button>`;
                            } else {
                                html += `<button onclick="currentPage = ${i}; loadMyScans(${i}); return false;">${i}</button>`;
                            }
                        }

                        if (endPage < data.total_pages) {
                            if (endPage < data.total_pages - 1) html += '<span class="pagination-dots">...</span>';
                            html += `<button onclick="currentPage = ${data.total_pages}; loadMyScans(${data.total_pages}); return false;">${data.total_pages}</button>`;
                        }

                        // Next button
                        if (data.page < data.total_pages) {
                            html += `<button onclick="currentPage = ${data.page + 1}; loadMyScans(${data.page + 1}); return false;">Next ›</button>`;
                        }

                        html += '</div></div>';
                    } else if (data.count > 0) {
                        html += `<div class="pagination-info">${data.count} result${data.count !== 1 ? 's' : ''}</div>`;
                    }

                    resultsEl.innerHTML = html;
                } else {
                    resultsEl.innerHTML = '<p>No scans found. Start scanning domains to see them here!</p>';
                }

            } catch (error) {
                resultsEl.innerHTML = `<p>Error: ${error.message}</p>`;
            }
        }

        // Load all domains on page load for the search tab
        window.addEventListener('load', () => {
            // Don't load by default to avoid unnecessary API call
        });

        // Theme Toggle Functionality
        const themeToggle = document.getElementById('themeToggle');
        const body = document.body;

        // Load saved theme preference (default to dark mode)
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme === 'light') {
            // Only switch to light if explicitly saved
            body.classList.remove('dark-mode');
        } else {
            // Default to dark mode (includes null/undefined savedTheme)
            body.classList.add('dark-mode');
        }

        // Toggle theme on button click
        themeToggle.addEventListener('click', () => {
            body.classList.toggle('dark-mode');
            const isDark = body.classList.contains('dark-mode');
            localStorage.setItem('theme', isDark ? 'dark' : 'light');
        });
    

        // Authentication system
        let currentUser = null;

        async function checkAuthStatus() {
            try {
                const response = await fetch('/api/auth/me');
                if (response.ok) {
                    const data = await response.json();
                    currentUser = data.user;
                    updateUIForLoggedInUser(data.user, data.usage);
                } else {
                    updateUIForAnonymousUser();
                }
            } catch (error) {
                updateUIForAnonymousUser();
            }
        }

        function updateUIForLoggedInUser(user, usage) {

            // Update navigation bar
            document.getElementById('nav-login').style.display = 'none';
            document.getElementById('nav-signup').style.display = 'none';
            document.getElementById('nav-user-info').style.display = 'flex';
            document.getElementById('nav-user-email').textContent = user.email;
            document.getElementById('nav-user-plan').textContent = user.plan_display_name || 'Free';

            // Hide stats-display when logged in
            const statsDisplay = document.querySelector('.stats-display');
            if (statsDisplay) statsDisplay.style.display = 'none';
        }

        function updateUIForAnonymousUser() {
            currentUser = null;


            // Update navigation bar
            document.getElementById('nav-login').style.display = 'inline-block';
            document.getElementById('nav-signup').style.display = 'inline-block';
            document.getElementById('nav-user-info').style.display = 'none';

            // Show stats-display for anonymous users
            const statsDisplay = document.querySelector('.stats-display');
            if (statsDisplay) statsDisplay.style.display = 'block';
        }

        function showLoginModal() {
            document.getElementById('loginModal').classList.add('active');
        }

        function closeLoginModal() {
            document.getElementById('loginModal').classList.remove('active');
            document.getElementById('login-error').style.display = 'none';
        }

        function showRegisterModal() {
            document.getElementById('registerModal').classList.add('active');
        }

        function closeRegisterModal() {
            document.getElementById('registerModal').classList.remove('active');
            document.getElementById('register-error').style.display = 'none';
        }

        async function handleLogin(event) {
            event.preventDefault();
            
            const email = document.getElementById('login-email').value;
            const password = document.getElementById('login-password').value;
            const remember_me = document.getElementById('login-remember').checked;

            try {
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password, remember_me })
                });

                const data = await response.json();

                if (response.ok) {
                    currentUser = data.user;
                    updateUIForLoggedInUser(data.user, {});
                    closeLoginModal();
                    showStatus('Logged in successfully!', 'success');
                    
                    if (currentTab === 'my-scans') {
                        loadMyScans();
                    }
                } else {
                    document.getElementById('login-error').textContent = data.error;
                    document.getElementById('login-error').style.display = 'block';
                }
            } catch (error) {
                document.getElementById('login-error').textContent = 'Login failed. Please try again.';
                document.getElementById('login-error').style.display = 'block';
            }
        }

        async function handleRegister(event) {
            event.preventDefault();
            
            const email = document.getElementById('register-email').value;
            const password = document.getElementById('register-password').value;
            const full_name = document.getElementById('register-name').value;
            const company = document.getElementById('register-company').value;

            try {
                const response = await fetch('/api/auth/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password, full_name, company })
                });

                const data = await response.json();

                if (response.ok) {
                    currentUser = data.user;
                    updateUIForLoggedInUser(data.user, {});
                    closeRegisterModal();
                    showStatus('Account created successfully!', 'success');
                } else {
                    document.getElementById('register-error').textContent = data.error;
                    document.getElementById('register-error').style.display = 'block';
                }
            } catch (error) {
                document.getElementById('register-error').textContent = 'Registration failed. Please try again.';
                document.getElementById('register-error').style.display = 'block';
            }
        }

        async function logoutUser() {
            try {
                await fetch('/api/auth/logout', { method: 'POST' });
                currentUser = null;
                updateUIForAnonymousUser();
                hideAccountDashboard();
                showStatus('Logged out successfully', 'success');
                
                if (currentTab === 'my-scans') {
                    loadMyScans();
                }
            } catch (error) {
                console.error('Logout failed:', error);
            }
        }

        async function showAccountDashboard() {
            document.getElementById('accountDashboard').style.display = 'block';
            document.getElementById('accountDashboard').scrollIntoView({ behavior: 'smooth' });
            await loadAccountDashboard();
        }

        function hideAccountDashboard() {
            document.getElementById('accountDashboard').style.display = 'none';
        }

        async function loadAccountDashboard() {
            try {
                const planResponse = await fetch('/api/account/plan');
                if (planResponse.ok) {
                    const planData = await planResponse.json();
                    document.getElementById('dashboard-plan').textContent = planData.plan.display_name;
                    document.getElementById('dashboard-scans-limit').textContent = planData.plan.max_scans_per_day;
                }

                const meResponse = await fetch('/api/auth/me');
                if (meResponse.ok) {
                    const meData = await meResponse.json();
                    const scansToday = parseInt(document.getElementById('dashboard-scans-limit').textContent) - meData.usage.scans_remaining_today;
                    document.getElementById('dashboard-scans-today').textContent = scansToday >= 0 ? scansToday : 0;
                }

                await loadAPIKeys();
            } catch (error) {
                console.error('Failed to load dashboard:', error);
            }
        }

        async function loadAPIKeys() {
            try {
                const response = await fetch('/api/account/api-keys');
                if (response.ok) {
                    const data = await response.json();
                    document.getElementById('dashboard-api-keys').textContent = data.api_keys.length;

                    const listEl = document.getElementById('api-keys-list');
                    if (data.api_keys.length === 0) {
                        listEl.innerHTML = '<p style="color: #666;">No API keys yet. Create one to get started!</p>';
                    } else {
                        listEl.innerHTML = data.api_keys.map(key => `
                            <div class="api-key-item">
                                <div class="api-key-info">
                                    <strong>${key.name}</strong><br>
                                    <span class="key-prefix">${key.key_prefix}</span><br>
                                    <small>Created: ${new Date(key.created_at).toLocaleDateString()}</small>
                                    ${key.last_used ? `<br><small>Last used: ${new Date(key.last_used).toLocaleString()}</small>` : ''}
                                </div>
                                <div class="api-key-actions">
                                    <button class="btn-danger" onclick="deleteAPIKey(${key.id}, '${key.name.replace("'", "\'")}')">Delete</button>
                                </div>
                            </div>
                        `).join('');
                    }
                }
            } catch (error) {
                console.error('Failed to load API keys:', error);
            }
        }

        function showCreateAPIKeyModal() {
            document.getElementById('createAPIKeyModal').classList.add('active');
            document.getElementById('apikey-display').style.display = 'none';
            document.getElementById('createAPIKeyForm').style.display = 'block';
        }

        function closeCreateAPIKeyModal() {
            document.getElementById('createAPIKeyModal').classList.remove('active');
            document.getElementById('apikey-error').style.display = 'none';
            document.getElementById('apikey-success').style.display = 'none';
            document.getElementById('createAPIKeyForm').reset();
        }

        async function handleCreateAPIKey(event) {
            event.preventDefault();

            const name = document.getElementById('apikey-name').value;
            const description = document.getElementById('apikey-description').value;

            try {
                const response = await fetch('/api/account/api-keys', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, description })
                });

                const data = await response.json();

                if (response.ok) {
                    document.getElementById('createAPIKeyForm').style.display = 'none';
                    document.getElementById('apikey-value').textContent = data.api_key;
                    document.getElementById('apikey-display').style.display = 'block';
                    
                    await loadAPIKeys();
                } else {
                    document.getElementById('apikey-error').textContent = data.error;
                    document.getElementById('apikey-error').style.display = 'block';
                }
            } catch (error) {
                document.getElementById('apikey-error').textContent = 'Failed to create API key';
                document.getElementById('apikey-error').style.display = 'block';
            }
        }

        function copyAPIKey() {
            const keyValue = document.getElementById('apikey-value').textContent;
            navigator.clipboard.writeText(keyValue);
            showStatus('API key copied to clipboard!', 'success');
        }

        async function deleteAPIKey(keyId, keyName) {
            if (!confirm(`Delete API key "${keyName}"? This cannot be undone.`)) {
                return;
            }

            try {
                const response = await fetch(`/api/account/api-keys/${keyId}`, {
                    method: 'DELETE'
                });

                if (response.ok) {
                    showStatus('API key deleted', 'success');
                    await loadAPIKeys();
                } else {
                    showStatus('Failed to delete API key', 'error');
                }
            } catch (error) {
                showStatus('Failed to delete API key', 'error');
            }
        }

        // Load platform statistics
        async function loadPlatformStats() {
            try {
                const response = await fetch('/api/stats/live');
                if (response.ok) {
                    const data = await response.json();
                    document.getElementById('total-domains').textContent = (data.total_domains || 0).toLocaleString();
                    document.getElementById('total-ssl-certs').textContent = (data.ssl_certificates || 0).toLocaleString();
                }
            } catch (error) {
                console.error('Failed to load platform stats:', error);
                document.getElementById('total-domains').textContent = '0';
                document.getElementById('total-ssl-certs').textContent = '0';
            }
        }

        // Check if domain parameter is in URL and auto-load
        function checkUrlParams() {
            const urlParams = new URLSearchParams(window.location.search);
            const domain = urlParams.get('domain');
            if (domain) {
                // Auto-load the domain
                document.getElementById('domain-input').value = domain;
                loadDomainDetails(domain);
            }
        }

        // Toggle advanced search
        function toggleAdvancedSearch() {
            const advSearch = document.getElementById('advanced-search');
            advSearch.style.display = advSearch.style.display === 'none' ? 'block' : 'none';
        }

        // Advanced domain search with pagination
        async function searchDomains(event) {
            event.preventDefault();
            currentSearchPage = 1;
            await performAdvancedSearch();
        }

        async function performAdvancedSearch(page = 1) {
            const query = document.getElementById('search-input').value;
            const gtld = document.getElementById('gtld-filter').value;
            const cctld = document.getElementById('cctld-filter').value;
            const country = document.getElementById('country-filter').value;

            const resultsDiv = document.getElementById('search-results');
            resultsDiv.innerHTML = '<div style="text-align: center; padding: 20px;">Loading...</div>';

            try {
                let url = `/api/domains/search/advanced?page=${page}&limit=50`;
                if (query) url += `&q=${encodeURIComponent(query)}`;
                if (gtld) url += `&gtld=${gtld}`;
                if (cctld) url += `&cctld=${cctld}`;
                if (country) url += `&country=${country}`;

                const response = await fetch(url);
                const data = await response.json();

                if (data.results && data.results.length > 0) {
                    let html = '<div class="search-result-list">';
                    data.results.forEach(domain => {
                        html += `
                            <div class="search-result-item" onclick="loadDomainDetails('${domain.domain}')">
                                <div class="domain-name">${domain.domain}</div>
                                <div class="domain-meta">
                                    ${domain.country ? `<span>Country: ${domain.country}</span>` : ''}
                                    ${domain.registrar ? `<span>Registrar: ${domain.registrar}</span>` : ''}
                                    ${domain.last_checked ? `<span>Last Scanned: ${new Date(domain.last_checked).toLocaleDateString()}</span>` : ''}
                                </div>
                            </div>
                        `;
                    });
                    html += '</div>';

                    // Add pagination
                    if (data.pages > 1) {
                        html += '<div id="search-pagination" style="text-align: center; margin-top: 20px;">';
                        if (page > 1) {
                            html += `<button onclick="performAdvancedSearch(${page - 1})" style="margin: 0 5px;">Previous</button>`;
                        }
                        html += `<span style="margin: 0 15px;">Page ${page} of ${data.pages}</span>`;
                        if (page < data.pages) {
                            html += `<button onclick="performAdvancedSearch(${page + 1})" style="margin: 0 5px;">Next</button>`;
                        }
                        html += '</div>';
                    }

                    resultsDiv.innerHTML = html;
                } else {
                    resultsDiv.innerHTML = '<div style="text-align: center; padding: 20px;">No results found</div>';
                }
            } catch (error) {
                resultsDiv.innerHTML = `<div style="text-align: center; padding: 20px; color: red;">Error: ${error.message}</div>`;
            }
        }

        // Load dashboard statistics and charts
        async function loadDashboardStats() {
            try {
                const response = await fetch('/api/stats/charts');
                if (!response.ok) throw new Error('Failed to fetch stats');

                const data = await response.json();

                // Update Market Value
                const marketValue = data.total_market_value || 0;
                document.getElementById('total-market-value').textContent =
                    '$' + marketValue.toLocaleString('en-US', {maximumFractionDigits: 0});
                document.getElementById('valued-domains-count').textContent =
                    `${(data.valued_domains || 0).toLocaleString()} domains valued`;

                // Update Domains Added
                document.getElementById('domains-added-today').textContent =
                    (data.domains_added_today || 0).toLocaleString();
                document.getElementById('domains-added-stats').textContent =
                    `This week: ${(data.domains_added_week || 0).toLocaleString()} | This month: ${(data.domains_added_month || 0).toLocaleString()}`;

                // Update Domain Status
                const status = data.domain_status || {};
                const active = status.active || 0;
                const inactive = status.inactive || 0;
                const total = active + inactive;
                document.getElementById('domain-status-chart').innerHTML = `
                    <div style="margin-bottom: 8px;"><strong>Active:</strong> ${active.toLocaleString()} (${total > 0 ? ((active/total)*100).toFixed(1) : 0}%)</div>
                    <div><strong>Inactive:</strong> ${inactive.toLocaleString()} (${total > 0 ? ((inactive/total)*100).toFixed(1) : 0}%)</div>
                `;

                // TLD Distribution Chart
                if (data.tld_distribution && data.tld_distribution.length > 0) {
                    const tldCtx = document.getElementById('tld-chart').getContext('2d');
                    if (tldChart) tldChart.destroy();
                    tldChart = new Chart(tldCtx, {
                        type: 'bar',
                        data: {
                            labels: data.tld_distribution.map(t => '.' + t.tld),
                            datasets: [{
                                label: 'Domains',
                                data: data.tld_distribution.map(t => t.count),
                                backgroundColor: '#667eea'
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: true,
                            plugins: {
                                legend: { display: false }
                            },
                            scales: {
                                y: { beginAtZero: true }
                            }
                        }
                    });
                }

                // Expiration Timeline Chart
                const expiration = data.expiration_timeline || {};
                const expirationCtx = document.getElementById('expiration-chart').getContext('2d');
                if (expirationChart) expirationChart.destroy();
                expirationChart = new Chart(expirationCtx, {
                    type: 'line',
                    data: {
                        labels: ['24h', '48h', '72h', '5d', '1w', '2w', '4w'],
                        datasets: [{
                            label: 'Expiring Domains',
                            data: [
                                expiration['24h'] || 0,
                                expiration['48h'] || 0,
                                expiration['72h'] || 0,
                                expiration['5d'] || 0,
                                expiration['1w'] || 0,
                                expiration['2w'] || 0,
                                expiration['4w'] || 0
                            ],
                            borderColor: '#f5576c',
                            backgroundColor: 'rgba(245, 87, 108, 0.1)',
                            tension: 0.4,
                            fill: true
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        plugins: {
                            legend: { display: false }
                        },
                        scales: {
                            y: { beginAtZero: true }
                        }
                    }
                });

            } catch (error) {
                console.error('Failed to load dashboard stats:', error);
            }
        }

        // Load security quick glance stats
        async function loadSecurityGlance() {
            try {
                const response = await fetch('/api/stats/security-glance');
                if (!response.ok) throw new Error('Failed to fetch security stats');

                const data = await response.json();

                // Update stat cards
                document.getElementById('stat-dnssec').textContent = (data.dnssec_enabled || 0).toLocaleString();
                document.getElementById('stat-dnssec-pct').textContent = `${data.dnssec_percentage || 0}% of domains`;

                document.getElementById('stat-dmarc').textContent = (data.dmarc_configured || 0).toLocaleString();
                document.getElementById('stat-dmarc-pct').textContent = `${data.dmarc_percentage || 0}% of domains`;

                document.getElementById('stat-dane').textContent = (data.dane_enabled || 0).toLocaleString();
                document.getElementById('stat-dane-pct').textContent = `${data.dane_percentage || 0}% of domains`;

                document.getElementById('stat-mta-sts').textContent = (data.mta_sts_enabled || 0).toLocaleString();
                document.getElementById('stat-mta-sts-pct').textContent = `${data.mta_sts_percentage || 0}% of domains`;

                document.getElementById('stat-tlsa').textContent = (data.tlsa_records || 0).toLocaleString();
                document.getElementById('stat-tlsa-pct').textContent = `${data.tlsa_percentage || 0}% of domains`;

                // GeoIP Chart
                if (data.ips_by_country && data.ips_by_country.length > 0) {
                    const geoipCtx = document.getElementById('geoip-chart').getContext('2d');
                    if (geoipChart) geoipChart.destroy();
                    geoipChart = new Chart(geoipCtx, {
                        type: 'bar',
                        data: {
                            labels: data.ips_by_country.map(c => c.country),
                            datasets: [{
                                label: 'IPs',
                                data: data.ips_by_country.map(c => c.count),
                                backgroundColor: '#764ba2'
                            }]
                        },
                        options: {
                            indexAxis: 'y',
                            responsive: true,
                            maintainAspectRatio: true,
                            plugins: {
                                legend: { display: false }
                            },
                            scales: {
                                x: { beginAtZero: true }
                            }
                        }
                    });
                }

            } catch (error) {
                console.error('Failed to load security glance:', error);
            }
        }

        // Initialize Sortable.js for drag-and-drop
        function initDraggable() {
            const grid = document.getElementById('quick-glance-grid');
            if (grid && typeof Sortable !== 'undefined') {
                new Sortable(grid, {
                    animation: 150,
                    ghostClass: 'sortable-ghost',
                    chosenClass: 'sortable-chosen',
                    dragClass: 'sortable-drag',
                    onEnd: function(evt) {
                        // Save layout to localStorage
                        const order = Array.from(grid.children).map(el => el.getAttribute('data-stat'));
                        localStorage.setItem('quickGlanceOrder', JSON.stringify(order));
                    }
                });

                // Restore saved layout
                const savedOrder = localStorage.getItem('quickGlanceOrder');
                if (savedOrder) {
                    const order = JSON.parse(savedOrder);
                    const cards = Array.from(grid.children);
                    order.forEach((statName, index) => {
                        const card = cards.find(c => c.getAttribute('data-stat') === statName);
                        if (card) grid.appendChild(card);
                    });
                }
            }
        }

        // Initialize auth status and stats on page load
        checkAuthStatus();
        loadPlatformStats();
        loadDashboardStats();
        loadSecurityGlance();
        checkUrlParams();

        // Initialize draggable after DOM is ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', initDraggable);
        } else {
            initDraggable();
        }

        // Refresh stats every 30 seconds
        setInterval(loadPlatformStats, 30000);
        // Refresh dashboard charts every 5 minutes
        setInterval(loadDashboardStats, 300000);
        setInterval(loadSecurityGlance, 300000);

        // Domain Registration Functions
        async function searchDomainAvailability(event) {
            event.preventDefault();

            const input = document.getElementById('domain-register-input');
            const domain = input.value.trim();
            const statusEl = document.getElementById('domain-search-status');
            const resultsEl = document.getElementById('domain-search-results');

            if (!domain) {
                statusEl.textContent = 'Please enter a domain name';
                statusEl.className = 'status error';
                return;
            }

            statusEl.textContent = 'Checking availability...';
            statusEl.className = 'status';
            resultsEl.innerHTML = '';

            try {
                const response = await fetch('/api/domains/search', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        domains: [domain]
                    })
                });

                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }

                const data = await response.json();

                if (!data.success) {
                    throw new Error(data.error || 'Failed to check domain availability');
                }

                displayDomainSearchResults(data.results);
                statusEl.textContent = '';
                statusEl.className = 'status';

            } catch (error) {
                statusEl.textContent = `Error: ${error.message}`;
                statusEl.className = 'status error';
                resultsEl.innerHTML = '';
            }
        }

        function displayDomainSearchResults(results) {
            const resultsEl = document.getElementById('domain-search-results');

            if (!results || results.length === 0) {
                resultsEl.innerHTML = '<p style="color: #666;">No results found</p>';
                return;
            }

            let html = '<div style="margin-top: 20px;">';

            for (const result of results) {
                const available = result.available;
                const statusColor = available ? '#10b981' : '#ef4444';
                const statusIcon = available ? '✅' : '❌';
                const statusText = available ? 'Available' : 'Not Available';

                html += `
                    <div style="background: white; border: 2px solid ${statusColor}; border-radius: 10px; padding: 20px; margin-bottom: 15px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <h3 style="margin: 0 0 5px 0; color: #333; font-size: 24px;">
                                    ${statusIcon} ${result.domain}
                                </h3>
                                <p style="margin: 0; color: ${statusColor}; font-weight: bold; font-size: 16px;">
                                    ${statusText}
                                </p>
                `;

                if (available) {
                    const price = result.price || result.price_1_year || '12.99';
                    html += `
                                <p style="margin: 10px 0 0 0; color: #666;">
                                    Price: <strong>$${price}/year</strong>
                                </p>
                    `;
                }

                html += `
                            </div>
                            <div>
                `;

                if (available) {
                    html += `
                                <button onclick="initiateRegistration('${result.domain}')"
                                        style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                                               color: white; border: none; padding: 12px 24px;
                                               border-radius: 8px; font-size: 16px; font-weight: bold;
                                               cursor: pointer; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                                    Register Now
                                </button>
                    `;
                } else {
                    html += `
                                <button disabled
                                        style="background: #ccc; color: #666; border: none;
                                               padding: 12px 24px; border-radius: 8px;
                                               font-size: 16px; cursor: not-allowed;">
                                    Unavailable
                                </button>
                    `;
                }

                html += `
                            </div>
                        </div>
                    </div>
                `;
            }

            html += '</div>';
            resultsEl.innerHTML = html;
        }

        function initiateRegistration(domain) {
            // TODO: Implement full registration flow
            alert(`Registration for ${domain} will be implemented soon! This will redirect to a checkout page with contact information form and payment processing.`);
        }

    </script>

    <!-- Login Modal -->
    <div id="loginModal" class="modal">
        <div class="modal-content">
            <h2>Login to DNS Science</h2>
            <div id="login-error" class="error-message" style="display: none;"></div>
            <form id="loginForm" onsubmit="handleLogin(event)">
                <div class="form-group">
                    <label>Email</label>
                    <input type="email" id="login-email" required>
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" id="login-password" required>
                </div>
                <div class="form-group">
                    <label>
                        <input type="checkbox" id="login-remember"> Remember me
                    </label>
                </div>
                <div class="form-actions">
                    <button type="button" class="btn-secondary" onclick="closeLoginModal()">Cancel</button>
                    <button type="submit" class="btn-primary">Login</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Register Modal -->
    <div id="registerModal" class="modal">
        <div class="modal-content">
            <h2>Create Account</h2>
            <div id="register-error" class="error-message" style="display: none;"></div>
            <form id="registerForm" onsubmit="handleRegister(event)">
                <div class="form-group">
                    <label>Email</label>
                    <input type="email" id="register-email" required>
                </div>
                <div class="form-group">
                    <label>Password (min 8 characters)</label>
                    <input type="password" id="register-password" required minlength="8">
                </div>
                <div class="form-group">
                    <label>Full Name (optional)</label>
                    <input type="text" id="register-name">
                </div>
                <div class="form-group">
                    <label>Company (optional)</label>
                    <input type="text" id="register-company">
                </div>
                <div class="form-actions">
                    <button type="button" class="btn-secondary" onclick="closeRegisterModal()">Cancel</button>
                    <button type="submit" class="btn-primary">Sign Up</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Account Dashboard -->
    <div id="accountDashboard" class="dashboard" style="display: none;">
        <h2>Account Dashboard</h2>
        
        <div class="dashboard-grid">
            <div class="dashboard-card">
                <h3>Current Plan</h3>
                <div class="value" id="dashboard-plan">Free</div>
                <div class="label">Upgrade for more features</div>
            </div>
            <div class="dashboard-card">
                <h3>Scans Today</h3>
                <div class="value"><span id="dashboard-scans-today">0</span>/<span id="dashboard-scans-limit">10</span></div>
                <div class="label">Resets daily</div>
            </div>
            <div class="dashboard-card">
                <h3>API Keys</h3>
                <div class="value" id="dashboard-api-keys">0</div>
                <div class="label">Active API keys</div>
            </div>
        </div>

        <div class="api-keys-section">
            <h3>API Keys</h3>
            <button onclick="showCreateAPIKeyModal()" class="btn-primary" style="margin-bottom: 15px;">Create New API Key</button>
            <div id="api-keys-list"></div>
        </div>

        <button onclick="hideAccountDashboard()" class="btn-secondary" style="margin-top: 20px;">Close</button>
    </div>

    <!-- Create API Key Modal -->
    <div id="createAPIKeyModal" class="modal">
        <div class="modal-content">
            <h2>Create API Key</h2>
            <div id="apikey-success" class="success-message" style="display: none;"></div>
            <div id="apikey-error" class="error-message" style="display: none;"></div>
            <form id="createAPIKeyForm" onsubmit="handleCreateAPIKey(event)">
                <div class="form-group">
                    <label>Key Name</label>
                    <input type="text" id="apikey-name" required placeholder="e.g., Production API Key">
                </div>
                <div class="form-group">
                    <label>Description (optional)</label>
                    <input type="text" id="apikey-description" placeholder="What will you use this key for?">
                </div>
                <div class="form-actions">
                    <button type="button" class="btn-secondary" onclick="closeCreateAPIKeyModal()">Cancel</button>
                    <button type="submit" class="btn-primary">Create Key</button>
                </div>
            </form>
            <div id="apikey-display" style="display: none; margin-top: 20px;">
                <strong>⚠️ Save this API key - you won't see it again!</strong>
                <div style="background: #f0f0f0; padding: 15px; border-radius: 5px; margin-top: 10px; font-family: monospace; word-break: break-all;" id="apikey-value"></div>
                <button onclick="copyAPIKey()" class="btn-primary" style="margin-top: 10px; width: 100%;">Copy to Clipboard</button>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer class="footer">
        <div class="footer-content">
            <!-- Company Info -->
            <div class="footer-column">
                <h3 class="footer-title">🔒 DNS Science</h3>
                <p class="footer-text">
                    Professional DNS intelligence and security platform. Track domains, monitor SSL certificates, and analyze DNS infrastructure in real-time.
                </p>
                <p class="footer-text" style="margin-top: 15px;">
                    An <a href="https://www.afterdarksys.com/" class="footer-company-link" target="_blank" rel="noopener">After Dark Systems, LLC</a> service
                </p>
                <p class="footer-copyright">
                    © 2025 DNS Science. All rights reserved.
                </p>
            </div>

            <!-- Quick Links -->
            <div class="footer-column">
                <h4 class="footer-heading">Quick Links</h4>
                <ul class="footer-links">
                    <li><a href="/">Home</a></li>
                    <li><a href="/explorer">Data Explorer</a></li>
                    <li><a href="/tools">DNS Tools</a></li>
                    <li><a href="/about">About Us</a></li>
                    <li><a href="/pricing">Pricing</a></li>
                    <li><a href="/docs/api">API Docs</a></li>
                    <li><a href="/docs/cli">CLI Docs</a></li>
                    <li><a href="/docs/architecture">Architecture</a></li>
                </ul>
            </div>

            <!-- Services -->
            <div class="footer-column">
                <h4 class="footer-heading">Services</h4>
                <ul class="footer-links">
                    <li><a href="/services">Professional Services</a></li>
                    <li><a href="/registrar">Domain Registrar</a></li>
                    <li><span>Dark Web Monitoring</span></li>
                    <li><span>SSL Monitoring</span></li>
                    <li><span>Threat Intelligence</span></li>
                </ul>
            </div>

            <!-- Contact -->
            <div class="footer-column">
                <h4 class="footer-heading">Contact</h4>
                <ul class="footer-links">
                    <li>
                        <strong>Email:</strong><br>
                        <a href="mailto:support@dnsscience.io">support@dnsscience.io</a>
                    </li>
                    <li>
                        <strong>Sales:</strong><br>
                        <a href="mailto:sales@dnsscience.io">sales@dnsscience.io</a>
                    </li>
                    <li>
                        <strong>Security:</strong><br>
                        <a href="mailto:security@dnsscience.io">security@dnsscience.io</a>
                    </li>
                </ul>
            </div>
        </div>

        <!-- Bottom Bar -->
        <div class="footer-bottom">
            <p>Built with ❤️ for DNS security professionals and researchers</p>
        </div>
    </footer>

</body>
</html>
