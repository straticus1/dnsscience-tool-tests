<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Custom Scanners - DNS Science</title>
    <link rel="stylesheet" href="/static/css/styles.css">
</head>
<body>
    <div class="container">
        <header>
            <div class="header-content">
                <h1>Custom Scanners</h1>
                <div class="nav-links">
                    <a href="/">Home</a>
                    <a href="/browse">Browse</a>
                    <a href="/settings">Settings</a>
                </div>
            </div>
        </header>

        <div class="action-bar">
            <button onclick="showCreateScannerModal()" class="btn btn-primary">Create Scanner</button>
        </div>

        <div class="scanners-grid" id="scanners-list"></div>

        <!-- Create Scanner Modal -->
        <div id="create-scanner-modal" class="modal" style="display: none;">
            <div class="modal-content">
                <h2>Create New Scanner</h2>
                <form id="create-scanner-form">
                    <div class="form-group">
                        <label>Scanner Name</label>
                        <input type="text" id="scanner_name" required>
                    </div>
                    <div class="form-group">
                        <label>Description</label>
                        <textarea id="description"></textarea>
                    </div>
                    <div class="form-group">
                        <label>Schedule</label>
                        <select id="schedule_type">
                            <option value="manual">Manual</option>
                            <option value="hourly">Hourly</option>
                            <option value="daily">Daily</option>
                            <option value="weekly">Weekly</option>
                        </select>
                    </div>
                    <div class="form-actions">
                        <button type="submit" class="btn btn-primary">Create</button>
                        <button type="button" onclick="hideCreateScannerModal()" class="btn btn-secondary">Cancel</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script src="/static/js/scanners.js"></script>
</body>
</html>
