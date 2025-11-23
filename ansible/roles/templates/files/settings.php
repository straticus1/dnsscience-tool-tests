<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Settings - DNS Science</title>
    <link rel="stylesheet" href="/static/css/styles.css">
</head>
<body>
    <div class="container">
        <header>
            <div class="header-content">
                <h1>Account Settings</h1>
                <div class="nav-links">
                    <a href="/">Home</a>
                    <a href="/browse">Browse</a>
                    <a href="/scanners">Scanners</a>
                </div>
            </div>
        </header>

        <div class="settings-grid">
            <div class="card">
                <h2>Profile Information</h2>
                <form id="profile-form">
                    <div class="form-group">
                        <label>First Name</label>
                        <input type="text" id="first_name" required>
                    </div>
                    <div class="form-group">
                        <label>Last Name</label>
                        <input type="text" id="last_name" required>
                    </div>
                    <div class="form-group">
                        <label>Email</label>
                        <input type="email" id="email" readonly>
                    </div>
                    <div class="form-group">
                        <label>Company</label>
                        <input type="text" id="company">
                    </div>
                    <button type="submit" class="btn btn-primary">Update Profile</button>
                </form>
            </div>

            <div class="card">
                <h2>Change Password</h2>
                <form id="password-form">
                    <div class="form-group">
                        <label>Current Password</label>
                        <input type="password" id="current_password" required>
                    </div>
                    <div class="form-group">
                        <label>New Password</label>
                        <input type="password" id="new_password" required>
                    </div>
                    <div class="form-group">
                        <label>Confirm New Password</label>
                        <input type="password" id="confirm_password" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Change Password</button>
                </form>
            </div>

            <div class="card">
                <h2>API Keys</h2>
                <div id="api-keys-list"></div>
                <button onclick="generateAPIKey()" class="btn btn-secondary">Generate New Key</button>
            </div>

            <div class="card">
                <h2>Notification Settings</h2>
                <form id="notifications-form">
                    <div class="form-group checkbox">
                        <input type="checkbox" id="email_notifications">
                        <label for="email_notifications">Email Notifications</label>
                    </div>
                    <div class="form-group checkbox">
                        <input type="checkbox" id="security_alerts">
                        <label for="security_alerts">Security Alerts</label>
                    </div>
                    <div class="form-group checkbox">
                        <input type="checkbox" id="weekly_reports">
                        <label for="weekly_reports">Weekly Reports</label>
                    </div>
                    <button type="submit" class="btn btn-primary">Save Preferences</button>
                </form>
            </div>
        </div>
    </div>

    <script src="/static/js/settings.js"></script>
</body>
</html>
