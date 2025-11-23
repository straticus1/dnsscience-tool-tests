"""
Automatically integrate account UI into index.php
"""
import re

def integrate_ui():
    # Read the current index.php
    with open('/Users/ryan/development/afterdarksys.com/subdomains/dnsscience/templates/index.php', 'r') as f:
        content = f.read()
    
    # Find the header section and add user section after h1
    header_pattern = r'(<h1>.*?</h1>\s*<p class="subtitle">.*?</p>)'
    user_section = r'''\1
        
        <div class="user-section" id="user-section">
            <div class="user-info" id="user-info" style="display: none;">
                <span id="user-email"></span>
                <span class="user-plan" id="user-plan"></span>
                <button onclick="showAccountDashboard()" class="account-btn">Account</button>
                <button onclick="logoutUser()" class="logout-btn">Logout</button>
            </div>
            <div class="auth-buttons" id="auth-buttons">
                <button onclick="showLoginModal()" class="login-btn">Login</button>
                <button onclick="showRegisterModal()" class="register-btn">Sign Up</button>
            </div>
        </div>'''
    
    content = re.sub(header_pattern, user_section, content, count=1, flags=re.DOTALL)
    
    # Add CSS for user section and modals before </style>
    css_additions = '''
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
'''
    
    content = content.replace('</style>', css_additions + '\n    </style>')
    
    # Add modal HTML before </body>
    modals_html = '''
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

'''
    
    content = content.replace('</body>', modals_html + '\n</body>')
    
    # Add JavaScript for authentication before </script>
    auth_js = '''

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
            document.getElementById('user-email').textContent = user.email;
            document.getElementById('user-plan').textContent = user.plan_display_name || 'Free';
            document.getElementById('user-info').style.display = 'flex';
            document.getElementById('auth-buttons').style.display = 'none';
        }

        function updateUIForAnonymousUser() {
            currentUser = null;
            document.getElementById('user-info').style.display = 'none';
            document.getElementById('auth-buttons').style.display = 'flex';
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
                                    <button class="btn-danger" onclick="deleteAPIKey(${key.id}, '${key.name.replace("'", "\\'")}')">Delete</button>
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

        // Initialize auth status on page load
        checkAuthStatus();
'''
    
    # Add before the last </script> tag
    last_script_close = content.rfind('</script>')
    if last_script_close != -1:
        content = content[:last_script_close] + auth_js + '\n    ' + content[last_script_close:]
    
    # Write the updated file
    with open('/Users/ryan/development/afterdarksys.com/subdomains/dnsscience/templates/index.php', 'w') as f:
        f.write(content)
    
    print("✅ UI integrated successfully!")
    print("   - Added login/register buttons to header")
    print("   - Added login/register modals")
    print("   - Added account dashboard")
    print("   - Added API key management")
    print("   - Added authentication JavaScript")

if __name__ == '__main__':
    integrate_ui()
