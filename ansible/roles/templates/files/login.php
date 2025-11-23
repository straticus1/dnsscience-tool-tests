<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - DNS Science</title>
    <link rel="stylesheet" href="/static/css/styles.css">
    <link rel="stylesheet" href="/static/css/auth.css">
    <script src="/static/js/theme-toggle.js" defer></script>
</head>
<body class="dark-mode">
    <!-- Navigation -->
    <nav class="navbar">
        <div class="container">
            <div class="nav-brand">
                <a href="/">
                    <h2>🔬 DNS Science</h2>
                </a>
            </div>

            <button class="theme-toggle" id="theme-toggle" aria-label="Toggle dark/light mode">
                <span class="theme-icon">🌙</span>
            </button>
        </div>
    </nav>

    <!-- Login Form -->
    <div class="auth-container">
        <div class="auth-card">
            <h1>Welcome Back</h1>
            <p class="auth-subtitle">Login to DNS Science</p>

            <form id="login-form" class="auth-form" onsubmit="handleLogin(event)">
                <div class="form-group">
                    <label for="email">Email Address</label>
                    <input type="email" id="email" name="email" required autofocus
                           placeholder="you@example.com">
                </div>

                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required
                           placeholder="Enter your password">
                </div>

                <div class="form-options">
                    <label class="checkbox-label">
                        <input type="checkbox" name="remember">
                        <span>Remember me</span>
                    </label>
                    <a href="/reset-password" class="link">Forgot password?</a>
                </div>

                <button type="submit" class="btn-auth">Login</button>

                <div id="login-status" class="status"></div>
            </form>

            <div class="auth-footer">
                <p>Don't have an account? <a href="/signup" class="link">Sign up</a></p>
            </div>

            <div class="divider">
                <span>OR</span>
            </div>

            <div class="social-auth">
                <button class="btn-social btn-google">
                    <span>Continue with Google</span>
                </button>
                <button class="btn-social btn-github">
                    <span>Continue with GitHub</span>
                </button>
            </div>
        </div>
    </div>

    <script>
        async function handleLogin(event) {
            event.preventDefault();

            const form = event.target;
            const statusEl = document.getElementById('login-status');
            const submitBtn = form.querySelector('button[type="submit"]');

            const formData = {
                email: form.email.value,
                password: form.password.value,
                remember: form.remember.checked
            };

            submitBtn.disabled = true;
            submitBtn.textContent = 'Logging in...';
            statusEl.className = 'status loading';
            statusEl.style.display = 'block';
            statusEl.textContent = 'Authenticating...';

            try {
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(formData)
                });

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.error || 'Login failed');
                }

                statusEl.className = 'status success';
                statusEl.textContent = 'Login successful! Redirecting...';

                // Store auth token
                if (data.token) {
                    localStorage.setItem('auth_token', data.token);
                }

                // Redirect to dashboard
                setTimeout(() => {
                    window.location.href = data.redirect || '/dashboard';
                }, 1000);

            } catch (error) {
                statusEl.className = 'status error';
                statusEl.textContent = `Error: ${error.message}`;
                submitBtn.disabled = false;
                submitBtn.textContent = 'Login';
            }
        }
    </script>
</body>
</html>
