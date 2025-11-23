<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password - DNS Science</title>
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

    <!-- Reset Password Form -->
    <div class="auth-container">
        <div class="auth-card">
            <h1>Reset Password</h1>
            <p class="auth-subtitle">Enter your email address and we'll send you a link to reset your password</p>

            <form id="reset-form" class="auth-form" onsubmit="handleReset(event)">
                <div class="form-group">
                    <label for="email">Email Address</label>
                    <input type="email" id="email" name="email" required autofocus
                           placeholder="you@example.com">
                </div>

                <button type="submit" class="btn-auth">Send Reset Link</button>

                <div id="reset-status" class="status"></div>
            </form>

            <div class="auth-footer">
                <p><a href="/login" class="link">← Back to Login</a></p>
            </div>
        </div>
    </div>

    <script>
        async function handleReset(event) {
            event.preventDefault();

            const form = event.target;
            const statusEl = document.getElementById('reset-status');
            const submitBtn = form.querySelector('button[type="submit"]');

            const formData = {
                email: form.email.value
            };

            submitBtn.disabled = true;
            submitBtn.textContent = 'Sending...';
            statusEl.className = 'status loading';
            statusEl.style.display = 'block';
            statusEl.textContent = 'Sending reset link...';

            try {
                const response = await fetch('/api/auth/reset-password', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(formData)
                });

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.error || 'Reset request failed');
                }

                statusEl.className = 'status success';
                statusEl.textContent = 'Reset link sent! Please check your email.';
                form.reset();

            } catch (error) {
                statusEl.className = 'status error';
                statusEl.textContent = `Error: ${error.message}`;
            } finally {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Send Reset Link';
            }
        }
    </script>
</body>
</html>
