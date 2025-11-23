<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign Up - DNS Science</title>
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

    <!-- Signup Form -->
    <div class="auth-container">
        <div class="auth-card">
            <h1>Get Started</h1>
            <p class="auth-subtitle">Create your DNS Science account</p>

            <form id="signup-form" class="auth-form" onsubmit="handleSignup(event)">
                <div class="form-row">
                    <div class="form-group">
                        <label for="first_name">First Name</label>
                        <input type="text" id="first_name" name="first_name" required
                               placeholder="John">
                    </div>
                    <div class="form-group">
                        <label for="last_name">Last Name</label>
                        <input type="text" id="last_name" name="last_name" required
                               placeholder="Doe">
                    </div>
                </div>

                <div class="form-group">
                    <label for="email">Email Address</label>
                    <input type="email" id="email" name="email" required
                           placeholder="you@example.com">
                </div>

                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required
                           minlength="8" placeholder="At least 8 characters">
                    <small class="form-hint">Must be at least 8 characters with uppercase, lowercase, and numbers</small>
                </div>

                <div class="form-group">
                    <label for="confirm_password">Confirm Password</label>
                    <input type="password" id="confirm_password" name="confirm_password" required
                           placeholder="Re-enter your password">
                </div>

                <div class="form-group">
                    <label class="checkbox-label">
                        <input type="checkbox" name="terms" required>
                        <span>I agree to the <a href="/terms" class="link" target="_blank">Terms of Service</a>
                        and <a href="/privacy" class="link" target="_blank">Privacy Policy</a></span>
                    </label>
                </div>

                <button type="submit" class="btn-auth">Create Account</button>

                <div id="signup-status" class="status"></div>
            </form>

            <div class="auth-footer">
                <p>Already have an account? <a href="/login" class="link">Login</a></p>
            </div>

            <div class="divider">
                <span>OR</span>
            </div>

            <div class="social-auth">
                <button class="btn-social btn-google">
                    <span>Sign up with Google</span>
                </button>
                <button class="btn-social btn-github">
                    <span>Sign up with GitHub</span>
                </button>
            </div>
        </div>
    </div>

    <script>
        async function handleSignup(event) {
            event.preventDefault();

            const form = event.target;
            const statusEl = document.getElementById('signup-status');
            const submitBtn = form.querySelector('button[type="submit"]');

            // Validate password match
            if (form.password.value !== form.confirm_password.value) {
                statusEl.className = 'status error';
                statusEl.style.display = 'block';
                statusEl.textContent = 'Passwords do not match';
                return;
            }

            // Validate password strength
            const password = form.password.value;
            const hasUppercase = /[A-Z]/.test(password);
            const hasLowercase = /[a-z]/.test(password);
            const hasNumber = /[0-9]/.test(password);

            if (!hasUppercase || !hasLowercase || !hasNumber) {
                statusEl.className = 'status error';
                statusEl.style.display = 'block';
                statusEl.textContent = 'Password must contain uppercase, lowercase, and numbers';
                return;
            }

            const formData = {
                first_name: form.first_name.value,
                last_name: form.last_name.value,
                email: form.email.value,
                password: form.password.value
            };

            submitBtn.disabled = true;
            submitBtn.textContent = 'Creating account...';
            statusEl.className = 'status loading';
            statusEl.style.display = 'block';
            statusEl.textContent = 'Creating your account...';

            try {
                const response = await fetch('/api/auth/signup', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(formData)
                });

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.error || 'Signup failed');
                }

                statusEl.className = 'status success';
                statusEl.textContent = 'Account created successfully! Redirecting to login...';

                // Redirect to login
                setTimeout(() => {
                    window.location.href = '/login?registered=true';
                }, 2000);

            } catch (error) {
                statusEl.className = 'status error';
                statusEl.textContent = `Error: ${error.message}`;
                submitBtn.disabled = false;
                submitBtn.textContent = 'Create Account';
            }
        }
    </script>
</body>
</html>
