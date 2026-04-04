package api

// auth.go — goauth integration for Argus.
//
// Auth model after this change:
//   - Loopback / allow_ips    → trusted unconditionally (nginx, CLI, CFM)
//   - Valid goauth session     → trusted for browser-facing routes
//   - Everything else          → redirect /login (browser) or 403 (API)
//
// The existing WithAuth (Bearer token) and globalGuard are unchanged.

import (
	"net/http"
	"strings"
	"log"
	"github.com/chrismfz/goauth"
)

// Auth is the shared goauth Manager. Set by main.go before api.Start().
// Nil when auth is disabled (e.g. dev mode without a db_path configured).
var Auth *goauth.Manager

// sessionAllowed returns true if the request carries a valid goauth session.
// Requires Auth to be set and LoadAndSave to have already run in the chain.
func sessionAllowed(r *http.Request) bool {
    if Auth == nil {
        log.Printf("[AUTH] sessionAllowed: Auth is nil")
        return false
    }
    result := Auth.IsAuthenticated(r)
    ip := realIP(r)
    log.Printf("[AUTH] sessionAllowed: ip=%s result=%v xff=%q",
        ip, result, r.Header.Get("X-Forwarded-For"))
    return result
}


// ── Login page ────────────────────────────────────────────────────────────────

// handleLoginPage serves the HTML login form (GET /login).
func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	// If already authenticated, bounce to dashboard.
	if sessionAllowed(r) {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(loginHTML)
}

// handleLoginAPI proxies to the goauth LoginHandler (POST /login).
func handleLoginAPI(w http.ResponseWriter, r *http.Request) {
	if Auth == nil {
		http.Error(w, "auth not configured", http.StatusServiceUnavailable)
		return
	}
	Auth.LoginHandler()(w, r)
}

// handleLogout proxies to the goauth LogoutHandler (GET|POST /logout).
func handleLogout(w http.ResponseWriter, r *http.Request) {
	if Auth == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	Auth.LogoutHandler()(w, r)
	// After destroying the session, redirect browsers to login.
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

// ── Login page HTML ───────────────────────────────────────────────────────────

var loginHTML = []byte(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Argus NOC — Login</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #0d1117;
      color: #c9d1d9;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
    }

    .card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 2.5rem 2rem;
      width: 100%;
      max-width: 360px;
    }

    .logo {
      text-align: center;
      margin-bottom: 1.75rem;
    }
    .logo-title {
      font-size: 1.5rem;
      font-weight: 700;
      letter-spacing: 0.04em;
      color: #58a6ff;
    }
    .logo-sub {
      font-size: 0.78rem;
      color: #8b949e;
      margin-top: 0.2rem;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }

    label {
      display: block;
      font-size: 0.82rem;
      color: #8b949e;
      margin-bottom: 0.35rem;
    }

    input[type=text],
    input[type=password] {
      width: 100%;
      padding: 0.55rem 0.75rem;
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 6px;
      color: #c9d1d9;
      font-size: 0.95rem;
      outline: none;
      transition: border-color 0.15s;
      margin-bottom: 1rem;
    }
    input:focus { border-color: #58a6ff; }

    button[type=submit] {
      width: 100%;
      padding: 0.6rem;
      background: #238636;
      border: 1px solid #2ea043;
      border-radius: 6px;
      color: #fff;
      font-size: 0.95rem;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.15s;
    }
    button[type=submit]:hover { background: #2ea043; }
    button[type=submit]:disabled { opacity: 0.5; cursor: not-allowed; }

    .error {
      display: none;
      background: #1f1b1b;
      border: 1px solid #6e1a1a;
      border-radius: 6px;
      color: #f85149;
      font-size: 0.85rem;
      padding: 0.55rem 0.75rem;
      margin-bottom: 1rem;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">
      <div class="logo-title">⬡ ARGUS</div>
      <div class="logo-sub">Network Operations Center</div>
    </div>

    <div class="error" id="err"></div>

    <form id="loginForm">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" autocomplete="username" autofocus required>

      <label for="password">Password</label>
      <input type="password" id="password" name="password" autocomplete="current-password" required>

      <button type="submit" id="submitBtn">Sign in</button>
    </form>
  </div>

  <script>
    const form     = document.getElementById('loginForm');
    const errBox   = document.getElementById('err');
    const submitBtn = document.getElementById('submitBtn');
    const next     = new URLSearchParams(location.search).get('next') || '/dashboard';

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      errBox.style.display = 'none';
      submitBtn.disabled = true;
      submitBtn.textContent = 'Signing in…';

      try {
        const res = await fetch('/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: document.getElementById('username').value,
            password: document.getElementById('password').value,
          }),
        });

        if (res.ok) {
          window.location.href = next;
        } else {
          const data = await res.json().catch(() => ({}));
          errBox.textContent = data.error || 'Login failed. Check your credentials.';
          errBox.style.display = 'block';
          submitBtn.disabled = false;
          submitBtn.textContent = 'Sign in';
        }
      } catch {
        errBox.textContent = 'Network error. Please try again.';
        errBox.style.display = 'block';
        submitBtn.disabled = false;
        submitBtn.textContent = 'Sign in';
      }
    });
  </script>
</body>
</html>
`)
