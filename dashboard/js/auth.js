"use strict";
// Session handling. Runs first, before anything else.
(function () {
    "use strict";
    const STORAGE_KEY = "safely_session_token";
    function captureSessionFromUrl() {
        const hash = window.location.hash;
        if (hash.indexOf("#session=") === 0) {
            const token = hash.slice("#session=".length);
            if (token) {
                localStorage.setItem(STORAGE_KEY, token);
            }
            history.replaceState(null, "", window.location.pathname + window.location.search);
        }
    }
    // Reads a ?error=... left in the URL by a failed auth attempt (e.g.
    // clicking an already-used magic link) and shows an honest message
    // about it, without implying the person isn't genuinely signed in.
    function checkForAuthErrorInUrl() {
        const params = new URLSearchParams(window.location.search);
        const error = params.get("error");
        if (!error)
            return;
        const messages = {
            expired_link: "That sign-in link had already been used or expired. You're still signed in from before, so nothing else to do here.",
            server_error: "Something went wrong on our end during that last sign-in attempt. If you're seeing this and aren't signed in, please try again.",
            google_denied: "Google sign-in was cancelled.",
            google_exchange_failed: "Couldn't complete Google sign-in. Please try again.",
            state_mismatch: "That sign-in attempt couldn't be verified. Please try again.",
            google_email_mismatch: "That Google account's email doesn't match your account's email, so it wasn't connected.",
            google_already_linked: "That Google account is already connected to a different Safely account.",
            session_expired: "Your session had expired. Please sign in again.",
        };
        if (window.showToast) {
            window.showToast(messages[error] || "Something didn't go as expected. Please try again.", 5000);
        }
        else {
            console.warn("Safely: showToast not yet available:", messages[error] || error);
        }
        // Clean the URL right after reading it, so a refresh doesn't show
        // this same message again.
        history.replaceState(null, "", window.location.pathname);
    }
    function getToken() {
        return localStorage.getItem(STORAGE_KEY);
    }
    function clearToken() {
        localStorage.removeItem(STORAGE_KEY);
    }
    async function renderAuthState() {
        const token = getToken();
        const app = document.getElementById("app");
        const gate = document.getElementById("login-gate");
        if (!token) {
            if (app)
                app.classList.add("hidden");
            if (gate)
                gate.classList.remove("hidden");
            return;
        }
        try {
            const response = await fetch("/api/v1/me", {
                headers: { Authorization: "Bearer " + token },
            });
            if (response.ok) {
                if (app)
                    app.classList.remove("hidden");
                if (gate)
                    gate.classList.add("hidden");
            }
            else {
                clearToken();
                if (app)
                    app.classList.add("hidden");
                if (gate)
                    gate.classList.remove("hidden");
            }
        }
        catch (e) {
            clearToken();
            if (app)
                app.classList.add("hidden");
            if (gate)
                gate.classList.remove("hidden");
        }
    }
    window.safelyAuth = {
        getToken,
        clearToken,
        authHeader: () => {
            const token = getToken();
            return token ? { Authorization: "Bearer " + token } : {};
        },
        logout: async () => {
            const token = getToken();
            if (token) {
                try {
                    await fetch("/api/v1/auth/logout", {
                        method: "POST",
                        headers: { Authorization: "Bearer " + token },
                    });
                }
                catch (e) {
                    console.error("Safely: logout request failed", e);
                }
            }
            clearToken();
            window.location.href = "/";
        },
    };
    // Attaches the real session token to every HTMX request automatically.
    document.body.addEventListener("htmx:configRequest", (event) => {
        const token = getToken();
        if (token) {
            event.detail.headers["Authorization"] = "Bearer " + token;
        }
    });
    captureSessionFromUrl();
    renderAuthState().then(() => {
        checkForAuthErrorInUrl();
    });
    const logoutBtn = document.getElementById("btnLogout");
    if (logoutBtn) {
        logoutBtn.addEventListener("click", (e) => {
            e.preventDefault();
            window.safelyAuth.logout();
        });
    }
})();
