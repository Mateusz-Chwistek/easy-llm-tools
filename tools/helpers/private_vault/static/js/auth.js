(function() {
    var tabs = document.querySelectorAll(".auth-tab");
    var loginForm = document.getElementById("login-form");
    var registerForm = document.getElementById("register-form");

    tabs.forEach(function(tab) {
        tab.addEventListener("click", function() {
            tabs.forEach(function(t) { t.classList.remove("active"); });
            tab.classList.add("active");

            var target = tab.getAttribute("data-tab");
            loginForm.classList.toggle("hidden", target !== "login");
            if (registerForm) {
                registerForm.classList.toggle("hidden", target !== "register");
            }
            clearMessage("message-container");
        });
    });

    loginForm.addEventListener("submit", async function(e) {
        e.preventDefault();
        clearMessage("message-container");

        var response = await apiPost("/auth/login", {
            login: document.getElementById("login-username").value,
            password: document.getElementById("login-password").value,
        });
        var data = await response.json();

        if (response.ok) {
            window.location.href = "/vault";
        } else if (response.status !== 429) {
            showMessage("message-container", data.error || "Login failed", true);
        }
    });

    if (!registerForm) return;

    registerForm.addEventListener("submit", async function(e) {
        e.preventDefault();
        clearMessage("message-container");

        var password = document.getElementById("register-password").value;
        var confirm = document.getElementById("register-confirm").value;

        if (password !== confirm) {
            showMessage("message-container", "Passwords do not match", true);
            return;
        }

        var response = await apiPost("/auth/register", {
            login: document.getElementById("register-username").value,
            password: password,
        });
        var data = await response.json();

        if (response.ok) {
            showFlash("Registration successful. You can now log in.", false);
            tabs[0].click();
        } else if (response.status !== 429) {
            var msg = data.error || (data.errors ? data.errors.join(", ") : "Registration failed");
            showMessage("message-container", msg, true);
        }
    });
})();
