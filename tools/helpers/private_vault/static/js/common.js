async function apiPost(url, data) {
    var token = document.querySelector('meta[name="csrf-token"]').getAttribute("content");
    var response = await fetch(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": token,
        },
        body: JSON.stringify(data),
    });

    if (response.status === 429) {
        var retryAfter = response.headers.get("Retry-After");
        var msg = "Too many requests. ";
        if (retryAfter) {
            msg += "Try again in " + retryAfter + " seconds.";
        } else {
            msg += "Please wait a moment and try again.";
        }
        showFlash(msg, true);
    }

    return response;
}

function showFlash(message, isError) {
    var value = (isError ? "error:" : "success:") + message;
    document.cookie = "flash=" + encodeURIComponent(value) + ";path=/;max-age=5;SameSite=Strict";

    var container = document.getElementById("flash-container");
    if (container) {
        container.innerHTML = "";
        var div = document.createElement("div");
        div.className = isError ? "message message-error" : "message message-success";
        div.textContent = message;
        container.appendChild(div);
    }
}

function _consumeFlash() {
    var match = document.cookie.match(/(?:^|; )flash=([^;]*)/);
    if (!match) return;

    document.cookie = "flash=;path=/;max-age=0;SameSite=Strict";
    var raw = decodeURIComponent(match[1]);
    var isError = raw.startsWith("error:");
    var message = raw.replace(/^(error|success):/, "");

    var container = document.getElementById("flash-container");
    if (container) {
        var div = document.createElement("div");
        div.className = isError ? "message message-error" : "message message-success";
        div.textContent = message;
        container.appendChild(div);
    }
}

function showMessage(containerId, message, isError) {
    var container = document.getElementById(containerId);
    if (!container) return;
    container.innerHTML = "";
    var div = document.createElement("div");
    div.className = isError ? "message message-error" : "message message-success";
    div.textContent = message;
    container.appendChild(div);
}

function clearMessage(containerId) {
    var container = document.getElementById(containerId);
    if (container) container.innerHTML = "";
}

function parseTags(raw) {
    if (!raw || !raw.trim()) return [];
    return raw.split(",").map(function(t) { return t.trim(); }).filter(function(t) { return t.length > 0; });
}

(function() {
    _consumeFlash();

    var logoutBtn = document.getElementById("logout-btn");
    if (logoutBtn) {
        logoutBtn.addEventListener("click", async function() {
            await apiPost("/auth/logout", {});
            window.location.href = "/auth/login";
        });
    }

    var regLockBtn = document.getElementById("reg-lock-btn");
    if (regLockBtn) {
        regLockBtn.addEventListener("click", async function() {
            var response = await apiPost("/auth/registration-lock", {});
            if (!response.ok) return;
            var data = await response.json();
            var locked = data.registration_locked;
            regLockBtn.setAttribute("data-locked", locked ? "true" : "false");
            regLockBtn.textContent = "Reg: " + (locked ? "Locked" : "Open");
        });
    }
})();
