(function() {
    var unlockForm = document.getElementById("unlock-form");
    var resultDiv = document.getElementById("session-key-result");
    var keyValue = document.getElementById("session-key-value");
    var copyBtn = document.getElementById("copy-key-btn");

    unlockForm.addEventListener("submit", async function(e) {
        e.preventDefault();
        clearMessage("message-container");

        var response = await apiPost("/unlock", {
            password: document.getElementById("unlock-password").value,
            secrecy_level: parseInt(document.getElementById("unlock-secrecy").value),
        });
        var data = await response.json();

        if (response.ok) {
            keyValue.textContent = data.request_key;
            resultDiv.classList.remove("hidden");
            unlockForm.classList.add("hidden");
        } else if (response.status !== 429) {
            showMessage("message-container", data.error || "Unlock failed", true);
        }
    });

    copyBtn.addEventListener("click", function() {
        navigator.clipboard.writeText(keyValue.textContent).then(function() {
            showMessage("message-container", "Copied to clipboard", false);
        });
    });
})();
