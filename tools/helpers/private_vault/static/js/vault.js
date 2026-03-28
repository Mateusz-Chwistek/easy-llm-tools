(function() {
    var addBtn = document.getElementById("add-entry-btn");
    var addFormContainer = document.getElementById("add-entry-form");
    var addCancelBtn = document.getElementById("add-cancel-btn");
    var addForm = document.getElementById("add-form");

    addBtn.addEventListener("click", function() {
        addFormContainer.classList.toggle("hidden");
    });

    addCancelBtn.addEventListener("click", function() {
        addFormContainer.classList.add("hidden");
        clearMessage("add-message");
    });

    addForm.addEventListener("submit", async function(e) {
        e.preventDefault();
        clearMessage("add-message");

        var response = await apiPost("/vault/add", {
            title: document.getElementById("add-title").value,
            content: document.getElementById("add-content").value,
            secrecy_level: parseInt(document.getElementById("add-secrecy").value),
            tags: parseTags(document.getElementById("add-tags").value),
        });
        var data = await response.json();

        if (response.ok) {
            showFlash("Entry created.", false);
            window.location.reload();
        } else if (response.status !== 429) {
            showMessage("add-message", data.error || "Failed to create entry", true);
        }
    });
})();
