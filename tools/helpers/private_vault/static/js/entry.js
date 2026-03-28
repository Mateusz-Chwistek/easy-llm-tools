(function() {
    var editBtn = document.getElementById("edit-btn");
    var deleteBtn = document.getElementById("delete-btn");
    var editFormContainer = document.getElementById("edit-form-container");
    var editCancelBtn = document.getElementById("edit-cancel-btn");
    var editForm = document.getElementById("edit-form");
    var entryView = document.getElementById("entry-view");
    var ENTRY_ID = deleteBtn.dataset.entryId;

    editBtn.addEventListener("click", function() {
        entryView.classList.add("hidden");
        editFormContainer.classList.remove("hidden");
        editBtn.classList.add("hidden");
    });

    editCancelBtn.addEventListener("click", function() {
        editFormContainer.classList.add("hidden");
        entryView.classList.remove("hidden");
        editBtn.classList.remove("hidden");
        clearMessage("edit-message");
    });

    editForm.addEventListener("submit", async function(e) {
        e.preventDefault();
        clearMessage("edit-message");

        var response = await apiPost("/vault/" + ENTRY_ID + "/edit", {
            title: document.getElementById("edit-title").value,
            content: document.getElementById("edit-content").value,
            secrecy_level: parseInt(document.getElementById("edit-secrecy").value),
            tags: parseTags(document.getElementById("edit-tags").value),
        });
        var data = await response.json();

        if (response.ok) {
            showFlash("Entry updated.", false);
            window.location.reload();
        } else if (response.status !== 429) {
            showMessage("edit-message", data.error || "Failed to update entry", true);
        }
    });

    deleteBtn.addEventListener("click", async function() {
        if (!confirm("Are you sure you want to delete this entry?")) return;

        var response = await apiPost("/vault/" + ENTRY_ID + "/delete", {});

        if (response.ok) {
            showFlash("Entry deleted.", false);
            window.location.href = "/vault";
        } else if (response.status !== 429) {
            var data = await response.json();
            showMessage("message-container", data.error || "Failed to delete entry", true);
        }
    });
})();
