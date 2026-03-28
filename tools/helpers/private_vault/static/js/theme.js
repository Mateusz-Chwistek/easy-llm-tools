(function() {
    var toggle = document.getElementById("theme-toggle");
    if (!toggle) return;

    var lightSheet = document.getElementById("theme-light");
    var darkSheet = document.getElementById("theme-dark");

    function isDark() {
        return !darkSheet.disabled;
    }

    function updateToggle() {
        toggle.classList.toggle("dark", isDark());
    }

    toggle.addEventListener("click", function() {
        lightSheet.disabled = !lightSheet.disabled;
        darkSheet.disabled = !darkSheet.disabled;
        localStorage.setItem("theme", isDark() ? "dark" : "light");
        updateToggle();
    });

    updateToggle();
})();
