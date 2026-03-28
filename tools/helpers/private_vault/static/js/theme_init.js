(function() {
    if (localStorage.getItem("theme") === "dark") {
        document.getElementById("theme-light").disabled = true;
        document.getElementById("theme-dark").disabled = false;
    }
})();
