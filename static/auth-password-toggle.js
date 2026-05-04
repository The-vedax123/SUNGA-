(function () {
    function bind(btn) {
        btn.addEventListener("click", function () {
            var id = btn.getAttribute("aria-controls");
            var input = id && document.getElementById(id);
            if (!input) return;
            var show = input.type === "password";
            input.type = show ? "text" : "password";
            btn.setAttribute("aria-pressed", show ? "true" : "false");
            btn.textContent = show ? "Hide" : "Show";
        });
    }
    document.querySelectorAll("[data-password-toggle]").forEach(bind);
})();
