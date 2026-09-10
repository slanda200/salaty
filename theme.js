(function () {
  const saved = localStorage.getItem("theme");
  if (saved === "dark") document.documentElement.setAttribute("data-theme", "dark");
})();

function initThemeToggle() {
  const btn = document.getElementById("theme-toggle");
  if (!btn) return;
  const root = document.documentElement;

  function apply(mode) {
    if (mode === "dark") {
      root.setAttribute("data-theme", "dark");
      btn.textContent = "🌙";
    } else {
      root.removeAttribute("data-theme");
      btn.textContent = "☀";
    }
  }

  apply(localStorage.getItem("theme") === "dark" ? "dark" : "light");

  btn.addEventListener("click", () => {
    const next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
    localStorage.setItem("theme", next);
    apply(next);
  });
}

document.addEventListener("DOMContentLoaded", initThemeToggle);
