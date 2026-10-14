// Progressive enhancement only: the page is complete without this file.
(function () {
  // 1. Offer the installer for the visitor's system.
  var ua = navigator.userAgent || "";
  var platform = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || "";
  var os = null;
  if (/iPhone|iPad|iPod|Android/i.test(ua)) os = null;
  else if (/win/i.test(platform) || /Windows/.test(ua)) os = "windows";
  else if (/mac/i.test(platform) || /Macintosh/.test(ua)) os = "mac";
  else if (/linux|x11|cros/i.test(platform + ua)) os = "linux";

  var cta = document.getElementById("cta");
  if (os && cta && cta.dataset["href" + os.charAt(0).toUpperCase() + os.slice(1)]) {
    var key = os.charAt(0).toUpperCase() + os.slice(1);
    cta.href = cta.dataset["href" + key];
    cta.querySelector("span").textContent = cta.dataset["label" + key];
  }
  var row = os && document.querySelector('.os__row[data-os="' + os + '"]');
  if (row) {
    var mark = document.documentElement.lang === "ru" ? "ваша система" : "your system";
    row.querySelector("h3").setAttribute("data-yours", mark);
  }

  // 2. Reveal on scroll (the CSS shows everything when this does not run).
  var hero = document.querySelectorAll(".hero .rise, .hero .draw");
  var items = document.querySelectorAll("main > section:not(.hero) .rise");
  requestAnimationFrame(function () {
    hero.forEach(function (el) { el.classList.add("in"); });
  });
  if (!("IntersectionObserver" in window)) {
    items.forEach(function (el) { el.classList.add("in"); });
    return;
  }
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (e) {
      if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); }
    });
  }, { rootMargin: "0px 0px -4% 0px", threshold: 0.01 });
  items.forEach(function (el) { io.observe(el); });
})();
