//! The widget's HTML, split at the interpolations of the template literals in the
//! Next route handler this replaces (client/src/app/widget/[siteId]/route.ts).
//! Generated from that file so every byte matches; non-ASCII characters are
//! written as escapes.

use super::{Colors, WidgetConfig};

/// `renderCardHTML`
pub(super) fn card(out: &mut String, c: &WidgetConfig, col: &Colors, logo: &str) {
    out.push_str("\n<div class=\"w card\">\n  <div class=\"header\">\n    <div class=\"header-left\"><span class=\"pulse pulse-md\"></span> VISITORS</div>\n    <span class=\"count\" id=\"count\">\u{2014}</span>\n  </div>\n  ");
    out.push_str(if c.chart { "<div class=\"chart\" id=\"chart\"></div>" } else { "" });
    out.push_str("\n  <div class=\"window-label\">");
    out.push_str(c.window_label);
    out.push_str("</div>\n  ");
    out.push_str(if c.countries { "<div class=\"countries\" id=\"countries\"></div>" } else { "" });
    out.push_str("\n  <a class=\"footer\" href=\"https://hygo.ai\" target=\"_blank\" rel=\"noopener noreferrer\">\n    Powered by <img src=\"");
    out.push_str(logo);
    out.push_str("\" alt=\"Hygo web analytics\" width=\"60\" height=\"12\" />\n  </a>\n</div>\n<style>\n  .w.card {\n    background: ");
    out.push_str(col.bg);
    out.push_str(";\n    color: ");
    out.push_str(col.fg);
    out.push_str(";\n    padding: 24px;\n    border-radius: 12px;\n    box-sizing: border-box;\n    width: 100%;\n    display: flex;\n    flex-direction: column;\n  }\n  .header {\n    display: flex;\n    align-items: flex-start;\n    justify-content: space-between;\n    gap: 4px;\n    font-size: 13px;\n    letter-spacing: 0.08em;\n    color: ");
    out.push_str(col.muted);
    out.push_str(";\n  }\n  .header-left {\n    display: flex;\n    align-items: center;\n    gap: 8px;\n    letter-spacing: 0.03em;\n  }\n  .count {\n    font-size: 32px;\n    font-weight: 700;\n    line-height: 1;\n    color: ");
    out.push_str(col.fg);
    out.push_str(";\n  }\n  .chart {\n    display: flex;\n    align-items: flex-end;\n    gap: 2px;\n    height: 90px;\n    overflow: hidden;\n  }\n  .chart .bar {\n    flex: 1 1 0;\n    min-width: 0;\n    background: ");
    out.push_str(&c.accent);
    out.push_str(";\n    border-radius: 2px;\n  }\n  .chart .empty { flex: 1; color: ");
    out.push_str(col.muted);
    out.push_str("; font-size: 12px; }\n  .window-label { color: ");
    out.push_str(col.muted);
    out.push_str("; font-size: 12px; margin-top: 12px; }\n  .countries { display: flex; flex-direction: column; gap: 8px; margin-top: 10px; }\n  .countries .row { display: flex; align-items: center; font-size: 14px; }\n  .countries .flag { width: 24px; font-size: 18px; line-height: 1; }\n  .countries .name { margin-left: 10px; flex: 1; }\n  .countries .users { color: ");
    out.push_str(col.muted);
    out.push_str("; }\n  .footer {\n    margin-top: 16px;\n    color: ");
    out.push_str(col.muted);
    out.push_str(";\n    font-size: 11px;\n    text-decoration: none;\n    display: flex;\n    align-items: center;\n    gap: 4px;\n  }\n</style>");
}

/// `renderInlineHTML`
pub(super) fn inline(out: &mut String, col: &Colors, logo: &str) {
    out.push_str("\n<div class=\"w inline\">\n  <span class=\"pulse pulse-sm\"></span>\n  <span class=\"count\" id=\"count\">\u{2014}</span>\n  <span class=\"muted\">online</span>\n  <span class=\"sep\">\u{b7}</span>\n  <a href=\"https://hygo.ai\" target=\"_blank\" rel=\"noopener noreferrer\">\n    <img src=\"");
    out.push_str(logo);
    out.push_str("\" alt=\"Hygo web analytics\" width=\"50\" height=\"10\" />\n  </a>\n</div>\n<style>\n  .w.inline {\n    background: ");
    out.push_str(col.bg);
    out.push_str(";\n    color: ");
    out.push_str(col.fg);
    out.push_str(";\n    padding: 6px 12px;\n    border-radius: 9999px;\n    border: 1px solid ");
    out.push_str(col.border);
    out.push_str(";\n    display: inline-flex;\n    align-items: center;\n    gap: 8px;\n    font-size: 14px;\n    line-height: 1;\n    box-sizing: border-box;\n    width: fit-content;\n  }\n  .w.inline .count { font-weight: 600; }\n  .w.inline .muted { color: ");
    out.push_str(col.muted);
    out.push_str("; margin-left: -4px; }\n  .w.inline .sep { color: ");
    out.push_str(col.muted);
    out.push_str("; opacity: 0.6; }\n  .w.inline a { color: ");
    out.push_str(col.muted);
    out.push_str("; font-size: 12px; text-decoration: none; display: inline-flex; align-items: center; }\n  .w.inline a img { display: block; opacity: 0.7; }\n</style>");
}

/// `renderHTML`
pub(super) fn document(out: &mut String, c: &WidgetConfig, body: &str, config: &str) {
    out.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\" />\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n<title>Hygo live visitors</title>\n<style>\n  html { color-scheme: ");
    out.push_str(c.theme.as_str());
    out.push_str("; }\n  html, body { background: transparent; margin: 0; padding: 0; }\n  body {\n    font-family: system-ui, -apple-system, \"Segoe UI\", Roboto, sans-serif;\n    -webkit-font-smoothing: antialiased;\n  }\n  .pulse {\n    position: relative;\n    display: inline-block;\n  }\n  .pulse-sm { width: 12px; height: 12px; }\n  .pulse-md { width: 14px; height: 14px; }\n  .pulse::before, .pulse::after {\n    content: \"\";\n    position: absolute;\n    inset: 0;\n    border-radius: 50%;\n    background: ");
    out.push_str(&c.accent);
    out.push_str(";\n  }\n  .pulse::before { opacity: 0.4; animation: hygo-pulse 1.6s ease-out infinite; }\n  .pulse-md::after { inset: 3px; }\n  .pulse-sm::after { inset: 2px; }\n  @keyframes hygo-pulse {\n    0%   { transform: scale(1); opacity: 0.5; }\n    100% { transform: scale(2.2); opacity: 0; }\n  }\n</style>\n</head>\n<body>\n");
    out.push_str(body);
    out.push_str("\n<script>\n(function () {\n  var cfg = ");
    out.push_str(config);
    out.push_str(";\n  var countEl = document.getElementById(\"count\");\n  var chartEl = document.getElementById(\"chart\");\n  var countriesEl = document.getElementById(\"countries\");\n\n  var timeFmt = new Intl.DateTimeFormat([], { hour: \"2-digit\", minute: \"2-digit\", hour12: false });\n  var dayFmt = new Intl.DateTimeFormat([], { month: \"short\", day: \"numeric\" });\n  var nameFmt;\n  try { nameFmt = new Intl.DisplayNames([], { type: \"region\" }); } catch (e) { nameFmt = null; }\n\n  function flagEmoji(cc) {\n    if (!cc || cc.length !== 2) return \"\";\n    var s = cc.toUpperCase();\n    return String.fromCodePoint(s.charCodeAt(0) + 127397, s.charCodeAt(1) + 127397);\n  }\n\n  function countryName(cc) {\n    try { return (nameFmt && nameFmt.of(cc)) || cc; } catch (e) { return cc; }\n  }\n\n  function formatTime(t, minutes) {\n    var d = new Date(t.replace(\" \", \"T\") + \"Z\");\n    if (isNaN(d)) return \"\";\n    return minutes >= 10080 ? dayFmt.format(d) : timeFmt.format(d);\n  }\n\n  function renderChart(series) {\n    if (!chartEl) return;\n    if (!series || !series.length) {\n      chartEl.innerHTML = '<div class=\"empty\">No data</div>';\n      return;\n    }\n    var max = 1;\n    for (var i = 0; i < series.length; i++) {\n      if (series[i].users > max) max = series[i].users;\n    }\n    var html = \"\";\n    for (var j = 0; j < series.length; j++) {\n      var s = series[j];\n      var h = Math.max(2, (s.users / max) * 86);\n      var label = s.users + \" users \u{b7} \" + formatTime(s.time, cfg.minutes);\n      html +=\n        '<div class=\"bar\" style=\"height:' + h + 'px\" title=\"' + label.replace(/\"/g, \"&quot;\") + '\"></div>';\n    }\n    chartEl.innerHTML = html;\n  }\n\n  function renderCountries(rows) {\n    if (!countriesEl) return;\n    if (!rows || !rows.length) {\n      countriesEl.innerHTML = '<div class=\"empty\" style=\"color:inherit;font-size:12px\">No data</div>';\n      return;\n    }\n    var html = \"\";\n    for (var i = 0; i < rows.length; i++) {\n      var r = rows[i];\n      var safeCC = String(r.country || \"\").replace(/[^A-Za-z]/g, \"\").slice(0, 2);\n      html +=\n        '<div class=\"row\">' +\n        '<span class=\"flag\">' + flagEmoji(safeCC) + '</span>' +\n        '<span class=\"name\">' + escapeHTML(countryName(safeCC)) + '</span>' +\n        '<span class=\"users\">' + r.users + '</span>' +\n        '</div>';\n    }\n    countriesEl.innerHTML = html;\n  }\n\n  function escapeHTML(s) {\n    return String(s).replace(/[&<>\"']/g, function (c) {\n      return { \"&\": \"&amp;\", \"<\": \"&lt;\", \">\": \"&gt;\", '\"': \"&quot;\", \"'\": \"&#39;\" }[c];\n    });\n  }\n\n  function fetchData() {\n    var url = cfg.backendUrl + \"/sites/\" + encodeURIComponent(cfg.siteId) +\n      \"/embed-stats?minutes=\" + cfg.minutes +\n      \"&chart=\" + cfg.chart +\n      \"&countries=\" + cfg.countries;\n    fetch(url)\n      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })\n      .then(function (data) {\n        if (countEl) countEl.textContent = (data.count || 0).toLocaleString();\n        if (cfg.chart) renderChart(data.series);\n        if (cfg.countries) renderCountries(data.topCountries);\n      })\n      .catch(function () { /* keep last value */ });\n  }\n\n  fetchData();\n  setInterval(fetchData, 60000);\n})();\n</script>\n</body>\n</html>");
}
