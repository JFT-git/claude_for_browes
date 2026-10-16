"use strict";
(() => {
  // ------------------------------------------------------------ token ----
  // The launch URL carries the token in its fragment (never sent to a server);
  // it moves to sessionStorage and leaves the address bar.
  const TOKEN_KEY = "claude-gateway-dashboard-token";
  let token = "";
  const fromHash = /(?:^#|&)token=([A-Za-z0-9_-]{16,})/.exec(location.hash);
  if (fromHash) {
    token = fromHash[1];
    try { sessionStorage.setItem(TOKEN_KEY, token); } catch (_) { /* memory only */ }
    history.replaceState(null, "", location.pathname);
  } else {
    try { token = sessionStorage.getItem(TOKEN_KEY) || ""; } catch (_) { token = ""; }
  }

  // ------------------------------------------------------------ helpers ----
  const $ = id => document.getElementById(id);
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : v);
    }
    for (const kid of kids.flat()) if (kid !== null && kid !== undefined && kid !== false) el.append(kid instanceof Node ? kid : String(kid));
    return el;
  }
  // replaceChildren() would print "null" for skipped optional parts.
  const fill = (el, ...kids) => el.replaceChildren(...kids.flat().filter(k => k !== null && k !== undefined && k !== false));
  const SVG = "http://www.w3.org/2000/svg";
  function s(tag, attrs) {
    const el = document.createElementNS(SVG, tag);
    for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
    return el;
  }
  const css = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

  const nf = new Intl.NumberFormat("ru-RU");
  const num = n => nf.format(Math.round(Number(n) || 0));
  function bytes(n) {
    n = Number(n) || 0;
    const u = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i && n < 10 ? n.toFixed(1).replace(".", ",") : Math.round(n)) + " " + u[i];
  }
  function ago(value, now) {
    if (!value) return "";
    const sec = Math.max(0, Math.round((now - (typeof value === "number" ? value : Date.parse(value))) / 1000));
    if (sec < 45) return "только что";
    if (sec < 3600) return Math.round(sec / 60) + " мин назад";
    if (sec < 86400) return Math.round(sec / 3600) + " ч назад";
    return Math.round(sec / 86400) + " дн назад";
  }
  function duration(sec) {
    sec = Math.max(0, Math.round(sec || 0));
    const d = Math.floor(sec / 86400), hrs = Math.floor(sec % 86400 / 3600), min = Math.floor(sec % 3600 / 60);
    if (d) return d + " дн " + hrs + " ч";
    if (hrs) return hrs + " ч " + min + " мин";
    return min + " мин";
  }
  const hhmm = t => new Date(t).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" });
  const plural = (n, one, few, many) => {
    const m10 = n % 10, m100 = n % 100;
    return m10 === 1 && m100 !== 11 ? one : m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14) ? few : many;
  };

  function toast(text, bad) {
    const el = $("toast");
    el.textContent = text;
    el.className = "toast" + (bad ? " bad" : "");
    el.hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => { el.hidden = true; }, bad ? 7000 : 3500);
  }

  async function api(method, url, body) {
    const headers = { "x-dashboard-token": token };
    if (body !== undefined) headers["content-type"] = "application/json";
    const res = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), cache: "no-store" });
    let data = {};
    try { data = await res.json(); } catch (_) { data = {}; }
    if (!res.ok) { const e = new Error(data.error || "HTTP " + res.status); e.status = res.status; throw e; }
    return data;
  }

  // ------------------------------------------------------------ state ----
  let state = null;
  let rangeMin = 60;
  try { rangeMin = Number(localStorage.getItem("claude-gateway-dashboard-range")) || 60; } catch (_) { /* default */ }

  function series(name) {
    const fields = state.history.fields || [];
    const idx = fields.indexOf(name);
    const byT = new Map((state.history.rows || []).map(r => [r[0], r]));
    const end = Math.floor(state.now / 60000) * 60000;
    const out = [], times = [];
    for (let t = end - (rangeMin - 1) * 60000; t <= end; t += 60000) {
      const row = byT.get(t);
      times.push(t);
      out.push(row && idx >= 0 ? Number(row[idx]) || 0 : 0);
    }
    return { times, values: out };
  }
  function lastMinutes(name, minutes, skipCurrent) {
    const fields = state.history.fields || [];
    const idx = fields.indexOf(name);
    if (idx < 0) return [];
    const end = Math.floor(state.now / 60000) * 60000 - (skipCurrent ? 60000 : 0);
    return (state.history.rows || []).filter(r => r[0] <= end && r[0] > end - minutes * 60000).map(r => Number(r[idx]) || 0);
  }
  const sum = a => a.reduce((x, y) => x + y, 0);

  // ------------------------------------------------------------ charts ----
  function niceMax(v) {
    if (v <= 0) return 1;
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
    return 10 * p;
  }

  function sparkline(values, color) {
    const svg = s("svg", { viewBox: "0 0 100 30", preserveAspectRatio: "none", "aria-hidden": "true" });
    if (values.length < 2) return svg;
    const max = Math.max(1, ...values);
    const pts = values.map((v, i) => [values.length === 1 ? 100 : i / (values.length - 1) * 100, 28 - v / max * 26]);
    const line = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(2) + " " + p[1].toFixed(2)).join(" ");
    svg.append(s("path", { d: line + " L100 30 L0 30 Z", fill: color, "fill-opacity": "0.12", stroke: "none" }));
    svg.append(s("path", { d: line, fill: "none", stroke: color, "stroke-width": "1.5", "vector-effect": "non-scaling-stroke" }));
    return svg;
  }

  function lineChart(figId, lines, times, fmt) {
    const fig = $(figId);
    const svg = fig.querySelector("svg");
    const legend = fig.querySelector(".legend");
    legend.replaceChildren(...lines.map(l => h("span", {}, h("i", { class: "sw-" + l.key }), l.name)));
    legend.querySelectorAll("i").forEach((el, i) => { el.style.background = lines[i].color; });
    const W = Math.max(200, svg.clientWidth || 400), H = 150, L = 46, R = 6, T = 6, B = 18;
    svg.setAttribute("viewBox", "0 0 " + W + " " + H);
    svg.replaceChildren();
    const max = niceMax(Math.max(0, ...lines.flatMap(l => l.values)));
    const x = i => L + (times.length < 2 ? 0 : i / (times.length - 1) * (W - L - R));
    const y = v => T + (1 - v / max) * (H - T - B);
    for (const f of [0, 0.5, 1]) {
      svg.append(s("line", { x1: L, x2: W - R, y1: y(max * f), y2: y(max * f), class: "grid" }));
      const label = s("text", { x: L - 6, y: y(max * f) + 3.5, "text-anchor": "end", class: "axis" });
      label.textContent = fmt(max * f, true);
      svg.append(label);
    }
    const marks = times.length > 1 ? [0, Math.floor((times.length - 1) / 2), times.length - 1] : [0];
    for (const i of marks) {
      const t = s("text", { x: x(i), y: H - 4, "text-anchor": i === 0 ? "start" : i === times.length - 1 ? "end" : "middle", class: "axis" });
      t.textContent = times.length ? hhmm(times[i]) : "";
      svg.append(t);
    }
    lines.forEach((l, li) => {
      const d = l.values.map((v, i) => (i ? "L" : "M") + x(i).toFixed(1) + " " + y(v).toFixed(1)).join(" ");
      if (li === 0 && l.values.length) svg.append(s("path", { d: d + " L" + x(l.values.length - 1) + " " + y(0) + " L" + x(0) + " " + y(0) + " Z", fill: l.color, "fill-opacity": "0.10" }));
      svg.append(s("path", { d, fill: "none", stroke: l.color, "stroke-width": "1.6", "stroke-linejoin": "round", "stroke-dasharray": l.dashed ? "4 3" : "none" }));
    });
    // Hover: vertical cursor and the values of that minute.
    const cursor = s("line", { y1: T, y2: H - B, class: "cursor", visibility: "hidden" });
    svg.append(cursor);
    let tip = fig.querySelector(".tip");
    if (!tip) { tip = h("div", { class: "tip", hidden: true }); fig.append(tip); }
    const hit = s("rect", { x: L, y: 0, width: W - L - R, height: H - B, fill: "transparent" });
    svg.append(hit);
    hit.addEventListener("mousemove", ev => {
      const box = svg.getBoundingClientRect();
      const px = (ev.clientX - box.left) / box.width * W;
      const i = Math.max(0, Math.min(times.length - 1, Math.round((px - L) / (W - L - R) * (times.length - 1))));
      cursor.setAttribute("x1", x(i)); cursor.setAttribute("x2", x(i)); cursor.setAttribute("visibility", "visible");
      tip.replaceChildren(h("div", { text: hhmm(times[i]) }), ...lines.map(l => h("div", { text: l.name + ": " + fmt(l.values[i]) })));
      tip.hidden = false;
      const fx = (x(i) / W) * box.width;
      tip.style.left = Math.min(box.width - tip.offsetWidth, Math.max(0, fx + 10)) + "px";
      tip.style.top = "26px";
    });
    hit.addEventListener("mouseleave", () => { cursor.setAttribute("visibility", "hidden"); tip.hidden = true; });
  }

  function renderCharts() {
    if (!state || !state.history.fields) return;
    const c = [css("--c1"), css("--c2"), css("--c3"), css("--c4"), css("--c5")];
    const req = series("req");
    const intFmt = (v, axis) => axis && v >= 1000 ? Math.round(v / 1000) + "k" : num(v);
    lineChart("chart-req", [
      { key: "req", name: "все", values: req.values, color: c[0] },
      { key: "s4", name: "4xx", values: series("s4").values, color: c[3] },
      { key: "s5", name: "5xx", values: series("s5").values, color: c[4] },
      { key: "r429", name: "429 от Claude", values: series("r429").values, color: c[1], dashed: true },
    ], req.times, intFmt);
    lineChart("chart-conn", [
      { key: "inflight", name: "запросы в работе", values: series("inflight").values, color: c[0] },
      { key: "ws", name: "WebSocket", values: series("ws").values, color: c[1] },
      { key: "tunnels", name: "туннели CONNECT", values: series("tunnels").values, color: c[2] },
      { key: "users", name: "пользователи", values: series("users").values, color: c[3], dashed: true },
    ], req.times, intFmt);
    lineChart("chart-traffic", [
      { key: "out", name: "к пользователям", values: series("bytesOut").values, color: c[1] },
      { key: "in", name: "от пользователей", values: series("bytesIn").values, color: c[2] },
    ], req.times, v => bytes(v));
    lineChart("chart-latency", [
      { key: "ttfb", name: "ответ Claude, среднее", values: series("ttfbAvg").values, color: c[0] },
      { key: "ttfbMax", name: "максимум", values: series("ttfbMax").values, color: c[3], dashed: true },
      { key: "lag", name: "задержка шлюза p99", values: series("lagP99").values, color: c[2] },
    ], req.times, v => num(v) + " мс");
  }

  // ------------------------------------------------------------ render ----
  function setConn() {
    const el = $("conn");
    const fresh = state.connected && state.now - state.lastUpdate < 30000;
    el.className = "conn " + (fresh ? "ok" : "bad");
    $("conn-text").textContent = fresh ? "на связи · " + ago(state.lastUpdate, state.now) : "нет связи";
    el.title = state.error || "";
  }

  function alerts() {
    const out = [];
    const g = state.gateway, cfg = state.config || {};
    if (!state.connected) out.push(["bad", "Нет связи с сервером по SSH", state.error ? ": " + state.error + "." : ".", " Панель переподключается сама."]);
    if (state.gatewayError) out.push(["bad", "Шлюз не ответил на служебный запрос.", " Контейнер gateway не запущен или на сервере старая версия gateway.js без служебного API."]);
    const fd = state.frontdoor.latest;
    if (fd && fd.capacity_rejected > 0) out.push(["bad", "Front door отклонил " + num(fd.capacity_rejected) + " " + plural(fd.capacity_rejected, "соединение", "соединения", "соединений") + " за 30 с:", " все 1024 слота были заняты."]);
    if (g && g.now && g.now.connectReady === false) out.push(["warn", "Защищённый маршрут CONNECT не готов:", " артефакты и hCaptcha не загрузятся. Проверьте IP-сертификат Caddy."]);
    const gw = state.containers.find(x => x.name === "gateway");
    if (gw && gw.memLimit && gw.memUsed / gw.memLimit > 0.8) out.push(["warn", "Шлюзу не хватает памяти:", " " + bytes(gw.memUsed) + " из " + bytes(gw.memLimit) + "."]);
    if (g) {
      const legacy = g.users.filter(u => u.encryption === "v1" || u.encryption === "plain").map(u => u.user);
      if (legacy.length) out.push(["warn", "Cookie на старом общем ключе: " + legacy.join(", ") + ".", " Перешифруются ключом от пароля при следующем запросе пользователя."]);
      const expired = g.users.filter(u => u.session === "expired").map(u => u.user);
      if (expired.length) out.push(["warn", "Сессия Claude истекла: " + expired.join(", ") + ".", " Пользователю нужно снова войти в Claude."]);
      if (g.bans.length) out.push(["info", "Заблокировано IP: " + g.bans.length + ".", " Список и разблокировка — в разделе «Защита»."]);
    }
    const host = state.host;
    if (host.disk_total_kb && host.disk_used_kb / host.disk_total_kb > 0.9) out.push(["warn", "Диск сервера заполнен на " + Math.round(host.disk_used_kb / host.disk_total_kb * 100) + "%."]);
    if (host.mem_total_kb && host.mem_available_kb / host.mem_total_kb < 0.1) out.push(["warn", "На сервере осталось мало памяти:", " " + bytes(host.mem_available_kb * 1024) + " свободно."]);
    if (cfg.frontdoor_diagnostics !== undefined && cfg.frontdoor_diagnostics !== "1") out.push(["info", "Счётчики front door выключены.", " Добавьте FRONTDOOR_DIAGNOSTICS=1 в .env и перезапустите frontdoor, чтобы видеть занятость 1024 слотов."]);
    fill($("alerts"), out.map(([level, strong, ...rest]) => h("div", { class: "alert " + level }, h("div", {}, h("b", { text: strong }), rest.join("")))));
  }

  function kpi(label, value, unit, hint, spark, color, level) {
    return h("div", { class: "kpi" + (level ? " " + level : "") },
      h("div", { class: "label", text: label }),
      h("div", { class: "value" }, value, unit ? h("small", { text: unit }) : null),
      h("div", { class: "hint", text: hint, title: hint }),
      spark ? sparkline(spark, color) : null);
  }

  function kpis() {
    const g = state.gateway;
    const c = [css("--c1"), css("--c2"), css("--c3"), css("--c4"), css("--c5")];
    if (!g) { $("kpis").replaceChildren(); return; }
    const reqLast = lastMinutes("req", 1, true)[0] || 0;
    const fd = state.frontdoor.latest;
    const fdSeries = state.frontdoor.series.map(p => p.active_peak || 0);
    const s5 = sum(lastMinutes("s5", 60)), r429 = sum(lastMinutes("r429", 60)), upErr = sum(lastMinutes("upErr", 60));
    const ttfb = lastMinutes("ttfbAvg", 5).filter(Boolean);
    const ttfbAvg = ttfb.length ? sum(ttfb) / ttfb.length : 0;
    const gw = state.containers.find(x => x.name === "gateway");
    const cpuSeries = state.cpu.map(p => p.gateway || 0);
    fill($("kpis"),
      kpi("Запросы в минуту", num(reqLast), "", "за 24 ч: " + num(sum(lastMinutes("req", 1440))), series("req").values.slice(-60), c[0]),
      fd ? kpi("Соединения front door", num(fd.active), "/ 1024", "пик " + num(fd.active_peak) + " · отказов " + num(fd.capacity_rejected), fdSeries, c[1], fd.capacity_rejected ? "bad" : fd.active_peak > 800 ? "warn" : "")
        : kpi("Соединения front door", "—", "", "счётчики выключены", null),
      kpi("WebSocket сейчас", num(g.now.websockets), "", "туннелей " + num(g.now.tunnels) + " из " + num(g.limits.tunnels), series("ws").values.slice(-60), c[2]),
      kpi("Ошибки 5xx за час", num(s5), "", "429: " + num(r429) + " · сбоев связи: " + num(upErr), series("s5").values.slice(-60), c[4], s5 ? "warn" : ""),
      kpi("Ответ Claude", ttfbAvg ? num(ttfbAvg) : "—", ttfbAvg ? "мс" : "", "среднее за 5 мин", series("ttfbAvg").values.slice(-60), c[3]),
      gw ? kpi("Нагрузка шлюза", (gw.cpu < 10 ? gw.cpu.toFixed(1).replace(".", ",") : Math.round(gw.cpu)) + "%", "CPU", "память " + bytes(gw.memUsed) + " / " + bytes(gw.memLimit), cpuSeries, c[0], gw.cpu > 80 ? "warn" : "")
        : kpi("Нагрузка шлюза", "—", "", "нет данных docker stats", null),
    );
  }

  function users() {
    const g = state.gateway, cfg = state.config || {};
    const configured = (cfg.users || "").split(" ").filter(Boolean);
    const admins = (cfg.admins || "").split(" ").filter(Boolean);
    const info = new Map((g ? g.users : []).map(u => [u.user, u]));
    const names = Array.from(new Set([...configured, ...info.keys()])).sort((a, b) => a.localeCompare(b));
    const body = $("users");
    if (!names.length) { body.replaceChildren(h("tr", {}, h("td", { colspan: 8, class: "empty", text: "Пользователей пока нет." }))); return; }
    body.replaceChildren(...names.map(name => {
      const u = info.get(name) || {};
      const hasLogin = configured.includes(name);
      const session = { ok: ["ok", "активна"], expired: ["warn", "истекла"], none: ["", "не входил"] }[u.session] || ["", "—"];
      const enc = { v2: ["ok", "зашифрованы паролем"], v1: ["warn", "старый общий ключ"], plain: ["bad", "без шифрования"] }[u.encryption] || ["", "—"];
      const a = u.active || {};
      const live = (a.requests || 0) + (a.websockets || 0) + (a.tunnels || 0);
      const recent = u.lastSeen && state.now - Date.parse(u.lastSeen) < 5 * 60000;
      const now = live ? ["ok", "онлайн"] : recent ? ["ok", "недавно"] : ["", "—"];
      const detail = live ? [a.websockets ? "WS " + a.websockets : "", a.tunnels ? "туннели " + a.tunnels : "", a.requests ? "запросы " + a.requests : ""].filter(Boolean).join(" · ") : "";
      return h("tr", {},
        h("td", { "data-label": "Пользователь" }, h("span", { class: "name", text: name }), admins.includes(name) ? h("span", { class: "badge", text: "админ" }) : null,
          !hasLogin ? h("span", { class: "badge", text: "нет входа в шлюз", title: "Файл cookie есть, а пароля в Caddyfile нет" }) : null),
        h("td", { "data-label": "Сессия Claude" }, h("span", { class: "pill " + session[0], text: session[1] })),
        h("td", { "data-label": "Cookie на диске" }, h("span", { class: "pill " + enc[0], text: enc[1], title: u.unlocked ? "Ключ сейчас в памяти шлюза" : "Ключа нет в памяти: файл не расшифровать без пароля" })),
        h("td", { "data-label": "Сейчас", title: detail }, h("span", {}, h("span", { class: "pill " + now[0], text: now[1] }), detail ? h("span", { class: "muted", text: " " + detail }) : null)),
        h("td", { "data-label": "Был активен", class: u.lastSeen ? "" : "muted", text: u.lastSeen ? ago(u.lastSeen, state.now) : "—",
          title: u.lastSeen ? new Date(u.lastSeen).toLocaleString("ru-RU") : "Запросов не было с запуска шлюза" }),
        h("td", { "data-label": "Запросы 24 ч", class: "num", text: u.requests24h !== undefined ? num(u.requests24h) : "—" }),
        h("td", { "data-label": "Трафик 24 ч", class: "num", text: u.bytes24h !== undefined ? bytes(u.bytes24h) : "—" }),
        h("td", { class: "actions" }, hasLogin ? [
          h("button", { type: "button", class: "small", text: "Новый пароль", onclick: () => resetUser(name) }),
          h("button", { type: "button", class: "small danger", text: "Удалить", onclick: () => removeUser(name) }),
        ] : null));
    }));
  }

  function barRow(label, ratio, text) {
    const bar = h("div", { class: "bar" + (ratio > 0.9 ? " bad" : ratio > 0.75 ? " warn" : "") }, h("span"));
    bar.firstChild.style.width = Math.max(0, Math.min(100, ratio * 100)).toFixed(1) + "%";
    return h("div", { class: "row" }, h("div", { class: "k", text: label }), bar, h("div", { class: "v", text }));
  }

  function resources() {
    const rows = [];
    const label = { gateway: "Шлюз", caddy: "Caddy", frontdoor: "Front door" };
    const cpus = Number(state.host.cpus) || 1;
    for (const c of state.containers) {
      rows.push(barRow((label[c.name] || c.name) + " · CPU", c.cpu / (100 * cpus), c.cpu.toFixed(1).replace(".", ",") + "%"));
      if (c.memLimit) rows.push(barRow((label[c.name] || c.name) + " · память", c.memUsed / c.memLimit, bytes(c.memUsed) + " / " + bytes(c.memLimit)));
    }
    const host = state.host;
    const facts = [];
    if (host.load) {
      const load = host.load.split(" ").map(Number);
      rows.push(barRow("Сервер · нагрузка", (load[0] || 0) / cpus, host.load.replace(/ /g, " · ") + " на " + cpus + " CPU"));
    }
    if (host.mem_total_kb) rows.push(barRow("Сервер · память", 1 - host.mem_available_kb / host.mem_total_kb, bytes((host.mem_total_kb - host.mem_available_kb) * 1024) + " / " + bytes(host.mem_total_kb * 1024)));
    if (host.disk_total_kb) rows.push(barRow("Сервер · диск", host.disk_used_kb / host.disk_total_kb, bytes(host.disk_used_kb * 1024) + " / " + bytes(host.disk_total_kb * 1024)));
    const g = state.gateway;
    if (host.uptime_sec) facts.push(["Сервер работает", duration(Number(host.uptime_sec))]);
    if (g) {
      facts.push(["Шлюз запущен", duration(g.gateway.uptimeSec) + " назад · Node " + g.gateway.node]);
      facts.push(["Кэш ассетов", num(g.cache.items) + " файлов · " + bytes(g.cache.bytes) + " из " + bytes(g.limits.cacheBytes)]);
      facts.push(["Всего с запуска", num(g.totals.req) + " запросов · " + bytes(g.totals.bytesOut) + " отдано"]);
    }
    fill($("resources"),
      rows.length ? h("div", { class: "rows" }, rows) : h("div", { class: "empty", text: "Нет данных docker stats." }),
      facts.length ? h("div", { class: "sep" }) : null,
      facts.length ? h("dl", { class: "facts" }, facts.map(([k, v]) => h("div", {}, h("dt", { text: k }), h("dd", { text: v })))) : null);
  }

  function security() {
    const g = state.gateway, cfg = state.config || {};
    const facts = [];
    if (g) {
      const j = g.encryption.jars, total = j.v2 + j.v1 + j.plain;
      facts.push(["Cookie Claude на диске", total ? j.v2 + " из " + total + " зашифрованы ключом от пароля пользователя" + (j.v1 + j.plain ? "; остальные перейдут при следующем входе" : "") : "файлов пока нет"]);
      facts.push(["Как шифруются", "AES-256-GCM, ключ из пароля через " + g.encryption.kdf + ". Без пароля файлы, бэкапы и снимки диска не расшифровать."]);
      facts.push(["Ключи в памяти", num(g.now.jarKeysInMemory) + " · стираются через " + g.encryption.keyIdleMinutes + " мин без запросов"]);
      facts.push(["Маршрут CONNECT", g.now.connectReady ? "готов · токенов: " + num(g.now.proxySessions) : "не готов"]);
    }
    if (cfg.legacy_key) facts.push(["Старый ключ COOKIES_KEY", cfg.legacy_key === "yes" ? (g && g.encryption.jars.v1 ? "нужен для " + g.encryption.jars.v1 + " старых файлов" : "в .env, новым файлам не нужен") : "не задан"]);
    if (cfg.backups !== undefined) {
      const m = /^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})/.exec(cfg.backup_latest || "");
      facts.push(["Бэкапы", (Number(cfg.backups) ? num(cfg.backups) + " шт." : "нет") + (m ? " · последний " + m[3] + "." + m[2] + "." + m[1] + " " + m[4] + ":" + m[5] : "")]);
    }
    const bans = g ? g.bans : [];
    fill($("security"),
      h("dl", { class: "facts" }, facts.map(([k, v]) => h("div", {}, h("dt", { text: k }), h("dd", { text: v })))),
      h("div", { class: "sep" }),
      h("div", { class: "muted", text: bans.length ? "Заблокированные IP (10 неверных паролей за 15 мин):" : "Заблокированных IP нет." }),
      bans.length ? h("div", { class: "bans" }, bans.map(b => h("div", { class: "ban" },
        h("span", {}, h("b", { text: b.ip }), h("span", { class: "muted", text: " до " + hhmm(Date.parse(b.until)) })),
        h("button", { type: "button", class: "small", text: "Разблокировать", onclick: () => unban(b.ip) })))) : null);
  }

  function render() {
    if (!state) return;
    const host = (state.config && state.config.public_host) || (state.gateway && state.gateway.gateway.publicHost) || "";
    $("host").textContent = (host ? host + " · " : "") + "SSH " + state.target;
    document.title = (host || "Шлюз Claude") + " — панель";
    setConn();
    alerts();
    kpis();
    renderCharts();
    users();
    resources();
    security();
  }

  // ------------------------------------------------------------ actions ----
  function showSecret(title, result) {
    const host = (state && state.config && state.config.public_host) || "";
    const items = [["Логин", result.user], ["Пароль", result.password]];
    if (host) items.push(["Шлюз", host], ["Расширение", "https://" + host + "/__ext/"]);
    $("secret-title").textContent = title;
    $("creds").replaceChildren(...items.map(([k, v]) => h("div", {}, h("dt", { text: k }), h("dd", { text: v }),
      h("button", { type: "button", class: "small", text: "Копировать", onclick: () => copy(v) }))));
    $("copy-all").onclick = () => copy(items.map(([k, v]) => k + ": " + v).join("\n"));
    $("secret-dialog").showModal();
  }
  // The password leaves the page as soon as the dialog closes.
  $("secret-dialog").addEventListener("close", () => { $("creds").replaceChildren(); $("copy-all").onclick = null; });

  async function copy(text) {
    try { await navigator.clipboard.writeText(text); toast("Скопировано"); }
    catch (_) { toast("Не удалось скопировать: выделите текст вручную", true); }
  }

  function confirmDialog({ title, text, typeName, ok }) {
    return new Promise(resolve => {
      const dlg = $("confirm-dialog"), input = $("confirm-input");
      $("confirm-title").textContent = title;
      $("confirm-text").textContent = text;
      $("confirm-ok").textContent = ok;
      $("confirm-type-wrap").hidden = !typeName;
      input.value = "";
      input.required = !!typeName;
      input.setCustomValidity(typeName ? "Введите имя пользователя" : "");
      input.oninput = () => input.setCustomValidity(input.value === typeName ? "" : "Имя не совпадает");
      dlg.returnValue = "";  // Esc keeps the previous value otherwise
      dlg.onclose = () => resolve(dlg.returnValue === "ok" && (!typeName || input.value === typeName));
      dlg.showModal();
      if (typeName) input.focus();
    });
  }

  async function withBusy(button, fn) {
    if (button) button.disabled = true;
    try { await fn(); } catch (e) { toast(e.message, true); } finally { if (button) button.disabled = false; }
  }

  $("add-form").addEventListener("submit", ev => {
    ev.preventDefault();
    const input = $("add-name"), name = input.value.trim();
    withBusy(ev.submitter, async () => {
      const r = await api("POST", "/api/users", { name });
      input.value = "";
      showSecret("Пользователь " + r.user + " создан", r);
      poll();
    });
  });

  async function resetUser(name) {
    const yes = await confirmDialog({ title: "Новый пароль для " + name + "?", ok: "Сменить пароль",
      text: "Старый пароль перестанет работать, подключения пользователя разорвутся. Сессия Claude сохранится, если пользователь заходил в последний час; иначе ему нужно будет снова войти в Claude." });
    if (!yes) return;
    await withBusy(null, async () => {
      const r = await api("POST", "/api/users/" + encodeURIComponent(name) + "/reset", {});
      showSecret("Новый пароль для " + r.user, r);
      poll();
    });
  }

  async function removeUser(name) {
    const yes = await confirmDialog({ title: "Удалить " + name + "?", ok: "Удалить", typeName: name,
      text: "Доступ к шлюзу закроется сразу, текущие соединения пользователя оборвутся, файл с его cookie Claude будет стёрт. Остальные пользователи не заметят изменений." });
    if (!yes) return;
    await withBusy(null, async () => {
      await api("DELETE", "/api/users/" + encodeURIComponent(name), { confirm: name });
      toast("Пользователь " + name + " удалён");
      poll();
    });
  }

  async function unban(ip) {
    await withBusy(null, async () => {
      await api("POST", "/api/bans/" + encodeURIComponent(ip) + "/clear", {});
      toast("IP " + ip + " разблокирован");
      poll();
    });
  }

  $("range").addEventListener("click", ev => {
    const b = ev.target.closest("button[data-min]");
    if (!b) return;
    rangeMin = Number(b.dataset.min);
    try { localStorage.setItem("claude-gateway-dashboard-range", String(rangeMin)); } catch (_) { /* per-tab only */ }
    for (const x of $("range").querySelectorAll("button")) x.classList.toggle("on", x === b);
    renderCharts();
  });
  for (const x of $("range").querySelectorAll("button")) x.classList.toggle("on", Number(x.dataset.min) === rangeMin);

  let resizeTimer;
  new ResizeObserver(() => { clearTimeout(resizeTimer); resizeTimer = setTimeout(renderCharts, 100); }).observe(document.querySelector(".charts"));

  // ------------------------------------------------------------ polling ----
  let pollTimer;
  async function poll() {
    clearTimeout(pollTimer);
    try {
      state = await api("GET", "/api/state");
      $("notice").hidden = true;
      render();
    } catch (e) {
      const n = $("notice");
      n.hidden = false;
      n.textContent = e.status === 401
        ? "Нет доступа: откройте ссылку с токеном, которую напечатал dashboard.js в терминале."
        : "Локальный процесс панели не отвечает (" + e.message + "). Запустите dashboard.js снова.";
      $("conn").className = "conn bad";
      $("conn-text").textContent = "нет связи";
    }
    pollTimer = setTimeout(poll, 5000);
  }
  if (!token) {
    const n = $("notice");
    n.hidden = false;
    n.textContent = "Нет доступа: откройте ссылку с токеном, которую напечатал dashboard.js в терминале.";
  } else poll();
})();
