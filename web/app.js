/* ═════════════════════════════════════════════════════════════════
   MySQL AI Agent — фронтенд
   WebSocket-чат со стримингом + панель кластеров + алерты
   ═════════════════════════════════════════════════════════════════ */

const App = (() => {

  // ── Состояние ──────────────────────────────────────────────────
  const state = {
    ws:            null,
    wsReady:       false,
    reconnectMs:   1000,
    sessionId:     'web-' + Math.random().toString(36).slice(2, 10),
    clusters:      [],
    currentTab:    'chat',
    streamingEl:   null,   // элемент .msg-body куда стримятся токены
    awaitingReply: false,
    pingTimer:     null,
  };

  const $ = (id) => document.getElementById(id);

  // ═══ WEBSOCKET ══════════════════════════════════════════════════

  // WebSocket не учитывает <base>, поэтому адрес строим от document.baseURI —
  // так он подхватывает префикс nginx (/ai-agent/ws) так же, как fetch ниже.
  function wsUrl() {
    const u = new URL('ws', document.baseURI);
    u.protocol = u.protocol === 'https:' ? 'wss:' : 'ws:';
    return u.href;
  }

  function connect() {
    setConnState('connecting');
    const ws = new WebSocket(wsUrl());
    state.ws = ws;

    ws.onopen = () => {
      state.wsReady     = true;
      state.reconnectMs = 1000;
      setConnState('online');
      // keepalive ping каждые 25с
      clearInterval(state.pingTimer);
      state.pingTimer = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'ping' }));
        }
      }, 25000);
    };

    ws.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }
      handleWsMessage(msg);
    };

    ws.onclose = () => {
      state.wsReady = false;
      setConnState('offline');
      clearInterval(state.pingTimer);
      // Если ждали ответ — закрыть стриминг с ошибкой
      if (state.awaitingReply) finishStreaming('\n\n[соединение прервано — переподключаюсь…]');
      // Экспоненциальный реконнект (max 15s)
      setTimeout(connect, state.reconnectMs);
      state.reconnectMs = Math.min(state.reconnectMs * 1.8, 15000);
    };

    ws.onerror = () => ws.close();
  }

  function handleWsMessage(msg) {
    switch (msg.type) {
      case 'pong':
        break;

      case 'context': {
        // Агент определил кластер/период — показать чип в метаданных
        if (state.streamingEl) {
          const meta = state.streamingEl.parentElement.querySelector('.msg-meta');
          let chips = '';
          if (msg.cluster) chips += `<span class="ctx-chip">${esc(msg.cluster)}</span>`;
          if (msg.hours)   chips += `<span class="ctx-chip">история ${msg.hours}ч</span>`;
          if (chips) meta.innerHTML = 'AI Agent ' + chips;
        }
        break;
      }

      case 'token': {
        if (!state.streamingEl) break;
        // Убрать индикатор "думает" при первом токене
        const think = state.streamingEl.querySelector('.thinking');
        if (think) { think.remove(); state.streamingEl.classList.add('streaming'); }
        state.streamingEl.textContent += msg.text;
        scrollToBottom();
        break;
      }

      case 'done':
        finishStreaming();
        break;

      case 'error':
        finishStreaming('\n[' + (msg.text || 'ошибка') + ']');
        break;
    }
  }

  function finishStreaming(suffix) {
    if (state.streamingEl) {
      const think = state.streamingEl.querySelector('.thinking');
      if (think) think.remove();
      if (suffix) state.streamingEl.textContent += suffix;
      state.streamingEl.classList.remove('streaming');
      state.streamingEl = null;
    }
    state.awaitingReply = false;
    $('input').disabled = false;
    $('send-btn').disabled = false;
    $('input').focus();
    scrollToBottom();
  }

  function setConnState(s) {
    const dot   = $('conn-dot');
    const badge = $('ws-badge');
    dot.className = 'conn-dot ' + (s === 'online' ? 'online' : s === 'offline' ? 'offline' : '');
    badge.textContent = s === 'online' ? 'wss ✓'
                       : s === 'offline' ? 'нет связи'
                       : 'подключение…';
  }

  // ═══ ЧАТ ════════════════════════════════════════════════════════

  function sendMessage() {
    const input = $('input');
    const text  = input.value.trim();
    if (!text || state.awaitingReply) return;

    if (!state.wsReady) {
      addAssistantMsg('Нет соединения с сервером. Переподключаюсь…');
      return;
    }

    // Сообщение пользователя
    addMsg('user', text, 'Вы');

    // Заготовка под ответ со стримингом
    const el = addMsg('assistant', '', 'AI Agent');
    el.innerHTML = '<span class="thinking"><i></i><i></i><i></i></span>';
    state.streamingEl   = el;
    state.awaitingReply = true;

    input.value    = '';
    autoResize(input);
    input.disabled = true;
    $('send-btn').disabled = true;

    state.ws.send(JSON.stringify({
      type:       'message',
      text:       text,
      session_id: state.sessionId,
    }));
  }

  function addMsg(role, text, metaText) {
    const wrap = $('messages');
    const div  = document.createElement('div');
    div.className = 'msg ' + role;
    div.innerHTML =
      `<div class="msg-meta">${esc(metaText)}</div>` +
      `<div class="msg-body"></div>`;
    div.querySelector('.msg-body').textContent = text;
    wrap.appendChild(div);
    scrollToBottom();
    return div.querySelector('.msg-body');
  }

  function addAssistantMsg(text) { return addMsg('assistant', text, 'AI Agent'); }

  function scrollToBottom() {
    const wrap = $('messages');
    wrap.scrollTop = wrap.scrollHeight;
  }

  function autoResize(el) {
    el.style.height = 'auto';
    el.style.height = Math.min(el.scrollHeight, 130) + 'px';
  }

  // ═══ КЛАСТЕРЫ ═══════════════════════════════════════════════════

  async function refreshClusters() {
    try {
      const r = await fetch('clusters');
      const d = await r.json();
      state.clusters = d.clusters || [];
      $('clusters-badge').textContent = state.clusters.length + ' кластеров';
      renderClusterList();
      buildSuggestions();
      // Живые бейджи — параллельно
      state.clusters.forEach(c => refreshClusterBadges(c.name));
    } catch (e) { console.error('clusters:', e); }
  }

  function renderClusterList() {
    const list = $('cluster-list');
    if (!state.clusters.length) {
      list.innerHTML = '<div class="muted pad">Кластеры не настроены.<br>Добавьте через manage_cluster.sh</div>';
      return;
    }
    list.innerHTML = state.clusters.map(c => `
      <div class="cluster-card" id="cc-${c.name}"
           onclick="App.pickCluster('${c.name}')">
        <div class="cname">${esc(c.label)}</div>
        <div class="cmeta">${esc(c.primary_ip)}${c.replica_ip ? ' · ' + esc(c.replica_ip) : ''}</div>
        ${c.description ? `<div class="cdesc">${esc(c.description)}</div>` : ''}
        <div class="cbadges" id="cb-${c.name}">
          <span class="mini-badge">…</span>
        </div>
      </div>`).join('');
  }

  async function refreshClusterBadges(name) {
    try {
      const r = await fetch(`clusters/${name}/status`);
      const d = await r.json();
      const el = $('cb-' + name);
      if (!el) return;

      const p    = d.primary || {};
      const up   = p.mysql_up === '1.0' || p.mysql_up === '1';
      const qps  = num(p.qps);
      const lag  = d.replica ? num(d.replica.replication_lag_s) : null;

      let html = `<span class="mini-badge ${up ? 'ok' : 'crit'}">${up ? '●&nbsp;UP' : '✕&nbsp;DOWN'}</span>`;
      html += `<span class="mini-badge">${qps.toFixed(0)} qps</span>`;
      if (lag !== null) {
        const cls = lag > 60 ? 'crit' : lag > 10 ? 'warn' : 'ok';
        html += `<span class="mini-badge ${cls}">лаг ${lag.toFixed(0)}s</span>`;
      }
      el.innerHTML = html;
    } catch { /* тихо */ }
  }

  function pickCluster(name) {
    document.querySelectorAll('.cluster-card').forEach(el => el.classList.remove('active'));
    $('cc-' + name)?.classList.add('active');
    const cluster = state.clusters.find(c => c.name === name);
    if (!cluster) return;
    const input = $('input');
    input.value = `Как дела в ${cluster.label}?`;
    input.focus();
    autoResize(input);
    if (state.currentTab !== 'chat') showTab('chat');
  }

  function buildSuggestions() {
    const el = $('suggestions');
    const items = [
      ...state.clusters.slice(0, 2).map(c => `Как дела в ${c.label}?`),
      'Какой кластер хуже всего?',
      'Есть ли лаг репликации?',
    ];
    el.innerHTML = items.map(s =>
      `<span class="sug" onclick="App.useSuggestion(this)">${esc(s)}</span>`).join('');
  }

  function useSuggestion(el) {
    const input = $('input');
    input.value = el.textContent;
    input.focus();
    autoResize(input);
  }

  // ═══ ВКЛАДКИ ════════════════════════════════════════════════════

  function showTab(tab) {
    state.currentTab = tab;
    document.querySelectorAll('.tab').forEach(el =>
      el.classList.toggle('active', el.dataset.tab === tab));
    ['chat', 'status', 'alerts'].forEach(t =>
      $('tab-' + t).hidden = (t !== tab));
    if (tab === 'status') loadStatus();
    if (tab === 'alerts') loadAlerts();
  }

  // ═══ СТАТУС ═════════════════════════════════════════════════════

  async function loadStatus() {
    const el = $('status-content');
    el.innerHTML = '<div class="muted">Загрузка…</div>';
    try {
      const r = await fetch('status');
      const d = await r.json();
      if (!d.clusters?.length) {
        el.innerHTML = '<div class="muted">Нет кластеров</div>';
        return;
      }
      el.innerHTML = d.clusters.map(renderClusterDetail).join('');
    } catch (e) {
      el.innerHTML = `<div class="muted" style="color:var(--red)">Ошибка: ${esc(e.message)}</div>`;
    }
  }

  function renderClusterDetail(s) {
    const p  = s.primary || {};
    const up = p.mysql_up === '1.0' || p.mysql_up === '1';

    const m = (label, value, warn, crit, unit = '') => {
      const v   = num(value);
      const cls = isNaN(v) ? '' : v >= crit ? 'crit' : v >= warn ? 'warn' : 'good';
      const txt = isNaN(v) ? '—' : v.toFixed(1) + unit;
      return `<div class="metric"><div class="lbl">${label}</div>
              <div class="val ${cls}">${txt}</div></div>`;
    };

    const mInv = (label, value, warnBelow, unit = '') => {
      const v   = num(value);
      const cls = isNaN(v) ? '' : v < warnBelow ? 'warn' : 'good';
      const txt = isNaN(v) ? '—' : v.toFixed(1) + unit;
      return `<div class="metric"><div class="lbl">${label}</div>
              <div class="val ${cls}">${txt}</div></div>`;
    };

    let replHtml = '';
    if (s.replica) {
      const rp    = s.replica;
      const lag   = num(rp.replication_lag_s);
      const ioUp  = rp.replication_io_up  === '1.0' || rp.replication_io_up  === '1';
      const sqlUp = rp.replication_sql_up === '1.0' || rp.replication_sql_up === '1';
      const lagCls = lag > 60 ? 'crit' : lag > 10 ? 'warn' : 'good';
      replHtml = `
        <div class="metric"><div class="lbl">Repl IO/SQL</div>
          <div class="val ${ioUp && sqlUp ? 'good' : 'crit'}">${ioUp?'✓':'✗'}/${sqlUp?'✓':'✗'}</div></div>
        <div class="metric"><div class="lbl">Лаг репл.</div>
          <div class="val ${lagCls}">${isNaN(lag)?'—':lag.toFixed(0)+'s'}</div></div>`;
    }

    return `
      <div class="cluster-detail">
        <h3>${esc(s.cluster_label)}
          <span class="sub">(${esc(s.cluster_name)})</span>
          <span class="mini-badge ${up ? 'ok' : 'crit'}">${up ? '● Online' : '✕ Down'}</span>
        </h3>
        <div class="metrics-grid">
          <div class="metric"><div class="lbl">QPS</div>
            <div class="val">${num(p.qps).toFixed(1)}</div></div>
          ${m('Slow q/s',   p.slow_qps,        1, 5)}
          ${m('Соединения', p.connections_pct, 75, 90, '%')}
          ${mInv('InnoDB hit', p.innodb_hit_pct, 95, '%')}
          ${m('CPU',        p.cpu_pct,          75, 90, '%')}
          ${m('Memory',     p.memory_pct,       80, 92, '%')}
          ${mInv('Disk free', p.disk_free_pct,  15, '%')}
          ${m('IO wait',    p.iowait_pct,       15, 30, '%')}
          ${replHtml}
        </div>
      </div>`;
  }

  // ═══ АЛЕРТЫ ═════════════════════════════════════════════════════

  async function loadAlerts() {
    const el = $('alerts-content');
    el.innerHTML = '<div class="muted">Загрузка…</div>';
    try {
      const r = await fetch('alerts/history?limit=30');
      const d = await r.json();

      // Счётчик на вкладке
      const cnt = $('alert-count');
      if (d.total > 0) { cnt.textContent = d.total; cnt.classList.add('show'); }
      else             { cnt.classList.remove('show'); }

      if (!d.items?.length) {
        el.innerHTML = '<div class="muted">Алертов ещё не было — это хорошо ✓</div>';
        return;
      }
      el.innerHTML = d.items.map((it, i) => `
        <div class="alert-item">
          <div class="ahead">
            <span class="aname">${esc(it.alert)}</span>
            <span class="mini-badge ${it.severity === 'critical' ? 'crit' : 'warn'}">${esc(it.severity)}</span>
          </div>
          <div class="ameta">${esc(it.cluster_label || it.instance)} · ${esc((it.timestamp||'').replace('T',' ').slice(0,19))} UTC</div>
          <div class="asummary">${esc(it.summary)}</div>
          <button class="expand-link" onclick="App.toggleAnalysis(${i}, this)">▸ Анализ ИИ</button>
          <div class="analysis-box" id="ab-${i}">${esc(it.analysis)}</div>
        </div>`).join('');
    } catch (e) {
      el.innerHTML = `<div class="muted" style="color:var(--red)">Ошибка: ${esc(e.message)}</div>`;
    }
  }

  function toggleAnalysis(i, btn) {
    const box = $('ab-' + i);
    const open = box.classList.toggle('open');
    btn.textContent = open ? '▾ Скрыть' : '▸ Анализ ИИ';
  }

  // ═══ УТИЛИТЫ ════════════════════════════════════════════════════

  function esc(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function num(v) { const n = parseFloat(v); return isNaN(n) ? NaN : n; }

  // ═══ ИНИЦИАЛИЗАЦИЯ ══════════════════════════════════════════════

  function init() {
    connect();
    refreshClusters();
    setInterval(refreshClusters, 60000);
    setInterval(() => {
      if (state.currentTab === 'status') loadStatus();
    }, 30000);

    const input = $('input');
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
      }
    });
    input.addEventListener('input', () => autoResize(input));
    $('send-btn').addEventListener('click', sendMessage);
  }

  document.addEventListener('DOMContentLoaded', init);

  // Публичный API для onclick в HTML
  return { showTab, pickCluster, useSuggestion, toggleAnalysis,
           loadStatus, loadAlerts, refreshClusters };
})();
