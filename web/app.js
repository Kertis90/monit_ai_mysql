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
    clientId:      null,   // стабильный id браузера (localStorage)
    fingerprint:   '',     // грубый отпечаток — только как подсказка
    isAdmin:       false,  // от /api/me — показывать ли действия админа
    clusters:      [],
    currentTab:    'chat',
    streamingEl:   null,   // элемент .msg-body куда стримятся токены
    streamBuf:     '',     // сырой текст ответа до разметки
    lastQuestion:  '',     // вопрос — сохраняем вместе с оценкой
    pendingCharts: null,   // графики, ждущие конца ответа
    awaitingReply: false,
    pingTimer:     null,
  };

  const $ = (id) => document.getElementById(id);

  // ═══ ИДЕНТИФИКАЦИЯ БРАУЗЕРА ════════════════════════════

  // Логина в системе нет, поэтому история чата привязана к браузеру.
  // Основной идентификатор — случайный UUID в localStorage: он стабилен между
  // перезагрузками и уникален. Чистый отпечаток для этого не годится: на
  // одинаковых корпоративных машинах он совпадает, и пользователи увидели бы
  // чужую переписку. Отпечаток храним рядом только как диагностическую метку.
  const CLIENT_KEY = 'mysql-ai-agent.client_id';

  function loadClientId() {
    let id = null;
    try { id = localStorage.getItem(CLIENT_KEY); } catch (e) { /* приватный режим */ }
    if (!id) {
      id = (crypto.randomUUID ? crypto.randomUUID()
                              : 'c-' + Math.random().toString(36).slice(2) + Date.now());
      try { localStorage.setItem(CLIENT_KEY, id); } catch (e) { /* не сохранится */ }
    }
    return id;
  }

  function browserFingerprint() {
    const parts = [
      navigator.userAgent, navigator.language,
      (navigator.languages || []).join(','),
      screen.width + 'x' + screen.height + 'x' + (screen.colorDepth || ''),
      new Date().getTimezoneOffset(),
      navigator.hardwareConcurrency || '',
      navigator.platform || '',
    ].join('|');
    // короткий стабильный хеш (FNV-1a) — не криптография, просто метка
    let h = 0x811c9dc5;
    for (let i = 0; i < parts.length; i++) {
      h ^= parts.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h.toString(16).padStart(8, '0');
  }

  async function restoreHistory() {
    try {
      const r = await fetch('chat/history?limit=50&client_id=' +
                            encodeURIComponent(state.clientId));
      if (!r.ok) return;
      const d = await r.json();
      if (!d.items || !d.items.length) return;

      for (const m of d.items) {
        const el = addMsg(m.role === 'user' ? 'user' : 'assistant', m.content,
                          m.role === 'user' ? 'Вы' : 'AI Agent');
        // ответы агента показываем размеченными, вопросы — как есть
        if (m.role !== 'user') el.innerHTML = renderMarkdown(m.content);
      }
      const div = document.createElement('div');
      div.className = 'muted';
      div.style.cssText = 'text-align:center;padding:8px 0;font-size:12px';
      div.textContent = '— продолжение сохранённой переписки —';
      $('messages').appendChild(div);
      scrollToBottom();
    } catch (e) {
      console.warn('История чата недоступна:', e);
    }
  }

  async function forgetHistory() {
    if (!confirm('Удалить сохранённую историю чата для этого браузера?')) return;
    try {
      await fetch('chat/history?client_id=' + encodeURIComponent(state.clientId),
                  { method: 'DELETE' });
      $('messages').innerHTML = '';
      addAssistantMsg('История очищена.');
    } catch (e) {
      addAssistantMsg('Не удалось очистить историю: ' + e);
    }
  }

  // ═══ АУТЕНТИФИКАЦИЯ ════════════════════════════════════════════

  async function loadUser() {
    try {
      const r = await fetch('api/me');
      if (r.status === 401) { location.href = new URL('login', document.baseURI).href; return; }
      if (!r.ok) return;
      const d = await r.json();
      if (d.source === 'disabled') return;   // аутентификация выключена

      const badge = $('user-badge');
      badge.textContent = d.username + (d.source === 'sso' ? ' · SSO'
                                      : d.source === 'ldap' ? ' · LDAP' : '');
      badge.style.display = '';
      // При SSO выход делает прокси, своя кнопка только путала бы
      if (d.source !== 'sso') $('logout-btn').style.display = '';
      state.isAdmin = !!d.is_admin;
      if (d.is_admin) $('tab-btn-access').style.display = '';
    } catch (e) {
      console.warn('Не удалось определить пользователя:', e);
    }
  }

  async function logout() {
    try {
      const r = await fetch('api/logout', { method: 'POST' });
      const d = await r.json().catch(() => ({}));
      location.href = d.sso_logout_url || new URL('login', document.baseURI).href;
    } catch (e) {
      location.href = new URL('login', document.baseURI).href;
    }
  }

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
        // Пока идёт стрим — простой текст: перерисовывать разметку
        // на каждом токене дорого. Разметку накладываем в finishStreaming.
        state.streamBuf += msg.text;
        state.streamingEl.textContent = state.streamBuf;
        scrollToBottom();
        break;
      }

      case 'tools':
        // какие инструменты модель запросила сама
        if (state.streamingEl) {
          const meta = state.streamingEl.parentElement.querySelector('.msg-meta');
          if (meta) meta.innerHTML += ' <span class="ctx-chip">' +
                                      esc(msg.used.join(', ')) + '</span>';
        }
        break;

      case 'charts':
        // Не рисуем сразу: ответ ещё стримится. Прикрепим к нему по 'done',
        // иначе графики влезали между вопросом и ответом.
        state.pendingCharts = msg;
        break;

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
      if (suffix) state.streamBuf += suffix;
      state.streamingEl.innerHTML = renderMarkdown(state.streamBuf);
      state.streamingEl.classList.remove('streaming');
      state.streamBuf = '';
      // Графики встраиваем в само сообщение, а не отдельным блоком снизу
      if (state.pendingCharts) {
        attachCharts(state.streamingEl.parentElement, state.pendingCharts);
        state.pendingCharts = null;
      }
      attachFeedback(state.streamingEl.parentElement, state.lastQuestion,
                     state.streamingEl.textContent || '');
      state.streamingEl = null;
    }
    state.awaitingReply = false;
    $('input').disabled = false;
    $('send-btn').style.display = '';
    $('send-btn').disabled = false;
    $('stop-btn').style.display = 'none';
    $('stop-btn').disabled = false;
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
    state.streamBuf = '';
    state.lastQuestion = text;
    const el = addMsg('assistant', '', 'AI Agent');
    el.innerHTML = '<span class="thinking"><i></i><i></i><i></i></span>';
    state.streamingEl   = el;
    state.awaitingReply = true;

    input.value    = '';
    autoResize(input);
    input.disabled = true;
    $('send-btn').style.display = 'none';
    $('stop-btn').style.display = '';

    state.ws.send(JSON.stringify({
      type:       'message',
      text:       text,
      session_id:  state.sessionId,
      client_id:   state.clientId,
      fingerprint: state.fingerprint,
    }));
  }

  function stopGeneration() {
    if (!state.awaitingReply) return;
    // Сервер прервёт стрим и пришлёт done — там же снимем блокировку ввода
    if (state.wsReady) state.ws.send(JSON.stringify({ type: 'stop' }));
    $('stop-btn').disabled = true;
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
      // отставание СВЕРХ плановой задержки; поле переименовано в агенте
      const lag  = d.replica ? num(d.replica.replication_lag_over_plan_s) : null;

      let html = `<span class="mini-badge ${up ? 'ok' : 'crit'}">${up ? '●&nbsp;UP' : '✕&nbsp;DOWN'}</span>`;
      if (!isNaN(qps)) html += `<span class="mini-badge">${qps.toFixed(0)} qps</span>`;
      if (lag !== null && !isNaN(lag)) {
        const cls = lag > 60 ? 'crit' : lag > 10 ? 'warn' : 'ok';
        html += `<span class="mini-badge ${cls}" title="Отставание сверх плановой задержки">лаг ${lag.toFixed(0)}s</span>`;
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

  // Загрузчики вкладок. Панели берём из DOM, а не из списка в коде: вкладку
  // «Доступы» когда-то добавили в разметку, а сюда вписать забыли — секция
  // никогда не показывалась, и на клик страница просто пустела.
  const TAB_LOADERS = { status: () => loadStatus(),
                        alerts: () => loadAlerts(),
                        access: () => loadAccess() };

  function showTab(tab) {
    state.currentTab = tab;
    document.querySelectorAll('.tab').forEach(el =>
      el.classList.toggle('active', el.dataset.tab === tab));
    document.querySelectorAll('.tab-pane').forEach(el =>
      el.hidden = (el.id !== 'tab-' + tab));
    if (TAB_LOADERS[tab]) TAB_LOADERS[tab]();
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
      const lag   = num(rp.replication_lag_over_plan_s);
      const plan  = num(rp.replication_planned_delay_s);
      const ioUp  = rp.replication_io_up  === '1.0' || rp.replication_io_up  === '1';
      const sqlUp = rp.replication_sql_up === '1.0' || rp.replication_sql_up === '1';
      const lagCls = lag > 60 ? 'crit' : lag > 10 ? 'warn' : 'good';
      replHtml = `
        <div class="metric"><div class="lbl">Repl IO/SQL</div>
          <div class="val ${ioUp && sqlUp ? 'good' : 'crit'}">${ioUp?'✓':'✗'}/${sqlUp?'✓':'✗'}</div></div>
        <div class="metric"><div class="lbl">Лаг сверх плана</div>
          <div class="val ${lagCls}">${isNaN(lag)?'—':lag.toFixed(0)+'s'}</div></div>
        ${!isNaN(plan) && plan > 0 ? `
        <div class="metric"><div class="lbl">Плановая задержка</div>
          <div class="val">${(plan/3600).toFixed(1)} ч</div></div>` : ''}`;
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
            <span class="src-badge" title="Источник алерта">${esc(srcLabel(it.source))}</span>
          </div>
          <div class="ameta">${esc(it.cluster_label || it.instance)} · ${esc((it.timestamp||'').replace('T',' ').slice(0,19))} UTC</div>
          <div class="asummary">${esc(it.summary)}</div>
          <button class="expand-link" onclick="App.toggleAnalysis(${i}, this)">▸ Анализ ИИ</button>
          ${it.id ? `<button class="expand-link" style="margin-left:12px"
             onclick="App.resolveAlert(${it.id})"
             title="Записать, чем закончился инцидент">✎ ${it.resolution ? 'Решение записано' : 'Записать решение'}</button>` : ''}
          ${state.isAdmin && it.id ? `<button class="expand-link" style="margin-left:12px"
             onclick="App.deleteAlert(${it.id})" title="Удалить ложное срабатывание">✕ Удалить</button>` : ''}
          ${it.resolution ? `<div class="resolution"><b>Что помогло:</b> ${esc(it.resolution)}${
             it.resolved_by ? ' <span class="muted">— ' + esc(it.resolved_by) + '</span>' : ''}</div>` : ''}
          <div class="analysis-box" id="ab-${i}">${esc(it.analysis)}</div>
        </div>`).join('');
    } catch (e) {
      el.innerHTML = `<div class="muted" style="color:var(--red)">Ошибка: ${esc(e.message)}</div>`;
    }
  }

  async function resolveAlert(id) {
    const txt = prompt('Чем закончился инцидент? Что именно помогло? '
                     + 'Запись всплывёт при следующем таком же алерте.');
    if (!txt || !txt.trim()) return;
    try {
      const r = await fetch('api/alerts/' + id + '/resolve', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ resolution: txt.trim() }),
      });
      if (!r.ok) { alert('Не удалось сохранить'); return; }
      await loadAlerts();
    } catch (e) { alert('Не удалось сохранить: ' + e); }
  }

  async function deleteAlert(id) {
    if (!confirm('Удалить эту запись из истории алертов?')) return;
    try {
      const r = await fetch('api/alerts/' + id, { method: 'DELETE' });
      if (!r.ok) {
        const d = await r.json().catch(() => ({}));
        alert('Не удалось удалить: ' + (d.detail || r.status));
        return;
      }
      await loadAlerts();
    } catch (e) {
      alert('Не удалось удалить: ' + e);
    }
  }

  async function deleteAlertsByName(name) {
    if (!name) return;
    if (!confirm('Удалить ВСЕ записи алерта "' + name + '" из истории?')) return;
    try {
      const r = await fetch('api/alerts?name=' + encodeURIComponent(name),
                            { method: 'DELETE' });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) { alert('Не удалось удалить: ' + (d.detail || r.status)); return; }
      await loadAlerts();
    } catch (e) {
      alert('Не удалось удалить: ' + e);
    }
  }

  // Источник алерта: prometheus — свой стек, остальное пришло по API
  const SRC_NAMES = { prometheus: 'Prometheus', api: 'API', zabbix: 'Zabbix',
                      nagios: 'Nagios', custom: 'Custom' };
  function srcLabel(src) {
    const s = (src || 'prometheus').toLowerCase();
    return SRC_NAMES[s] || s;
  }

  function toggleAnalysis(i, btn) {
    const box = $('ab-' + i);
    const open = box.classList.toggle('open');
    btn.textContent = open ? '▾ Скрыть' : '▸ Анализ ИИ';
  }

  // ═══ УПРАВЛЕНИЕ ДОСТУПАМИ (только для админов) ══════════════════

  async function loadAccess() {
    const box = $('access-list');
    box.innerHTML = '<div class="muted">Загрузка…</div>';
    try {
      const r = await fetch('api/users');
      if (r.status === 403) {
        box.innerHTML = '<div class="muted">Нужны права администратора.</div>';
        return;
      }
      const d = await r.json();

      // Раньше блок поиска просто прятался, и админ видел пустой список без
      // единой подсказки. Теперь он на месте, но с причиной.
      const why = d.ldap_search_reason || '';
      $('dir-query').disabled      = !!why;
      $('dir-search-btn').disabled = !!why;
      $('dir-results').innerHTML = why
        ? '<div class="muted" style="font-size:12px;line-height:1.5">' +
          'Поиск по каталогу недоступен: ' + esc(why) + '.<br>' +
          'Поправьте <code>config.env</code> (или запустите ' +
          '<code>sudo ./scripts/import_nslcd.py --write</code>) и переустановите ' +
          'агента: <code>sudo ./scripts/install_agent.sh</code>.<br>' +
          'Выдать доступ по логину вручную можно и сейчас — форма ниже.</div>'
        : '';

      if (!d.items.length) {
        box.innerHTML = '<div class="muted">Пока никому не выдан. ' +
                        'Войти сможет только локальный администратор.</div>';
        return;
      }
      box.innerHTML = d.items.map(u => `
        <div class="alert-item" style="display:flex;align-items:center;gap:12px">
          <div style="flex:1">
            <div><b>${esc(u.username)}</b>${u.role === 'admin'
                 ? ' <span class="ctx-chip">админ</span>' : ''}${!u.enabled
                 ? ' <span class="ctx-chip">отозван</span>' : ''}</div>
            <div class="muted" style="font-size:12px">
              ${esc(u.display_name || '')}${u.email ? ' · ' + esc(u.email) : ''}
              ${u.granted_by ? ' · выдал ' + esc(u.granted_by) : ''}
              ${u.granted_at ? ' · ' + esc(String(u.granted_at).slice(0, 10)) : ''}
            </div>
          </div>
          ${u.enabled
            ? `<button class="ghost-btn" onclick="App.revokeAccess('${esc(u.username)}')">Отозвать</button>`
            : `<button class="ghost-btn" onclick="App.grantAgain('${esc(u.username)}','${esc(u.role)}')">Вернуть</button>`}
        </div>`).join('');
    } catch (e) {
      box.innerHTML = '<div class="muted">Не удалось загрузить список: ' + esc(e) + '</div>';
    }
  }

  async function searchDirectory() {
    const q   = $('dir-query').value.trim();
    const box = $('dir-results');
    if (q.length < 2) { box.innerHTML = '<div class="muted">Введите хотя бы 2 символа.</div>'; return; }
    box.innerHTML = '<div class="muted">Ищу в каталоге…</div>';
    try {
      const r = await fetch('api/directory/search?q=' + encodeURIComponent(q));
      const d = await r.json();
      if (d.error) {
        box.innerHTML = '<div class="muted">Поиск не выполнен: ' + esc(d.error) + '</div>';
        return;
      }
      if (!d.items.length) {
        box.innerHTML = '<div class="muted">Никого не найдено по запросу «' +
                        esc(q) + '».</div>';
        return;
      }
      box.innerHTML = d.items.map(u => `
        <div class="alert-item" style="display:flex;align-items:center;gap:12px">
          <div style="flex:1">
            <div><b>${esc(u.username)}</b></div>
            <div class="muted" style="font-size:12px">
              ${esc(u.display_name || '')}${u.email ? ' · ' + esc(u.email) : ''}</div>
          </div>
          ${u.already_granted
            ? '<span class="ctx-chip">уже выдан</span>'
            : `<button class="ghost-btn" onclick="App.grantFound('${esc(u.username)}','${esc(u.display_name || '')}','${esc(u.email || '')}')">Выдать доступ</button>`}
        </div>`).join('');
    } catch (e) {
      box.innerHTML = '<div class="muted">Поиск не удался: ' + esc(e) + '</div>';
    }
  }

  async function grant(payload) {
    const r = await fetch('api/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      alert('Не удалось выдать доступ: ' + (d.detail || r.status));
      return;
    }
    await loadAccess();
    await searchDirectoryIfOpen();
  }

  async function searchDirectoryIfOpen() {
    if ($('dir-query').value.trim().length >= 2) await searchDirectory();
  }

  function grantFound(username, displayName, email) {
    grant({ username, display_name: displayName, email, role: 'user' });
  }

  function grantAgain(username, role) {
    grant({ username, role: role || 'user' });
  }

  function grantManual() {
    const login = $('manual-login').value.trim();
    if (!login) return;
    grant({ username: login, role: $('manual-role').value });
    $('manual-login').value = '';
  }

  async function revokeAccess(username) {
    if (!confirm('Отозвать доступ у ' + username + '?')) return;
    const r = await fetch('api/users/' + encodeURIComponent(username), { method: 'DELETE' });
    if (!r.ok) { alert('Не удалось отозвать доступ'); return; }
    await loadAccess();
  }

  // ═══ ОЦЕНКА ОТВЕТА ══════════════════════════════════════════════
  // Без неё непонятно, где агент систематически промахивается,
  // и улучшения делаются вслепую.

  function attachFeedback(msgEl, question, answer) {
    if (!msgEl || msgEl.querySelector('.fb-bar')) return;
    const bar = document.createElement('div');
    bar.className = 'fb-bar';
    bar.innerHTML = '<span class="fb-q">Ответ помог?</span>' +
                    '<button class="fb-btn" data-r="1" type="button">да</button>' +
                    '<button class="fb-btn" data-r="-1" type="button">нет</button>';

    bar.addEventListener('click', async (e) => {
      const b = e.target.closest('.fb-btn');
      if (!b) return;
      const rating = parseInt(b.dataset.r, 10);
      let comment = '';
      if (rating < 0) comment = prompt('Что было не так? (необязательно)') || '';
      bar.innerHTML = '<span class="fb-q">Спасибо, учтём</span>';
      try {
        await fetch('api/feedback', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ rating, comment, question, answer,
                                 client_id: state.clientId }),
        });
      } catch (err) { console.warn('Оценка не отправлена:', err); }
    });
    msgEl.appendChild(bar);
  }

  // ═══ РАЗМЕТКА ОТВЕТА ════════════════════════════════════════════
  // Свой минимальный markdown: в закрытом контуре библиотеку не подтянуть.
  // Порядок важен — СНАЧАЛА экранируем HTML, потом расставляем теги.
  // Текст приходит от LLM, вставлять его как HTML напрямую нельзя.

  function mdInline(s) {
    return s
      .replace(/`([^`]+)`/g, (m, c) => '<code>' + c + '</code>')
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
      .replace(/(^|[\s(])\*([^*\n]+)\*(?=[\s.,;:)]|$)/g, '$1<em>$2</em>');
  }

  // Строка-разделитель таблицы: |---|---| у markdown и -+- у наших блоков
  const isTableSep = (l) => /^[\s|:+-]+$/.test(l) && /[-—]/.test(l);
  const looksLikeRow = (l) => l.includes('|');

  function splitRow(line) {
    return line.replace(/^\s*\|/, '').replace(/\|\s*$/, '')
               .split('|').map(c => c.trim());
  }

  function renderTable(rows) {
    if (!rows.length) return '';
    const head = splitRow(rows[0]);
    const body = rows.slice(1).map(splitRow);
    // числовые колонки прижимаем вправо — так их удобнее сравнивать глазом
    const numeric = head.map((_, i) =>
      body.length > 0 && body.every(r =>
        r[i] === undefined || r[i] === '' || r[i] === '—' ||
        /^[-+]?[\d\s.,]+[%a-zA-Zа-яА-Я/]*$/.test(r[i])));
    const th = head.map((c, i) =>
      '<th' + (numeric[i] ? ' class="num"' : '') + '>' + mdInline(c) + '</th>').join('');
    const tr = body.map(r =>
      '<tr>' + head.map((_, i) =>
        '<td' + (numeric[i] ? ' class="num"' : '') + '>' +
        mdInline(r[i] === undefined ? '' : r[i]) + '</td>').join('') + '</tr>').join('');
    return '<div class="md-tablewrap"><table class="md-table"><thead><tr>' +
           th + '</tr></thead><tbody>' + tr + '</tbody></table></div>';
  }

  function renderMarkdown(raw) {
    if (!raw) return '';
    let text = esc(raw);

    // Блоки кода вынимаем первыми, чтобы внутри ничего не форматировалось
    const blocks = [];
    text = text.replace(/```(\w*)\n?([\s\S]*?)```/g, (m, lang, code) => {
      blocks.push({ lang: lang || '', code: code.replace(/\n$/, '') });
      return '@@CODEBLOCK@@' + (blocks.length - 1) + '';
    });

    const lines = text.split('\n');
    const out = [];
    let list = null;          // 'ul' | 'ol'
    let para = [];
    let table = [];

    const flushPara = () => {
      if (para.length) { out.push('<p>' + mdInline(para.join(' ')) + '</p>'); para = []; }
    };
    const flushList = () => { if (list) { out.push('</' + list + '>'); list = null; } };
    const flushTable = () => {
      if (table.length) {
        // без строки-разделителя это не таблица, а просто текст с |
        out.push(table.length >= 2 ? renderTable(table)
                                   : '<p>' + mdInline(table[0]) + '</p>');
        table = [];
      }
    };
    const flushAll = () => { flushPara(); flushList(); flushTable(); };

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const t = line.trim();

      if (t.startsWith('@@CODEBLOCK@@')) { flushAll(); out.push(t); continue; }

      if (!t) { flushAll(); continue; }

      // Таблица: строка с | , следующая — разделитель
      if (!table.length && looksLikeRow(t) && i + 1 < lines.length &&
          isTableSep(lines[i + 1].trim())) {
        flushPara(); flushList();
        table.push(t); i++;                     // разделитель пропускаем
        continue;
      }
      if (table.length) {
        if (looksLikeRow(t)) { table.push(t); continue; }
        flushTable();
      }

      const h = t.match(/^(#{1,6})\s+(.+)$/);
      if (h) {
        flushAll();
        const lvl = Math.min(h[1].length + 2, 6);   // ## -> h4, чтобы не спорить с заголовками страницы
        out.push('<h' + lvl + ' class="md-h">' + mdInline(h[2]) + '</h' + lvl + '>');
        continue;
      }

      const ul = t.match(/^[-*•]\s+(.+)$/);
      const ol = t.match(/^(\d+)[.)]\s+(.+)$/);
      if (ul || ol) {
        flushPara(); flushTable();
        const want = ul ? 'ul' : 'ol';
        if (list !== want) { flushList(); out.push('<' + want + ' class="md-list">'); list = want; }
        out.push('<li>' + mdInline((ul ? ul[1] : ol[2])) + '</li>');
        continue;
      }
      flushList();

      if (/^([-–—]{3,}|_{3,})$/.test(t)) { flushAll(); out.push('<hr class="md-hr">'); continue; }

      para.push(t);
    }
    flushAll();

    let html = out.join('');
    html = html.replace(/@@CODEBLOCK@@(\d+)/g, (m, n) => {
      const b = blocks[+n];
      const label = b.lang ? '<span class="md-lang">' + esc(b.lang) + '</span>' : '';
      return '<div class="md-code">' + label +
             '<button class="md-copy" type="button" title="Скопировать">копировать</button>' +
             '<pre><code>' + b.code + '</code></pre></div>';
    });
    return html;
  }

  // Копирование кода: делегируем на контейнер, чтобы не вешать слушатель
  // на каждый блок при каждом ответе
  document.addEventListener('click', (e) => {
    const btn = e.target.closest && e.target.closest('.md-copy');
    if (!btn) return;
    const code = btn.parentElement.querySelector('code');
    if (!code) return;
    const done = () => { btn.textContent = 'скопировано';
                         setTimeout(() => { btn.textContent = 'копировать'; }, 1500); };
    if (navigator.clipboard) {
      navigator.clipboard.writeText(code.textContent).then(done, () => {});
    } else {
      const ta = document.createElement('textarea');
      ta.value = code.textContent;
      document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); done(); } catch (err) {}
      document.body.removeChild(ta);
    }
  });

  // ═══ ГРАФИКИ ════════════════════════════════════════════════════
  // Рисуем сами, инлайновым SVG: в закрытом контуре CDN недоступен,
  // а тащить библиотеку графиков ради линии — лишняя зависимость.

  function fmtNum(v) {
    const a = Math.abs(v);
    if (a >= 1e9) return (v / 1e9).toFixed(1) + 'G';
    if (a >= 1e6) return (v / 1e6).toFixed(1) + 'M';
    if (a >= 1e3) return (v / 1e3).toFixed(1) + 'k';
    if (a >= 10)  return v.toFixed(0);
    if (a >= 1)   return v.toFixed(1);
    return v.toFixed(2);
  }

  function fmtTime(ts) {
    const d = new Date(ts * 1000);
    return String(d.getHours()).padStart(2, '0') + ':' +
           String(d.getMinutes()).padStart(2, '0');
  }

  // Для длинных периодов одного времени мало — нужна дата
  function fmtTick(ts, spanSec) {
    const d = new Date(ts * 1000);
    const hm = String(d.getHours()).padStart(2, '0') + ':' +
               String(d.getMinutes()).padStart(2, '0');
    if (spanSec > 36 * 3600) {
      return String(d.getDate()).padStart(2, '0') + '.' +
             String(d.getMonth() + 1).padStart(2, '0') + ' ' + hm;
    }
    if (spanSec < 600) {   // меньше 10 минут — показываем секунды
      return hm + ':' + String(d.getSeconds()).padStart(2, '0');
    }
    return hm;
  }

  function sparkSvg(chart, w, h) {
    const pts = chart.points;
    if (!pts.length) return '';
    const padL = 46, padR = 10, padT = 12, padB = 20;
    const iw = w - padL - padR, ih = h - padT - padB;

    const xs = pts.map(p => p[0]), ys = pts.map(p => p[1]);
    const x0 = xs[0], x1 = xs[xs.length - 1] || x0 + 1;
    let lo = Math.min(...ys), hi = Math.max(...ys);
    if (hi === lo) { hi = lo + 1; lo = Math.max(0, lo - 1); }
    // немного воздуха сверху, чтобы пик не упирался в рамку
    hi += (hi - lo) * 0.1;

    const px = t => padL + ((t - x0) / (x1 - x0 || 1)) * iw;
    const py = v => padT + ih - ((v - lo) / (hi - lo)) * ih;

    const line = pts.map((p, i) => (i ? 'L' : 'M') + px(p[0]).toFixed(1) +
                                   ' ' + py(p[1]).toFixed(1)).join(' ');
    const area = line + ` L${px(x1).toFixed(1)} ${(padT + ih).toFixed(1)}` +
                        ` L${px(x0).toFixed(1)} ${(padT + ih).toFixed(1)} Z`;

    // три горизонтальные линии сетки с подписями
    let grid = '';
    for (let k = 0; k <= 2; k++) {
      const v = lo + (hi - lo) * (k / 2), y = py(v);
      grid += `<line x1="${padL}" y1="${y.toFixed(1)}" x2="${w - padR}" y2="${y.toFixed(1)}"
                     class="cg-gridline"/>
               <text x="${padL - 6}" y="${(y + 3).toFixed(1)}" class="cg-lbl"
                     text-anchor="end">${esc(fmtNum(v))}</text>`;
    }
    // Четыре отметки вместо двух: по двум крайним нельзя понять масштаб,
    // а на коротком периоде они ещё и совпадали (обе показывали 7:41).
    const span = x1 - x0;
    let tAxis = '';
    for (let k = 0; k <= 3; k++) {
      const ts = x0 + span * (k / 3);
      const x  = px(ts);
      const anchor = k === 0 ? 'start' : k === 3 ? 'end' : 'middle';
      tAxis += `<text x="${x.toFixed(1)}" y="${h - 5}" class="cg-lbl"
                      text-anchor="${anchor}">${esc(fmtTick(ts, span))}</text>`;
    }

    // preserveAspectRatio="none" растягивал и текст подписей — убрано.
    return `<svg viewBox="0 0 ${w} ${h}" class="cg-svg"
                 role="img" aria-label="${esc(chart.title)}">
              ${grid}
              <path d="${area}" class="cg-area"/>
              <path d="${line}" class="cg-line"/>
              ${tAxis}
            </svg>`;
  }

  function chartCard(chart) {
    const u = chart.unit ? ' ' + esc(chart.unit) : '';
    return `<div class="cg-card">
      <div class="cg-head">
        <span class="cg-title">${esc(chart.title)}</span>
        <span class="cg-stats">сейчас ${esc(fmtNum(chart.last))}${u}
          · средн ${esc(fmtNum(chart.avg))}${u}
          · макс ${esc(fmtNum(chart.max))}${u}</span>
      </div>
      ${sparkSvg(chart, 420, 96)}
    </div>`;
  }

  // Компактная строка под ответом: две ссылки, ничего лишнего.
  // Графики разворачиваются по клику — стена картинок под каждым ответом
  // мешала читать сам ответ.
  function attachCharts(msgEl, msg) {
    if (!msgEl) return;
    const wrap = document.createElement('div');
    wrap.className = 'cg-block';

    const period = msg.hours >= 24
      ? (msg.hours / 24).toFixed(1).replace('.0', '') + ' сут'
      : msg.hours + ' ч';
    const pdfUrl = 'report?cluster=' + encodeURIComponent(msg.cluster) +
                   '&hours=' + encodeURIComponent(msg.hours);

    const bar = document.createElement('div');
    bar.className = 'cg-bar';
    bar.innerHTML =
      `<button class="cg-link" type="button">📈 Графики за ${esc(period)}</button>
       <a class="cg-link ${msg.highlight_pdf ? 'accent' : ''}" href="${pdfUrl}"
          target="_blank" rel="noopener">📄 Выгрузить PDF</a>`;

    const body = document.createElement('div');
    body.className = 'cg-body';

    const toggle = bar.querySelector('button');
    let loaded = false;

    function draw(charts) {
      body.innerHTML = charts.length
        ? '<div class="cg-grid">' + charts.map(chartCard).join('') + '</div>'
        : '<div class="muted" style="font-size:12px">За этот период данных нет.</div>';
    }

    toggle.addEventListener('click', async () => {
      const open = body.classList.toggle('open');
      toggle.textContent = (open ? '▾ Графики за ' : '📈 Графики за ') + period;
      if (!open || loaded) return;
      loaded = true;
      if (msg.charts && msg.charts.length) { draw(msg.charts); return; }
      body.innerHTML = '<div class="muted" style="font-size:12px">Загружаю…</div>';
      try {
        const r = await fetch('api/charts/' + encodeURIComponent(msg.cluster) +
                              '?hours=' + encodeURIComponent(msg.hours));
        draw((await r.json()).charts || []);
      } catch (e) {
        body.innerHTML = '<div class="muted" style="font-size:12px">Не удалось: ' +
                         esc(e.message) + '</div>';
        loaded = false;
      }
      scrollToBottom();
    });

    wrap.appendChild(bar);
    wrap.appendChild(body);
    msgEl.appendChild(wrap);

    // Просили графики явно — сразу разворачиваем
    if (msg.mode === 'inline' && msg.charts && msg.charts.length) toggle.click();
    scrollToBottom();
  }


  // ═══ УТИЛИТЫ ════════════════════════════════════════════════════

  function esc(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function num(v) { const n = parseFloat(v); return isNaN(n) ? NaN : n; }

  // ═══ ИНИЦИАЛИЗАЦИЯ ══════════════════════════════════════════════

  function init() {
    // Опознаём браузер до всего остального: от clientId зависит история
    state.clientId    = loadClientId();
    state.fingerprint = browserFingerprint();

    loadUser();

    restoreHistory();
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
    $('stop-btn').addEventListener('click', stopGeneration);
  }

  document.addEventListener('DOMContentLoaded', init);

  // Публичный API для onclick в HTML
  return { showTab, pickCluster, useSuggestion, toggleAnalysis,
           loadStatus, loadAlerts, refreshClusters, forgetHistory, logout,
           loadAccess, searchDirectory, grantFound, grantAgain,
           grantManual, revokeAccess, deleteAlert, deleteAlertsByName,
           resolveAlert,
           stopGeneration };
})();
