const $ = (s, r = document) => r.querySelector(s);

const GROUPS = [
  ['delivery', '收信与投递', 'MX、A、PTR'],
  ['auth', '发信认证', 'SPF、DKIM、DMARC'],
  ['discovery', '服务发现', 'SRV 与自动配置域名'],
  ['endpoint', '自动配置端点', '实际抓取 XML 校验'],
  ['transport', '端口与证书', '连得上、证书对得上'],
  ['account', '账号实测', '真实登录验证'],
];

const CH_LABEL = {
  autoconfig_xml: 'autoconfig',
  autoconfig_wellknown: '.well-known',
  autodiscover_xml: 'Autodiscover',
  srv_imap: 'SRV',
  srv_submission: 'SRV',
  srv_autodiscover: 'SRV',
  mobileconfig: 'mobileconfig',
  guess: '按惯例猜测',
};

const RING_C = 2 * Math.PI * 52;
let scanning = false;

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.classList.remove('show'), 1600);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast('已复制到剪贴板');
  } catch (e) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); toast('已复制到剪贴板'); }
    catch (_) { toast('复制失败，请手动选择'); }
    ta.remove();
  }
}

/* ---------------- 高级选项 ---------------- */
$('#advToggle').addEventListener('click', () => {
  const open = $('#adv').classList.toggle('open');
  $('#advCaret').textContent = open ? '▾' : '▸';
});

/* ---------------- 骨架 ---------------- */
function renderSkeleton(domain, mailHost, notice) {
  const groupHtml = GROUPS.map(([id, title, desc]) => `
    <div class="group" data-gid="${id}">
      <div class="group-head">
        <span class="group-title">${title}</span>
        <span class="group-desc">${desc}</span>
        <span class="group-bar"><i style="width:0%"></i></span>
        <span class="group-pct">—</span>
        <span class="group-caret">▶</span>
      </div>
      <div class="group-body">
        <div class="skeleton"><span class="spinner"></span>检查中…</div>
      </div>
    </div>`).join('');

  $('#result').innerHTML = `
    ${notice ? `<div class="notice">${esc(notice)}</div>` : ''}
    <div class="panel summary">
      <div class="ring-wrap">
        <svg class="ring" viewBox="0 0 120 120">
          <circle class="ring-bg" cx="60" cy="60" r="52"></circle>
          <circle class="ring-fg" id="ring" cx="60" cy="60" r="52"
                  stroke-dasharray="${RING_C}" stroke-dashoffset="${RING_C}"></circle>
        </svg>
        <div class="ring-val"><b id="scoreVal">0</b><span>就绪度</span></div>
      </div>
      <div class="verdict">
        <h2>正在检查 ${esc(domain)}</h2>
        <p>正在核对 DNS 记录并模拟各邮件客户端的自动配置探测流程…</p>
        <div class="meta">${esc(mailHost)}</div>
      </div>
      <div class="counts">
        <div class="c-pass"><b id="cPass">0</b><span>通过</span></div>
        <div class="c-warn"><b id="cWarn">0</b><span>警告</span></div>
        <div class="c-fail"><b id="cFail">0</b><span>失败</span></div>
        <div class="c-info"><b id="cInfo">0</b><span>提示</span></div>
      </div>
    </div>
    <div id="clientsBox"></div>
    <div id="groupsBox">${groupHtml}</div>
    <div id="recordsBox"></div>`;
}

/* ---------------- 分组 ---------------- */
function renderItem(it) {
  const hasBody = it.detail || it.fix || (it.records && it.records.length);
  const recs = (it.records || []).map((r) => `
    <div class="rec">
      <code>${esc(r)}</code>
      <button class="copy" data-copy="${esc(r)}">复制</button>
    </div>`).join('');

  return `
    <div class="item" data-status="${it.status}">
      <div class="item-head">
        <span class="dot"></span>
        <span class="item-title">${esc(it.title)}</span>
        <span class="item-summary">${esc(it.summary)}</span>
        ${hasBody ? '<span class="item-caret">›</span>' : ''}
      </div>
      ${hasBody ? `<div class="item-body">
        ${it.detail ? `<div class="detail">${esc(it.detail)}</div>` : ''}
        ${it.fix ? `<div class="fix"><b>怎么修</b><span>${esc(it.fix)}</span></div>` : ''}
        ${recs ? `<div class="recs">${recs}</div>` : ''}
      </div>` : ''}
    </div>`;
}

function paintGroup(ev) {
  const el = $(`.group[data-gid="${ev.group}"]`);
  if (!el) return;
  el.querySelector('.group-pct').textContent = ev.percent + '%';
  el.querySelector('.group-bar i').style.width = ev.percent + '%';
  el.querySelector('.group-body').innerHTML = ev.items.map(renderItem).join('');
  // 有失败/警告的组自动展开，用户一眼能看到问题
  const bad = ev.items.some((i) => i.status === 'fail' || i.status === 'warn');
  if (bad) el.classList.add('open');
}

/* ---------------- 汇总 ---------------- */
function renderSummary(d) {
  const pct = d.score.percent;
  const ring = $('#ring');
  if (ring) {
    const color = pct >= 85 ? 'var(--pass)' : pct >= 60 ? 'var(--brand)'
      : pct >= 35 ? 'var(--warn)' : 'var(--fail)';
    ring.style.stroke = color;
    requestAnimationFrame(() => {
      ring.style.strokeDashoffset = RING_C * (1 - pct / 100);
    });
  }
  const sv = $('#scoreVal');
  if (sv) {
    let cur = 0;
    const step = Math.max(1, Math.round(pct / 28));
    const timer = setInterval(() => {
      cur = Math.min(pct, cur + step);
      sv.textContent = cur;
      if (cur >= pct) clearInterval(timer);
    }, 26);
  }

  const v = $('.verdict');
  if (v) {
    v.innerHTML = `
      <h2>${esc(d.verdict.title)}</h2>
      <p>${esc(d.verdict.desc)}</p>
      <div class="meta">${esc(d.target.domain)} · ${esc(d.target.mail_host)} · 耗时 ${d.elapsed}s</div>`;
  }
  const counts = d.score.counts;
  if ($('#cPass')) {
    $('#cPass').textContent = counts.pass || 0;
    $('#cWarn').textContent = counts.warn || 0;
    $('#cFail').textContent = counts.fail || 0;
    $('#cInfo').textContent = counts.info || 0;
  }
}

function renderClients(clients) {
  const box = $('#clientsBox');
  if (!box) return;
  const cards = clients.map((c) => {
    const mark = c.status === 'pass' ? '✓' : c.status === 'warn' ? '!' : '✕';
    const note = c.status === 'pass' ? '只需输入邮箱和密码'
      : c.guessed ? '会靠默认猜测连上，标准发现链路未覆盖'
      : c.status === 'warn' ? '可以配置，但有隐患'
      : '会自动配置失败，需要补记录';
    const chans = [...new Set((c.via || []).map((x) => CH_LABEL[x] || x))];
    const via = chans.length
      ? `<span class="client-via">${esc(chans.join(' + '))}</span>`
      : (c.failed_at ? `<span class="client-via">卡在 ${esc(c.failed_at)}</span>` : '');
    return `
      <div class="client ${c.status}">
        <div class="mark">${mark}</div>
        <div class="client-body">
          <div class="client-name">${esc(c.name)}</div>
          <div class="client-note">${esc(note)}</div>
          ${via}
        </div>
      </div>`;
  }).join('');

  box.innerHTML = `
    <div class="section-head">
      <h3>客户端自动配置能力</h3>
      <span class="hint">只需输入邮箱地址就能完成配置的客户端</span>
    </div>
    <div class="clients">${cards}</div>`;
}

function renderRecords(d) {
  const box = $('#recordsBox');
  if (!box) return;
  const todo = d.todo_records || [];
  const todoHtml = todo.length ? `
    <div class="section-head" style="margin-top:0">
      <h3>需要补充的记录</h3>
      <span class="hint">复制后粘贴到你的 DNS 服务商</span>
    </div>
    <ul class="todo-list">${todo.map((r) => `<li>${esc(r)}</li>`).join('')}</ul>
    <div style="margin-top:10px">
      <button class="btn btn-ghost" data-copy-all="todo">复制全部 ${todo.length} 条</button>
    </div>` : '';

  box.innerHTML = `
    <div class="section-head">
      <h3>DNS 记录对照清单</h3>
      <span class="hint">✓ 已就绪 · ✗ 待处理</span>
    </div>
    <div class="panel records-panel">
      ${todoHtml}
      <div class="section-head"><h3>完整 zone 片段</h3></div>
      <pre id="zonePre">${esc(d.zone)}</pre>
      <div style="margin-top:10px">
        <button class="btn btn-ghost" data-copy-all="zone">复制 zone 片段</button>
      </div>
    </div>`;

  box._todo = todo;
  box._zone = d.zone;
}

/* ---------------- 事件 ---------------- */
$('#result').addEventListener('click', (e) => {
  const copyBtn = e.target.closest('.copy');
  if (copyBtn) {
    e.stopPropagation();
    copyText(copyBtn.dataset.copy);
    return;
  }
  const allBtn = e.target.closest('[data-copy-all]');
  if (allBtn) {
    e.stopPropagation();
    const box = $('#recordsBox');
    const kind = allBtn.dataset.copyAll;
    if (kind === 'todo') copyText((box._todo || []).join('\n'));
    else copyText(box._zone || '');
    return;
  }
  const head = e.target.closest('.item-head');
  if (head) { head.parentElement.classList.toggle('open'); return; }
  const ghead = e.target.closest('.group-head');
  if (ghead) { ghead.parentElement.classList.toggle('open'); return; }
});

/* ---------------- 扫描 ---------------- */
function renderFromData(d) {
  const input = $('#domain');
  if (input) input.value = d.target.domain;
  renderSkeleton(d.target.domain, d.target.mail_host, '');
  const byGroup = {};
  for (const it of d.items) (byGroup[it.group] = byGroup[it.group] || []).push(it);
  for (const [gid] of GROUPS) {
    if (!byGroup[gid]) continue;
    const meta = (d.groups || []).find((g) => g.id === gid) || {};
    paintGroup({ group: gid, percent: meta.percent ?? 100, items: byGroup[gid] });
  }
  renderSummary(d);
  renderClients(d.clients);
  renderRecords(d);
}

async function startScan() {
  if (scanning) return;
  if (window.__MD_MOCK__) { renderFromData(window.__MD_MOCK__); return; }
  const domain = $('#domain').value.trim();
  if (!/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
    toast('请输入正确的域名，例如 example.com');
    $('#domain').focus();
    return;
  }

  const payload = {
    domain,
    mail_host: $('#mailhost').value.trim(),
    dkim_selector: $('#dkim').value.trim(),
    email: $('#email').value.trim(),
    password: $('#password').value,
  };

  scanning = true;
  const btn = $('#go');
  btn.disabled = true;
  btn.textContent = '检查中…';
  renderSkeleton(domain, payload.mail_host || ('mail.' + domain), '');

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!res.ok || !res.body) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || ('服务返回 HTTP ' + res.status));
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let idx;
      while ((idx = buf.indexOf('\n\n')) >= 0) {
        const chunk = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        const line = chunk.split('\n').find((l) => l.startsWith('data:'));
        if (!line) continue;
        let ev;
        try { ev = JSON.parse(line.slice(5).trim()); } catch (_) { continue; }

        if (ev.type === 'start') {
          if (ev.notice) {
            const notice = document.createElement('div');
            notice.className = 'notice';
            notice.textContent = ev.notice;
            $('#result').prepend(notice);
          }
          const meta = document.querySelector('.verdict .meta');
          if (meta) meta.textContent = ev.domain + ' · ' + ev.mail_host;
        } else if (ev.type === 'group') {
          paintGroup(ev);
        } else if (ev.type === 'done') {
          renderSummary(ev);
          renderClients(ev.clients);
          renderRecords(ev);
        } else if (ev.type === 'error') {
          throw new Error(ev.message);
        }
      }
    }
  } catch (err) {
    const box = $('#result');
    const div = document.createElement('div');
    div.className = 'notice';
    div.style.background = 'var(--fail-soft)';
    div.style.borderColor = '#f5c6c2';
    div.style.color = '#a11a10';
    div.textContent = '检查失败：' + err.message;
    box.prepend(div);
    toast('检查失败');
  } finally {
    scanning = false;
    btn.disabled = false;
    btn.textContent = '开始检查';
  }
}

$('#go').addEventListener('click', startScan);
$('#domain').addEventListener('keydown', (e) => { if (e.key === 'Enter') startScan(); });
$('#domain').focus();

// 支持 ?d=example.com 直接开跑，方便分享链接和自动化截图
const preset = new URLSearchParams(location.search).get('d');
if (window.__MD_MOCK__) {
  // 离线报告模式：结果已内嵌在页面里
  setTimeout(() => renderFromData(window.__MD_MOCK__), 30);
} else if (preset) {
  $('#domain').value = preset;
  setTimeout(startScan, 120);
}

/* ---------- 关于 ---------- */
let aboutData = null;

// 标题栏带上版本号：常驻版本只出现在标题栏和「关于」，版本号唯一来源是后端 __version__
fetch('/api/about')
  .then((r) => r.json())
  .then((d) => {
    aboutData = d;
    if (d.version) document.title = (d.name || 'MailDoctor') + ' ' + d.version + ' · 自建邮箱配置体检';
  })
  .catch(() => { /* 拿不到就保持静态标题 */ });

function mdInline(s) {
  return esc(s).replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
}

// 只解析 ABOUT.md 用到的那几种语法：## 标题行、**小节**、- 列表、普通段落、含 © 的页脚。
// 文案的唯一来源是根目录 ABOUT.md，这里不重复写任何一句。
function mdToHtml(md) {
  const out = [];
  let list = null;
  const flush = () => {
    if (list) { out.push('<ul class="about-list">' + list.join('') + '</ul>'); list = null; }
  };

  for (const raw of md.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) { flush(); continue; }

    if (line.startsWith('## ')) {
      flush();
      const parts = [...line.slice(3).matchAll(/\*\*(.+?)\*\*/g)].map((m) => m[1]);
      out.push('<div class="about-title">' + esc(parts[0] || '') +
               '<span class="ver">' + esc(parts[1] || '') + '</span></div>');
      continue;
    }
    if (line.startsWith('- ')) {
      (list = list || []).push('<li>' + mdInline(line.slice(2)) + '</li>');
      continue;
    }
    if (/^\*\*[^*]+\*\*$/.test(line)) {
      flush();
      out.push('<div class="about-h">' + mdInline(line) + '</div>');
      continue;
    }
    if (line.startsWith('©')) {
      flush();
      const last = out.pop();
      if (last && last.startsWith('<p>')) {
        out.push('<div class="about-foot">' + last.slice(3, -4) + '<br>' + mdInline(line) + '</div>');
      } else {
        out.push('<div class="about-foot">' + mdInline(line) + '</div>');
      }
      continue;
    }

    flush();
    const onlyTitle = out.length === 1 && out[0].startsWith('<div class="about-title">');
    out.push((onlyTitle ? '<div class="about-sub">' : '<p>') + mdInline(line) +
             (onlyTitle ? '</div>' : '</p>'));
  }

  flush();
  return out.join('');
}

async function openAbout() {
  const modal = $('#aboutModal');
  if (!modal.hidden) return;
  if (!aboutData) {
    try {
      aboutData = await (await fetch('/api/about')).json();
    } catch (_) {
      aboutData = { markdown: '', author: 'Rex Lee', email: '' };
    }
  }
  $('#aboutBody').innerHTML = mdToHtml(aboutData.markdown || '');
  $('#aboutAuthor').textContent = aboutData.author || '';
  $('#mailText').textContent = aboutData.email || '';
  modal.hidden = false;
  $('#aboutClose').focus();
}

function closeAbout() { $('#aboutModal').hidden = true; }

$('#aboutBtn').addEventListener('click', openAbout);
$('#aboutClose').addEventListener('click', closeAbout);
$('#aboutModal').addEventListener('click', (e) => {
  if (e.target.id === 'aboutModal') closeAbout();
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !$('#aboutModal').hidden) closeAbout();
});

// 邮箱只复制，不打开邮件客户端、不跳转网页
$('#mailPill').addEventListener('click', async () => {
  const email = $('#mailText').textContent;
  if (!email) return;
  try {
    await navigator.clipboard.writeText(email);
  } catch (_) {
    const ta = document.createElement('textarea');
    ta.value = email;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (_) { /* 浏览器拒绝就算了 */ }
    ta.remove();
  }
  const pill = $('#mailPill');
  const hint = $('#copyHint');
  pill.classList.add('copied');
  hint.textContent = '已复制到剪贴板';
  hint.classList.add('show');
  clearTimeout(pill._t);
  pill._t = setTimeout(() => {
    pill.classList.remove('copied');
    hint.classList.remove('show');
  }, 1600);
});
