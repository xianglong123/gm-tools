/* 证书解析页交互与渲染 */
(function () {
  'use strict';

  const $ = s => document.querySelector(s);
  const T = window.CertTool;

  const input = $('#input');
  const statusEl = $('#status');
  const listEl = $('#list');
  const chainBar = $('#chainBar');
  const notesEl = $('#notes');
  const toastEl = $('#toast');

  let current = null;
  let toastTimer = null;

  function toast(msg, bad) {
    toastEl.textContent = msg;
    toastEl.className = 'toast show' + (bad ? ' bad' : '');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { toastEl.className = 'toast'; }, 2200);
  }

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function bytesOf(buf) {
    if (buf instanceof Uint8Array) return buf;
    if (ArrayBuffer.isView(buf)) return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    return new Uint8Array(buf);
  }

  function looksBinary(b) {
    if (b.length < 4) return false;
    if (b[0] === 0xfe && b[1] === 0xed && b[2] === 0xfe && b[3] === 0xed) return true;
    if (b[0] === 0xce && b[1] === 0xce && b[2] === 0xce && b[3] === 0xce) return true;
    if (b[0] === 0x30 && b[1] !== 0x2d && b[1] !== 0x0a && b[1] !== 0x0d) return true;
    return false;
  }

  function readFile(file) {
    if (file.size > 2 * 1024 * 1024) { toast('文件超过 2MB，多半不是证书', true); return; }
    const fr = new FileReader();
    fr.onload = () => {
      const b = bytesOf(fr.result);
      if (looksBinary(b)) {
        input.value = '';
        statusEl.textContent = '已读取 ' + file.name + '（' + b.length + ' 字节）';
        run(b, file.name);
      } else {
        const text = new TextDecoder('utf-8', { fatal: false }).decode(b);
        input.value = text;
        statusEl.textContent = '已读取 ' + file.name;
        run(text, file.name);
      }
    };
    fr.onerror = () => toast('文件读取失败', true);
    fr.readAsArrayBuffer(file);
  }

  function run(raw, label) {
    const src = raw !== undefined ? raw : input.value;
    if (!src || (typeof src === 'string' && !src.trim())) { toast('先粘贴或上传证书内容', true); return; }
    let res;
    try {
      res = T.analyze(src);
    } catch (e) {
      current = null;
      listEl.innerHTML = '';
      chainBar.className = 'chainbar bad';
      chainBar.textContent = '解析失败：' + e.message;
      notesEl.classList.add('hidden');
      statusEl.textContent = '未解析出证书';
      return;
    }
    current = res;
    statusEl.textContent = (label ? label + ' · ' : '') + '识别为 ' + (res.sourceKind || '未知') + '，共 ' + res.certs.length + ' 张证书';
    render();
  }

  function render() {
    const res = current;
    if (!res) return;
    const c = res.chain;

    const cls = c.state === 'complete' ? 'ok' : (c.state === 'broken' || c.state === 'empty') ? 'bad' : 'warn';
    const title = c.state === 'complete' ? '证书链完整' :
      c.state === 'broken' ? '证书链不完整' :
        c.state === 'ca-set' ? '这是一组 CA 证书' :
          c.state === 'single' ? '只有一张证书' :
            c.state === 'partial' ? '链未闭合' : '无法判断链';

    chainBar.className = 'chainbar ' + cls;
    chainBar.innerHTML = '<div class="cb-title">' + esc(title) +
      '<span class="cb-count">' + res.certs.length + ' 张</span></div>' +
      '<div class="cb-body">' + c.messages.map(m => '<p>' + esc(m) + '</p>').join('') + '</div>' +
      (c.chain.length > 1 ? '<div class="cb-path">' + c.chain.map((x, i) =>
        '<span class="cb-step">' + (i === 0 ? '终端' : x.isSelfSigned ? '根' : '中间') + ' · ' + esc(x.commonName || x.subject) + '</span>'
      ).join('<span class="cb-arrow">→</span>') + '</div>' : '');

    const notes = (res.notes || []).slice();
    if (c.state === 'broken') notes.push('补救：向颁发者索取中间证书，按「终端在前、中间在后」拼进同一个 PEM（或服务器的 fullchain 文件），不要只下发终端证书。');
    const cnOnly = res.certs.filter(x => x.cnOnly);
    if (cnOnly.length) notes.push(cnOnly.length + ' 张证书只有 CN、没有 SAN。Chrome 58+ 和现代 Java 已忽略 CN，这类证书用在 HTTPS 上不会被信任。');

    if (notes.length) {
      notesEl.innerHTML = notes.map(n => '<div class="note-line">' + esc(n) + '</div>').join('');
      notesEl.classList.remove('hidden');
    } else {
      notesEl.classList.add('hidden');
    }

    const ordered = c.chain.length ? c.chain.concat(c.extra || []) : res.certs;
    listEl.innerHTML = ordered.map((cert, i) => cardHtml(cert, i)).join('');
    ordered.forEach((cert, i) => {
      T.sha256Fp(cert.der).then(fp => {
        const el = document.getElementById('fp-' + i);
        if (el && fp) el.textContent = fp;
      }).catch(() => { });
    });
  }

  function roleOf(cert) {
    if (cert.isSelfSigned && cert.isCA) return { text: '根证书', cls: 'root' };
    if (cert.isSelfSigned) return { text: '自签证书', cls: 'root' };
    if (cert.isCA) return { text: '中间证书', cls: 'ca' };
    return { text: '终端证书', cls: 'leaf' };
  }

  function cardHtml(cert, i) {
    const role = roleOf(cert);
    const v = T.validityOf(cert);
    const spki = cert.spki;
    const extRows = cert.extensions.map(e => {
      const detail = esc(e.detail).replace(/\n/g, '<br>');
      return '<tr><td class="ext-name">' + esc(e.name) +
        (e.critical ? '<span class="crit">关键</span>' : '') + '</td>' +
        '<td class="ext-val mono">' + detail + '</td></tr>';
    }).join('');

    const sanBlock = cert.san && cert.san.length
      ? '<div class="cc-field full"><label>可用于（SAN）</label><div class="san-list">' +
      cert.san.map(s => '<span class="san ' + (s.type === 2 ? 'dns' : s.type === 7 ? 'ip' : '') + '">' + esc(s.value) + '</span>').join('') +
      '</div></div>'
      : '';

    return '<div class="certcard">' +
      '<div class="cc-head"><span class="cc-idx">#' + (i + 1) + '</span>' +
      '<div class="cc-title">' + esc(cert.commonName || cert.subject) + '</div>' +
      '<span class="role ' + role.cls + '">' + role.text + '</span>' +
      '<span class="valid ' + v.state + '">' + esc(v.text) + '</span></div>' +
      '<div class="cc-grid">' +
      '<div class="cc-field full"><label>主体 Subject</label><span>' + esc(cert.subject) + '</span></div>' +
      '<div class="cc-field full"><label>颁发者 Issuer</label><span>' + esc(cert.issuer) + '</span></div>' +
      '<div class="cc-field"><label>生效</label><span class="mono">' + esc(T.fmtDate(cert.notBefore)) + '</span></div>' +
      '<div class="cc-field"><label>到期</label><span class="mono">' + esc(T.fmtDate(cert.notAfter)) + '</span></div>' +
      '<div class="cc-field"><label>签名算法</label><span>' + esc(cert.sigAlg) + '</span></div>' +
      '<div class="cc-field"><label>公钥</label><span>' + esc(spki.alg) +
      (spki.curve ? ' · ' + esc(spki.curve) : '') + (spki.bits ? ' · ' + spki.bits + ' 位' : '') + '</span></div>' +
      '<div class="cc-field"><label>版本</label><span>v' + cert.version + '</span></div>' +
      '<div class="cc-field"><label>序列号</label><span class="mono serial">' + esc(cert.serial) + '</span></div>' +
      sanBlock +
      '<div class="cc-field full"><label>SHA-256 指纹</label><span class="mono fp" id="fp-' + i + '">计算中…</span></div>' +
      '</div>' +
      '<div class="cc-acts"><button class="mini" data-act="ext" data-i="' + i + '">全部扩展（' + cert.extensions.length + '）</button>' +
      '<button class="mini" data-act="copy" data-i="' + i + '">复制 PEM</button>' +
      '<button class="mini" data-act="dl" data-i="' + i + '">下载 PEM</button></div>' +
      '<div class="cc-ext hidden" id="ext-' + i + '"><table class="ext-table">' +
      (extRows || '<tr><td>（无扩展）</td></tr>') + '</table></div></div>';
  }

  function certsNow() {
    if (!current) return [];
    const c = current.chain;
    return c.chain.length ? c.chain.concat(c.extra || []) : current.certs;
  }

  function saveText(name, text) {
    const blob = new Blob([text], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 400);
  }

  listEl.addEventListener('click', ev => {
    const btn = ev.target.closest('button[data-act]');
    if (!btn) return;
    const i = +btn.dataset.i;
    const cert = certsNow()[i];
    if (!cert) return;
    const act = btn.dataset.act;
    if (act === 'ext') {
      const box = document.getElementById('ext-' + i);
      if (!box) return;
      box.classList.toggle('hidden');
      btn.textContent = box.classList.contains('hidden') ? '全部扩展（' + cert.extensions.length + '）' : '收起扩展';
    } else if (act === 'copy') {
      navigator.clipboard.writeText(cert.pem).then(() => toast('已复制 PEM')).catch(() => toast('复制失败', true));
    } else if (act === 'dl') {
      const name = (cert.commonName || 'cert-' + (i + 1)).replace(/[^\w.\-]+/g, '_').slice(0, 60) + '.pem';
      saveText(name, cert.pem);
    }
  });

  $('#drop').addEventListener('click', () => $('#file').click());
  $('#file').addEventListener('change', e => {
    if (e.target.files && e.target.files[0]) readFile(e.target.files[0]);
    e.target.value = '';
  });

  ['dragenter', 'dragover'].forEach(t => $('#drop').addEventListener(t, e => {
    e.preventDefault(); e.stopPropagation();
    $('#drop').classList.add('over');
  }));
  $('#drop').addEventListener('dragleave', e => {
    e.preventDefault(); e.stopPropagation();
    $('#drop').classList.remove('over');
  });
  $('#drop').addEventListener('drop', e => {
    e.preventDefault(); e.stopPropagation();
    $('#drop').classList.remove('over');
    const f = e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) readFile(f);
  });
  window.addEventListener('dragover', e => e.preventDefault());
  window.addEventListener('drop', e => e.preventDefault());

  $('#btnGo').addEventListener('click', () => run());
  input.addEventListener('keydown', e => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') run();
  });
  input.addEventListener('input', () => {
    statusEl.textContent = input.value.trim() ? '内容已改，点「解析」' : '还没有内容';
  });

  $('#btnClear').addEventListener('click', () => {
    input.value = '';
    current = null;
    listEl.innerHTML = '';
    chainBar.classList.add('hidden');
    notesEl.classList.add('hidden');
    statusEl.textContent = '还没有内容';
    toast('已清空');
  });

  $('#btnDownloadAll').addEventListener('click', () => {
    const certs = certsNow();
    if (!certs.length) { toast('先解析出证书', true); return; }
    saveText('cert-chain.pem', certs.map(c => c.pem).join(''));
    toast('已导出 ' + certs.length + ' 张证书');
  });

  $('#btnSample').addEventListener('click', () => {
    input.value = SAMPLE;
    statusEl.textContent = '已填入示例证书';
    run();
  });

  const SAMPLE = '-----BEGIN CERTIFICATE-----\n' +
    'MIID4DCCAsigAwIBAgIUICXi0ZfAUywjbiWCoP5uudHb5TgwDQYJKoZIhvcNAQEL\n' +
    'BQAwVjELMAkGA1UEBhMCQ04xHTAbBgNVBAoMFFhpYW5nbG9uZyBUZWNobm9sb2d5\n' +
    'MQwwCgYDVQQLDANPcHMxGjAYBgNVBAMMEWFwaS54aWFuZ2xvbmcudmlwMB4XDTI2\n' +
    'MTEyMjEwNTc1NVoXDTM2MTExOTEwNTc1NVowVjELMAkGA1UEBhMCQ04xHTAbBgNV\n' +
    'BAoMFFhpYW5nbG9uZyBUZWNobm9sb2d5MQwwCgYDVQQLDANPcHMxGjAYBgNVBAMM\n' +
    'EWFwaS54aWFuZ2xvbmcudmlwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n' +
    'AQEAlvYk/Ie/Clon5G80PlCecinIhE2gFjum7BXGRkwHuvPaSZLF82O+J0DAxKjn\n' +
    'kCelau+caVnch2trec8n1Dn3nY7KqZGMSuJNZmM4hwq31OLgXZ6uw46ed9LtGrs7\n' +
    '0tfyPneRGBHxdc9ZYD5elAlV1qH8z4Vp8xugwY350BJoAXkn8M59U11NPowPif1b\n' +
    'c/Buou708aEX9QQacXOGzFiyB7T1ZF8wvNg5Tge2bYTQNABswtirT5Qjh+GD1/Zk\n' +
    'EdltQYpGMqcWrCfCE2D2t1lO7VspcUJTwnReD7RzQVZITOMroKyU5K9MbZrfCqdi\n' +
    'MaDpfmRtZ+yvTvtq+uvKht3mGQIDAQABo4GlMIGiMB0GA1UdDgQWBBR8EnPyJsBF\n' +
    '8wcAUq7Cib+zrNq+VTAfBgNVHSMEGDAWgBR8EnPyJsBF8wcAUq7Cib+zrNq+VTAP\n' +
    'BgNVHRMBAf8EBTADAQH/MC0GA1UdEQQmMCSCEWFwaS54aWFuZ2xvbmcudmlwgg8q\n' +
    'LnhpYW5nbG9uZy52aXAwCwYDVR0PBAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMB\n' +
    'MA0GCSqGSIb3DQEBCwUAA4IBAQBEtWPZOtNiWGQIZgKvbmT9iGnFj6osO8dQriDA\n' +
    'NyQwlgswrwoY7G+96LCG6Lwp2bQ5p/ewINW7pv5arEQws76khFaWiiXZSbOdVi+p\n' +
    'jx8ikembhQCxh0/UfplaR7UGkkuimCvtS/GGIyTyKryIp14fWrUUA7rUnxF8r5S+\n' +
    '3yzxBbZprwK6Y5rrPTeJtpVXZg3YCK5Q9hFFJ0LATRhlsSzM6GvF8dQ64roQNuFK\n' +
    'PJxYDm2ZFtOzUQpovHZppeORDrIF/H+BIAqWNJlVySnaqAcJ9HM4oCGBrmkt1l9C\n' +
    'PHchUhrWxRzdH8ZgSRSiRW0mPvv7iKqOxsaNFUYWzyffG29H\n' +
    '-----END CERTIFICATE-----\n';

  window.CertUI = { run: run, certsNow: certsNow };
})();
