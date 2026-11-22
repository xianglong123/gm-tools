/* 证书 / 密钥库解析 —— 纯前端，不上传任何内容
   支持：PEM（含多段证书链）、DER（二进制证书）、JKS（证书条目，私钥条目不解密）
   依赖：无 */
(function () {
  'use strict';

  /* =========================================================
     1. ASN.1 / DER 解析
     ========================================================= */

  function bytesOf(buf) {
    if (buf instanceof Uint8Array) return buf;
    if (ArrayBuffer.isView(buf)) return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    return new Uint8Array(buf);
  }

  // 解析一个 DER 节点（含子节点）
  function asn1(bytes, off) {
    const b = bytes;
    off = off || 0;
    if (off >= b.length) throw new Error('DER 数据在偏移 ' + off + ' 处意外结束');

    const first = b[off];
    const cls = (first & 0xc0) >> 6;       // 0=universal 1=application 2=context 3=private
    const cons = (first & 0x20) !== 0;
    let tag = first & 0x1f;
    let p = off + 1;

    if (tag === 0x1f) {                    // 长标签
      tag = 0;
      let c;
      do { c = b[p++]; tag = (tag << 7) | (c & 0x7f); } while (c & 0x80);
    }

    if (p >= b.length) throw new Error('DER 长度字段缺失');
    let len = b[p++];
    if (len === 0x80) throw new Error('不支持不定长 DER 编码');
    if (len > 0x80) {
      const n = len & 0x7f;
      if (n > 4) throw new Error('DER 长度字段过长');
      len = 0;
      for (let i = 0; i < n; i++) len = (len << 8) | b[p++];
    }

    const start = p;
    const end = start + len;
    if (end > b.length) throw new Error('DER 内容越界（声明 ' + len + ' 字节，实际剩余 ' + (b.length - start) + '）');

    const node = { tag: tag, cls: cls, cons: cons, start: start, end: end, headerLen: start - off, raw: b.subarray(off, end) };

    if (cons) {
      const kids = [];
      let q = start;
      while (q < end) {
        const k = asn1(b, q);
        if (k.end <= q) throw new Error('DER 子节点长度为零');
        kids.push(k);
        q = k.end;
      }
      node.children = kids;
    }
    return node;
  }

  function rawOf(node) { return node.raw; }

  function bytesOfNode(node) { return node.raw.subarray(node.headerLen, node.headerLen + (node.end - node.start)); }

  function hex(bytes, sep) {
    const a = Array.from(bytes, x => x.toString(16).padStart(2, '0'));
    return sep ? a.join(sep).toUpperCase() : a.join('');
  }

  function str(node) {
    // 字符串类节点：UTF8String / PrintableString / IA5String / BMPString / T61
    const c = bytesOfNode(node);
    if (node.tag === 30) {                 // BMPString (UTF-16BE)
      let s = '';
      for (let i = 0; i + 1 < c.length; i += 2) s += String.fromCharCode((c[i] << 8) | c[i + 1]);
      return s;
    }
    return new TextDecoder('utf-8', { fatal: false }).decode(c);
  }

  function num(node) {
    // INTEGER → BigInt 字符串
    let n = 0n;
    for (const v of bytesOfNode(node)) n = (n << 8n) | BigInt(v);
    return n;
  }

  function oid(node) {
    const c = bytesOfNode(node);
    const parts = [];
    let v = 0;
    for (let i = 0; i < c.length; i++) {
      v = v * 128 + (c[i] & 0x7f);
      if (!(c[i] & 0x80)) {
        if (parts.length === 0) {
          parts.push(Math.floor(v / 40), v % 40);
        } else {
          parts.push(v);
        }
        v = 0;
      }
    }
    return parts.join('.');
  }

  /* =========================================================
     2. OID 名称表
     ========================================================= */

  const DNAME = {
    '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.9': 'STREET',
    '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.5': 'serialNumber', '2.5.4.4': 'SN',
    '2.5.4.42': 'GN', '2.5.4.12': 'title', '2.5.4.13': 'description', '2.5.4.15': 'businessCategory',
    '2.5.4.17': 'postalCode', '2.5.4.45': 'x500UniqueIdentifier',
    '1.2.840.113549.1.9.1': 'E', '1.2.840.113549.1.9.2': 'unstructuredName',
    '0.9.2342.19200300.100.1.25': 'DC', '0.9.2342.19200300.100.1.1': 'UID',
    '1.3.6.1.4.1.311.60.2.1.1': 'jurisdictionL', '1.3.6.1.4.1.311.60.2.1.2': 'jurisdictionST',
    '1.3.6.1.4.1.311.60.2.1.3': 'jurisdictionC',
    '1.2.156.112.113.2.1': 'SM2-signer'
  };

  const SIGALG = {
    '1.2.840.113549.1.1.2': 'MD2withRSA',
    '1.2.840.113549.1.1.4': 'MD5withRSA',
    '1.2.840.113549.1.1.5': 'SHA1withRSA',
    '1.2.840.113549.1.1.11': 'SHA256withRSA',
    '1.2.840.113549.1.1.12': 'SHA384withRSA',
    '1.2.840.113549.1.1.13': 'SHA512withRSA',
    '1.2.840.113549.1.1.14': 'SHA224withRSA',
    '1.2.840.113549.1.1.10': 'RSASSA-PSS',
    '1.2.840.10045.4.1': 'ECDSA-with-SHA1',
    '1.2.840.10045.4.3.1': 'ECDSA-with-SHA224',
    '1.2.840.10045.4.3.2': 'ECDSA-with-SHA256',
    '1.2.840.10045.4.3.3': 'ECDSA-with-SHA384',
    '1.2.840.10045.4.3.4': 'ECDSA-with-SHA512',
    '1.2.156.10197.1.501': 'SM3withSM2',
    '1.2.156.10197.1.502': 'SM3withSM2',
    '1.3.101.112': 'Ed25519',
    '1.3.101.113': 'Ed448',
    '1.2.840.113549.1.1.1': 'RSA',
    '1.2.840.10045.2.1': 'EC',
    '1.2.156.10197.1.301': 'SM2'
  };

  const CURVE = {
    '1.2.840.10045.3.1.7': 'P-256 (prime256v1)',
    '1.3.132.0.34': 'P-384 (secp384r1)',
    '1.3.132.0.35': 'P-521 (secp521r1)',
    '1.3.132.0.10': 'secp256k1',
    '1.2.156.10197.1.301': 'SM2 (sm2p256v1)'
  };

  const EKU = {
    '1.3.6.1.5.5.7.3.1': '服务器身份 (serverAuth)',
    '1.3.6.1.5.5.7.3.2': '客户端身份 (clientAuth)',
    '1.3.6.1.5.5.7.3.3': '代码签名 (codeSigning)',
    '1.3.6.1.5.5.7.3.4': '邮件保护 (emailProtection)',
    '1.3.6.1.5.5.7.3.8': '时间戳 (timeStamping)',
    '1.3.6.1.5.5.7.3.9': 'OCSP 签名 (OCSPSigning)',
    '2.5.29.37.0': '任意用途 (anyExtendedKeyUsage)'
  };

  const KU_BITS = ['数字签名', '不可否认', '密钥加密', '数据加密', '密钥协商', '证书签名', 'CRL 签名', '仅加密', '仅解密'];

  const EXT_NAME = {
    '2.5.29.19': '基本约束',
    '2.5.29.15': '密钥用法',
    '2.5.29.37': '扩展密钥用法',
    '2.5.29.17': '主体备用名',
    '2.5.29.14': '主体密钥标识',
    '2.5.29.35': '颁发者密钥标识',
    '2.5.29.31': 'CRL 分发点',
    '1.3.6.1.5.5.7.1.1': '授权信息访问',
    '2.5.29.32': '证书策略',
    '2.5.29.30': '名称约束'
  };

  function nameOf(map, key, fallback) {
    return map[key] || (fallback ? fallback + ' ' + key : key);
  }

  /* =========================================================
     3. 时间解析
     ========================================================= */

  function parseTime(node) {
    const s = str(node).trim();
    let iso;
    if (node.tag === 23) {                  // UTCTime
      const yy = +s.slice(0, 2);
      const y = yy >= 50 ? 1900 + yy : 2000 + yy;
      iso = String(y) + s.slice(2);
    } else if (node.tag === 24) {           // GeneralizedTime
      iso = s;
    } else {
      throw new Error('时间字段标签异常：' + node.tag);
    }
    // 20251122093000Z / 20251122093000+0800 / 251122093000Z
    const m = /^(\d{8})(\d{2})?(\d{2})?(\d{2})?(?:\.\d+)?(Z|[+-]\d{4})?$/.exec(iso);
    if (!m) throw new Error('无法解析时间：' + s);
    const y = +m[1].slice(0, 4), mo = +m[1].slice(4, 6) - 1, d = +m[1].slice(6, 8);
    const h = +(m[2] || 9), mi = +(m[3] || 0), sec = +(m[4] || 0);

    // 处理时区偏移
    let t;
    if (m[5] && m[5] !== 'Z') {
      const sign = m[5][0] === '-' ? -1 : 1;
      const hh = +m[5].slice(1, 3), mm = +m[5].slice(3, 5);
      t = Date.UTC(y, mo, d, h, mi, sec) - sign * (hh * 60 + mm) * 60000;
    } else {
      t = Date.UTC(y, mo, d, h, mi, sec);
    }
    return new Date(t);
  }

  function fmtDate(d) {
    if (!d || isNaN(d.getTime())) return '—';
    const p = n => String(n).padStart(2, '0');
    return d.getUTCFullYear() + '-' + p(d.getUTCMonth() + 1) + '-' + p(d.getUTCDate()) +
      ' ' + p(d.getUTCHours()) + ':' + p(d.getUTCMinutes()) + ':' + p(d.getUTCSeconds()) + ' UTC';
  }

  /* =========================================================
     4. 名称 / 扩展解析
     ========================================================= */

  // Name → [{k, v, oid}]
  function parseName(node) {
    const out = [];
    for (const rdn of node.children || []) {
      for (const atv of rdn.children || []) {
        if (!atv.children || atv.children.length < 2) continue;
        const oidNode = atv.children[0];
        const valNode = atv.children[1];
        const o = oid(oidNode);
        let v;
        try {
          v = str(valNode);
        } catch (e) {
          v = '<无法解码>';
        }
        out.push({ k: nameOf(DNAME, o, ''), oid: o, v: v });
      }
    }
    return out;
  }

  function formatName(rdns) {
    if (!rdns || !rdns.length) return '（空）';
    return rdns.map(x => (x.k || x.oid) + '=' + x.v).join(', ');
  }

  function nameKey(rdns) {
    // 用于链匹配的规范化名称（只用 CN/O/C，避免编码差异）
    return rdns.map(x => (x.k || x.oid).toUpperCase() + '=' + x.v.trim().toLowerCase()).join('|');
  }

  function parseSAN(node) {
    const out = [];
    for (const gn of node.children || []) {
      const t = gn.tag;
      let v;
      if (t === 7) {                       // iPAddress
        const c = bytesOfNode(gn);
        v = c.length === 4 ? Array.from(c).join('.')
          : c.length === 16 ? Array.from(c, (x, i) => (i % 2 ? '' : (i ? ':' : '') + x.toString(16))).join('')
            .replace(/\b0(?=[:]|$)/g, '') : hex(c, ':');
      } else if (t === 4) {                 // directoryName
        v = formatName(parseName(gn.children[0] || gn));
      } else {
        v = str(gn);
      }
      const label = { 1: '邮箱', 2: 'DNS', 6: 'URI', 7: 'IP', 4: '目录名', 8: '注册ID' }[t] || ('类型' + t);
      out.push({ type: t, label: label, value: v });
    }
    return out;
  }

  function bitStringFlags(node) {
    const c = bytesOfNode(node);
    const pad = c[0];
    const flags = [];
    for (let i = 0; i < KU_BITS.length; i++) {
      const byteIdx = 1 + Math.floor(i / 8);
      const bitIdx = 7 - (i % 8);
      if (byteIdx < c.length && ((c[byteIdx] >> bitIdx) & 1)) flags.push(KU_BITS[i]);
    }
    return { flags: flags, pad: pad };
  }

  function parseExtension(extNode) {
    const kids = extNode.children || [];
    const id = oid(kids[0]);
    let critical = false, valueNode = null, idx = 1;
    if (kids[1] && kids[1].tag === 1) { critical = bytesOfNode(kids[1])[0] !== 0; idx = 2; }
    valueNode = kids[idx];
    const ext = { oid: id, name: nameOf(EXT_NAME, id, '扩展'), critical: critical, detail: '', raw: '' };

    try {
      if (id === '2.5.29.19') {           // basicConstraints
        const inner = asn1(bytesOfNode(valueNode), 0);
        const parts = (inner.children || []);
        let ca = false, pathLen = null;
        parts.forEach(p => {
          if (p.tag === 1) ca = bytesOfNode(p)[0] !== 0;
          if (p.tag === 2) pathLen = Number(num(p));
        });
        ext.detail = ca ? ('CA 证书' + (pathLen !== null ? '，路径长度 ' + pathLen : '，路径不限')) : '非 CA 证书（终端实体）';
        ext.isCA = ca;
        ext.pathLen = pathLen;
      } else if (id === '2.5.29.15') {    // keyUsage
        const inner = asn1(bytesOfNode(valueNode), 0);
        const f = bitStringFlags(inner);
        ext.detail = f.flags.length ? f.flags.join('、') : '（无任何位）';
      } else if (id === '2.5.29.37') {    // extKeyUsage
        const inner = asn1(bytesOfNode(valueNode), 0);
        ext.detail = (inner.children || []).map(c => nameOf(EKU, oid(c), '') + ' (' + oid(c) + ')').join('；') || '（空）';
      } else if (id === '2.5.29.17') {    // SAN
        const inner = asn1(bytesOfNode(valueNode), 0);
        ext.san = parseSAN(inner);
        ext.detail = ext.san.map(s => s.label + ': ' + s.value).join('\n');
      } else if (id === '2.5.29.14') {    // SKI
        const inner = asn1(bytesOfNode(valueNode), 0);
        ext.detail = hex(bytesOfNode(inner), ':');
        ext.ski = hex(bytesOfNode(inner));
      } else if (id === '2.5.29.35') {    // AKI
        const inner = asn1(bytesOfNode(valueNode), 0);
        const parts = [];
        (inner.children || []).forEach(c => {
          if (c.tag === 0) { parts.push('keyId=' + hex(bytesOfNode(c), ':')); ext.aki = hex(bytesOfNode(c)); }
        });
        ext.detail = parts.join('；') || '（仅部分字段）';
      } else if (id === '2.5.29.31') {    // CRL DP
        const inner = asn1(bytesOfNode(valueNode), 0);
        ext.detail = collectURIs(inner).join('\n');
      } else if (id === '1.3.6.1.5.5.7.1.1') { // AIA
        const inner = asn1(bytesOfNode(valueNode), 0);
        const parts = [];
        (inner.children || []).forEach(ad => {
          const kids2 = ad.children || [];
          if (kids2.length >= 2) {
            const m = { '1.3.6.1.5.5.7.48.1': 'OCSP', '1.3.6.1.5.5.7.48.2': 'CA 签发者' }[oid(kids2[0])] || oid(kids2[0]);
            parts.push(m + ': ' + str(kids2[1]));
          }
        });
        ext.detail = parts.join('\n');
        if (parts.length) ext.ocsp = parts.find(p => p.indexOf('OCSP') === 0) || null;
      } else {
        ext.detail = '（未单独解析）';
      }
    } catch (e) {
      ext.detail = '解析失败：' + e.message;
    }
    ext.raw = hex(bytesOfNode(valueNode), ' ');
    return ext;
  }

  function collectURIs(node, acc) {
    acc = acc || [];
    if (node.cls === 2 && node.tag === 6) { try { acc.push(str(node)); } catch (e) { } }
    (node.children || []).forEach(c => collectURIs(c, acc));
    return acc;
  }

  /* =========================================================
     5. 公钥信息
     ========================================================= */

  function parseSPKI(spki) {
    const kids = spki.children || [];
    const algKids = (kids[0] && kids[0].children) || [];
    const algOid = algKids[0] ? oid(algKids[0]) : '';
    const info = { algOid: algOid, alg: nameOf(SIGALG, algOid, ''), curve: null, bits: 0, hex: '' };

    if (algOid === '1.2.840.10045.2.1' && algKids[1]) {
      const c = oid(algKids[1]);
      info.curve = nameOf(CURVE, c, '');
      info.curveOid = c;
    }
    if (algOid === '1.2.156.10197.1.301') info.curve = 'SM2 (sm2p256v1)';

    const pubNode = kids[1];
    if (pubNode) {
      const raw = bytesOfNode(pubNode);
      const body = raw.subarray(1);      // 去掉 unused bits 计数
      info.hex = hex(body);
      if (algOid === '1.2.840.113549.1.1.1') {
        try {
          const rsa = asn1(body, 0);
          const n = rsa.children[0];
          info.bits = Number(num(n).toString(2).length);
          info.rsaModulus = hex(bytesOfNode(n));
          info.rsaExponent = String(num(rsa.children[1]));
        } catch (e) { }
      } else if (info.curve) {
        const bits = {
          '1.2.840.10045.3.1.7': 256,
          '1.3.132.0.34': 384,
          '1.3.132.0.35': 521,
          '1.3.132.0.10': 256,
          '1.2.156.10197.1.301': 256
        }[info.curveOid];
        info.bits = bits || (body.length * 4);
        info.ecPoint = hex(body);
      } else if (algOid === '1.3.101.112') {
        info.bits = 256;
      } else if (body.length > 0) {
        info.bits = body.length * 8;
      }
    }
    return info;
  }

  /* =========================================================
     6. 证书总解析
     ========================================================= */

  function parseCertificate(der) {
    const root = asn1(der, 0);
    if (!root.children || root.children.length < 3) throw new Error('不是合法的 X.509 证书结构');
    const tbs = root.children[0];
    let p = 0;

    const cert = {};
    // version
    cert.version = 1;
    if (tbs.children[p] && tbs.children[p].cls === 2 && tbs.children[p].tag === 0) {
      cert.version = Number(num(tbs.children[p].children[0])) + 1;
      p++;
    }
    cert.serial = num(tbs.children[p]).toString(16).toUpperCase();
    p++;

    cert.sigAlgOid = oid(tbs.children[p].children[0]);
    cert.sigAlg = nameOf(SIGALG, cert.sigAlgOid, '');
    p++;

    cert.issuerRDNs = parseName(tbs.children[p++]);

    const validity = tbs.children[p++];
    cert.notBefore = parseTime(validity.children[0]);
    cert.notAfter = parseTime(validity.children[1]);

    cert.subjectRDNs = parseName(tbs.children[p++]);
    cert.issuer = formatName(cert.issuerRDNs);
    cert.subject = formatName(cert.subjectRDNs);
    cert.issuerKey = nameKey(cert.issuerRDNs);
    cert.subjectKey = nameKey(cert.subjectRDNs);

    cert.spki = parseSPKI(tbs.children[p++]);

    // 跳过 optional [1]/[2]，找 extensions [3]
    cert.extensions = [];
    for (; p < tbs.children.length; p++) {
      const n = tbs.children[p];
      if (n.cls === 2 && n.tag === 3) {
        const exts = n.children[0];
        (exts.children || []).forEach(e => {
          try { cert.extensions.push(parseExtension(e)); } catch (err) { }
        });
      }
    }

    // 从扩展里取常用字段
    cert.extensions.forEach(e => {
      if (e.oid === '2.5.29.17') cert.san = e.san;
      if (e.oid === '2.5.29.19') {
        cert.isCA = e.isCA === true;
        cert.pathLen = e.pathLen !== undefined ? e.pathLen : null;
        cert.hasBasicConstraints = true;
      }
      if (e.oid === '2.5.29.15') cert.keyUsage = e.detail;
      if (e.oid === '2.5.29.37') cert.extKeyUsage = e.detail;
      if (e.oid === '2.5.29.14') cert.ski = e.ski;
      if (e.oid === '2.5.29.35') cert.aki = e.aki;
    });

    cert.isSelfSigned = cert.issuerKey === cert.subjectKey;
    cert.der = der;
    cert.pem = derToPem(der);

    // 通用名称
    const cn = cert.subjectRDNs.filter(x => x.k === 'CN').pop();
    cert.commonName = cn ? cn.v : '';
    cert.org = (cert.subjectRDNs.filter(x => x.k === 'O').pop() || {}).v || '';

    // 缺少 SAN 但 CN 有值 —— 现代浏览器已不看 CN，这点要提示
    cert.cnOnly = !cert.san && !!cert.commonName;

    return cert;
  }

  function derToPem(der) {
    const b64 = base64Of(der);
    const lines = b64.match(/.{1,64}/g) || [];
    return '-----BEGIN CERTIFICATE-----\n' + lines.join('\n') + '\n-----END CERTIFICATE-----\n';
  }

  function base64Of(bytes) {
    let s = '';
    const c = bytesOf(bytes);
    for (let i = 0; i < c.length; i++) s += String.fromCharCode(c[i]);
    return btoa(s);
  }

  function bytesFromBase64(b64) {
    const clean = b64.replace(/[^A-Za-z0-9+/=]/g, '');
    const bin = atob(clean);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  /* =========================================================
     7. PEM / JKS 容器
     ========================================================= */

  function parsePem(text) {
    const blocks = [];
    const re = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;
    let m;
    while ((m = re.exec(text))) {
      blocks.push({ label: m[1].trim(), body: m[2] });
    }
    const certs = [];
    const ignored = [];
    blocks.forEach(b => {
      if (/^CERTIFICATE$|^X509 CERTIFICATE$|^TRUSTED CERTIFICATE$/.test(b.label)) {
        try { certs.push(bytesFromBase64(b.body)); } catch (e) { }
      } else {
        ignored.push(b.label);
      }
    });
    return { certs: certs, ignored: ignored, count: blocks.length };
  }

  // JKS / JCEKS 二进制解析（证书条目不加密，私钥条目不尝试解密）
  function parseJks(bytes) {
    const b = bytesOf(bytes);
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const be32 = o => dv.getUint32(o, false);
    const be64 = o => {
      // 只用低 32 位判时间戳（JKS 时间戳毫秒级 long）
      return Number(dv.getBigUint64 ? dv.getBigUint64(o, false) : BigInt(dv.getUint32(o, false)));
    };

    const magic = be32(0);
    if (magic !== 0xfeedfeed) throw new Error('不是 JKS 格式（magic 不符）');
    const version = be32(4);
    if (version !== 1 && version !== 2) throw new Error('JKS 版本不支持：' + version);
    const count = be32(8);

    let off = 12;
    const certs = [];
    const keys = [];
    const aliases = [];

    function readUtf(o) {
      const len = dv.getUint16(o, false);
      const s = new TextDecoder('utf-8').decode(b.subarray(o + 2, o + 2 + len));
      return { s: s, next: o + 2 + len };
    }

    for (let i = 0; i < count; i++) {
      const tag = be32(off); off += 4;
      const al = readUtf(off); off = al.next;
      const ts = be64(off); off += 8;

      if (tag === 1) {                       // private key entry
        const keyLen = be32(off); off += 4;
        off += keyLen;                       // 跳过加密私钥
        const chainLen = be32(off); off += 4;
        const chain = [];
        for (let c = 0; c < chainLen; c++) {
          const t = readUtf(off); off = t.next;
          const len = be32(off); off += 4;
          chain.push(b.subarray(off, off + len));
          off += len;
        }
        keys.push({ alias: al.s, timestamp: ts, chainLength: chainLen });
        chain.forEach(cd => certs.push({ der: cd, from: al.s }));
      } else if (tag === 2) {                // trusted cert entry
        const t = readUtf(off); off = t.next;
        const len = be32(off); off += 4;
        certs.push({ der: b.subarray(off, off + len), from: al.s });
        off += len;
      } else {
        throw new Error('未知的 JKS 条目类型：' + tag);
      }
      aliases.push(al.s);
    }

    return { certs: certs, keys: keys, aliases: aliases, version: version };
  }

  function isJks(bytes) {
    const b = bytesOf(bytes);
    if (b.length < 12) return false;
    return b[0] === 0xfe && b[1] === 0xed && b[2] === 0xfe && b[3] === 0xed;
  }

  function isJceks(bytes) {
    const b = bytesOf(bytes);
    if (b.length < 4) return false;
    return b[0] === 0xce && b[1] === 0xce && b[2] === 0xce && b[3] === 0xce;
  }

  /* =========================================================
     8. 链组织与完整性检查
     ========================================================= */

  function buildChain(certs) {
    const result = { chain: [], extra: [], state: 'unknown', messages: [], missing: [] };

    if (!certs.length) { result.state = 'empty'; return result; }

    const used = new Set();
    const leaves = certs.filter(c => !c.isCA);

    if (leaves.length) {
      // 有终端证书：从它往上走到根
      const start = leaves[0];
      used.add(certs.indexOf(start));
      let node = start;
      for (let g = 0; g < 20; g++) {
        result.chain.push(node);
        const up = certs.findIndex((c, i) => !used.has(i) && c.subjectKey === node.issuerKey);
        if (up < 0) {
          if (!node.isSelfSigned) result.missing.push(node.issuer);
          break;
        }
        used.add(up);
        node = certs[up];
      }
    } else if (certs.length === 1) {
      used.add(0);
      result.chain.push(certs[0]);
    } else {
      // 全是 CA：从自签根往下排
      const rootIdx = certs.findIndex(c => c.isSelfSigned);
      const startIdx = rootIdx >= 0 ? rootIdx : 0;
      used.add(startIdx);
      let node = certs[startIdx];
      for (let g = 0; g < 20; g++) {
        result.chain.push(node);
        const down = certs.findIndex((c, i) => !used.has(i) && c.issuerKey === node.subjectKey);
        if (down < 0) break;
        used.add(down);
        node = certs[down];
      }
    }

    certs.forEach((c, i) => { if (!used.has(i)) result.extra.push(c); });

    const top = result.chain[result.chain.length - 1];
    const allCA = certs.every(c => c.isCA);

    if (result.missing.length) {
      result.state = 'broken';
      result.messages.push('链不完整：最上层的证书由「' + result.missing[0] + '」签发，但这个证书不在你提供的证书里。');
      result.messages.push('这是线上最典型的事故原因——服务器只下发终端证书、漏掉中间证书，Java 客户端会报 PKIX path building failed。');
    } else if (top && top.isSelfSigned && result.chain.length > 1) {
      result.state = 'complete';
      result.messages.push('链完整：从终端证书一路签到自签根「' + (top.commonName || top.subject) + '」。');
    } else if (allCA && result.chain.length > 1) {
      result.state = 'ca-set';
      result.messages.push('这是一组 CA 证书（' + result.chain.length + ' 张），按签发关系从「' + (result.chain[0].commonName) + '」往下排好了，但没有走到自签根，无法确认是否完整。');
    } else if (result.chain.length === 1) {
      result.state = 'single';
      result.messages.push('只提供了 1 张证书。' + (top.isSelfSigned ? '它是自签证书（无上级）。' : '它的上级证书不在其中，无法判断链是否完整。'));
    } else {
      result.state = 'partial';
      result.messages.push('链在此中断，但已有多张证书按签发关系串起来了。');
    }

    if (result.extra.length) {
      result.messages.push('另有 ' + result.extra.length + ' 张证书无法按签发关系接入这条链，已单独列在后面。');
    }

    return result;
  }

  function validityOf(cert, now) {
    const t = (now || new Date()).getTime();
    const nb = cert.notBefore.getTime(), na = cert.notAfter.getTime();
    const days = Math.floor((na - t) / 86400000);
    let state, text;
    if (t < nb) { state = 'notyet'; text = '尚未生效（还有 ' + Math.ceil((nb - t) / 86400000) + ' 天生效）'; }
    else if (t > na) { state = 'expired'; text = '已过期 ' + (-days) + ' 天'; }
    else if (days <= 30) { state = 'soon'; text = '还可以用 ' + days + ' 天，即将到期'; }
    else { state = 'ok'; text = '有效，剩余 ' + days + ' 天'; }
    return { state: state, text: text, days: days };
  }

  /* =========================================================
     9. 密码学辅助（指纹）
     ========================================================= */

  async function sha256Of(bytes) {
    if (window.crypto && crypto.subtle) {
      const buf = await crypto.subtle.digest('SHA-256', bytesOf(bytes));
      return new Uint8Array(buf);
    }
    return null;
  }

  function sha256Fp(bytes) {
    // SSH 风格：SHA256:base64url(43 字符，无填充)
    return sha256Of(bytes).then(h => {
      if (!h) return null;
      let s = '';
      for (const v of h) s += String.fromCharCode(v);
      return 'SHA256:' + btoa(s).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
    });
  }

  /* =========================================================
     10. 对外 API
     ========================================================= */

  function analyze(textOrBytes, opts) {
    const notes = [];
    const certs = [];
    let keys = [];
    let sourceKind = '';

    let input;
    if (typeof textOrBytes === 'string') {
      const trimmed = textOrBytes.trim();
      if (!trimmed) throw new Error('没有内容可解析');
      if (/-----BEGIN/.test(trimmed)) {
        sourceKind = 'PEM';
        const p = parsePem(trimmed);
        if (!p.certs.length) {
          throw new Error('PEM 里没有找到证书段（发现：' + (p.ignored.join('、') || '无') + '）。本工具目前只解析证书，私钥段会被忽略。');
        }
        p.certs.forEach(d => certs.push(parseCertificate(d)));
        if (p.ignored.length) notes.push('忽略了 ' + p.ignored.length + ' 个非证书的 PEM 段（' + p.ignored.join('、') + '）。');
      } else {
        // 尝试当作裸 base64 证书
        const clean = trimmed.replace(/\s+/g, '');
        if (/^[A-Za-z0-9+/=]{60,}$/.test(clean)) {
          sourceKind = 'Base64';
          const der = bytesFromBase64(clean);
          certs.push(parseCertificate(der));
          notes.push('输入像是裸 Base64，已自动按单张证书解析。');
        } else {
          throw new Error('无法识别的内容。请粘贴带 -----BEGIN CERTIFICATE----- 的 PEM，或上传 .pem/.crt/.der/.jks 文件。');
        }
      }
    } else {
      input = bytesOf(textOrBytes);
      if (isJks(input)) {
        sourceKind = 'JKS';
        const j = parseJks(input);
        j.certs.forEach(c => {
          try {
            const cert = parseCertificate(c.der);
            cert.alias = c.from;
            certs.push(cert);
          } catch (e) {
            notes.push('别名 ' + (c.from || '?') + ' 的证书解析失败：' + e.message);
          }
        });
        keys = j.keys;
        notes.push('这是一个 JKS 密钥库（version ' + j.version + '）：' + j.aliases.length + ' 个条目，其中 ' + j.keys.length + ' 个私钥条目、' + j.certs.length + ' 张证书。');
        if (j.keys.length) {
          notes.push('私钥条目（' + j.keys.map(k => k.alias).join('、') + '）是加密的，需要 keystore 口令才能解开 —— 本工具在本地也不做这件事，只解析证书部分。');
        }
      } else if (isJceks(input)) {
        throw new Error('这是 JCEKS（jceks）格式，目前只支持 JKS / PEM / DER。');
      } else if (input[0] === 0x30) {
        sourceKind = 'DER';
        certs.push(parseCertificate(input));
      } else {
        throw new Error('无法识别的内容。支持 PEM 文本、DER 二进制、JKS 密钥库。');
      }
    }

    const chain = buildChain(certs);
    return { sourceKind: sourceKind, certs: certs, chain: chain, notes: notes, keys: keys };
  }

  window.CertTool = {
    analyze: analyze,
    validityOf: validityOf,
    fmtDate: fmtDate,
    sha256Fp: sha256Fp,
    parseCertificate: parseCertificate,
    derToPem: derToPem,
    asn1: asn1,
    oid: oid
  };
})();
