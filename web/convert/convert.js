/* 证书 / 密钥容器格式互转 —— 纯前端
   PEM ⇄ PKCS#12(.pfx/.p12) ⇄ JKS(.jks/.keystore)，附单证书 DER ⇄ PEM
   依赖：vendor/forge.min.js（PKCS#12）、cert.js（ASN.1 与证书解析） */
(function () {
  'use strict';

  var F = window.forge;
  var CT = window.CertTool;

  /* ---------------- 基础工具 ---------------- */

  function bytesOf(x) {
    if (x instanceof Uint8Array) return x;
    if (ArrayBuffer.isView(x)) return new Uint8Array(x.buffer, x.byteOffset, x.byteLength);
    if (x instanceof ArrayBuffer) return new Uint8Array(x);
    throw new Error('不是二进制数据');
  }

  function concat() {
    var total = 0, i, a;
    for (i = 0; i < arguments.length; i++) total += arguments[i].length;
    var out = new Uint8Array(total), off = 0;
    for (i = 0; i < arguments.length; i++) { a = arguments[i]; out.set(a, off); off += a.length; }
    return out;
  }

  function contentOf(node) {
    return node.raw.subarray(node.headerLen, node.headerLen + (node.end - node.start));
  }

  function binOf(bytes) {
    var s = '', c = bytesOf(bytes);
    for (var i = 0; i < c.length; i++) s += String.fromCharCode(c[i]);
    return s;
  }

  function bytesOfBin(bin) {
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i) & 0xff;
    return out;
  }

  function b64Of(bytes) {
    return btoa(binOf(bytes));
  }

  function fromB64(s) {
    var bin = atob(s.replace(/[^A-Za-z0-9+/=]/g, ''));
    return bytesOfBin(bin);
  }

  function derLen(n) {
    if (n < 0x80) return Uint8Array.of(n);
    if (n < 0x100) return Uint8Array.of(0x81, n);
    if (n < 0x10000) return Uint8Array.of(0x82, n >> 8, n & 0xff);
    return Uint8Array.of(0x83, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
  }

  function derWrap(tag, content) {
    return concat(Uint8Array.of(tag), derLen(content.length), content);
  }

  function sha1(bytes) {
    return crypto.subtle.digest('SHA-1', bytes).then(function (b) { return new Uint8Array(b); });
  }

  function rand(n) {
    var a = new Uint8Array(n);
    crypto.getRandomValues(a);
    return a;
  }

  // Java 的 JavaKeyStore.convertToBytes：每个 char 拆成两个字节（UTF-16BE，高位在前）
  function passBytes(str) {
    var out = new Uint8Array(str.length * 2);
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      out[i * 2] = (c >> 8) & 0xff;
      out[i * 2 + 1] = c & 0xff;
    }
    return out;
  }

  function pemBody(text) {
    var lines = text.split('\n');
    var out = [];
    for (var i = 0; i < lines.length; i++) if (!/-----/.test(lines[i])) out.push(lines[i].trim());
    return out.join('');
  }

  /* ---------------- JKS 私钥保护（OpenJDK KeyProtector） ---------------- */

  var OID_KEYPROT = Uint8Array.of(0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x2a, 0x02, 0x11, 0x01, 0x01);

  // 由 salt 与口令派生和密钥等长的异或流
  async function xorStream(len, pb, salt) {
    var out = new Uint8Array(len);
    var digest = salt;
    var off = 0;
    var rounds = Math.ceil(len / 20);
    for (var i = 0; i < rounds; i++) {
      digest = await sha1(concat(pb, digest));
      var take = Math.min(20, len - off);
      out.set(digest.subarray(0, take), off);
      off += take;
    }
    return out;
  }

  async function jksUnwrap(protectedDer, password) {
    var root = CT.asn1(protectedDer, 0);
    if (!root.children || root.children.length < 2) throw new Error('私钥保护结构异常');
    var algOid = CT.oid(root.children[0].children[0]);
    if (algOid !== '1.3.6.1.4.1.42.2.17.1.1') {
      throw new Error('不支持的私钥保护算法：' + algOid + '（JKS 里通常只有 JDK KeyProtector）');
    }
    var encr = contentOf(root.children[1]);
    if (encr.length < 41) throw new Error('受保护的私钥数据长度异常');
    var salt = encr.subarray(0, 20);
    var body = encr.subarray(20, encr.length - 20);
    var check = encr.subarray(encr.length - 20);
    var pb = passBytes(password);
    var xk = await xorStream(body.length, pb, salt);
    var plain = new Uint8Array(body.length);
    for (var i = 0; i < body.length; i++) plain[i] = body[i] ^ xk[i];
    var d = await sha1(concat(pb, plain));
    var same = true;
    for (var j = 0; j < 20; j++) if (d[j] !== check[j]) same = false;
    if (!same) throw new Error('口令不对，解不开这个私钥条目');
    return plain;
  }

  async function jksWrap(pkcs8, password) {
    var pb = passBytes(password);
    var salt = rand(20);
    var xk = await xorStream(pkcs8.length, pb, salt);
    var tmp = new Uint8Array(pkcs8.length);
    for (var i = 0; i < pkcs8.length; i++) tmp[i] = pkcs8[i] ^ xk[i];
    var tail = await sha1(concat(pb, pkcs8));
    var encr = concat(salt, tmp, tail);
    var alg = derWrap(0x30, concat(OID_KEYPROT, Uint8Array.of(0x05, 0x00)));
    return derWrap(0x30, concat(alg, derWrap(0x04, encr)));
  }

  /* ---------------- JKS 读写 ---------------- */

  function isJks(b) {
    b = bytesOf(b);
    return b.length > 12 && b[0] === 0xfe && b[1] === 0xed && b[2] === 0xfe && b[3] === 0xed;
  }

  function readJksStructure(bytes) {
    var b = bytesOf(bytes);
    var dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    if (dv.getUint32(0, false) !== 0xfeedfeed) throw new Error('不是 JKS 文件');
    var version = dv.getUint32(4, false);
    if (version !== 1 && version !== 2) throw new Error('不支持的 JKS 版本 ' + version);
    var count = dv.getUint32(8, false);
    var off = 12;
    var entries = [];

    function readUtf(o) {
      var len = dv.getUint16(o, false);
      var s = new TextDecoder('utf-8').decode(b.subarray(o + 2, o + 2 + len));
      return { s: s, next: o + 2 + len };
    }

    for (var i = 0; i < count; i++) {
      var tag = dv.getUint32(off, false); off += 4;
      var al = readUtf(off); off = al.next;
      var tsLo = Number(dv.getBigUint64(off, false)); off += 8;

      if (tag === 1) {
        var keyLen = dv.getUint32(off, false); off += 4;
        var protKey = b.subarray(off, off + keyLen); off += keyLen;
        var chainLen = dv.getUint32(off, false); off += 4;
        var chain = [];
        for (var c = 0; c < chainLen; c++) {
          var t = readUtf(off); off = t.next;
          var len = dv.getUint32(off, false); off += 4;
          chain.push(b.subarray(off, off + len)); off += len;
        }
        entries.push({ tag: 1, alias: al.s, timestamp: tsLo, protectedKey: protKey, chain: chain });
      } else if (tag === 2) {
        var t2 = readUtf(off); off = t2.next;
        var len2 = dv.getUint32(off, false); off += 4;
        entries.push({ tag: 2, alias: al.s, timestamp: tsLo, cert: b.subarray(off, off + len2) });
        off += len2;
      } else {
        throw new Error('JKS 条目类型异常：' + tag);
      }
    }
    return { version: version, entries: entries };
  }

  function u16(v) { return Uint8Array.of((v >> 8) & 0xff, v & 0xff); }
  function u32(v) { return Uint8Array.of((v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff); }
  function u64(v) {
    var out = new Uint8Array(8);
    var dv = new DataView(out.buffer);
    dv.setBigUint64(0, BigInt(v), false);
    return out;
  }
  function utf8Bytes(s) { return new TextEncoder().encode(s); }

  // 文件尾完整性摘要：SHA1(UTF-16BE 口令 + "Mighty Aphrodite" + 前述全部字节)
  var JKS_SALT = new TextEncoder().encode('Mighty Aphrodite');

  async function buildJks(entries, storePass) {
    if (!storePass) throw new Error('写 JKS 需要 storepass');
    var parts = [u32(0xfeedfeed), u32(2), u32(entries.length)];
    var now = Date.now();
    entries.forEach(function (e) {
      var alias = utf8Bytes(e.alias);
      parts.push(u32(e.tag), u16(alias.length), alias, u64(e.timestamp || now));
      var typeName = utf8Bytes('X.509');
      if (e.tag === 1) {
        parts.push(u32(e.protectedKey.length), e.protectedKey);
        parts.push(u32(e.chain.length));
        e.chain.forEach(function (der) {
          parts.push(u16(typeName.length), typeName, u32(der.length), der);
        });
      } else {
        parts.push(u16(typeName.length), typeName, u32(e.cert.length), e.cert);
      }
    });
    var body = concat.apply(null, parts);
    var digest = await sha1(concat(passBytes(storePass), JKS_SALT, body));
    return concat(body, digest);
  }

  /* ---------------- PKCS#12 ---------------- */

  // 私钥对象 → PKCS#8 DER（forge 的 min 版没有 wrapPrivateKeyInfo，这里按标准手拼）
  function pkcs8Of(keyObj) {
    if (!keyObj || !keyObj.n) {
      throw new Error('目前只支持 RSA 私钥走格式转换；EC / SM2 私钥请用 openssl pkcs12 -export 处理');
    }
    var S = F.asn1.Class.UNIVERSAL, T = F.asn1.Type;
    var rsaDer = F.asn1.toDer(F.pki.privateKeyToRSAPrivateKey(keyObj)).getBytes();
    var alg = F.asn1.create(S, T.SEQUENCE, true, [
      F.asn1.create(S, T.OID, false, F.asn1.oidToDer('1.2.840.113549.1.1.1').getBytes()),
      F.asn1.create(S, T.NULL, false, '')
    ]);
    var pki = F.asn1.create(S, T.SEQUENCE, true, [
      F.asn1.create(S, T.INTEGER, false, F.asn1.integerToDer(0).getBytes()),
      alg,
      F.asn1.create(S, T.OCTETSTRING, false, rsaDer)
    ]);
    return bytesOfBin(F.asn1.toDer(pki).getBytes());
  }

  function p12Read(bytes, password) {
    var asn1;
    try {
      asn1 = F.asn1.fromDer(F.util.createBuffer(binOf(bytes)));
    } catch (e) {
      throw new Error('不是合法的 PKCS#12 文件');
    }
    var p12;
    try {
      p12 = F.pkcs12.pkcs12FromAsn1(asn1, password || '');
    } catch (e) {
      throw new Error('PKCS#12 解析失败：口令不对，或者文件已损坏');
    }

    var certs = [];
    var certOid = F.pki.oids.certBag;
    var bags = p12.getBags({ bagType: certOid })[certOid] || [];
    bags.forEach(function (bag) {
      if (!bag.cert) return;
      try {
        var der = F.asn1.toDer(F.pki.certificateToAsn1(bag.cert)).getBytes();
        certs.push({ der: bytesOfBin(der), alias: (bag.attributes && bag.attributes.friendlyName && bag.attributes.friendlyName[0]) || '', localKeyId: null });
      } catch (e) { /* 跳过异常证书 */ }
    });

    var privKeyObj = null, privDer = null, privAlias = '';
    [F.pki.oids.pkcs8ShroudedKeyBag, F.pki.oids.keyBag].forEach(function (type) {
      var kb = p12.getBags({ bagType: type })[type] || [];
      kb.forEach(function (bag) {
        if (!bag.key || privKeyObj) return;
        privKeyObj = bag.key;
        privAlias = (bag.attributes && bag.attributes.friendlyName && bag.attributes.friendlyName[0]) || '';
      });
    });

    if (privKeyObj) {
      privDer = pkcs8Of(privKeyObj);
    }

    return { kind: 'pkcs12', certs: certs, privateKeyDer: privDer, privateAlias: privAlias };
  }

  function p12Write(certs, privateKeyDer, privateAlias, password) {
    var certObjs = certs.map(function (c) {
      return F.pki.certificateFromPem(CT.derToPem(c.der));
    });
    var privObj = null;
    if (privateKeyDer) {
      privObj = F.pki.privateKeyFromPem(
        '-----BEGIN PRIVATE KEY-----\n' + wrapper(privateKeyDer) + '-----END PRIVATE KEY-----\n'
      );
    }
    var asn1 = F.pkcs12.toPkcs12Asn1(privObj, certObjs, password || '', {
      algorithm: '3des',
      friendlyName: privateAlias || 'server'
    });
    return bytesOfBin(F.asn1.toDer(asn1).getBytes());
  }

  function wrapper(der) {
    var b64 = b64Of(der);
    return (b64.match(/.{1,64}/g) || []).join('\n') + '\n';
  }

  /* ---------------- PEM 组装 ---------------- */

  function parsePemText(text) {
    var re = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;
    var m, blocks = [];
    while ((m = re.exec(text))) blocks.push({ label: m[1].trim(), body: m[2] });
    var certs = [], privDer = null, privLabel = '';
    blocks.forEach(function (b) {
      if (/^CERTIFICATE$|^X509 CERTIFICATE$|^TRUSTED CERTIFICATE$/.test(b.label)) {
        try { certs.push(fromB64(b.body)); } catch (e) { }
      } else if (/^PRIVATE KEY$|^RSA PRIVATE KEY$|^EC PRIVATE KEY$|^ENCRYPTED PRIVATE KEY$/.test(b.label)) {
        if (privDer) return;
        if (b.label === 'ENCRYPTED PRIVATE KEY') throw new Error('这是加密过的私钥（ENCRYPTED PRIVATE KEY），先用 openssl pkey 解成明文再转');
        try {
          if (b.label === 'PRIVATE KEY') {
            // 本来就是 PKCS#8，原样保留，避免重编码丢信息
            privDer = fromB64(b.body);
          } else {
            var obj = F.pki.privateKeyFromPem('-----BEGIN ' + b.label + '-----\n' + b.body + '-----END ' + b.label + '-----\n');
            privDer = pkcs8Of(obj);
          }
          privLabel = b.label;
        } catch (e) {
          throw new Error('私钥解析失败：' + e.message);
        }
      }
    });
    return { certs: certs, privateKeyDer: privDer, privateLabel: privLabel };
  }

  /* ---------------- 统一入口 ---------------- */

  async function load(input, password) {
    var notes = [];
    var b;

    if (typeof input === 'string') {
      if (!input.trim()) throw new Error('没有内容');
      if (!/-----BEGIN/.test(input)) throw new Error('这段文本里没有 PEM 段');
      var p = parsePemText(input);
      if (!p.certs.length && !p.privateKeyDer) throw new Error('PEM 里没有证书也没有私钥');
      var res = { kind: 'pem', certs: p.certs.map(function (d) { return { der: d, alias: '' }; }), privateKeyDer: p.privateKeyDer, privateAlias: '' };
      if (!p.certs.length) notes.push('只有私钥，没有证书。转成 JKS / PFX 后是没有证书链的。');
      return { value: res, notes: notes };
    }

    b = bytesOf(input);
    if (isJks(b)) {
      var st = readJksStructure(b);
      var out = { kind: 'jks', certs: [], privateKeyDer: null, privateAlias: '', entries: st.entries.length };
      var keyEntry = null;
      st.entries.forEach(function (e) {
        if (e.tag === 1) {
          if (!keyEntry) keyEntry = e;
          e.chain.forEach(function (der) { out.certs.push({ der: der, alias: e.alias }); });
        } else {
          out.certs.push({ der: e.cert, alias: e.alias });
        }
      });
      if (keyEntry) {
        out.privateAlias = keyEntry.alias;
        if (!password) {
          notes.push('这个 JKS 里有一个私钥条目（' + keyEntry.alias + '），填入口令才能一并导出私钥。');
        } else {
          try {
            out.privateKeyDer = await jksUnwrap(keyEntry.protectedKey, password);
          } catch (e) {
            notes.push('私钥解密失败：' + e.message);
          }
        }
      }
      notes.push('JKS 版本 ' + st.version + '，共 ' + st.entries.length + ' 个条目，解析出 ' + out.certs.length + ' 张证书。');
      return { value: out, notes: notes };
    }

    // 二进制 DER：可能是 PKCS#12，也可能是单张证书
    var p12Err = '';
    try {
      var p12 = p12Read(b, password);
      if (p12.certs.length || p12.privateKeyDer) {
        return { value: p12, notes: [] };
      }
      p12Err = 'PKCS#12 里没有可用的条目';
    } catch (e) { p12Err = e.message; }

    try {
      var single = CT.parseCertificate(b);
      return { value: { kind: 'der', certs: [{ der: b, alias: '' }], privateKeyDer: null, privateAlias: '' }, notes: ['识别为单张 DER 证书。'] };
    } catch (e) {
      throw new Error('无法识别的文件：既不是 JKS，也不是 PKCS#12，也不是 DER 证书' + (p12Err ? '（PKCS#12 尝试：' + p12Err + '）' : ''));
    }
  }

  async function toPem(bundle) {
    var certPem = bundle.certs.map(function (c) { return CT.derToPem(c.der); }).join('');
    var keyPem = '';
    if (bundle.privateKeyDer) {
      keyPem = '-----BEGIN PRIVATE KEY-----\n' + wrapper(bundle.privateKeyDer) + '-----END PRIVATE KEY-----\n';
    }
    return { fullchain: certPem, privateKey: keyPem };
  }

  async function toJks(bundle, password, keyPassword) {
    if (!password) throw new Error('JKS 需要一个口令（后面用 keytool 打开时也要它）');
    var entries = [];
    var certs = bundle.certs.slice();
    var used = certs.length ? 1 : 0;
    if (bundle.privateKeyDer) {
      var kp = keyPassword || password;
      var prot = await jksWrap(bundle.privateKeyDer, kp);
      entries.push({
        tag: 1,
        alias: bundle.privateAlias || 'server',
        protectedKey: prot,
        chain: bundle.certs.map(function (c) { return c.der; })
      });
    }
    // 若没有私钥条目，则每张证书单独作为一个 trusted cert 条目
    if (!entries.length) {
      if (!certs.length) throw new Error('没有证书可写入');
      certs.forEach(function (c, i) {
        entries.push({ tag: 2, alias: c.alias || ('cert-' + (i + 1)), cert: c.der });
      });
    }
    return buildJks(entries, password);
  }

  function toPkcs12(bundle, password, alias) {
    if (!password) throw new Error('PKCS#12 需要设置一个口令');
    if (!bundle.certs.length && !bundle.privateKeyDer) throw new Error('没有内容可写入');
    return p12Write(bundle.certs, bundle.privateKeyDer, alias || bundle.privateAlias || 'server', password);
  }

  window.Convert = {
    load: load,
    toPem: toPem,
    toJks: toJks,
    toPkcs12: toPkcs12,
    readJksStructure: readJksStructure,
    isJks: isJks
  };
})();
