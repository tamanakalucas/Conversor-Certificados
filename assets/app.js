/* Central de Certificados — geração de CSR/chave, conversão entre formatos e inspeção.
   100% client-side, criptografia via node-forge (vendor/forge.min.js).
   Interface seguindo Material Design 3. */
(function () {
  'use strict';

  var pki = forge.pki;

  /* ============================================================
     Estado
     ============================================================ */
  var parsedCerts = [];   // [{cert, alias, isLeaf, include}]
  var parsedKey = null;   // chave privada RSA carregada na etapa 1
  var selectedFmt = null;
  var sessionKey = null;  // {key, pem, name} — chave gerada na aba "Gerar CSR"
  var generated = null;   // {csrPem, keyPem, base, key}
  var sanList = [];       // SANs adicionados como chips

  /* ============================================================
     Helpers
     ============================================================ */
  function $(id) { return document.getElementById(id); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  function esc(s) {
    return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
  function svgIcon(name, cls) {
    return '<svg class="icon ' + (cls || '') + '" viewBox="0 0 24 24"><use href="#i-' + name + '"/></svg>';
  }

  var MSG_ICON = { success: 'check', error: 'error', warn: 'warn', info: 'info' };
  function showMsg(el, text, type) {
    el.className = 'msg ' + type;
    el.innerHTML = svgIcon(MSG_ICON[type] || 'info') + '<span>' + esc(text) + '</span>';
  }
  function showMsgHtml(el, html, type) {
    el.className = 'msg ' + type;
    el.innerHTML = svgIcon(MSG_ICON[type] || 'info') + '<span>' + html + '</span>';
  }
  function clearMsg(el) { el.className = 'msg'; el.innerHTML = ''; }

  var snackTimer = null;
  function snack(text) {
    var el = $('snackbar');
    el.textContent = text;
    el.classList.add('show');
    clearTimeout(snackTimer);
    snackTimer = setTimeout(function () { el.classList.remove('show'); }, 3600);
  }

  function ab2binstr(buf) {
    var u8 = new Uint8Array(buf), s = '', CHUNK = 0x8000;
    for (var i = 0; i < u8.length; i += CHUNK) s += String.fromCharCode.apply(null, u8.subarray(i, i + CHUNK));
    return s;
  }
  function binStrToUint8(str) {
    var arr = new Uint8Array(str.length);
    for (var i = 0; i < str.length; i++) arr[i] = str.charCodeAt(i) & 0xFF;
    return arr;
  }
  function uint8ToBinStr(u8) {
    var s = '', CHUNK = 0x8000;
    for (var i = 0; i < u8.length; i += CHUNK) s += String.fromCharCode.apply(null, u8.subarray(i, i + CHUNK));
    return s;
  }
  function readFileAsArrayBuffer(file) {
    return new Promise(function (res, rej) {
      var r = new FileReader();
      r.onload = function () { res(r.result); };
      r.onerror = function () { rej(new Error('Falha ao ler o arquivo')); };
      r.readAsArrayBuffer(file);
    });
  }
  function readFileAsBinStr(file) { return readFileAsArrayBuffer(file).then(ab2binstr); }
  function readFileAsText(file) {
    return new Promise(function (res, rej) {
      var r = new FileReader();
      r.onload = function () { res(r.result); };
      r.onerror = function () { rej(new Error('Falha ao ler o arquivo')); };
      r.readAsText(file);
    });
  }
  function triggerDownload(blob, filename) {
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
  }
  function downloadText(text, filename) {
    triggerDownload(new Blob([text], { type: 'text/plain;charset=utf-8' }), filename);
    snack('Arquivo baixado: ' + filename);
  }
  function downloadBinary(u8orBinStr, filename, mime) {
    var u8 = (typeof u8orBinStr === 'string') ? binStrToUint8(u8orBinStr) : u8orBinStr;
    triggerDownload(new Blob([u8], { type: mime || 'application/octet-stream' }), filename);
    snack('Arquivo baixado: ' + filename);
  }
  function safeName(s, fallback) {
    s = (s || '').trim().replace(/^\*\./, 'wildcard.').replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '');
    return s || fallback;
  }

  /* ============================================================
     Tema
     ============================================================ */
  var root = document.documentElement;
  try {
    var saved = localStorage.getItem('certkit-theme');
    if (saved) root.setAttribute('data-theme', saved);
  } catch (e) {}
  $('themeToggle').addEventListener('click', function () {
    var cur = root.getAttribute('data-theme') || 'dark';
    var next = cur === 'light' ? 'dark' : 'light';
    root.setAttribute('data-theme', next);
    try { localStorage.setItem('certkit-theme', next); } catch (e) {}
    snack(next === 'light' ? 'Tema claro' : 'Tema escuro');
  });

  /* ============================================================
     Navegação: tabs primárias e segmented buttons
     ============================================================ */
  function showMode(name) {
    $$('.tab').forEach(function (b) {
      var on = b.dataset.mode === name;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    $$('.pane').forEach(function (p) { p.classList.toggle('active', p.id === 'mode-' + name); });
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
  $$('.tab').forEach(function (b) {
    b.addEventListener('click', function () { showMode(b.dataset.mode); });
  });

  $$('.segment').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var group = btn.dataset.seg;
      $$('.segment[data-seg="' + group + '"]').forEach(function (b) {
        var on = b === btn;
        b.classList.toggle('active', on);
        b.setAttribute('aria-selected', on ? 'true' : 'false');
        var pane = $(b.dataset.target);
        if (pane) pane.classList.toggle('active', on);
      });
    });
  });

  /* senha: olho */
  $$('.tf-trailing').forEach(function (b) {
    b.addEventListener('click', function () {
      var input = $(b.dataset.pw);
      var vis = input.type === 'text';
      input.type = vis ? 'password' : 'text';
      b.innerHTML = svgIcon(vis ? 'eye' : 'eye-off');
      b.setAttribute('aria-label', vis ? 'Mostrar senha' : 'Ocultar senha');
    });
  });

  /* copiar */
  $$('.copy').forEach(function (b) {
    b.addEventListener('click', function () {
      var ta = $(b.dataset.target);
      var done = function () { snack('Copiado para a área de transferência'); };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(ta.value).then(done, function () { legacyCopy(ta); done(); });
      } else { legacyCopy(ta); done(); }
    });
  });
  function legacyCopy(ta) {
    ta.removeAttribute('readonly');
    ta.select();
    try { document.execCommand('copy'); } catch (e) {}
    ta.setAttribute('readonly', 'readonly');
    window.getSelection().removeAllRanges();
  }

  /* ============================================================
     Dropzones
     ============================================================ */
  function makeDrop(zoneId, inputId, onFiles) {
    var zone = $(zoneId), input = $(inputId);
    var body = Array.prototype.slice.call(zone.children).filter(function (el) { return el !== input; });
    var fileEl = document.createElement('div');
    fileEl.className = 'dz-file';
    fileEl.hidden = true;
    zone.appendChild(fileEl);

    function setFiles(names) {
      if (!names || !names.length) {
        body.forEach(function (e) { e.style.display = ''; });
        fileEl.hidden = true;
        zone.classList.remove('filled');
        input.value = '';
      } else {
        body.forEach(function (e) { e.style.display = 'none'; });
        fileEl.hidden = false;
        fileEl.innerHTML = svgIcon('file') + '<span class="dz-title">' + esc(names.join(', ')) +
          '</span><button type="button" class="dz-clear" aria-label="Remover arquivo">' + svgIcon('trash') + '</button>';
        zone.classList.add('filled');
      }
    }

    fileEl.addEventListener('click', function (e) {
      var btn = e.target.closest('.dz-clear');
      if (!btn) return;
      e.stopPropagation();
      setFiles(null);
      onFiles([], setFiles);
    });

    zone.addEventListener('click', function (e) {
      if (e.target.closest('.dz-clear')) return;
      input.click();
    });
    zone.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); }
    });
    ['dragenter', 'dragover'].forEach(function (ev) {
      zone.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.add('over'); });
    });
    ['dragleave', 'drop'].forEach(function (ev) {
      zone.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.remove('over'); });
    });
    zone.addEventListener('drop', function (e) {
      var files = Array.prototype.slice.call(e.dataTransfer.files || []);
      if (!files.length) return;
      try {
        var dt = new DataTransfer();
        files.forEach(function (f) { dt.items.add(f); });
        input.files = dt.files;
      } catch (err) {}
      setFiles(files.map(function (f) { return f.name; }));
      onFiles(files, setFiles);
    });
    input.addEventListener('change', function () {
      var files = Array.prototype.slice.call(input.files || []);
      setFiles(files.map(function (f) { return f.name; }));
      if (files.length) onFiles(files, setFiles);
    });

    return setFiles;
  }

  /* ============================================================
     Parsing de certificados e chaves
     ============================================================ */
  function looksPem(bin) { return bin.indexOf('-----BEGIN') !== -1; }

  function pemBlocks(text, label) {
    return text.match(new RegExp('-----BEGIN ' + label + '-----[\\s\\S]*?-----END ' + label + '-----', 'g')) || [];
  }

  function bareBase64ToDer(bin) {
    var t = bin.replace(/\s+/g, '');
    if (!t || t.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(t)) return null;
    try { return forge.util.decode64(t); } catch (e) { return null; }
  }

  function parseCertificates(bin) {
    var certs = [], i;
    if (looksPem(bin)) {
      var blocks = pemBlocks(bin, 'CERTIFICATE');
      if (blocks.length) {
        for (i = 0; i < blocks.length; i++) certs.push(pki.certificateFromPem(blocks[i]));
        return certs;
      }
      var p7 = pemBlocks(bin, 'PKCS7');
      if (p7.length) {
        for (i = 0; i < p7.length; i++) certs = certs.concat(forge.pkcs7.messageFromPem(p7[i]).certificates || []);
        if (certs.length) return certs;
      }
      if (/-----BEGIN[^-]*PRIVATE KEY-----/.test(bin)) throw new Error('Este arquivo contém uma chave privada, não um certificado.');
      if (/-----BEGIN (NEW )?CERTIFICATE REQUEST-----/.test(bin)) throw new Error('Este arquivo é um CSR, não um certificado emitido.');
      throw new Error('Bloco PEM não reconhecido.');
    }

    var der = bareBase64ToDer(bin) || bin;
    var asn1;
    try { asn1 = forge.asn1.fromDer(forge.util.createBuffer(der, 'binary')); }
    catch (e) { throw new Error('Formato não reconhecido (não é PEM nem DER válido).'); }

    try { return [pki.certificateFromAsn1(asn1)]; } catch (e) {}
    try {
      var msg = forge.pkcs7.messageFromAsn1(asn1);
      if (msg.certificates && msg.certificates.length) return msg.certificates;
    } catch (e) {}
    throw new Error('Não foi possível interpretar o arquivo como certificado.');
  }

  function parsePrivateKey(bin, password) {
    password = password || '';
    if (looksPem(bin)) {
      if (/-----BEGIN EC PRIVATE KEY-----/.test(bin) || /-----BEGIN DSA PRIVATE KEY-----/.test(bin)) {
        throw new Error('Apenas chaves RSA são suportadas — chaves EC/DSA não podem ser processadas aqui.');
      }
      if (/-----BEGIN CERTIFICATE-----/.test(bin)) throw new Error('Este arquivo é um certificado, não uma chave privada.');

      var enc = /ENCRYPTED PRIVATE KEY/.test(bin) || /Proc-Type:\s*4,ENCRYPTED/i.test(bin);
      if (enc && !password) throw new Error('A chave está protegida por senha. Preencha o campo "Senha da chave".');

      var key = null;
      try { key = pki.decryptRsaPrivateKey(bin, password); } catch (e) { key = null; }
      if (!key) {
        if (enc) throw new Error('Senha da chave incorreta.');
        try { key = pki.privateKeyFromPem(bin); }
        catch (e2) { throw new Error('Não foi possível ler a chave privada: ' + e2.message); }
      }
      return key;
    }

    var der = bareBase64ToDer(bin) || bin;
    var asn1;
    try { asn1 = forge.asn1.fromDer(forge.util.createBuffer(der, 'binary')); }
    catch (e) { throw new Error('Formato de chave não reconhecido (não é PEM nem DER válido).'); }

    try { return pki.privateKeyFromAsn1(asn1); } catch (e) {}
    if (password) {
      try {
        var info = pki.decryptPrivateKeyInfo(asn1, password);
        if (info) return pki.privateKeyFromAsn1(info);
      } catch (e) {}
      throw new Error('Não foi possível decifrar a chave (senha incorreta?).');
    }
    throw new Error('Chave em DER não reconhecida — se estiver protegida, informe a senha.');
  }

  /* ============================================================
     Metadados / renderização
     ============================================================ */
  function dnToString(attrs) {
    return (attrs || []).map(function (a) { return (a.shortName || a.name || a.type) + '=' + a.value; }).join(', ');
  }
  function dnKey(attrs) {
    return (attrs || []).map(function (a) {
      return (a.shortName || a.name || a.type) + '=' + String(a.value).trim().toLowerCase();
    }).sort().join('|');
  }
  function cnOf(cert) {
    var f = cert.subject.getField('CN');
    return f ? f.value : '';
  }
  function altNamesOf(holder) {
    var ext = null;
    if (holder.getExtension) { try { ext = holder.getExtension('subjectAltName'); } catch (e) {} }
    if (!ext && holder.attributes) {
      (holder.attributes || []).forEach(function (a) {
        if (a.name === 'extensionRequest') {
          (a.extensions || []).forEach(function (e) { if (e.name === 'subjectAltName') ext = e; });
        }
      });
    }
    if (!ext || !ext.altNames) return [];
    return ext.altNames.map(function (an) {
      if (an.type === 2) return 'DNS:' + an.value;
      if (an.type === 7) return 'IP:' + (an.ip || an.value);
      if (an.type === 1) return 'email:' + an.value;
      if (an.type === 6) return 'URI:' + an.value;
      return 'outro:' + (an.value || '');
    });
  }
  function fmtDate(d) {
    try { return d.toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }); }
    catch (e) { return String(d); }
  }
  function keyInfo(pubKey) { return (pubKey && pubKey.n) ? 'RSA ' + pubKey.n.bitLength() + ' bits' : 'desconhecida'; }
  function fingerprint(cert) {
    try {
      var md = forge.md.sha256.create();
      md.update(forge.asn1.toDer(pki.certificateToAsn1(cert)).getBytes());
      return md.digest().toHex().toUpperCase().replace(/(.{2})(?=.)/g, '$1:');
    } catch (e) { return '—'; }
  }
  function dumpBlock(title, rows) {
    var html = '<div class="dump"><div class="dump-title">' + esc(title) + '</div><dl>';
    rows.forEach(function (r) {
      if (r[1] === '' || r[1] == null) return;
      html += '<dt>' + esc(r[0]) + '</dt><dd>' + (r[2] === 'html' ? r[1] : esc(r[1])) + '</dd>';
    });
    return html + '</dl></div>';
  }
  function validityBadge(cert) {
    var now = new Date();
    if (cert.validity.notAfter < now) return '<span class="badge err">expirado</span>';
    if (cert.validity.notBefore > now) return '<span class="badge warn">ainda não válido</span>';
    var days = Math.round((cert.validity.notAfter - now) / 86400000);
    return '<span class="badge">válido · ' + days + ' dia(s)</span>';
  }
  function certDump(cert, title) {
    return dumpBlock(title || 'Certificado', [
      ['subject', dnToString(cert.subject.attributes)],
      ['issuer', dnToString(cert.issuer.attributes)],
      ['válido de', fmtDate(cert.validity.notBefore)],
      ['válido até', esc(fmtDate(cert.validity.notAfter)) + ' ' + validityBadge(cert), 'html'],
      ['SAN', altNamesOf(cert).join(', ')],
      ['chave pública', keyInfo(cert.publicKey)],
      ['serial', cert.serialNumber],
      ['assinatura', pki.oids[cert.siginfo && cert.siginfo.algorithmOid] || cert.signatureOid || '—'],
      ['SHA-256', fingerprint(cert)]
    ]);
  }
  function csrDump(csr, title) {
    return dumpBlock(title || 'Certificate Signing Request', [
      ['subject', dnToString(csr.subject.attributes)],
      ['SAN', altNamesOf(csr).join(', ')],
      ['chave pública', keyInfo(csr.publicKey)],
      ['assinatura', pki.oids[csr.siginfo && csr.siginfo.algorithmOid] || csr.signatureOid || '—'],
      ['auto-assinatura', csr.verify() ? 'válida' : 'INVÁLIDA']
    ]);
  }

  /* ============================================================
     SAN — chips
     ============================================================ */
  function sanType(v) {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v) || /^[0-9a-f:]+:[0-9a-f:]*$/i.test(v)) return 'IP';
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return 'email';
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) return 'URI';
    return 'DNS';
  }
  function cnAsSan() {
    var cn = $('g_cn').value.trim();
    return (cn && /^[A-Za-z0-9*._-]+\.[A-Za-z]{2,}$/.test(cn)) ? cn : null;
  }
  function renderChips() {
    var host = $('sanChips');
    host.innerHTML = '';
    var cn = cnAsSan();
    var seen = {};
    if (cn && sanList.indexOf(cn) === -1) {
      seen[cn.toLowerCase()] = 1;
      host.insertAdjacentHTML('beforeend',
        '<span class="chip" title="Incluído automaticamente a partir do CN">' +
        '<span class="chip-type">' + sanType(cn) + '</span><span class="chip-text">' + esc(cn) + '</span></span>');
    }
    sanList.forEach(function (v, i) {
      if (seen[v.toLowerCase()]) return;
      seen[v.toLowerCase()] = 1;
      host.insertAdjacentHTML('beforeend',
        '<span class="chip"><span class="chip-type">' + sanType(v) + '</span>' +
        '<span class="chip-text">' + esc(v) + '</span>' +
        '<button type="button" data-i="' + i + '" aria-label="Remover ' + esc(v) + '">' + svgIcon('close') + '</button></span>');
    });
  }
  function addSan(raw) {
    String(raw).split(/[\n,;\s]+/).forEach(function (v) {
      v = v.trim();
      if (!v) return;
      if (sanList.some(function (x) { return x.toLowerCase() === v.toLowerCase(); })) return;
      sanList.push(v);
    });
    renderChips();
  }
  $('sanChips').addEventListener('click', function (e) {
    var btn = e.target.closest('button[data-i]');
    if (!btn) return;
    sanList.splice(+btn.dataset.i, 1);
    renderChips();
  });
  $('sanInput').addEventListener('keydown', function (e) {
    if (e.key === 'Enter' || e.key === ',' || e.key === ';') {
      e.preventDefault();
      if (this.value.trim()) { addSan(this.value); this.value = ''; }
    } else if (e.key === 'Backspace' && !this.value && sanList.length) {
      sanList.pop(); renderChips();
    }
  });
  $('sanInput').addEventListener('blur', function () {
    if (this.value.trim()) { addSan(this.value); this.value = ''; }
  });
  $('sanInput').addEventListener('paste', function (e) {
    var txt = (e.clipboardData || window.clipboardData).getData('text');
    if (txt && /[\n,;]/.test(txt)) { e.preventDefault(); addSan(txt); this.value = ''; }
  });
  $('sanField').addEventListener('click', function (e) {
    if (e.target === this || e.target.id === 'sanChips') $('sanInput').focus();
  });
  $('g_cn').addEventListener('input', renderChips);

  /* ============================================================
     GERAR CSR — arquivo .cnf do OpenSSL
     ============================================================ */
  var DN_ALIASES = {
    c: 'C', countryname: 'C',
    st: 'ST', stateorprovincename: 'ST', stateorprovince: 'ST',
    l: 'L', localityname: 'L', locality: 'L',
    o: 'O', organizationname: 'O', organization: 'O',
    ou: 'OU', organizationalunitname: 'OU', organizationalunit: 'OU',
    cn: 'CN', commonname: 'CN',
    e: 'E', email: 'E', emailaddress: 'E'
  };

  function parseCnf(text) {
    var sections = { '': [] };
    var current = '';
    var subjectLine = null;

    text.replace(/\r\n?/g, '\n').split('\n').forEach(function (raw) {
      var line = raw.replace(/#.*$/, '').trim();
      if (!line) return;

      var sec = line.match(/^\[\s*([^\]]+?)\s*\]$/);
      if (sec) {
        current = sec[1].toLowerCase();
        if (!sections[current]) sections[current] = [];
        return;
      }
      if (line.charAt(0) === '/' && line.indexOf('=') !== -1) { subjectLine = line; return; }

      var eq = line.indexOf('=');
      if (eq === -1) return;
      var k = line.slice(0, eq).trim();
      var v = line.slice(eq + 1).trim().replace(/^["'](.*)["']$/, '$1');
      if (!k) return;
      sections[current].push([k, v]);
    });

    var get = function (secName, key) {
      var s = sections[(secName || '').toLowerCase()] || [];
      for (var i = 0; i < s.length; i++) if (s[i][0].toLowerCase() === key) return s[i][1];
      return null;
    };

    var dn = {}, sans = [], warnings = [];
    var reqPrompt = (get('req', 'prompt') || '').toLowerCase();
    var promptMode = reqPrompt !== '' && reqPrompt !== 'no';

    if (subjectLine) {
      subjectLine.split('/').forEach(function (part) {
        var eq = part.indexOf('=');
        if (eq < 1) return;
        var norm = DN_ALIASES[part.slice(0, eq).trim().toLowerCase()];
        if (norm && !dn[norm]) dn[norm] = part.slice(eq + 1).trim();
      });
    }

    var dnSecName = (get('req', 'distinguished_name') || 'req_distinguished_name').toLowerCase();
    var dnPairs = sections[dnSecName] || [];
    if (!dnPairs.length) dnPairs = sections[''] || [];

    var defaults = {};
    dnPairs.forEach(function (p) {
      var m = p[0].match(/^(.*)_default$/i);
      if (m) defaults[m[1].toLowerCase().replace(/^\d+\./, '')] = p[1];
    });

    dnPairs.forEach(function (p) {
      var key = p[0];
      if (/_(default|min|max)$/i.test(key)) return;
      var base = key.toLowerCase().replace(/^\d+\./, '');
      var norm = DN_ALIASES[base];
      if (!norm) return;
      var has = defaults.hasOwnProperty(base);
      if (!has && promptMode) {
        warnings.push(key + ' ignorado (arquivo em modo prompt e sem ' + key + '_default)');
        return;
      }
      var val = has ? defaults[base] : p[1];
      if (val) dn[norm] = val;
    });

    var extSecName = (get('req', 'req_extensions') || get('req', 'x509_extensions') || 'v3_req').toLowerCase();
    var sanValue = get(extSecName, 'subjectaltname');
    if (!sanValue) {
      Object.keys(sections).some(function (s) {
        var v = get(s, 'subjectaltname');
        if (v) { sanValue = v; return true; }
        return false;
      });
    }
    if (sanValue) {
      var ref = sanValue.match(/^@\s*(.+)$/);
      if (ref) {
        var refName = ref[1].trim().toLowerCase();
        if (!sections[refName]) warnings.push('seção [' + ref[1].trim() + '] referenciada em subjectAltName não foi encontrada');
        (sections[refName] || []).forEach(function (p) { if (p[1]) sans.push(p[1]); });
      } else {
        sanValue.split(',').forEach(function (item) {
          var v = item.trim().replace(/^(DNS|IP|IP\.\d+|email|URI|otherName)\s*:\s*/i, '');
          if (v) sans.push(v);
        });
      }
    }

    return {
      dn: dn, sans: sans, warnings: warnings,
      bits: get('req', 'default_bits'),
      digest: (get('req', 'default_md') || '').toLowerCase()
    };
  }

  function applyCnf(parsed) {
    var map = { CN: 'g_cn', O: 'g_o', OU: 'g_ou', L: 'g_l', ST: 'g_st', C: 'g_c', E: 'g_email' };
    var filled = [];
    Object.keys(map).forEach(function (k) {
      if (parsed.dn[k]) { $(map[k]).value = parsed.dn[k]; filled.push(k); }
    });

    if (parsed.sans.length) { sanList = []; addSan(parsed.sans.join('\n')); }
    renderChips();

    var extras = [];
    if (parsed.bits && ['2048', '3072', '4096'].indexOf(String(parsed.bits)) !== -1) {
      $('g_bits').value = String(parsed.bits);
      extras.push('RSA ' + parsed.bits);
    } else if (parsed.bits) {
      parsed.warnings.push('default_bits = ' + parsed.bits + ' não está entre as opções (2048/3072/4096) — mantido ' + $('g_bits').value);
    }
    if (parsed.digest && ['sha256', 'sha384', 'sha512'].indexOf(parsed.digest) !== -1) {
      $('g_digest').value = parsed.digest;
      extras.push(parsed.digest.toUpperCase());
    } else if (parsed.digest) {
      parsed.warnings.push('default_md = ' + parsed.digest + ' não suportado — mantido SHA-256');
    }

    if (!filled.length && !parsed.sans.length) {
      throw new Error('Nenhum dado de subject encontrado. Verifique se o arquivo tem uma seção [ req_distinguished_name ] com CN, O, OU, L, ST ou C.');
    }
    return { filled: filled, sans: sanList.slice(), extras: extras };
  }

  function loadCnf(text) {
    var msgEl = $('cnfMsg');
    clearMsg(msgEl);
    try {
      var parsed = parseCnf(text);
      var res = applyCnf(parsed);
      var linhas = ['Dados carregados: ' + (res.filled.length ? res.filled.join(', ') : 'nenhum campo de subject')];
      if (res.sans.length) linhas.push(res.sans.length + ' SAN: ' + res.sans.join(', '));
      if (res.extras.length) linhas.push('Opções: ' + res.extras.join(' · '));
      if (parsed.warnings.length) linhas.push('Avisos: ' + parsed.warnings.join(' | '));

      var manualBtn = $$('.segment[data-seg="dados"]')[0];
      if (manualBtn) manualBtn.click();
      showMsg($('genMsg'), linhas.join('\n') + '\nRevise os campos acima e clique em "Gerar CSR e chave".',
        parsed.warnings.length ? 'warn' : 'success');
      snack('Dados do arquivo carregados no formulário');
    } catch (e) {
      showMsg(msgEl, 'Erro ao ler a configuração. ' + e.message, 'error');
    }
  }

  makeDrop('dropCnf', 'cnfFile', function (files) {
    if (!files.length) return;
    readFileAsText(files[0]).then(function (t) { $('cnfText').value = t; loadCnf(t); })
      .catch(function (e) { showMsg($('cnfMsg'), e.message, 'error'); });
  });

  $('btnLoadCnf').addEventListener('click', function () {
    var typed = $('cnfText').value.trim();
    if (!typed) { showMsg($('cnfMsg'), 'Envie um arquivo .cnf ou cole o conteúdo no campo acima.', 'error'); return; }
    loadCnf(typed);
  });

  $('btnExemploCnf').addEventListener('click', function () {
    $('cnfText').value = [
      '[ req ]', 'default_bits = 2048', 'default_md = sha256', 'prompt = no',
      'distinguished_name = req_distinguished_name', 'req_extensions = v3_req', '',
      '[ req_distinguished_name ]', 'C  = BR', 'ST = SP', 'L  = São Paulo',
      'O  = Minha Empresa LTDA', 'OU = TI', 'CN = exemplo.com.br', '',
      '[ v3_req ]', 'subjectAltName = @alt_names', '',
      '[ alt_names ]', 'DNS.1 = exemplo.com.br', 'DNS.2 = www.exemplo.com.br', 'IP.1  = 192.168.0.10'
    ].join('\n');
    showMsg($('cnfMsg'), 'Exemplo preenchido. Clique em "Carregar dados" para aplicá-lo ao formulário.', 'info');
  });

  /* ============================================================
     GERAR CSR — geração
     ============================================================ */
  $('g_protect').addEventListener('change', function () {
    $('g_passRow').classList.toggle('hidden', !this.checked);
  });

  function buildSubject() {
    var out = [];
    function add(name, id, tagClass) {
      var v = $(id).value.trim();
      if (!v) return;
      var item = { name: name, value: v };
      if (tagClass) item.valueTagClass = tagClass;
      out.push(item);
    }
    add('commonName', 'g_cn');
    add('organizationName', 'g_o');
    add('organizationalUnitName', 'g_ou');
    add('localityName', 'g_l');
    add('stateOrProvinceName', 'g_st');
    add('countryName', 'g_c', forge.asn1.Type.PRINTABLESTRING);
    add('emailAddress', 'g_email', forge.asn1.Type.IA5STRING);
    return out;
  }

  function parseSans() {
    var lines = sanList.slice();
    var cn = cnAsSan();
    if (cn && lines.indexOf(cn) === -1) lines.unshift(cn);

    var seen = {}, alt = [];
    lines.forEach(function (v) {
      var k = v.toLowerCase();
      if (seen[k]) return;
      seen[k] = 1;
      var t = sanType(v);
      if (t === 'IP') alt.push({ type: 7, ip: v });
      else if (t === 'email') alt.push({ type: 1, value: v });
      else if (t === 'URI') alt.push({ type: 6, value: v });
      else alt.push({ type: 2, value: v });
    });
    return alt;
  }

  function opensslCsrCommand(subject, alt, bits, digest, base, encrypted) {
    var m = { commonName: 'CN', organizationName: 'O', organizationalUnitName: 'OU', localityName: 'L', stateOrProvinceName: 'ST', countryName: 'C', emailAddress: 'emailAddress' };
    var dn = subject.map(function (a) { return (m[a.name] || a.name) + '=' + a.value; }).join('/');
    var san = alt.map(function (a) {
      if (a.type === 7) return 'IP:' + a.ip;
      if (a.type === 1) return 'email:' + a.value;
      if (a.type === 6) return 'URI:' + a.value;
      return 'DNS:' + a.value;
    }).join(',');

    var cmd = 'openssl req -new -newkey rsa:' + bits + ' -' + digest + ' \\\n';
    cmd += '  ' + (encrypted ? '-aes256' : '-nodes') + ' \\\n';
    cmd += '  -keyout ' + base + '.key -out ' + base + '.csr \\\n';
    cmd += '  -subj "/' + dn + '"';
    if (san) cmd += ' \\\n  -addext "subjectAltName=' + san + '"';
    cmd += '\n\n# conferir o CSR gerado:\nopenssl req -in ' + base + '.csr -noout -text';
    return cmd;
  }

  function generateKeyPair(bits, cb) {
    var opts = { bits: bits, e: 0x10001 };
    var script;
    try { script = new URL('vendor/prime.worker.min.js', document.baseURI).href; } catch (e) { script = 'vendor/prime.worker.min.js'; }
    var done = false;
    try {
      pki.rsa.generateKeyPair({ bits: bits, e: 0x10001, workers: -1, workerScript: script }, function (err, kp) {
        if (done) return;
        done = true;
        if (err) pki.rsa.generateKeyPair(opts, cb);
        else cb(null, kp);
      });
    } catch (e) {
      pki.rsa.generateKeyPair(opts, cb);
    }
  }

  function keyToPem(privateKey, format, password) {
    if (password) return pki.encryptRsaPrivateKey(privateKey, password, { algorithm: 'aes256', legacy: format === 'pkcs1' });
    if (format === 'pkcs1') return pki.privateKeyToPem(privateKey);
    return pki.privateKeyInfoToPem(pki.wrapRsaPrivateKey(pki.privateKeyToAsn1(privateKey)));
  }

  function markError(id, on) {
    $(id).parentElement.classList.toggle('error', !!on);
  }

  $('btnGenerate').addEventListener('click', function () {
    var btn = this, msgEl = $('genMsg');
    clearMsg(msgEl);
    ['g_cn', 'g_c', 'g_keyPass', 'g_keyPass2'].forEach(function (id) { markError(id, false); });

    var cn = $('g_cn').value.trim();
    if (!cn) {
      showMsg(msgEl, 'Informe o Common Name (CN).', 'error');
      markError('g_cn', true); $('g_cn').focus();
      var manual = $$('.segment[data-seg="dados"]')[0];
      if (manual && !manual.classList.contains('active')) manual.click();
      return;
    }

    var c = $('g_c').value.trim();
    if (c && !/^[A-Za-z]{2}$/.test(c)) {
      showMsg(msgEl, 'O país (C) deve ter exatamente 2 letras. Ex.: BR', 'error');
      markError('g_c', true); return;
    }
    $('g_c').value = c.toUpperCase();

    var protect = $('g_protect').checked;
    var pass = $('g_keyPass').value;
    if (protect) {
      if (!pass) { showMsg(msgEl, 'Informe a senha da chave.', 'error'); markError('g_keyPass', true); return; }
      if (pass !== $('g_keyPass2').value) {
        showMsg(msgEl, 'As senhas da chave não conferem.', 'error');
        markError('g_keyPass2', true); return;
      }
    }

    var bits = parseInt($('g_bits').value, 10);
    var digest = $('g_digest').value;
    var format = $('g_keyfmt').value;
    var subject = buildSubject();
    var alt = parseSans();
    var base = safeName($('g_basename').value || cn, 'certificado');

    btn.disabled = true;
    btn.querySelector('.btn-label').textContent = 'Gerando chave de ' + bits + ' bits…';
    $('genProgress').classList.remove('hidden');
    var t0 = Date.now();

    setTimeout(function () {
      generateKeyPair(bits, function (err, keys) {
        var restore = function () {
          btn.disabled = false;
          btn.querySelector('.btn-label').textContent = 'Gerar CSR e chave';
          $('genProgress').classList.add('hidden');
        };
        if (err) { restore(); showMsg(msgEl, 'Falha ao gerar a chave: ' + err.message, 'error'); return; }
        try {
          var csr = pki.createCertificationRequest();
          csr.publicKey = keys.publicKey;
          csr.setSubject(subject);
          if (alt.length) {
            csr.setAttributes([{ name: 'extensionRequest', extensions: [{ name: 'subjectAltName', altNames: alt }] }]);
          }
          csr.sign(keys.privateKey, forge.md[digest].create());

          var csrPem = pki.certificationRequestToPem(csr);
          var keyPem = keyToPem(keys.privateKey, format, protect ? pass : null);
          generated = { csrPem: csrPem, keyPem: keyPem, base: base, key: keys.privateKey };

          $('csrOut').value = csrPem;
          $('keyOut').value = keyPem;
          $('csrDump').innerHTML = csrDump(pki.certificationRequestFromPem(csrPem));
          $('cmdCsr').textContent = opensslCsrCommand(subject, alt, bits, digest, base, protect);
          $('panelCsrResult').classList.remove('hidden');
          restore();
          showMsg(msgEl, 'CSR e chave gerados em ' + ((Date.now() - t0) / 1000).toFixed(1) + 's.', 'success');
          snack('Pronto! Baixe os dois arquivos abaixo');
          $('panelCsrResult').scrollIntoView({ behavior: 'smooth', block: 'start' });
        } catch (e) {
          restore();
          showMsg(msgEl, 'Erro ao montar o CSR: ' + e.message, 'error');
        }
      });
    }, 30);
  });

  $('dlCsr').addEventListener('click', function () {
    if (generated) downloadText(generated.csrPem, generated.base + '.csr');
  });
  $('dlKey').addEventListener('click', function () {
    if (generated) downloadText(generated.keyPem, generated.base + '.key');
  });

  $('btnClearCsr').addEventListener('click', function () {
    ['g_cn', 'g_o', 'g_ou', 'g_l', 'g_st', 'g_c', 'g_email', 'g_basename', 'g_keyPass', 'g_keyPass2', 'cnfText', 'sanInput'].forEach(function (id) { $(id).value = ''; });
    ['g_cn', 'g_c', 'g_keyPass', 'g_keyPass2'].forEach(function (id) { markError(id, false); });
    sanList = [];
    renderChips();
    $('g_bits').value = '2048';
    $('g_digest').value = 'sha256';
    $('g_keyfmt').value = 'pkcs8';
    $('g_protect').checked = false;
    $('g_passRow').classList.add('hidden');
    $('panelCsrResult').classList.add('hidden');
    $('csrOut').value = ''; $('keyOut').value = '';
    generated = null;
    clearMsg($('genMsg')); clearMsg($('cnfMsg'));
    snack('Formulário limpo');
  });

  $('sendToConvert').addEventListener('click', function () {
    if (!generated) return;
    sessionKey = { key: generated.key, pem: generated.keyPem, name: generated.base + '.key' };
    $('sessionKeyName').textContent = sessionKey.name;
    $('useSessionKeyWrap').classList.remove('hidden');
    $('useSessionKey').checked = true;
    if (!$('pfxOutAlias').value || $('pfxOutAlias').value === 'certificado') $('pfxOutAlias').value = generated.base;
    showMode('convert');
    $$('.segment[data-seg="src"]')[1].click();
    showMsg($('sourceMsg'), 'Chave gerada nesta sessão pronta para uso. Envie o certificado emitido pela AC e clique em "Ler certificado".', 'info');
  });

  /* ============================================================
     CONVERSOR — etapa 1
     ============================================================ */
  var resetDrops = ['dropPfx|pfxFile', 'dropCert|certFile', 'dropKey|keyFile', 'dropChain|chainFile']
    .map(function (pair) {
      var p = pair.split('|');
      return makeDrop(p[0], p[1], function () { clearMsg($('sourceMsg')); });
    });

  $('btnParsePfx').addEventListener('click', function () {
    var msgEl = $('sourceMsg'); clearMsg(msgEl);
    var file = $('pfxFile').files[0];
    if (!file) { showMsg(msgEl, 'Selecione um arquivo .pfx ou .p12.', 'error'); return; }
    var password = $('pfxPassword').value;

    readFileAsBinStr(file).then(function (bin) {
      var asn1 = forge.asn1.fromDer(forge.util.createBuffer(bin));
      var p12 = forge.pkcs12.pkcs12FromAsn1(asn1, password);

      var certBags = p12.getBags({ bagType: pki.oids.certBag })[pki.oids.certBag] || [];
      var keyBags = p12.getBags({ bagType: pki.oids.pkcs8ShroudedKeyBag })[pki.oids.pkcs8ShroudedKeyBag] || [];
      if (!keyBags.length) keyBags = p12.getBags({ bagType: pki.oids.keyBag })[pki.oids.keyBag] || [];
      if (!certBags.length) throw new Error('Nenhum certificado encontrado dentro do PFX.');

      parsedCerts = certBags.map(function (b, i) {
        return {
          cert: b.cert,
          alias: (b.attributes && b.attributes.friendlyName && b.attributes.friendlyName[0]) || ('cert' + i)
        };
      });
      parsedKey = keyBags.length ? keyBags[0].key : null;

      renderDetected();
      showMsg(msgEl, 'Certificado lido com sucesso: ' + certBags.length + ' certificado(s)' +
        (parsedKey ? ' + chave privada' : ' (sem chave privada)') + '.', 'success');
      snack('PFX lido com sucesso');
    }).catch(function (e) {
      showMsg(msgEl, 'Erro ao ler o PFX/P12 — verifique a senha ou o arquivo. ' + e.message, 'error');
      $('panelDetected').classList.add('hidden');
      $('panelOutput').classList.add('hidden');
    });
  });

  $('btnParsePem').addEventListener('click', function () {
    var msgEl = $('sourceMsg'); clearMsg(msgEl);
    var certFile = $('certFile').files[0];
    if (!certFile) { showMsg(msgEl, 'Selecione o arquivo do certificado.', 'error'); return; }

    var chainFiles = Array.prototype.slice.call($('chainFile').files || []);
    var keyFile = $('keyFile').files[0];
    var useSession = $('useSessionKey').checked && sessionKey;

    readFileAsBinStr(certFile).then(function (bin) {
      var certs = parseCertificates(bin);
      if (!certs.length) throw new Error('Nenhum certificado válido encontrado no arquivo.');

      return Promise.all(chainFiles.map(readFileAsBinStr)).then(function (bins) {
        bins.forEach(function (b) { certs = certs.concat(parseCertificates(b)); });

        var seen = {};
        certs = certs.filter(function (c) {
          var k = dnKey(c.subject.attributes) + '#' + c.serialNumber;
          if (seen[k]) return false;
          seen[k] = 1;
          return true;
        });

        parsedCerts = certs.map(function (c, i) { return { cert: c, alias: 'cert' + i }; });
        parsedKey = null;

        if (keyFile) {
          return readFileAsBinStr(keyFile).then(function (kb) {
            parsedKey = parsePrivateKey(kb, $('keyPassword').value);
          });
        }
        if (useSession) parsedKey = sessionKey.key;
      });
    }).then(function () {
      renderDetected();
      showMsg($('sourceMsg'), 'Certificado lido com sucesso: ' + parsedCerts.length + ' certificado(s)' +
        (parsedKey ? ' + chave privada' + ($('useSessionKey').checked && !$('keyFile').files[0] ? ' (gerada nesta sessão)' : '') : '') + '.', 'success');
      snack('Certificado lido com sucesso');
    }).catch(function (e) {
      showMsg($('sourceMsg'), 'Erro ao ler o certificado. ' + e.message, 'error');
      $('panelDetected').classList.add('hidden');
      $('panelOutput').classList.add('hidden');
    });
  });

  /* ============================================================
     CONVERSOR — etapa 2
     ============================================================ */
  function guessLeafIndex(items) {
    for (var i = 0; i < items.length; i++) {
      var subj = dnKey(items[i].cert.subject.attributes);
      var isIssuerOfOther = items.some(function (c, j) { return j !== i && dnKey(c.cert.issuer.attributes) === subj; });
      if (!isIssuerOfOther) return i;
    }
    return 0;
  }
  function keyMatches(cert) {
    return !!(parsedKey && cert.publicKey && cert.publicKey.n && cert.publicKey.n.compareTo(parsedKey.n) === 0);
  }

  function renderDetected() {
    var leafIdx = guessLeafIndex(parsedCerts);
    var list = $('certList');
    list.innerHTML = '';

    parsedCerts.forEach(function (item, i) {
      if (typeof item.include === 'undefined') item.include = true;
      if (typeof item.isLeaf === 'undefined' || parsedCerts.every(function (c) { return !c.isLeaf; })) item.isLeaf = (i === leafIdx);

      var cert = item.cert;
      var badges = '';
      if (item.isLeaf) badges += '<span class="badge pri">leaf</span>';
      if (parsedKey && keyMatches(cert)) badges += '<span class="badge">chave privada</span>';
      badges += validityBadge(cert);

      var el = document.createElement('div');
      el.className = 'cert-item' + (item.isLeaf ? ' is-leaf' : '');
      el.innerHTML =
        '<div class="cert-top">' +
          '<label class="chk"><input type="checkbox" data-idx="' + i + '" class="chk-include"' + (item.include ? ' checked' : '') + '>' +
          '<span class="cert-name">' + esc(cnOf(cert) || dnToString(cert.subject.attributes).split(',')[0] || ('Certificado ' + (i + 1))) + '</span></label>' +
          badges +
          '<button type="button" class="leaf-toggle' + (item.isLeaf ? ' on' : '') + '" data-idx="' + i + '">' +
            (item.isLeaf ? 'é o leaf' : 'definir como leaf') + '</button>' +
        '</div>' +
        '<div class="cert-meta">' +
          '<b>subject</b> ' + esc(dnToString(cert.subject.attributes)) + '<br>' +
          '<b>issuer</b> ' + esc(dnToString(cert.issuer.attributes)) + '<br>' +
          '<b>válido</b> ' + esc(fmtDate(cert.validity.notBefore)) + ' → ' + esc(fmtDate(cert.validity.notAfter)) + '<br>' +
          '<b>serial</b> ' + esc(cert.serialNumber) +
          (altNamesOf(cert).length ? '<br><b>SAN</b> ' + esc(altNamesOf(cert).join(', ')) : '') +
        '</div>';
      list.appendChild(el);
    });

    $$('.chk-include', list).forEach(function (chk) {
      chk.addEventListener('change', function (e) { parsedCerts[+e.target.dataset.idx].include = e.target.checked; });
    });
    $$('.leaf-toggle', list).forEach(function (btn) {
      btn.addEventListener('click', function () {
        var idx = +btn.dataset.idx;
        parsedCerts.forEach(function (c, i) { c.isLeaf = (i === idx); });
        renderDetected();
      });
    });

    var pairEl = $('pairMsg');
    clearMsg(pairEl);
    if (parsedKey) {
      var leaf = (parsedCerts.find(function (c) { return c.isLeaf; }) || parsedCerts[0]).cert;
      if (keyMatches(leaf)) {
        showMsg(pairEl, 'A chave privada corresponde ao certificado leaf (RSA ' + parsedKey.n.bitLength() + ' bits).', 'success');
      } else if (parsedCerts.some(function (c) { return keyMatches(c.cert); })) {
        showMsg(pairEl, 'A chave corresponde a outro certificado da lista, não ao leaf selecionado. Ajuste qual é o leaf antes de exportar.', 'warn');
      } else {
        showMsg(pairEl, 'A chave privada NÃO corresponde a nenhum certificado carregado. Um PFX gerado assim não funcionaria.', 'error');
      }
    }
    $('pfxNeedKey').classList.toggle('hidden', !!parsedKey);
    $('keyNeedKey').classList.toggle('hidden', !!parsedKey);

    $('panelDetected').classList.remove('hidden');
    $('panelOutput').classList.remove('hidden');
    updateConvertEnabled();
    refreshPfxCmd();
  }

  /* ============================================================
     CONVERSOR — etapa 3
     ============================================================ */
  $$('.fmt').forEach(function (card) {
    card.addEventListener('click', function () {
      $$('.fmt').forEach(function (c) { c.setAttribute('aria-checked', 'false'); });
      card.setAttribute('aria-checked', 'true');
      selectedFmt = card.dataset.fmt;
      $('optsPem').classList.toggle('hidden', selectedFmt !== 'pem');
      $('optsPfx').classList.toggle('hidden', selectedFmt !== 'pfx');
      $('optsJks').classList.toggle('hidden', selectedFmt !== 'jks');
      $('optsKey').classList.toggle('hidden', selectedFmt !== 'key');
      updateConvertEnabled();
      refreshPfxCmd();
    });
  });

  function updateConvertEnabled() {
    $('btnConvert').disabled = !selectedFmt || parsedCerts.length === 0;
  }

  function refreshPfxCmd() {
    var alias = $('pfxOutAlias').value.trim() || 'certificado';
    var alg = $('pfxOutAlg').value;
    var temCadeia = parsedCerts.filter(function (c) { return c.include && !c.isLeaf; }).length > 0;
    var cmd = 'openssl pkcs12 -export \\\n  -inkey chave.key \\\n  -in certificado.crt \\\n';
    if (temCadeia) cmd += '  -certfile cadeia.crt \\\n';
    cmd += '  -name "' + alias + '" \\\n';
    if (alg === '3des') cmd += '  -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 \\\n';
    else {
      var c = alg === 'aes256' ? 'AES-256-CBC' : 'AES-128-CBC';
      cmd += '  -keypbe ' + c + ' -certpbe ' + c + ' \\\n';
    }
    cmd += '  -out certificado.pfx\n\n# conferir:\nopenssl pkcs12 -info -in certificado.pfx -nodes';
    $('cmdPfx').textContent = cmd;
  }
  ['pfxOutAlias', 'pfxOutAlg'].forEach(function (id) {
    $(id).addEventListener('input', refreshPfxCmd);
    $(id).addEventListener('change', refreshPfxCmd);
  });

  function leafCert() {
    return (parsedCerts.find(function (c) { return c.isLeaf; }) || parsedCerts[0]).cert;
  }
  function selectedCertsOrdered() {
    var included = parsedCerts.filter(function (c) { return c.include; });
    if (!included.length) throw new Error('Nenhum certificado selecionado na etapa 2.');
    var leaf = included.filter(function (c) { return c.isLeaf; });
    var rest = included.filter(function (c) { return !c.isLeaf; });
    var ordered = leaf.map(function (c) { return c.cert; });
    var pool = rest.map(function (c) { return c.cert; });
    var current = ordered[0], guard = 0;
    while (current && pool.length && guard++ < 20) {
      var issuer = dnKey(current.issuer.attributes);
      var idx = -1;
      for (var i = 0; i < pool.length; i++) {
        if (dnKey(pool[i].subject.attributes) === issuer) { idx = i; break; }
      }
      if (idx === -1) break;
      current = pool.splice(idx, 1)[0];
      ordered.push(current);
    }
    return ordered.concat(pool);
  }
  function toPkcs8Pem(key) {
    return pki.privateKeyInfoToPem(pki.wrapRsaPrivateKey(pki.privateKeyToAsn1(key)));
  }
  function outBase() { return safeName(cnOf(leafCert()), 'certificado'); }

  function buildPemOutput() {
    var out = '';
    selectedCertsOrdered().forEach(function (c) { out += pki.certificateToPem(c) + '\n'; });
    var includeKey = $('pemIncludeKey').checked;
    if (includeKey && parsedKey) {
      var fmt = $('pemKeyFormat').value;
      out += (fmt === 'pkcs8' ? toPkcs8Pem(parsedKey) : pki.privateKeyToPem(parsedKey)) + '\n';
    } else if (includeKey && !parsedKey) {
      throw new Error('Nenhuma chave privada disponível para incluir. Desligue a opção ou carregue a chave na etapa 1.');
    }
    downloadText(out, outBase() + '.pem');
    return out.match(/BEGIN CERTIFICATE/g).length + ' certificado(s)' + (includeKey && parsedKey ? ' + chave privada' : '');
  }

  function buildCrtOutput(variant, ext) {
    var cert = leafCert();
    var filename = outBase() + '.' + ext;
    if (variant === 'der') {
      downloadBinary(forge.asn1.toDer(pki.certificateToAsn1(cert)).getBytes(), filename, 'application/x-x509-ca-cert');
      return 'certificado leaf em DER (binário)';
    }
    downloadText(pki.certificateToPem(cert), filename);
    return 'certificado leaf em PEM (Base64)';
  }

  function buildKeyOutput() {
    if (!parsedKey) throw new Error('É necessária uma chave privada carregada na etapa 1 para exportar um .KEY.');
    var password = $('keyOutPassword').value;
    var fmt = $('keyOutFormat').value;
    if (password) {
      var encAsn1 = pki.encryptPrivateKeyInfo(pki.wrapRsaPrivateKey(pki.privateKeyToAsn1(parsedKey)), password, { algorithm: 'aes256' });
      downloadText(pki.encryptedPrivateKeyToPem(encAsn1), outBase() + '.key');
      return 'chave em PKCS#8 cifrada com AES-256';
    }
    downloadText(fmt === 'pkcs8' ? toPkcs8Pem(parsedKey) : pki.privateKeyToPem(parsedKey), outBase() + '.key');
    return 'chave em ' + (fmt === 'pkcs8' ? 'PKCS#8' : 'PKCS#1') + ' sem senha';
  }

  function buildPfxOutput() {
    if (!parsedKey) throw new Error('É necessária uma chave privada carregada na etapa 1 para gerar um PFX/P12.');
    var password = $('pfxOutPassword').value;
    if (!password) throw new Error('Defina uma senha para o arquivo PFX de saída.');
    var chain = selectedCertsOrdered();
    if (!keyMatches(chain[0])) {
      throw new Error('A chave privada não corresponde ao certificado leaf. Corrija a etapa 1/2 antes de gerar o PFX.');
    }
    var alias = $('pfxOutAlias').value.trim() || 'certificado';
    var asn1 = forge.pkcs12.toPkcs12Asn1(parsedKey, chain, password, {
      algorithm: $('pfxOutAlg').value,
      friendlyName: alias,
      generateLocalKeyId: true
    });
    downloadBinary(forge.asn1.toDer(asn1).getBytes(), outBase() + '.pfx', 'application/x-pkcs12');
    return chain.length + ' certificado(s) + chave privada, cifrado com ' + $('pfxOutAlg').value.toUpperCase();
  }

  /* ---- JKS truststore writer (TrustedCertEntry apenas) ---- */
  function ByteWriter() { this.bytes = []; }
  ByteWriter.prototype.u8 = function (b) { this.bytes.push(b & 0xFF); };
  ByteWriter.prototype.u32 = function (n) {
    this.u8((n >>> 24) & 0xFF); this.u8((n >>> 16) & 0xFF); this.u8((n >>> 8) & 0xFF); this.u8(n & 0xFF);
  };
  ByteWriter.prototype.u64 = function (n) {
    var high = Math.floor(n / 4294967296);
    var low = n - high * 4294967296;
    this.u32(high); this.u32(low >>> 0);
  };
  ByteWriter.prototype.utf = function (str) {
    var bytes = new TextEncoder().encode(str);
    this.u8((bytes.length >> 8) & 0xFF); this.u8(bytes.length & 0xFF);
    for (var i = 0; i < bytes.length; i++) this.u8(bytes[i]);
  };
  ByteWriter.prototype.raw = function (u8arr) { for (var i = 0; i < u8arr.length; i++) this.u8(u8arr[i]); };
  ByteWriter.prototype.toUint8Array = function () { return new Uint8Array(this.bytes); };

  function buildJksBytes(entries, password) {
    var w = new ByteWriter();
    w.u32(0xFEEDFEED);
    w.u32(0x00000002);
    w.u32(entries.length);
    entries.forEach(function (e) {
      w.u32(2);
      w.utf(e.alias);
      w.u64(Date.now());
      w.utf('X.509');
      var certDerBytes = binStrToUint8(forge.asn1.toDer(pki.certificateToAsn1(e.cert)).getBytes());
      w.u32(certDerBytes.length);
      w.raw(certDerBytes);
    });
    var body = w.toUint8Array();

    var pwBytes = [];
    for (var i = 0; i < password.length; i++) {
      var code = password.charCodeAt(i);
      pwBytes.push((code >> 8) & 0xFF, code & 0xFF);
    }
    var md = forge.md.sha1.create();
    md.update(uint8ToBinStr(new Uint8Array(pwBytes)));
    md.update(uint8ToBinStr(new TextEncoder().encode('Mighty Aphrodite')));
    md.update(uint8ToBinStr(body));
    var digestBytes = binStrToUint8(md.digest().getBytes());

    var final = new Uint8Array(body.length + digestBytes.length);
    final.set(body, 0);
    final.set(digestBytes, body.length);
    return final;
  }

  function buildJksOutput() {
    var password = $('jksOutPassword').value;
    if (!password) throw new Error('Defina uma senha para o keystore JKS.');
    var aliasBase = ($('jksOutAlias').value || 'certificado').toLowerCase().replace(/\s+/g, '-');
    var included = parsedCerts.filter(function (c) { return c.include; });
    if (!included.length) throw new Error('Nenhum certificado selecionado.');
    var entries = included.map(function (c, i) {
      return { alias: aliasBase + (included.length > 1 ? '-' + (i + 1) : ''), cert: c.cert };
    });
    downloadBinary(buildJksBytes(entries, password), 'truststore.jks', 'application/octet-stream');
    return included.length + ' certificado(s) confiável(is)';
  }

  $('btnConvert').addEventListener('click', function () {
    var msgEl = $('outputMsg'); clearMsg(msgEl);
    try {
      var detail;
      switch (selectedFmt) {
        case 'pem': detail = buildPemOutput(); break;
        case 'crt-pem': detail = buildCrtOutput('pem', 'crt'); break;
        case 'crt-der': detail = buildCrtOutput('der', 'crt'); break;
        case 'cer-pem': detail = buildCrtOutput('pem', 'cer'); break;
        case 'cer-der': detail = buildCrtOutput('der', 'cer'); break;
        case 'pfx': detail = buildPfxOutput(); break;
        case 'jks': detail = buildJksOutput(); break;
        case 'key': detail = buildKeyOutput(); break;
        default: throw new Error('Selecione um formato de saída.');
      }
      showMsg(msgEl, 'Arquivo gerado e baixado — ' + detail + '.', 'success');
    } catch (e) {
      showMsg(msgEl, e.message, 'error');
    }
  });

  $('btnResetConvert').addEventListener('click', function () {
    parsedCerts = []; parsedKey = null; selectedFmt = null;
    ['pfxPassword', 'keyPassword', 'pfxOutPassword', 'jksOutPassword', 'keyOutPassword'].forEach(function (id) { $(id).value = ''; });
    $('pfxOutAlias').value = 'certificado';
    $('jksOutAlias').value = 'certificado';
    $$('.fmt').forEach(function (c) { c.setAttribute('aria-checked', 'false'); });
    ['optsPem', 'optsPfx', 'optsJks', 'optsKey'].forEach(function (id) { $(id).classList.add('hidden'); });
    ['sourceMsg', 'pairMsg', 'outputMsg'].forEach(function (id) { clearMsg($(id)); });
    $('panelDetected').classList.add('hidden');
    $('panelOutput').classList.add('hidden');
    $('certList').innerHTML = '';
    resetDrops.forEach(function (fn) { fn(null); });
    $('useSessionKey').checked = false;
    updateConvertEnabled();
    snack('Conversor reiniciado');
  });

  /* ============================================================
     INSPECIONAR
     ============================================================ */
  makeDrop('dropInspect', 'inspectFile', function (files) {
    if (!files.length) return;
    readFileAsBinStr(files[0]).then(function (bin) {
      $('inspectPem').value = looksPem(bin) ? bin : '';
      inspect(bin);
    }).catch(function (e) { showMsg($('inspectMsg'), e.message, 'error'); });
  });

  $('btnInspect').addEventListener('click', function () {
    var txt = $('inspectPem').value.trim();
    if (txt) { inspect(txt); return; }
    var f = $('inspectFile').files[0];
    if (f) { readFileAsBinStr(f).then(inspect); return; }
    showMsg($('inspectMsg'), 'Envie um arquivo ou cole um PEM.', 'error');
  });

  function inspect(bin) {
    var out = $('inspectOut'), msgEl = $('inspectMsg');
    out.innerHTML = '';
    clearMsg(msgEl);
    try {
      if (looksPem(bin) && /-----BEGIN (NEW )?CERTIFICATE REQUEST-----/.test(bin)) {
        out.innerHTML = csrDump(pki.certificationRequestFromPem(bin));
        showMsg(msgEl, 'CSR interpretado.', 'success');
        return;
      }
      if (looksPem(bin) && /-----BEGIN[^-]*PRIVATE KEY-----/.test(bin)) {
        var enc = /ENCRYPTED PRIVATE KEY/.test(bin) || /Proc-Type:\s*4,ENCRYPTED/i.test(bin);
        var rows = [
          ['tipo', /RSA PRIVATE KEY/.test(bin) ? 'RSA (PKCS#1)' : 'PKCS#8'],
          ['protegida por senha', enc ? 'sim' : 'não']
        ];
        if (!enc) {
          try { rows.push(['tamanho', 'RSA ' + parsePrivateKey(bin, '').n.bitLength() + ' bits']); } catch (e) {}
        }
        out.innerHTML = dumpBlock('Chave privada', rows);
        showMsg(msgEl, 'Chave privada interpretada. Nenhum dado sai do navegador.', 'success');
        return;
      }
      var certs = parseCertificates(bin);
      out.innerHTML = certs.map(function (c, i) {
        return certDump(c, certs.length > 1 ? 'Certificado ' + (i + 1) + ' de ' + certs.length : 'Certificado');
      }).join('');
      showMsg(msgEl, certs.length + ' certificado(s) interpretado(s).', 'success');
    } catch (e) {
      showMsg(msgEl, e.message, 'error');
    }
  }

  /* init */
  renderChips();
  refreshPfxCmd();
})();
