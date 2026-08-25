/* Central de Certificados — geração de CSR/chave, conversão entre formatos e inspeção.
   100% client-side, criptografia via node-forge (vendor/forge.min.js). */
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
  var generated = null;   // {csrPem, keyPem, base}

  /* ============================================================
     Helpers genéricos
     ============================================================ */
  function $(id) { return document.getElementById(id); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

  function showMsg(el, text, type) {
    el.className = 'msg ' + type;
    el.textContent = text;
    el.style.display = 'block';
  }
  function showMsgHtml(el, html, type) {
    el.className = 'msg ' + type;
    el.innerHTML = html;
    el.style.display = 'block';
  }
  function clearMsg(el) { el.style.display = 'none'; el.textContent = ''; }

  function esc(s) {
    return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
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
  function readFileAsBinStr(file) {
    return readFileAsArrayBuffer(file).then(ab2binstr);
  }
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
  }
  function downloadBinary(u8orBinStr, filename, mime) {
    var u8 = (typeof u8orBinStr === 'string') ? binStrToUint8(u8orBinStr) : u8orBinStr;
    triggerDownload(new Blob([u8], { type: mime || 'application/octet-stream' }), filename);
  }
  function safeName(s, fallback) {
    s = (s || '').trim().replace(/^\*\./, 'wildcard.').replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '');
    return s || fallback;
  }

  /* ============================================================
     Navegação: modos (topo) e abas (dentro dos painéis)
     ============================================================ */
  function showMode(name) {
    $$('.mode-btn').forEach(function (b) { b.classList.toggle('active', b.dataset.mode === name); });
    $$('.mode-pane').forEach(function (p) { p.classList.toggle('active', p.id === 'mode-' + name); });
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
  $$('.mode-btn').forEach(function (b) {
    b.addEventListener('click', function () { showMode(b.dataset.mode); });
  });

  // cada grupo .tabs controla apenas os .tab-pane irmãos do próprio grupo
  $$('.tabs').forEach(function (group) {
    var container = group.parentElement;
    var panes = $$('.tab-pane', container).filter(function (p) { return p.parentElement === container; });
    $$('.tab-btn', group).forEach(function (btn) {
      btn.addEventListener('click', function () {
        $$('.tab-btn', group).forEach(function (b) { b.classList.remove('active'); });
        panes.forEach(function (p) { p.classList.remove('active'); });
        btn.classList.add('active');
        var pane = $('tab-' + btn.dataset.tab);
        if (pane) pane.classList.add('active');
        if (container.querySelector('#sourceMsg')) clearMsg($('sourceMsg'));
      });
    });
  });

  $$('.copy').forEach(function (b) {
    b.addEventListener('click', function () {
      var ta = $(b.dataset.target);
      var flash = function () {
        var old = b.textContent;
        b.textContent = 'copiado!';
        setTimeout(function () { b.textContent = old; }, 1600);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(ta.value).then(flash, function () { legacyCopy(ta); flash(); });
      } else { legacyCopy(ta); flash(); }
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
     Parsing de certificados e chaves (PEM, DER, base64 puro, PKCS#7)
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
     Metadados / renderização de detalhes
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
  function certDump(cert, title) {
    var now = new Date();
    var expired = cert.validity.notAfter < now;
    var notYet = cert.validity.notBefore > now;
    var days = Math.round((cert.validity.notAfter - now) / 86400000);
    var status = expired ? '<span class="badge expired">expirado</span>'
      : notYet ? '<span class="badge expired">ainda não válido</span>'
      : '<span class="badge">válido · ' + days + ' dia(s)</span>';
    return dumpBlock(title || 'Certificado', [
      ['subject', dnToString(cert.subject.attributes)],
      ['issuer', dnToString(cert.issuer.attributes)],
      ['válido de', fmtDate(cert.validity.notBefore)],
      ['válido até', esc(fmtDate(cert.validity.notAfter)) + ' ' + status, 'html'],
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
     ABA: GERAR CSR — leitura de arquivo .cnf do OpenSSL
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

  /* Converte um openssl.cnf (ou variantes simples) em {dn, sans, bits, digest, warnings} */
  function parseCnf(text) {
    var sections = { '': [] };   // nome -> [[chave, valor], ...] (ordem preservada)
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
      // linha de subject no formato /C=BR/O=Empresa/CN=exemplo.com.br
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

    /* ---- Subject ---- */
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
    if (!dnPairs.length) dnPairs = sections[''] || [];   // pares soltos, sem seção

    var defaults = {};
    dnPairs.forEach(function (p) {
      var m = p[0].match(/^(.*)_default$/i);
      if (m) defaults[m[1].toLowerCase().replace(/^\d+\./, '')] = p[1];
    });

    dnPairs.forEach(function (p) {
      var key = p[0];
      if (/_(default|min|max)$/i.test(key)) return;
      var base = key.toLowerCase().replace(/^\d+\./, '');   // "0.organizationName" -> "organizationname"
      var norm = DN_ALIASES[base];
      if (!norm) return;
      var val = defaults.hasOwnProperty(base) ? defaults[base] : p[1];
      if (defaults.hasOwnProperty(base) === false && promptMode) {
        warnings.push(key + ' ignorado (arquivo em modo prompt e sem ' + key + '_default)');
        return;
      }
      if (val) dn[norm] = val;
    });

    /* ---- SAN ---- */
    var extSecName = (get('req', 'req_extensions') || get('req', 'x509_extensions') || 'v3_req').toLowerCase();
    var sanValue = get(extSecName, 'subjectaltname');
    if (!sanValue) {
      // procura subjectAltName em qualquer seção
      Object.keys(sections).some(function (s) {
        var v = get(s, 'subjectaltname');
        if (v) { sanValue = v; return true; }
        return false;
      });
    }
    if (sanValue) {
      var ref = sanValue.match(/^@\s*(.+)$/);
      if (ref) {
        (sections[ref[1].trim().toLowerCase()] || []).forEach(function (p) {
          if (p[1]) sans.push(p[1]);
        });
        if (!sections[ref[1].trim().toLowerCase()]) warnings.push('seção [' + ref[1].trim() + '] referenciada em subjectAltName não foi encontrada');
      } else {
        sanValue.split(',').forEach(function (item) {
          var v = item.trim().replace(/^(DNS|IP|IP\.\d+|email|URI|otherName)\s*:\s*/i, '');
          if (v) sans.push(v);
        });
      }
    }

    var bits = get('req', 'default_bits');
    var digest = (get('req', 'default_md') || '').toLowerCase();

    return { dn: dn, sans: sans, bits: bits, digest: digest, warnings: warnings };
  }

  function applyCnf(parsed) {
    var map = { CN: 'g_cn', O: 'g_o', OU: 'g_ou', L: 'g_l', ST: 'g_st', C: 'g_c', E: 'g_email' };
    var filled = [];
    Object.keys(map).forEach(function (k) {
      if (parsed.dn[k]) { $(map[k]).value = parsed.dn[k]; filled.push(k); }
    });

    var sans = parsed.sans.filter(function (s, i, arr) { return arr.indexOf(s) === i; });
    if (sans.length) $('g_sans').value = sans.join('\n');

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

    if (!filled.length && !sans.length) {
      throw new Error('Nenhum dado de subject encontrado. Verifique se o arquivo tem uma seção [ req_distinguished_name ] com CN, O, OU, L, ST ou C.');
    }
    return { filled: filled, sans: sans, extras: extras };
  }

  function loadCnf(text) {
    var msgEl = $('cnfMsg');
    clearMsg(msgEl);
    try {
      var parsed = parseCnf(text);
      var res = applyCnf(parsed);
      var linhas = ['Dados carregados: ' + (res.filled.length ? res.filled.join(', ') : 'nenhum campo de subject')];
      if (res.sans.length) linhas.push(res.sans.length + ' SAN: ' + res.sans.join(', '));
      if (res.extras.length) linhas.push('opções: ' + res.extras.join(' · '));
      if (parsed.warnings.length) linhas.push('avisos: ' + parsed.warnings.join(' | '));
      // leva o usuário aos campos já preenchidos; a mensagem vai para o painel 2, que fica sempre visível
      var manualBtn = $$('#mode-csr .tab-btn').filter(function (b) { return b.dataset.tab === 'manual'; })[0];
      if (manualBtn) manualBtn.click();
      showMsg($('genMsg'), linhas.join('\n') + '\nRevise os campos acima e clique em "Gerar CSR e chave".',
        parsed.warnings.length ? 'warn' : 'success');
    } catch (e) {
      showMsg(msgEl, 'Erro ao ler a configuração.\n' + e.message, 'error');
    }
  }

  $('btnLoadCnf').addEventListener('click', function () {
    var file = $('cnfFile').files[0];
    var typed = $('cnfText').value.trim();
    if (!file && !typed) { showMsg($('cnfMsg'), 'Selecione um arquivo .cnf ou cole o conteúdo no campo abaixo.', 'error'); return; }
    if (file) {
      readFileAsText(file).then(function (t) { $('cnfText').value = t; loadCnf(t); })
        .catch(function (e) { showMsg($('cnfMsg'), e.message, 'error'); });
    } else {
      loadCnf(typed);
    }
  });
  $('cnfFile').addEventListener('change', function () {
    var file = this.files[0];
    if (!file) return;
    readFileAsText(file).then(function (t) { $('cnfText').value = t; loadCnf(t); })
      .catch(function (e) { showMsg($('cnfMsg'), e.message, 'error'); });
  });

  /* ============================================================
     ABA: GERAR CSR — geração
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
    var lines = $('g_sans').value.split(/[\n,;]+/).map(function (s) { return s.trim(); }).filter(Boolean);
    var cn = $('g_cn').value.trim();
    if (cn && /^[A-Za-z0-9*._-]+\.[A-Za-z]{2,}$/.test(cn) && lines.indexOf(cn) === -1) lines.unshift(cn);

    var seen = {}, alt = [];
    lines.forEach(function (v) {
      var k = v.toLowerCase();
      if (seen[k]) return;
      seen[k] = 1;
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v) || /^[0-9a-f:]+:[0-9a-f:]*$/i.test(v)) alt.push({ type: 7, ip: v });
      else if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) alt.push({ type: 1, value: v });
      else if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) alt.push({ type: 6, value: v });
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
        if (err) pki.rsa.generateKeyPair(opts, cb);   // fallback sem Web Workers
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

  $('btnGenerate').addEventListener('click', function () {
    var btn = this, msgEl = $('genMsg');
    clearMsg(msgEl);

    var cn = $('g_cn').value.trim();
    if (!cn) { showMsg(msgEl, 'Informe o Common Name (CN).', 'error'); $('g_cn').focus(); return; }

    var c = $('g_c').value.trim();
    if (c && !/^[A-Za-z]{2}$/.test(c)) { showMsg(msgEl, 'O país (C) deve ter exatamente 2 letras. Ex.: BR', 'error'); return; }
    $('g_c').value = c.toUpperCase();

    var protect = $('g_protect').checked;
    var pass = $('g_keyPass').value;
    if (protect) {
      if (!pass) { showMsg(msgEl, 'Informe a senha da chave.', 'error'); return; }
      if (pass !== $('g_keyPass2').value) { showMsg(msgEl, 'As senhas da chave não conferem.', 'error'); return; }
    }

    var bits = parseInt($('g_bits').value, 10);
    var digest = $('g_digest').value;
    var format = $('g_keyfmt').value;
    var subject = buildSubject();
    var alt = parseSans();
    var base = safeName($('g_basename').value || cn, 'certificado');

    btn.disabled = true;
    btn.innerHTML = '<span class="spin"></span>Gerando chave de ' + bits + " bits…";
    var t0 = Date.now();

    setTimeout(function () {
      generateKeyPair(bits, function (err, keys) {
        var restore = function () { btn.disabled = false; btn.textContent = 'Gerar CSR e chave'; };
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
          showMsg(msgEl, 'CSR e chave gerados em ' + ((Date.now() - t0) / 1000).toFixed(1) + 's. Baixe os dois arquivos — a chave não fica salva em lugar nenhum.', 'success');
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
    ['g_cn', 'g_o', 'g_ou', 'g_l', 'g_st', 'g_c', 'g_email', 'g_sans', 'g_basename', 'g_keyPass', 'g_keyPass2', 'cnfText'].forEach(function (id) { $(id).value = ''; });
    $('cnfFile').value = '';
    $('g_bits').value = '2048';
    $('g_digest').value = 'sha256';
    $('g_keyfmt').value = 'pkcs8';
    $('g_protect').checked = false;
    $('g_passRow').classList.add('hidden');
    $('panelCsrResult').classList.add('hidden');
    $('csrOut').value = ''; $('keyOut').value = '';
    generated = null;
    clearMsg($('genMsg')); clearMsg($('cnfMsg'));
  });

  /* passa a chave recém-gerada para o conversor */
  $('sendToConvert').addEventListener('click', function () {
    if (!generated) return;
    sessionKey = { key: generated.key, pem: generated.keyPem, name: generated.base + '.key' };
    $('sessionKeyName').textContent = sessionKey.name;
    $('useSessionKeyWrap').classList.remove('hidden');
    $('useSessionKey').checked = true;
    if (!$('pfxOutAlias').value || $('pfxOutAlias').value === 'certificado') $('pfxOutAlias').value = generated.base;
    showMode('convert');
    var pemTabBtn = $$('#mode-convert .tab-btn').filter(function (b) { return b.dataset.tab === 'pem'; })[0];
    if (pemTabBtn) pemTabBtn.click();
    showMsg($('sourceMsg'), 'Chave gerada nesta sessão pronta para uso. Selecione o certificado emitido pela AC e clique em "Ler certificado".', 'info');
  });

  /* ============================================================
     CONVERSOR — etapa 1: leitura da origem
     ============================================================ */
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
    }).catch(function (e) {
      showMsg(msgEl, 'Erro ao ler o PFX/P12 — verifique a senha ou o arquivo.\n' + e.message, 'error');
      $('panelDetected').classList.add('hidden');
      $('panelOutput').classList.add('hidden');
    });
  });

  $('btnParsePem').addEventListener('click', function () {
    var msgEl = $('sourceMsg'); clearMsg(msgEl);
    var certFile = $('certFile').files[0];
    if (!certFile) { showMsg(msgEl, 'Selecione um arquivo de certificado.', 'error'); return; }

    var chainFiles = Array.prototype.slice.call($('chainFile').files || []);
    var keyFile = $('keyFile').files[0];
    var useSession = $('useSessionKey').checked && sessionKey;

    readFileAsBinStr(certFile).then(function (bin) {
      var certs = parseCertificates(bin);
      if (!certs.length) throw new Error('Nenhum certificado válido encontrado no arquivo.');

      return Promise.all(chainFiles.map(readFileAsBinStr)).then(function (bins) {
        bins.forEach(function (b) { certs = certs.concat(parseCertificates(b)); });

        // remove duplicados pelo subject+serial
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
    }).catch(function (e) {
      showMsg($('sourceMsg'), 'Erro ao ler o certificado.\n' + e.message, 'error');
      $('panelDetected').classList.add('hidden');
      $('panelOutput').classList.add('hidden');
    });
  });

  /* ============================================================
     CONVERSOR — etapa 2: conteúdo detectado
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
      item.isLeaf = (i === leafIdx);

      var cert = item.cert;
      var expired = cert.validity.notAfter < new Date();
      var badges = '';
      if (item.isLeaf) badges += '<span class="badge leaf">leaf</span>';
      if (parsedKey && keyMatches(cert)) badges += '<span class="badge key">chave privada</span>';
      if (expired) badges += '<span class="badge expired">expirado</span>';

      var card = document.createElement('div');
      card.className = 'cert-card';
      card.innerHTML =
        '<div class="top">' +
          '<label>' +
            '<input type="checkbox" data-idx="' + i + '" class="chk-include"' + (item.include ? ' checked' : '') + '>' +
            esc(cnOf(cert) || dnToString(cert.subject.attributes).split(',')[0] || ('Certificado ' + (i + 1))) +
            badges +
          '</label>' +
          '<label style="margin:0;display:flex;align-items:center;gap:6px;">' +
            '<input type="radio" name="leafRadio" data-idx="' + i + '" class="rad-leaf"' + (item.isLeaf ? ' checked' : '') + '>' +
            '<span style="font-size:11px;">definir como leaf</span>' +
          '</label>' +
        '</div>' +
        '<div class="cert-meta">' +
          'subject: ' + esc(dnToString(cert.subject.attributes)) + '<br>' +
          'issuer:&nbsp; ' + esc(dnToString(cert.issuer.attributes)) + '<br>' +
          'válido:&nbsp; ' + esc(fmtDate(cert.validity.notBefore)) + ' → ' + esc(fmtDate(cert.validity.notAfter)) + '<br>' +
          'serial:&nbsp; ' + esc(cert.serialNumber) +
          (altNamesOf(cert).length ? '<br>SAN:&nbsp;&nbsp;&nbsp;&nbsp; ' + esc(altNamesOf(cert).join(', ')) : '') +
        '</div>';
      list.appendChild(card);
    });

    $$('.chk-include', list).forEach(function (chk) {
      chk.addEventListener('change', function (e) { parsedCerts[+e.target.dataset.idx].include = e.target.checked; });
    });
    $$('.rad-leaf', list).forEach(function (rad) {
      rad.addEventListener('change', function (e) {
        var idx = +e.target.dataset.idx;
        parsedCerts.forEach(function (c, i) { c.isLeaf = (i === idx); });
        renderDetected();
      });
    });

    // validação chave x certificado
    var pairEl = $('pairMsg');
    clearMsg(pairEl);
    if (parsedKey) {
      var leaf = (parsedCerts.find(function (c) { return c.isLeaf; }) || parsedCerts[0]).cert;
      if (keyMatches(leaf)) {
        showMsg(pairEl, '✔ A chave privada corresponde ao certificado leaf (RSA ' + parsedKey.n.bitLength() + ' bits).', 'success');
      } else if (parsedCerts.some(function (c) { return keyMatches(c.cert); })) {
        showMsg(pairEl, 'A chave corresponde a outro certificado da lista, não ao leaf selecionado. Ajuste qual é o leaf antes de exportar.', 'warn');
      } else {
        showMsg(pairEl, '✖ A chave privada NÃO corresponde a nenhum certificado carregado. Um PFX gerado assim não funcionaria.', 'error');
      }
    }

    $('panelDetected').classList.remove('hidden');
    $('panelOutput').classList.remove('hidden');
    updateConvertEnabled();
    refreshPfxCmd();
  }

  /* ============================================================
     CONVERSOR — etapa 3: formato de saída
     ============================================================ */
  $$('.fmt-card').forEach(function (card) {
    card.addEventListener('click', function () {
      $$('.fmt-card').forEach(function (c) { c.classList.remove('selected'); });
      card.classList.add('selected');
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
    var cmd = 'openssl pkcs12 -export \\\n';
    cmd += '  -inkey chave.key \\\n';
    cmd += '  -in certificado.crt \\\n';
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

  /* ---------- builders ---------- */
  function leafCert() {
    return (parsedCerts.find(function (c) { return c.isLeaf; }) || parsedCerts[0]).cert;
  }
  function selectedCertsOrdered() {
    var included = parsedCerts.filter(function (c) { return c.include; });
    if (!included.length) throw new Error('Nenhum certificado selecionado na etapa 2.');
    var leaf = included.filter(function (c) { return c.isLeaf; });
    var rest = included.filter(function (c) { return !c.isLeaf; });
    // ordena a cadeia: leaf -> emissor -> ... -> raiz
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
  function outBase() {
    return safeName(cnOf(leafCert()), 'certificado');
  }

  function buildPemOutput() {
    var out = '';
    selectedCertsOrdered().forEach(function (c) { out += pki.certificateToPem(c) + '\n'; });
    var includeKey = $('pemIncludeKey').checked;
    if (includeKey && parsedKey) {
      var fmt = $('pemKeyFormat').value;
      out += (fmt === 'pkcs8' ? toPkcs8Pem(parsedKey) : pki.privateKeyToPem(parsedKey)) + '\n';
    } else if (includeKey && !parsedKey) {
      throw new Error('Nenhuma chave privada disponível para incluir. Desmarque a opção ou carregue a chave na etapa 1.');
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
      w.u32(2); // trusted cert tag
      w.utf(e.alias);
      w.u64(Date.now());
      w.utf('X.509');
      var certDerBytes = binStrToUint8(forge.asn1.toDer(pki.certificateToAsn1(e.cert)).getBytes());
      w.u32(certDerBytes.length);
      w.raw(certDerBytes);
    });
    var body = w.toUint8Array();

    // digest de integridade = SHA1( senha(UTF-16BE) + "Mighty Aphrodite"(UTF-8) + body )
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
      showMsg(msgEl, 'Arquivo gerado e baixado com sucesso — ' + detail + '.', 'success');
    } catch (e) {
      showMsg(msgEl, e.message, 'error');
    }
  });

  /* ============================================================
     ABA: INSPECIONAR
     ============================================================ */
  $('inspectFile').addEventListener('change', function () {
    var f = this.files[0];
    if (!f) return;
    readFileAsBinStr(f).then(function (bin) {
      $('inspectPem').value = looksPem(bin) ? bin : '';
      inspect(bin);
    }).catch(function (e) { showMsg($('inspectMsg'), e.message, 'error'); });
  });

  $('btnInspect').addEventListener('click', function () {
    var txt = $('inspectPem').value.trim();
    if (txt) { inspect(txt); return; }
    var f = $('inspectFile').files[0];
    if (f) { readFileAsBinStr(f).then(inspect); return; }
    showMsg($('inspectMsg'), 'Selecione um arquivo ou cole um PEM.', 'error');
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
  refreshPfxCmd();
})();
