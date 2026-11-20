/**
 * 访问日志服务 —— 真实访客 IP 追踪（XFF / CDN 链分析）
 *
 * 部署：Render Web Service
 *   Build Command : (空)
 *   Start Command : node server.js
 *   环境变量：
 *     PORT          监听端口（Render 自动注入，一般为 10000）
 *     ADMIN_TOKEN   后台日志页 token（务必改成强密码）
 *     TRUST_PRIVATE 是否信任内网/回环地址作为反代（Render 场景需为 1）
 *
 * 关键逻辑：可信代理链自右向左剥离，剥到第一个「不可信」的 IP 才是真实访客。
 * 直连来源不在可信名单时，所有 XFF / CF 头一律视为伪造并丢弃。
 */
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');

const PORT = process.env.PORT || 8099;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '123456';
// 日志页访问令牌（可选）。设置后 /jilu.html 必须带 ?token= 才能访问，
// 这样「知道域名就能拿到后台」的路就断了
const LOG_PAGE_TOKEN = process.env.LOG_PAGE_TOKEN || '';
const ROOT = __dirname;
// 日志文件：优先放 Render 持久化磁盘，其次本地目录
const LOG_FILE = process.env.LOG_FILE || path.join(ROOT, 'visits.log');
const HTML_FILE = path.join(ROOT, 'jilu.html');
const TRUSTED_FILE = path.join(ROOT, 'trusted-proxy.txt');

// 是否把内网/回环视为可信反代（Render / 同机 Nginx 场景需要）
const TRUST_PRIVATE = process.env.TRUST_PRIVATE !== '0';

// ---------- 可信代理网段 ----------
function loadTrustedProxy() {
  let list = [];
  try {
    list = fs.readFileSync(TRUSTED_FILE, 'utf8')
      .split(/\r?\n/).map(s => s.trim())
      .filter(s => s && !s.startsWith('#'));
  } catch (e) {}
  if (process.env.TRUSTED_PROXY) {
    list = list.concat(process.env.TRUSTED_PROXY.split(',').map(s => s.trim()).filter(Boolean));
  }
  return Array.from(new Set(list));
}
const TRUSTED_PROXY = loadTrustedProxy();

// ============================================================
// 代理 / 真实 IP 增强模块
//  1) 读取代理透传头（代理软件有时会带出原始 IP，但可被伪造，仅作线索）
//  2) WebRTC / DNS 泄漏探针：浏览器侧泄露出的真实出口 IP -> /api/leak
//  3) 出口 IP 归属查询：判定该 IP 是「住宅宽带」还是「机房/代理池」
// ============================================================

const SID_STORE = new Map();   // sid -> 发放时间
const LEAK_STORE = new Map();  // sid -> { ip, ts, type }
const GEO_CACHE = new Map();   // ip -> { ts, data }

const PROXY_HINT_HEADERS = [
  'x-client-ip', 'x-originating-ip', 'x-original-forwarded-for', 'x-cluster-client-ip',
  'client-ip', 'proxy-client-ip', 'http_client_ip', 'http_x_forwarded_for',
  'forwarded', 'x-real-ip', 'true-client-ip', 'x-forwarded-host', 'x-remote-addr',
  'x-forwarded-server', 'via'
];

function isPrivateIp(ip) {
  ip = String(ip || '').replace(/^::ffff:/, '');
  return /^127\./.test(ip) || /^10\./.test(ip) || /^192\.168\./.test(ip)
    || /^172\.(1[6-9]|2\d|3[01])\./.test(ip) || /^169\.254\./.test(ip)
    || /^::1$/.test(ip) || /^fc00:/i.test(ip) || /^fd00:/i.test(ip) || /^fe80:/i.test(ip)
    || ip === '';
}

// 收集代理软件可能透传的头（这些头客户端可伪造，仅作线索展示）
function proxyHints(headers) {
  const out = {};
  for (const h of PROXY_HINT_HEADERS) {
    const v = headers[h];
    if (v) out[h] = String(v).slice(0, 160);
  }
  return out;
}

// 常见 IDC / 云厂商 / 代理服务商 ASN 关键字（ipwho.is 对部分云厂商 connection.type 判定不准，用 ASN 兜底）
const IDC_KEYWORDS = [
  'tencent', 'tencentcloud', 'qcloud', 'aliyun', 'alibaba', 'alicloud', 'huawei cloud',
  'huaweicloud', 'amazon', 'aws', 'microsoft', 'azure', 'google', 'gcp', 'digitalocean',
  'linode', 'akamai', 'cloudflare', 'vultr', 'hetzner', 'ovh', 'contabo', 'oracle',
  'scaleway', 'leaseweb', 'm247', 'choopa', 'hosting', 'datacenter', 'data center',
  'colocation', 'cloud', 'proxy', 'vpn', 'bulletproof'
];
function looksLikeIDC(org, isp, connType) {
  const hay = String(org || '') + ' ' + String(isp || '') + ' ' + String(connType || '').toLowerCase();
  const h = hay.toLowerCase();
  if (connType === 'hosting' || connType === 'business' && /cloud|data|hosting|dedicated/i.test(h)) return true;
  return IDC_KEYWORDS.some(k => h.includes(k));
}

function httpGetJson(url, timeoutMs, depth) {
  depth = depth || 0;
  return new Promise(resolve => {
    if (depth > 3) return resolve(null);
    const mod = url.startsWith('https') ? https : http;
    let done = false;
    const fin = v => { if (!done) { done = true; resolve(v); } };
    let rq;
    try {
      rq = mod.get(url, {
        timeout: timeoutMs,
        headers: {
          // 部分 IP 归属站会拒绝非浏览器 UA
          'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36',
          'accept': 'application/json,text/plain,*/*',
          'accept-language': 'en-US,en;q=0.9'
        }
      }, r => {
        if (r.statusCode >= 300 && r.statusCode < 400 && r.headers.location) {
          try { rq.destroy(); } catch (e) {}
          const next = new URL(r.headers.location, url).href;
          return fin(httpGetJson(next, timeoutMs, depth + 1));
        }
        let b = '';
        r.on('data', c => { if (b.length < 200000) b += c; });
        r.on('end', () => {
          if (r.statusCode !== 200) return fin(null);
          try { fin(JSON.parse(b)); } catch (e) { fin(null); }
        });
      });
    } catch (e) { return fin(null); }
    rq.on('error', () => fin(null));
    rq.on('timeout', () => { try { rq.destroy(); } catch (e) {} fin(null); });
  });
}

// 出口 IP 归属 / 是否机房代理
// 多数据源并发竞速：Render 容器出网可能被某一个源拒掉，必须有多个备胎
const GEO_SOURCES = [
  {
    name: 'freeipapi',
    url: ip => 'https://freeipapi.com/api/json/' + encodeURIComponent(ip),
    parse: j => {
      if (!j || !j.ipAddress) return null;
      const rawAsn = String(j.asn || '').replace(/^AS/i, '');
      const org = j.asnOrganization || j.asn_organization || '';
      return {
        country: j.countryCode || '', region: j.regionName || '', city: j.cityName || '',
        isp: j.isp || org, asn: rawAsn ? ('AS' + rawAsn) : '', asnOrg: org,
        proxy: !!j.isProxy, hosting: looksLikeIDC(org, j.isp || org, ''),
        vpn: false, tor: false, connType: '', fraudScore: null, source: 'freeipapi'
      };
    }
  },
  {
    name: 'ip.sb',
    url: ip => 'https://api.ip.sb/geoip/' + encodeURIComponent(ip),
    parse: j => {
      if (!j || !j.asn) return null;
      const rawAsn = String(j.asn).replace(/^AS/i, '');
      const org = j.asn_organization || j.organization || '';
      return {
        country: j.country_code || '', region: j.region || '', city: j.city || '',
        isp: j.isp || org, asn: rawAsn ? ('AS' + rawAsn) : '', asnOrg: org,
        proxy: false, hosting: looksLikeIDC(org, j.isp || org, ''),
        vpn: false, tor: false, connType: '', fraudScore: null, source: 'ip.sb'
      };
    }
  },
  {
    name: 'ipwho.is',
    url: ip => 'https://ipwho.is/' + encodeURIComponent(ip),
    parse: j => {
      if (!j || j.success === false || !j.connection) return null;
      const c = j.connection;
      return {
        country: j.country_code || '', region: j.region || '', city: j.city || '',
        isp: c.isp || '', asn: c.asn ? ('AS' + c.asn) : '', asnOrg: c.org || '',
        proxy: false, hosting: c.type === 'hosting', vpn: false, tor: false,
        connType: c.type || '', fraudScore: null, source: 'ipwho.is'
      };
    }
  },
  {
    name: 'ipinfo.io',
    url: ip => 'https://ipinfo.io/' + encodeURIComponent(ip) + '/json',
    parse: j => {
      if (!j || !j.ip) return null;
      const m = String(j.org || '').match(/AS(\d+)/);
      return {
        country: j.country || '', region: j.region || '', city: j.city || '',
        isp: j.org || '', asn: m ? ('AS' + m[1]) : '', asnOrg: j.org || '',
        proxy: /\b(cloud|hosting|vpn|proxy)\b/i.test(String(j.org || '')), hosting: looksLikeIDC(j.org, j.org, ''),
        vpn: false, tor: false, connType: '', fraudScore: null, source: 'ipinfo.io'
      };
    }
  },
  {
    name: 'ipapi.co',
    url: ip => 'https://ipapi.co/' + encodeURIComponent(ip) + '/json/',
    parse: j => {
      if (!j || j.error || !j.org) return null;
      const m = String(j.org || '').match(/AS(\d+)/);
      return {
        country: j.country_code || '', region: j.region || '', city: j.city || '',
        isp: j.org || '', asn: m ? ('AS' + m[1]) : '', asnOrg: j.org || '',
        proxy: false, hosting: looksLikeIDC(j.org, j.org, ''),
        vpn: false, tor: false, connType: '', fraudScore: null, source: 'ipapi.co'
      };
    }
  },
  {
    name: 'ip-api.com',
    url: ip => 'http://ip-api.com/json/' + encodeURIComponent(ip) + '?fields=status,message,country,regionName,city,isp,org,as,query',
    parse: j => {
      if (!j || j.status !== 'success') return null;
      const m = String(j.as || '').match(/AS(\d+)/);
      return {
        country: j.country || '', region: j.regionName || '', city: j.city || '',
        isp: j.isp || '', asn: m ? ('AS' + m[1]) : '', asnOrg: j.org || '',
        proxy: /\b(cloud|hosting|vpn|proxy)\b/i.test(String(j.org || '')), hosting: looksLikeIDC(j.org, j.isp || '', ''),
        vpn: false, tor: false, connType: '', fraudScore: null, source: 'ip-api.com'
      };
    }
  },
  {
    name: 'ipwhois.app',
    url: ip => 'https://ipwhois.app/json/' + encodeURIComponent(ip),
    parse: j => {
      if (!j || j.success === false || !j.connection) return null;
      const c = j.connection;
      const m = String(c.asn || '').match(/AS(\d+)/);
      return {
        country: j.country_code || '', region: j.region || '', city: j.city || '',
        isp: c.isp || '', asn: m ? ('AS' + m[1]) : '', asnOrg: c.org || '',
        proxy: false, hosting: c.type === 'hosting', vpn: false, tor: false,
        connType: c.type || '', fraudScore: null, source: 'ipwhois.app'
      };
    }
  },
  {
    name: 'iplocation',
    url: ip => 'https://api.iplocation.net/?ip=' + encodeURIComponent(ip),
    parse: j => {
      if (!j || !j.asn) return null;
      const m = String(j.asn).match(/AS(\d+)/);
      return {
        country: j.country_code2 || '', region: j.region_name || '', city: j.city_name || '',
        isp: j.isp || '', asn: m ? ('AS' + m[1]) : '', asnOrg: j.asn || '',
        proxy: false, hosting: looksLikeIDC(j.asn, j.isp || '', ''),
        vpn: false, tor: false, connType: '', fraudScore: null, source: 'iplocation'
      };
    }
  },
];

// 最近一次查询的诊断信息（便于线上排查为什么全是"查询中"）
const GEO_DIAG = { at: 0, ip: '', tried: [], ok: false };

async function lookupIp(ip, wantDiag) {
  if (!ip || isPrivateIp(ip)) return null;
  const hit = GEO_CACHE.get(ip);
  if (hit && Date.now() - hit.ts < 6 * 3600 * 1000) {
    if (!hit.data && Date.now() - hit.ts < 90 * 1000) return null;   // 负缓存窗口
    if (!hit.data) GEO_CACHE.delete(ip);                            // 过期负缓存，允许重试
    else return hit.data;
  }

  // 商业代理检测库（可选，环境变量配置），命中最准，优先
  if (process.env.IPQS_KEY) {
    const j = await httpGetJson('https://ipqualityscore.com/api/json/ip/' + process.env.IPQS_KEY + '/' + encodeURIComponent(ip), 6000);
    if (j && j.success) {
      const data = {
        country: j.country_code || '', region: j.region || '', city: j.city || '',
        isp: j.isp || '', asn: j.ASN ? ('AS' + j.ASN) : '', asnOrg: j.organization || '',
        proxy: !!j.proxy, hosting: !!j.hosting, vpn: !!j.vpn, tor: !!j.tor,
        connType: '', fraudScore: typeof j.fraud_score === 'number' ? j.fraud_score : null,
        source: 'ipqualityscore'
      };
      finalizeGeo(data);
      GEO_CACHE.set(ip, { ts: Date.now(), data });
      return data;
    }
  }

  // 多源并发竞速，谁先成功用谁
  const tried = [];
  const results = await Promise.all(GEO_SOURCES.map(async src => {
    const t0 = Date.now();
    const j = await httpGetJson(src.url(ip), 6000);
    let d = null;
    try { d = src.parse(j); } catch (e) { d = null; }
    tried.push({ source: src.name, ok: !!d, ms: Date.now() - t0 });
    return d;
  }));

  let data = results.find(Boolean) || null;

  // 全军覆没时等 800ms 再打一轮（部分源是按请求频率限流，退避一下就能过）
  if (!data) {
    await new Promise(r => setTimeout(r, 800));
    const retry = await Promise.all(GEO_SOURCES.map(async src => {
      const t0 = Date.now();
      const j = await httpGetJson(src.url(ip), 6000);
      let d = null;
      try { d = src.parse(j); } catch (e) { d = null; }
      tried.push({ source: src.name + '(retry)', ok: !!d, ms: Date.now() - t0 });
      return d;
    }));
    data = retry.find(Boolean) || null;
  }

  if (data) finalizeGeo(data);
  if (wantDiag) {
    GEO_DIAG.at = Date.now();
    GEO_DIAG.ip = ip;
    GEO_DIAG.tried = tried;
    GEO_DIAG.ok = !!data;
  }
  if (!data) {
    // 负缓存 90 秒，避免每次刷新都把 8 个源打一遍
    GEO_CACHE.set(ip, { ts: Date.now(), data: null });
    return null;
  }
  GEO_CACHE.set(ip, { ts: Date.now(), data });
  return data;
}

function finalizeGeo(data) {
  if (!data) return;
  if (looksLikeIDC(data.asnOrg, data.isp, data.connType)) { data.hosting = true; }
  data.type = data.hosting ? '机房/IDC' : (data.proxy ? '代理/代理池' : (data.vpn ? 'VPN 出口' : '住宅宽带'));
}

// ---------- 浏览器侧泄漏探针（WebRTC 拿到代理后面的真实出口 IP） ----------
const LEAK_JS = "<script id=\"__iplog_leak__\">\n(function(){\n  var sid = window.__SID__ || \"\";\n  if (!sid) return;\n  var done = false;\n  function post(ip, type){ if(done||!ip) return; done=true;\n    try{ fetch(\"/api/leak\",{method:\"POST\",headers:{\"Content-Type\":\"application/json\"},\n      body:JSON.stringify({sid:sid,ip:ip,type:type}),keepalive:true}); }catch(e){} }\n  function handle(cand){\n    if(!cand) return;\n    var m = String(cand).match(/(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})/);\n    if(m){ post(m[1], \"webrtc-ipv4\"); return; }\n    var m6 = String(cand).match(/((?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4})/i);\n    if(m6 && !/^(fe80|::)/i.test(m6[1])) post(m6[1], \"webrtc-ipv6\");\n  }\n  try{\n    var pc = new RTCPeerConnection({iceServers:[{urls:\"stun:stun.cloudflare.com:3478\"},{urls:\"stun:stun.l.google.com:19302\"},{urls:\"stun:qq.com:3478\"}]});\n    pc.createDataChannel(\"x\");\n    pc.onicecandidate = function(e){ handle(e && e.candidate && e.candidate.candidate); };\n    pc.createOffer().then(function(o){ return pc.setLocalDescription(o); }).catch(function(){});\n  }catch(e){}\n  // 补充：STUN 拿不到时，用 fetch 到 STUN-over-HTTP 不可行，改用多源 STUN 重试\n})();\n</script>";

function pruneStores() {
  const now = Date.now();
  for (const [k, v] of SID_STORE) if (now - v > 3600e3) SID_STORE.delete(k);
  for (const [k, v] of LEAK_STORE) if (now - v.ts > 86400e3) LEAK_STORE.delete(k);
}
setInterval(pruneStores, 10 * 60e3).unref();

const PRIVATE_RANGES = [
  /^127\./, /^10\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./,
  /^::1$/, /^fc00:/i, /^fd00:/i, /^fe80:/i
];

function ipToLong(ip) {
  const m = String(ip).match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  let n = 0;
  for (let i = 1; i <= 4; i++) {
    const v = +m[i];
    if (v > 255) return null;
    n = (n * 256) + v;
  }
  return n;
}

function inCidr(ip, cidr) {
  const parts = String(cidr).split('/');
  const net = parts[0];
  const bits = parts[1] === undefined ? 32 : +parts[1];
  const a = ipToLong(ip), b = ipToLong(net);
  if (a === null || b === null) return false;
  if (bits <= 0) return true;
  if (bits > 32) return false;
  const mask = bits === 32 ? 0xFFFFFFFF : (~0 << (32 - bits)) >>> 0;
  return ((a & mask) >>> 0) === ((b & mask) >>> 0);
}

function isTrustedProxy(ip) {
  if (!ip) return false;
  for (const c of TRUSTED_PROXY) {
    if (c.includes('/')) { if (inCidr(ip, c)) return true; }
    else if (ip === c) return true;
  }
  if (!TRUST_PRIVATE) return false;
  return PRIVATE_RANGES.some(re => re.test(ip));
}

// 判断某个 IP 本身是不是「代理节点」（用于过滤 CDN 单值头里的边缘 IP）
function isProxyNode(ip) {
  return isTrustedProxy(ip);
}

// ---------- IP 解析 ----------
/**
 * 优先级：
 *  1) 直连来源不可信            -> 全部头部视为伪造，只用 socket 地址
 *  2) CDN 单值头（且值本身不是代理节点）-> CF-Connecting-IP / True-Client-IP / X-Real-IP ...
 *  3) XFF 链自右向左剥离可信代理 -> 剥到第一个不可信 IP = 真实访客
 */
function parseIp(req) {
  const headers = req.headers || {};
  const socketIp = (req.socket && req.socket.remoteAddress) || '';
  const socket = String(socketIp).replace(/^::ffff:/, '');

  const rawXff = headers['x-forwarded-for'];
  const chain = rawXff
    ? String(rawXff).split(',').map(s => s.trim()).filter(Boolean)
    : [];

  const singleHeaders = [
    ['cf-connecting-ip', headers['cf-connecting-ip']],
    ['true-client-ip', headers['true-client-ip']],
    ['x-client-ip', headers['x-client-ip']],
    ['fastly-client-ip', headers['fastly-client-ip']],
    ['x-real-ip', headers['x-real-ip']]
  ];

  const trusted = isTrustedProxy(socket);

  let realIp, source, cdnIp = '', cdnKey = '';

  if (!trusted) {
    realIp = socket || 'unknown';
    source = socket ? '直连socket(来源不可信,已忽略伪造头)' : '-';
  } else {
    // 单值头里挑第一个「不是代理节点自身」的值
    for (const [k, v] of singleHeaders) {
      if (!v) continue;
      const ip = String(v).split(',')[0].trim();
      if (!ip) continue;
      if (isProxyNode(ip)) continue;   // 边缘节点把自己的 IP 填进来了，跳过
      cdnIp = ip; cdnKey = k;
      break;
    }
    if (cdnIp) {
      realIp = cdnIp;
      source = 'CDN头(' + cdnKey + ')';
    } else if (chain.length) {
      let idx = chain.length - 1;
      while (idx >= 0 && isTrustedProxy(chain[idx])) idx--;
      if (idx >= 0) {
        realIp = chain[idx];
        source = 'XFF链自右剥离后第' + (idx + 1) + '段';
      } else {
        realIp = chain[0];
        source = 'XFF首段(整链均为可信代理)';
      }
    } else {
      realIp = socket;
      source = 'socket(可信反代但未带XFF)';
    }
  }

  return {
    realIp,
    source,
    chain,
    chainFirst: chain.length ? chain[0] : '',
    chainLast: chain.length ? chain[chain.length - 1] : '',
    socket,
    rawXff: rawXff ? String(rawXff) : '',
    trustedProxy: trusted,
    cdnIp
  };
}

// ---------- UA 解析 ----------
function browser(ua) {
  ua = ua || '';
  const b = /Edg\//.test(ua) ? 'Edge'
    : /Chrome\//.test(ua) ? 'Chrome'
    : /Firefox\//.test(ua) ? 'Firefox'
    : /Safari\//.test(ua) ? 'Safari'
    : /MicroMessenger/i.test(ua) ? '微信'
    : /QQ\//.test(ua) ? 'QQ'
    : /Bot|crawler|spider|curl|python|wget/i.test(ua) ? '爬虫/脚本' : '其他';
  const os = /Windows/i.test(ua) ? 'Windows'
    : /Android/i.test(ua) ? 'Android'
    : /iPhone|iPad|iOS/i.test(ua) ? 'iOS'
    : /Mac OS/i.test(ua) ? 'macOS'
    : /Linux/i.test(ua) ? 'Linux' : '-';
  return b + ' / ' + os;
}

// ---------- 日志读写 ----------
function readLogs() {
  let raw = '';
  try { raw = fs.readFileSync(LOG_FILE, 'utf8'); } catch (e) { return []; }
  return raw.split('\n').filter(Boolean).slice(-2000).reverse().map(line => {
    try { return JSON.parse(line); } catch (e) { return null; }
  }).filter(Boolean);
}

// 安全响应头：防止 Referer 泄露、点击劫持、MIME 嗅探
const SEC_HEADERS = {
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' https:; frame-ancestors 'none'; base-uri 'none'",
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), interest-cohort=()'
};

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
  'Access-Control-Max-Age': '86400'
};

function json(res, code, obj) {
  res.writeHead(code, Object.assign({ 'Content-Type': 'application/json; charset=utf-8' }, CORS, SEC_HEADERS));
  res.end(JSON.stringify(obj));
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.gif': 'image/gif', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8', '.md': 'text/plain; charset=utf-8',
  '.log': 'text/plain; charset=utf-8'
};

// ---------- 服务器 ----------
const server = http.createServer(async (req, res) => {
  const ipInfo = parseIp(req);
  let u;
  try { u = new URL(req.url, 'http://localhost'); } catch (e) { u = new URL('/', 'http://localhost'); }
  const p = decodeURIComponent(u.pathname);

  // 页面访问分配 sid（用于关联浏览器侧 WebRTC 泄漏探针）
  const isPage = /\.(html?)$/i.test(p) || p === '/';
  let pageSid = '';
  if (isPage) {
    pageSid = require('crypto').randomBytes(12).toString('hex');
    SID_STORE.set(pageSid, Date.now());
  }

  if (req.method === 'OPTIONS') {
    res.writeHead(204, CORS);
    return res.end();
  }

  if (p === '/api/myip') {
    return json(res, 200, Object.assign({}, ipInfo, { trustedList: TRUSTED_PROXY, trustPrivate: TRUST_PRIVATE }));
  }

  // 回显本次收到的全部请求头，方便排查各层反代到底传了什么
  if (p === '/api/headers') {
    return json(res, 200, {
      headers: req.headers,
      parsed: ipInfo,
      trustedList: TRUSTED_PROXY,
      trustPrivate: TRUST_PRIVATE,
      socket: ipInfo.socket
    });
  }

  // 发放会话 sid（前端带在后续请求上，用于关联泄漏探针结果）
  if (p === '/api/session') {
    const sid = (u.searchParams.get('sid') || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64)
      || require('crypto').randomBytes(12).toString('hex');
    SID_STORE.set(sid, Date.now());
    return json(res, 200, { sid, ok: true });
  }

  // 接收浏览器 WebRTC 泄漏探针上报的「代理后面」真实出口 IP
  if (p === '/api/leak' && req.method === 'POST') {
    let raw = '';
    req.on('data', c => { if (raw.length < 4096) raw += c; });
    req.on('end', () => {
      let b = {};
      try { b = JSON.parse(raw || '{}'); } catch (e) {}
      const sid = String(b.sid || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64);
      const ip = String(b.ip || '').trim().slice(0, 64);
      if (sid && ip && !isPrivateIp(ip)) {
        LEAK_STORE.set(sid, { ip, ts: Date.now(), type: b.type || 'webrtc' });
      }
      return json(res, 200, { ok: true });
    });
    return;
  }

  // 查询某 sid 已上报的泄漏 IP
  if (p === '/api/leak') {
    const sid = (u.searchParams.get('sid') || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64);
    const rec = LEAK_STORE.get(sid);
    return json(res, 200, rec ? { ip: rec.ip, ts: rec.ts, type: rec.type } : { ip: '', ts: 0, type: '' });
  }

  // 批量取所有 sid 的泄漏 IP（前端合并到表格行）
  if (p === '/api/leaks') {
    if (u.searchParams.get('token') !== ADMIN_TOKEN) return json(res, 403, { error: 'token 错误' });
    const out = {};
    for (const [k, v] of LEAK_STORE) out[k] = { ip: v.ip, ts: v.ts, type: v.type };
    return json(res, 200, out);
  }

  // IP 归属 / 代理判定查询
  if (p === '/api/geo') {
    const ip = (u.searchParams.get('ip') || '').trim().slice(0, 64);
    if (!ip) return json(res, 400, { error: '缺少 ip 参数' });
    const d = await lookupIp(ip, true);
    if (!d) {
      return json(res, 200, {
        error: '查询失败', ip,
        diag: {
          tried: GEO_DIAG.tried,
          hint: '所有归属数据源都不可达（容器出网受限或源被限流）',
          ipqsKey: !!process.env.IPQS_KEY
        }
      });
    }
    return json(res, 200, d);
  }

  // 批量归属查询：一次请求返回多个 IP 的判定
  if (p === '/api/geo/batch') {
    const ips = String(u.searchParams.get('ips') || '')
      .split(',').map(s => s.trim().slice(0, 64)).filter(Boolean).slice(0, 80);
    const out = {};
    await Promise.all(ips.map(async ip => {
      const d = await lookupIp(ip);
      out[ip] = d || { error: '查询失败', ip };
    }));
    return json(res, 200, out);
  }

  // 归属查询自检：逐个源测试连通性
  if (p === '/api/geo/health') {
    const out = [];
    for (const src of GEO_SOURCES) {
      const t0 = Date.now();
      const j = await httpGetJson(src.url('8.8.8.8'), 6000);
      let ok = false;
      try { ok = !!src.parse(j); } catch (e) { ok = false; }
      out.push({ source: src.name, ok, ms: Date.now() - t0 });
    }
    return json(res, 200, { at: new Date().toISOString(), sources: out, ipqsKey: !!process.env.IPQS_KEY });
  }

  if (p === '/api/logs' || p === '/api/visits') {
    if (u.searchParams.get('token') !== ADMIN_TOKEN) return json(res, 403, { error: 'token 错误' });
    return json(res, 200, readLogs());
  }

  if (p === '/api/clear' || p === '/api/visits/clear') {
    if (u.searchParams.get('token') !== ADMIN_TOKEN) return json(res, 403, { error: 'token 错误' });
    try { fs.writeFileSync(LOG_FILE, ''); } catch (e) {}
    return json(res, 200, { ok: true });
  }

  // 本机出口公网 IP（用于确认已暴露公网）
  if (p === '/api/netinfo') {
    const sources = ['https://api.ipify.org?format=json', 'https://ifconfig.me/ip', 'https://icanhazip.com'];
    let i = 0;
    const tryNext = () => {
      if (i >= sources.length) {
        return json(res, 200, { serverPublicIp: '获取失败(服务器无法访问外网查询接口)', trustedList: TRUSTED_PROXY, port: PORT });
      }
      const u2 = sources[i++];
      const mod = u2.startsWith('https') ? https : http;
      const rq = mod.get(u2, { timeout: 4000 }, r => {
        let b = '';
        r.on('data', c => b += c);
        r.on('end', () => {
          let out = String(b).trim();
          try { out = JSON.parse(b).ip; } catch (e) {}
          if (!out || !/[0-9]/.test(out)) return tryNext();
          return json(res, 200, { serverPublicIp: out, trustedList: TRUSTED_PROXY, port: PORT });
        });
      });
      rq.on('error', tryNext);
      rq.on('timeout', () => rq.destroy());
    };
    return tryNext();
  }

  // 日志页门禁：设置了 LOG_PAGE_TOKEN 后，/jilu.html 必须带 ?token= 或 Bearer 头
  if (p === '/jilu.html' && LOG_PAGE_TOKEN) {
    const need = LOG_PAGE_TOKEN;
    const q = u.searchParams.get('token') || '';
    const auth = String(req.headers.authorization || '');
    const bearer = /^Bearer\s+(.+)$/i.exec(auth);
    const ok = q === need || (bearer && bearer[1] === need);
    if (!ok) {
      res.writeHead(401, Object.assign({ 'Content-Type': 'text/plain; charset=utf-8' }, CORS, SEC_HEADERS));
      return res.end('401 需要访问令牌：/jilu.html?token=YOUR_TOKEN');
    }
  }

  // 历史拼写兼容
  if (p === '/jillu.html') {
    res.writeHead(302, { Location: '/jilu.html' });
    return res.end();
  }

  if (p === '/favicon.ico') { res.writeHead(204); return res.end(); }

  // 记录访问日志（API 与静态资源不记录，避免噪音）
  const isAsset = /\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf)$/i.test(p);
  const shouldLog = !p.startsWith('/api/') && !isAsset;
  try {
    if (shouldLog) {
      fs.appendFileSync(LOG_FILE, JSON.stringify({
        time: new Date().toISOString(),
        ip: ipInfo.realIp,
        ipSource: ipInfo.source,
        xff: ipInfo.rawXff,
        xffChain: ipInfo.chain,
        chainFirst: ipInfo.chainFirst,
        chainLast: ipInfo.chainLast,
        socketIp: ipInfo.socket,
        trustedProxy: ipInfo.trustedProxy,
        cdnIp: ipInfo.cdnIp || '',
        sid: pageSid || '',
        proxyHints: proxyHints(req.headers),
        method: req.method,
        path: p + (u.search || ''),
        referer: req.headers.referer || '',
        ua: req.headers['user-agent'] || '',
        client: browser(req.headers['user-agent'])
      }) + '\n');
    }
  } catch (e) {}

  // 后台异步补全该 IP 的归属（住宅宽带 / 机房代理），供前端判定列使用
  if (shouldLog && ipInfo.realIp && !isPrivateIp(ipInfo.realIp) && !GEO_CACHE.has(ipInfo.realIp)) {
    lookupIp(ipInfo.realIp).catch(() => {});
  }

  // 静态文件
  const rel = p === '/' ? '/index.html' : p;
  const file = path.join(ROOT, path.normalize(rel).replace(/^([\/])+/, ''));
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end('forbidden'); }

  fs.readFile(file, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('404 Not Found: ' + p);
    }
    const ext = path.extname(file).toLowerCase();
    res.writeHead(200, Object.assign({
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Cache-Control': ext === '.html' ? 'no-store' : 'public, max-age=300'
    }, CORS, SEC_HEADERS));

    // HTML 页面：注入 WebRTC 泄漏探针（拿到访客代理后面的真实出口 IP）
    if (ext === '.html' && pageSid) {
      let html = data.toString('utf8');
      const inject = '<script>window.__SID__=' + JSON.stringify(pageSid) + ';</script>' + LEAK_JS;
      if (html.includes('</body>')) html = html.replace('</body>', inject + '</body>');
      else html += inject;
      return res.end(Buffer.from(html, 'utf8'));
    }
    res.end(data);
  });
});

server.on('error', e => {
  if (e.code === 'EADDRINUSE') console.error('端口 ' + PORT + ' 已被占用，换 PORT 启动');
  else console.error(e);
  process.exit(1);
});

server.listen(PORT, '0.0.0.0', () => {
  const nets = os.networkInterfaces();
  const addrs = [];
  for (const k in nets) for (const n of nets[k]) if (n.family === 'IPv4') addrs.push(k + '=' + n.address);
  console.log('访问日志服务已启动: http://0.0.0.0:' + PORT);
  console.log('页面文件: ' + HTML_FILE + (fs.existsSync(HTML_FILE) ? '' : '  << 缺失'));
  console.log('日志文件: ' + LOG_FILE);
  console.log('后台 token: ' + ADMIN_TOKEN + (ADMIN_TOKEN === '123456' ? '   << 弱密码，公网务必改' : ''));
  console.log('可信代理网段(' + TRUSTED_PROXY.length + '): ' + TRUSTED_PROXY.join(', '));
  console.log('信任内网地址: ' + (TRUST_PRIVATE ? '是' : '否'));
  console.log('本机 IPv4: ' + addrs.join(', '));
});
