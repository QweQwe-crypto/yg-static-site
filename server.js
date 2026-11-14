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

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
  'Access-Control-Max-Age': '86400'
};

function json(res, code, obj) {
  res.writeHead(code, Object.assign({ 'Content-Type': 'application/json; charset=utf-8' }, CORS));
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
const server = http.createServer((req, res) => {
  const ipInfo = parseIp(req);
  let u;
  try { u = new URL(req.url, 'http://localhost'); } catch (e) { u = new URL('/', 'http://localhost'); }
  const p = decodeURIComponent(u.pathname);

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
        method: req.method,
        path: p + (u.search || ''),
        referer: req.headers.referer || '',
        ua: req.headers['user-agent'] || '',
        client: browser(req.headers['user-agent'])
      }) + '\n');
    }
  } catch (e) {}

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
    }, CORS));
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
