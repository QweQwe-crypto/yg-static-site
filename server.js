/**
 * 极简访问者 IP 记录工具（支持真实 IP / XFF 链分析）
 * 运行: node server.js
 *      PORT=9000 ADMIN_TOKEN=abc123 node server.js
 */
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 8080;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '123456';
const LOG_FILE = path.join(__dirname, 'visits.log');
const HTML_FILE = path.join(__dirname, 'jillu.html');

/**
 * 解析客户端 IP。
 * 优先级：CF-Connecting-IP / True-Client-IP / X-Real-IP（CDN/反代给的单值真实IP）
 *        > X-Forwarded-For 最后一段（按你的要求：链路最末端即最靠近你服务器的那一跳来源）
 *        > socket 地址
 * 同时保留完整 XFF 链，供页面查看每一跳。
 */
function parseIp(req) {
  const headers = req.headers || {};
  const socketIp = (req.socket && req.socket.remoteAddress) || '';
  const socket = socketIp.replace(/^::ffff:/, '');

  const rawXff = headers['x-forwarded-for'];
  const chain = rawXff
    ? String(rawXff).split(',').map(s => s.trim()).filter(Boolean)
    : [];

  const cf = headers['cf-connecting-ip'] || headers['true-client-ip'] || headers['x-real-ip'];

  let realIp, source;
  if (cf) {
    realIp = String(cf).trim().split(',')[0].trim();
    source = 'CDN头(CF/True-Client/X-Real-IP)';
  } else if (chain.length) {
    realIp = chain[chain.length - 1];   // XFF 最后一段
    source = 'XFF最后一段';
  } else if (socket) {
    realIp = socket;
    source = '直连socket';
  } else {
    realIp = 'unknown';
    source = '-';
  }

  return {
    realIp,
    source,
    chain,
    chainFirst: chain.length ? chain[0] : '',
    socket,
    rawXff: rawXff ? String(rawXff) : ''
  };
}

function browser(ua) {
  ua = ua || '';
  const b = /Edg\//.test(ua) ? 'Edge'
    : /Chrome\//.test(ua) ? 'Chrome'
    : /Firefox\//.test(ua) ? 'Firefox'
    : /Safari\//.test(ua) ? 'Safari'
    : /MicroMessenger/i.test(ua) ? '微信'
    : /QQ\//.test(ua) ? 'QQ'
    : /Bot|crawler|spider|curl|python/i.test(ua) ? '爬虫/脚本' : '其他';
  const os = /Windows/i.test(ua) ? 'Windows'
    : /Android/i.test(ua) ? 'Android'
    : /iPhone|iPad|iOS/i.test(ua) ? 'iOS'
    : /Mac OS/i.test(ua) ? 'macOS'
    : /Linux/i.test(ua) ? 'Linux' : '-';
  return b + ' / ' + os;
}

function readLogs() {
  let raw = '';
  try { raw = fs.readFileSync(LOG_FILE, 'utf8'); } catch (e) { return []; }
  return raw.split('\n').filter(Boolean).slice(-2000).reverse().map(line => {
    try { return JSON.parse(line); } catch (e) { return null; }
  }).filter(Boolean);
}

function json(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}

const server = http.createServer((req, res) => {
  const ipInfo = parseIp(req);
  let u;
  try { u = new URL(req.url, 'http://localhost'); } catch (e) { u = new URL('/', 'http://localhost'); }
  const p = u.pathname;

  if (p === '/api/myip') return json(res, 200, ipInfo);

  if (p === '/api/logs') {
    if (u.searchParams.get('token') !== ADMIN_TOKEN) return json(res, 403, { error: 'token 错误' });
    return json(res, 200, readLogs());
  }

  if (p === '/api/clear') {
    if (u.searchParams.get('token') !== ADMIN_TOKEN) return json(res, 403, { error: 'token 错误' });
    fs.writeFileSync(LOG_FILE, '');
    return json(res, 200, { ok: true });
  }

  // 普通页面访问 -> 记录一条日志
  try {
    fs.appendFileSync(LOG_FILE, JSON.stringify({
      time: new Date().toISOString(),
      ip: ipInfo.realIp,           // 真实 IP（XFF 最后一段）
      ipSource: ipInfo.source,      // 取值来源
      xff: ipInfo.rawXff,           // 原始 XFF 头
      xffChain: ipInfo.chain,       // 链数组
      chainFirst: ipInfo.chainFirst,// 链首段
      chainLast: ipInfo.chain.length ? ipInfo.chain[ipInfo.chain.length - 1] : '',
      socketIp: ipInfo.socket,      // TCP 直连地址（可能是 CDN/反代）
      method: req.method,
      path: p + (u.search || ''),
      referer: req.headers.referer || '',
      ua: req.headers['user-agent'] || '',
      client: browser(req.headers['user-agent'])
    }) + '\n');
  } catch (e) {}

  fs.readFile(HTML_FILE, (err, data) => {
    if (err) { res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('jillu.html 缺失'); }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(data);
  });
});

server.listen(PORT, () => {
  console.log('访问日志工具已启动: http://localhost:' + PORT);
  console.log('日志文件: ' + LOG_FILE);
  console.log('后台 token: ' + ADMIN_TOKEN);
});
