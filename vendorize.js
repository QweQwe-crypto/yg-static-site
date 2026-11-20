#!/usr/bin/env node
/**
 * vendorize.js —— 第三方资源自托管化工具
 *
 * 目的：页面引用第三方 CDN 时，第三方会拿到访客的真实 IP / UA / Referer。
 * 本工具把所有第三方资源下载到 vendor/ 目录并改写本地引用，
 * 同时给外链加 rel="noreferrer noopener"、插入 <meta name="referrer" content="no-referrer">。
 *
 * 用法：
 *   node vendorize.js                      # 处理仓库内所有 .html
 *   node vendorize.js 靶机网.html           # 只处理指定文件
 *   node vendorize.js --dry                # 只报告不落盘
 */
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const crypto = require('crypto');

const argv = process.argv.slice(2);
const DRY = argv.includes('--dry');
const ROOT = __dirname;
const VENDOR = path.join(ROOT, 'vendor');

// 站点内部地址，不处理
const SELF = /^https?:\/\/(?:localhost|127\.0\.0\.1|\d{1,3}(?:\.\d{1,3}){3})/i;

function hash8(buf) {
  return crypto.createHash('sha1').update(buf).digest('hex').slice(0, 8);
}

function safeName(u) {
  const p = u.pathname;
  let name = (p.split('/').filter(Boolean).pop() || 'index').replace(/[^A-Za-z0-9._-]/g, '_');
  if (!/\.[A-Za-z0-9]{1,6}$/.test(name)) name += (u.pathname.match(/\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf)$/i) || ['', '.bin'])[0];
  if (!name || name.length < 2) name = 'res';
  return name;
}

// 远程资源的本地目录名：host_路径，非法字符全部替换
function vendorDirOf(url) {
  let u;
  try { u = new URL(url); } catch (e) { return '_misc'; }
  const raw = u.hostname + u.pathname;
  const dir = raw.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^_+|_+$/g, '') || '_misc';
  return dir;
}

function download(url, redirects) {
  redirects = redirects || 0;
  return new Promise(resolve => {
    if (redirects > 4) return resolve(null);
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, {
      timeout: 15000,
      headers: {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36',
        'accept': '*/*'
      }
    }, res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        const next = new URL(res.headers.location, url).href;
        return resolve(download(next, redirects + 1));
      }
      if (res.statusCode !== 200) { res.resume(); return resolve(null); }
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ body: Buffer.concat(chunks), type: res.headers['content-type'] || '' }));
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { try { req.destroy(); } catch (e) {} resolve(null); });
  });
}

// CSS 内部的 url() / @import 递归本地化
async function localizeCss(css, baseUrl, outDir) {
  let out = css;
  const urls = [...css.matchAll(/url\(\s*['"]?([^'")]+)['"]?\s*\)/gi)].map(m => m[1]);
  for (const u of urls) {
    if (/^(data:|https?:\/\/\/)/i.test(u)) continue;
    if (u.startsWith('//')) continue;
    let abs;
    try { abs = new URL(u, baseUrl).href; } catch (e) { continue; }
    if (SELF.test(abs)) continue;
    const r = await download(abs);
    if (!r) continue;
    if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
    const name = safeName(new URL(abs)) + '.' + hash8(r.body) + '.bin';
    fs.writeFileSync(path.join(outDir, name), r.body);
    out = out.split(u).join(name);
  }
  const imports = [...css.matchAll(/@import\s+url\(\s*['"]([^'"]+)['"]\s*\)/gi)];
  for (const m of imports) {
    let abs;
    try { abs = new URL(m[1], baseUrl).href; } catch (e) { continue; }
    const r = await download(abs);
    if (!r) continue;
    if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
    const name = safeName(new URL(abs)) + '.' + hash8(r.body) + '.css';
    fs.writeFileSync(path.join(outDir, name), r.body);
    out = out.split(m[1]).join(name);
  }
  return out;
}

async function processHtml(file) {
  let html = fs.readFileSync(file, 'utf8');
  const rel = path.relative(ROOT, file);
  const dir = path.join(VENDOR, path.dirname(rel).replace(/^\.\./, '_') || '_root');
  const changed = { local: [], failed: [], left: [] };

  // 1) <link href> / <script src> / <img src> / <source src>
  const tags = [...html.matchAll(/<(link|script|img|source|iframe|video|audio)\b[^>]*\b(?:href|src)=["'](https?:\/\/[^"']+)["']/gi)];
  for (const t of tags) {
    const url = t[2];
    if (SELF.test(url)) continue;
    const upath = (new URL(url).pathname || '').toLowerCase();
    const ext = (t[1].toLowerCase() === 'link' && /stylesheet/i.test(t[0])) ? 'css'
      : (t[1].toLowerCase() === 'script' ? 'js'
      : (upath.endsWith('.css') ? 'css' : (upath.endsWith('.js') ? 'js'
      : (upath.endsWith('.png') ? 'png' : (upath.endsWith('.jpg') || upath.endsWith('.jpeg')) ? 'jpg'
      : (upath.endsWith('.gif') ? 'gif' : (upath.endsWith('.svg') ? 'svg'
      : (upath.endsWith('.ico') ? 'ico' : 'bin')))))));
    const r = await download(url);
    if (!r) { changed.failed.push(url); continue; }
    let body = r.body;
    const name = safeName(new URL(url)) + '.' + hash8(body) + '.' + ext;
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    if (ext === 'css') {
      body = Buffer.from(await localizeCss(body.toString('utf8'), new URL(url).href, dir), 'utf8');
    }
    fs.writeFileSync(path.join(dir, name), body);
    const local = path.relative(path.dirname(file), path.join(dir, name)).replace(/\\/g, '/');
    html = html.split(url).join(local);
    changed.local.push(url + ' -> ' + local);
  }

  // 2) CSS <style> 块里的外链
  const styleBlocks = [...html.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/gi)];
  for (const sb of styleBlocks) {
    const inner = await localizeCss(sb[1], 'https://placeholder.local/', path.join(VENDOR, '_inline'));
    if (inner !== sb[1]) html = html.split(sb[1]).join(inner);
  }

  // 3) 外链 <a> 加 rel=noreferrer noopener
  html = html.replace(/<a\b([^>]*\bhref=["']https?:\/\/[^"']+["'][^>]*)>/gi, (m, attrs) => {
    if (/rel=["']/i.test(attrs)) return m.replace(/rel=["'][^"']*["']/i, 'rel="noreferrer noopener"');
    return '<a' + attrs + ' rel="noreferrer noopener">';
  });

  // 3.5) 删除 dns-prefetch（会让访客 DNS 查询泄露给第三方）与第三方 1x1 追踪像素
  html = html.replace(/<link\b[^>]*\brel=["']?dns-prefetch["']?[^>]*>/gi, '');
  html = html.replace(/<img\b[^>]*\bwidth=["']?0["']?[^>]*>/gi, '');
  html = html.replace(/<img\b[^>]*\bheight=["']?0["']?[^>]*>/gi, '');

  // 4) meta referrer
  if (!/name=["']referrer["']/i.test(html)) {
    html = html.replace(/<head([^>]*)>/i, '<head$1>\n<meta name="referrer" content="no-referrer">');
  }

  // 5) 剩余外链（导航跳转）单独报告
  const left = [...new Set([...html.matchAll(/https?:\/\/([^\/"'\s>]+)/g)].map(m => m[1]))]
    .filter(h => !/^(www\.w3\.org)$/.test(h));
  changed.left = left;

  if (!DRY) fs.writeFileSync(file, html, 'utf8');
  return { file: rel, changed };
}

(async () => {
  const targets = argv.filter(a => !a.startsWith('--'));
  const files = targets.length
    ? targets.map(t => path.resolve(ROOT, t))
    : fs.readdirSync(ROOT).filter(f => /\.html?$/i.test(f)).map(f => path.join(ROOT, f));

  for (const f of files) {
    if (!fs.existsSync(f)) { console.log('跳过（不存在）: ' + f); continue; }
    const res = await processHtml(f);
    console.log('\n== ' + res.file);
    res.changed.local.forEach(x => console.log('  本地化: ' + x));
    res.changed.failed.forEach(x => console.log('  下载失败: ' + x));
    if (res.changed.left.length) console.log('  仍为外链(仅跳转/文本): ' + res.changed.left.join(', '));
  }
  console.log('\n完成' + (DRY ? '（dry-run，未落盘）' : ''));
})();
