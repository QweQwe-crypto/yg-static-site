#!/usr/bin/env node
/**
 * trace-audit.js —— 反溯源自查工具
 *
 * 用法：
 *   node trace-audit.js                    # 审计当前目录的 git 仓库
 *   node trace-audit.js --repo <路径>      # 指定仓库目录
 *   node trace-audit.js --site <URL>       # 顺带审计线上站点的响应头
 *   node trace-audit.js --json             # 输出 JSON（供 CI 使用）
 *
 * 退出码：0 = 无高危；1 = 存在高危项
 */
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const argv = process.argv.slice(2);
function arg(name, def) {
  const i = argv.indexOf(name);
  return (i >= 0 && argv[i + 1]) ? argv[i + 1] : def;
}
const REPO = path.resolve(arg('--repo', process.cwd()));
const SITE = arg('--site', '');
const AS_JSON = argv.includes('--json');

const findings = [];
function add(level, title, detail, fix, evidence) {
  findings.push({ level, title, detail, fix, evidence: evidence || '' });
}

/* ---------- 规则 ---------- */
const LEVELS = ['高危', '中危', '提示', '信息'];

const SECRET_PATTERNS = [
  { re: /(token|password|passwd|secret|api[_-]?key|access[_-]?key|private[_-]?key)\s*[:=]\s*['"`]([^'"`]{6,})['"`]/gi, name: '疑似硬编码口令/密钥' },
  { re: /AKIA[0-9A-Z]{16}/g, name: 'AWS AccessKey' },
  { re: /ghp_[A-Za-z0-9]{30,}/g, name: 'GitHub PAT' },
  { re: /sk-[A-Za-z0-9]{20,}/g, name: 'OpenAI/兼容密钥' },
  { re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g, name: '私钥文件' }
];
const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
// 文档/白名单：这些 IP 不算泄露
const IP_ALLOW = new Set(['6.6.6.6', '8.8.8.8', '1.1.1.1', '127.0.0.1', '0.0.0.0', '255.255.255.255']);
const PUBLIC_IP_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;

function walk(dir, out, depth) {
  if (depth > 4) return out;
  let items = [];
  try { items = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return out; }
  for (const it of items) {
    if (it.name === '.git' || it.name === 'node_modules' || it.name === 'vendor') continue;
    const full = path.join(dir, it.name);
    if (it.isDirectory()) walk(full, out, depth + 1);
    else out.push(full);
  }
  return out;
}

function git(args) {
  try {
    return execFileSync('git', args, { cwd: REPO, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  } catch (e) { return ''; }
}

/* ---------- A. Git 身份审计 ---------- */
function auditGit() {
  const log = git(['log', '--all', '--format=%an|%ae|%cn|%ce']);
  if (!log.trim()) return;
  const emails = new Map();
  for (const line of log.split('\n')) {
    if (!line.trim()) continue;
    const parts = line.split('|');
    for (const e of [parts[1], parts[3]]) {
      if (!e) continue;
      if (!emails.has(e)) emails.set(e, 0);
      emails.set(e, emails.get(e) + 1);
    }
  }
  for (const [mail, n] of emails) {
    if (/users\.noreply\.github\.com$/.test(mail) || /noreply@github\.com$/.test(mail)) continue;
    if (/@example\.(com|net)$/.test(mail)) continue;
    add('高危', 'Git 提交历史含真实邮箱',
      '作者邮箱 ' + mail + ' 出现在 ' + n + ' 条提交中。任何人都能用它反查你的 QQ / 邮箱绑定关系。',
      '重写历史：git filter-repo --email-callback "return email == \'' + mail + '\' ? \'QweQwe-crypto@users.noreply.github.com\' : email" --force；改完后 git push --force。',
      mail + ' ×' + n);
  }
  const cfg = git(['config', '--list', '--local']);
  const userName = (cfg.match(/^user\.name=(.*)$/m) || [])[1];
  if (userName && !/QweQwe-crypto/i.test(userName)) {
    add('中危', 'git 本地配置含真实姓名',
      'user.name = ' + userName,
      'git config user.name "QweQwe-crypto"',
      userName);
  }
  const remote = (git(['remote', '-v']).match(/\S+@\S+:/g) || []).join(' ');
  if (remote) {
    add('信息', '远程仓库地址',
      remote,
      '若含真实账号请换成与公开身份一致的无关联账号。',
      remote);
  }
}

/* ---------- B/C. 仓库文件扫描 ---------- */
function auditFiles() {
  const files = walk(REPO, [], 0);
  const selfName = path.basename(__filename);
  for (const f of files) {
    const base = path.basename(f);
    if (base === selfName) continue;              // 工具自身跳过
    let txt = '';
    try { txt = fs.readFileSync(f, 'utf8'); } catch (e) { continue; }
    if (txt.length > 4 * 1024 * 1024) continue;
    const rel = path.relative(REPO, f);

    const isDoc = /\.md$/i.test(rel);
    for (const p of SECRET_PATTERNS) {
      p.re.lastIndex = 0;
      let m = txt.match(p.re);
      // 过滤：模板拼接、占位符、文档示例不算高危
      if (m) {
        m = m.filter(x => {
          if (/\$\{|\$\(|\+\s*encodeURIComponent|\+\s*[A-Z_]{3,}|\+\s*'\s*\+|placeholder|your[_-]|xxx|TODO/i.test(x)) return false;
          const v = (x.match(/['"`]([^'"`]{6,})['"`]/) || [])[1] || '';
          // 真口令：>=12 位，字母数字混合或含随机串特征
          if (v.length < 12) return false;
          if (!/[A-Za-z]/.test(v) || !/[0-9]/.test(v)) return false;
          if (/^(https?|localhost|application|text\/)/i.test(v)) return false;
          return true;
        });
      }
      if (m && m.length && !isDoc) {
        add('高危', '文件含疑似密钥：' + rel,
          p.name + '（' + m.length + ' 处）。前端能看到的文件 = 任何人都能看到。',
          '把密钥移到服务端环境变量（如 Render Environment），前端只留接口地址。',
          m.slice(0, 3).map(x => x.slice(0, 40)).join(' / '));
      }
    }

    // 真实邮箱（排除示例、noreply、图片资源）
    if (/\.(html|js|md|json|yml|yaml|txt)$/i.test(rel)) {
      EMAIL_RE.lastIndex = 0;
      const mails = [...new Set(txt.match(EMAIL_RE) || [])]
        .filter(x => !/noreply|example\.|w3\.org|schema\.org|@2x|@media/i.test(x))
        .filter(x => !/\.(png|jpg|gif|svg)$/i.test(rel));
      if (mails.length) {
        add('中危', '文件含真实邮箱：' + rel,
          mails.join(', ') + '。可用于把站点与你的实名账号绑定。',
          '替换为专用客服邮箱或占位邮箱，或整体移除。',
          mails.join(', '));
      }
    }

    // 本机路径 / 用户名
    const winPath = [...new Set((txt.match(/[A-Za-z]:\\[\\A-Za-z0-9_.\- ]{4,}/g) || []))];
    if (winPath.length) {
      add('中危', '文件含本机绝对路径：' + rel,
        winPath.slice(0, 3).join(' | ') + '。泄露 Windows 用户名与目录结构。',
        '路径改成相对路径（__dirname / path.join）。',
        winPath.slice(0, 3).join(' | '));
    }
    if (/fanae/i.test(txt)) {
      add('中危', '文件含本机用户名：' + rel,
        '出现 "fanae" 字样（Windows 账户名）。',
        '移除或替换为通用占位。', 'fanae');
    }

    // 真实公网 IP（排除文档示例与白名单）
    const ips = [...new Set(txt.match(PUBLIC_IP_RE) || [])].filter(ip => !IP_ALLOW.has(ip));
    if (ips.length && !/trusted-proxy\.txt$/.test(rel)) {
      add('提示', '文件含公网 IP：' + rel,
        ips.slice(0, 5).join(', ') + '。若是你的家庭/办公出口 IP，等于直接交出位置。',
        '删除；文档示例请用 RFC 5737 保留段（192.0.2.x / 198.51.100.x / 203.0.113.x）。',
        ips.slice(0, 5).join(', '));
    }

    // 第三方域名（第三方能拿到访客 IP + Referer）
    const ext = [...new Set([...txt.matchAll(/https?:\/\/([^\/"'`\s]+)/g)].map(m => m[1]))]
      .filter(h => !/^(www\.w3\.org|localhost|127\.0\.0\.1|schemas?\.|xmlns\.)/.test(h));
    if (ext.length && /\.html?$/i.test(rel)) {
      add('提示', '页面引用第三方域名：' + rel,
        ext.slice(0, 8).join(', ') + '。这些站点会收到访客的真实 IP、UA 与 Referer。',
        '用 vendorize.js 把资源自托管；或至少加 rel="noreferrer noopener" 与 <meta name="referrer" content="no-referrer">。',
        ext.slice(0, 8).join(', '));
    }

    // 业务身份文案
    const biz = [...new Set((txt.match(/学籍|靶机网|学信网|验证报告/g) || []))];
    if (biz.length && /\.html?$/i.test(rel)) {
      add('中危', '页面暴露业务身份：' + rel,
        '出现：' + biz.join('、') + '。标题、favicon、文案都能让搜索者把站点与你正在做的事对上号。',
        '改成中性命名（demo / lab / test），去掉真实业务词与机构标识。',
        biz.join('、'));
    }
  }
}

/* ---------- D. 线上响应头 ---------- */
const SEC_WANT = {
  'content-security-policy': 'CSP：限制页面加载外部资源、禁止内联脚本注入',
  'referrer-policy': 'Referrer-Policy：防止路径/参数被外链带走',
  'x-content-type-options': 'X-Content-Type-Options：防 MIME 嗅探',
  'x-frame-options': 'X-Frame-Options：防点击劫持',
  'strict-transport-security': 'HSTS：强制 HTTPS'
};
async function auditSite() {
  if (!SITE) return;
  let res, text = '';
  try {
    res = await fetch(SITE, { redirect: 'follow' });
    text = await res.text();
  } catch (e) {
    add('中危', '线上站点不可访问', SITE + ' → ' + e.message, '确认服务在跑。', e.message);
    return;
  }
  const h = {};
  for (const [k, v] of res.headers) h[k.toLowerCase()] = v;

  const tech = [];
  if (h['server'] && /cloudflare/i.test(h['server'])) tech.push('Cloudflare');
  if (h['x-render-origin-server']) tech.push('Render');
  if (h['x-powered-by']) tech.push('X-Powered-By: ' + h['x-powered-by']);
  if (h['x-generator']) tech.push('X-Generator: ' + h['x-generator']);
  if (h['cf-ray']) {
    const suf = (h['cf-ray'].match(/-([A-Z]{3})\s*$/) || [])[1];
    if (suf) tech.push('Cloudflare 边缘机房 ' + suf + '（可推断你的服务器所在大区）');
  }
  if (tech.length) {
    add('中危', '响应头泄露技术栈',
      tech.join(' / '),
      '在反代层抹掉：server、x-powered-by、x-render-origin-server、cf-ray（Cloudflare 侧关掉 cf-ray 头）。',
      tech.join(' / '));
  }
  for (const [k, why] of Object.entries(SEC_WANT)) {
    if (!h[k]) add('提示', '缺少安全响应头：' + k, why, '在响应头里加上：' + k + ': ...', '');
  }
  // 前端是否预填 token
  const prefill = text.match(/id="token"[^>]*value="([^"]{4,})"/);
  if (prefill) {
    add('高危', '前端硬编码后台口令',
      'jilu 页面 token 输入框预填了 "' + prefill[1] + '"，打开页面源码即得后台权限。',
      '前端不预填；改为 URL ?token= 传入 + localStorage 保存；口令只放服务端环境变量。',
      prefill[1]);
  }
  const bodyToken = [...new Set((text.match(/[\u4e00-\u9fa5]{0,4}token["'\s:=]{1,4}[A-Za-z0-9\-]{10,}/g) || []))];
  if (bodyToken.length) {
    add('提示', '页面正文出现疑似 token 字符串',
      bodyToken.slice(0, 3).join(' | '),
      '确认是否为口令；是则移出前端。', bodyToken.slice(0, 3).join(' | '));
  }
}

/* ---------- F. 关联资产 ---------- */
async function auditAssets() {
  const ghUser = 'QweQwe-crypto';
  try {
    const r = await fetch('https://api.github.com/users/' + ghUser);
    if (r.ok) {
      const j = await r.json();
      const leak = [];
      if (j.name) leak.push('name=' + j.name);
      if (j.email) leak.push('email=' + j.email);
      if (j.blog) leak.push('blog=' + j.blog);
      if (j.location) leak.push('location=' + j.location);
      if (j.bio) leak.push('bio=' + j.bio);
      if (j.company) leak.push('company=' + j.company);
      if (leak.length) {
        add('中危', 'GitHub 账号公开资料带个人信息',
          'github.com/' + ghUser + ' → ' + leak.join(', '),
          '在 GitHub Settings → Profile 里清空 name/email/bio/location/company。',
          leak.join(', '));
      } else {
        add('信息', 'GitHub 账号资料',
          'github.com/' + ghUser + ' 公开资料为空（干净），公开仓库 ' + j.public_repos + ' 个，建于 ' + j.created_at,
          '保持为空。', ghUser);
      }
    }
  } catch (e) { /* 忽略 */ }
}

/* ---------- 输出 ---------- */
function report() {
  const order = { '高危': 0, '中危': 1, '提示': 2, '信息': 3 };
  findings.sort((a, b) => order[a.level] - order[b.level]);
  if (AS_JSON) {
    console.log(JSON.stringify({
      repo: REPO, site: SITE || null,
      summary: {
        高危: findings.filter(f => f.level === '高危').length,
        中危: findings.filter(f => f.level === '中危').length,
        提示: findings.filter(f => f.level === '提示').length,
        信息: findings.filter(f => f.level === '信息').length
      },
      findings
    }, null, 2));
  } else {
    const cnt = { '高危': 0, '中危': 0, '提示': 0, '信息': 0 };
    findings.forEach(f => cnt[f.level]++);
    console.log('\n=== 反溯源自查 ===');
    console.log('仓库: ' + REPO + (SITE ? '  站点: ' + SITE : ''));
    console.log('高危 ' + cnt['高危'] + ' | 中危 ' + cnt['中危'] + ' | 提示 ' + cnt['提示'] + ' | 信息 ' + cnt['信息']);
    console.log('-'.repeat(60));
    for (const f of findings) {
      console.log('[' + f.level + '] ' + f.title);
      console.log('  现象: ' + f.detail);
      console.log('  修复: ' + f.fix);
      if (f.evidence) console.log('  证据: ' + f.evidence);
      console.log('');
    }
    if (!findings.length) console.log('未发现可被利用的溯源线索。');
  }
  process.exit(findings.some(f => f.level === '高危') ? 1 : 0);
}

(async () => {
  auditGit();
  auditFiles();
  await auditSite();
  await auditAssets();
  report();
})();
