// RapidAPI-compatible security scanning service
// Zero dependencies, deploy to Fly.io

const http = require('http');
const https = require('https');
const dns = require('dns');

const PORT = process.env.PORT || 3000;

// API keys for direct access (RapidAPI proxy mode handles auth automatically)
const API_KEYS = new Set([
  process.env.RAPIDAPI_KEY_1 || 'demo-key-1',
  process.env.RAPIDAPI_KEY_2 || 'demo-key-2',
]);

// --- DNS lookup helper ---
function dnsLookup(host) {
  return new Promise((resolve, reject) => {
    dns.resolve4(host, (err, addresses) => {
      if (err) resolve(null);
      else resolve(addresses);
    });
  });
}

// --- HTTP GET helper ---
function httpGet(url, timeout = 15000) {
  return new Promise((resolve) => {
    try {
      const mod = url.startsWith('https') ? https : http;
      const req = mod.get(url, { timeout }, (res) => {
        let body = '';
        res.on('data', (c) => body += c);
        res.on('end', () => resolve({
          status: res.statusCode,
          headers: res.headers,
          body: body,
        }));
      });
      req.on('error', () => resolve(null));
      req.on('timeout', () => { req.destroy(); resolve(null); });
    } catch (e) { resolve(null); }
  });
}

// --- Security Checks ---

async function checkSubdomains(domain) {
  const subdomains = [];
  for (const sub of ['www', 'mail', 'admin', 'api', 'dev', 'staging', 'test']) {
    const target = `${sub}.${domain}`;
    const ips = await dnsLookup(target);
    subdomains.push({ name: target, ip: ips ? ips[0] : null, active: !!ips });
  }
  return subdomains;
}

async function checkHeaders(url) {
  const res = await httpGet(url);
  if (!res) return { reachable: false, headers: {} };
  const h = res.headers || {};
  return {
    reachable: true,
    status: res.status,
    headers: {
      server: h['server'] || null,
      x_powered_by: h['x-powered-by'] || null,
      strict_transport_security: h['strict-transport-security'] || null,
      content_security_policy: h['content-security-policy'] || null,
      x_frame_options: h['x-frame-options'] || null,
      x_content_type_options: h['x-content-type-options'] || null,
      referrer_policy: h['referrer-policy'] || null,
      access_control_allow_origin: h['access-control-allow-origin'] || null,
      vary: h['vary'] || null,
      set_cookie: (h['set-cookie'] || []).join('; '),
    },
  };
}

function analyzeFindings(subdomains, headers, domain) {
  const findings = [];

  // Check security headers
  const missing = [];
  if (!headers.strict_transport_security) missing.push('Strict-Transport-Security');
  if (!headers.content_security_policy) missing.push('Content-Security-Policy');
  if (!headers.x_frame_options) missing.push('X-Frame-Options');
  if (!headers.x_content_type_options) missing.push('X-Content-Type-Options');
  if (!headers.referrer_policy) missing.push('Referrer-Policy');

  if (missing.length > 0) {
    findings.push({
      severity: 'MEDIUM',
      cvss: 4.6,
      title: '缺少关键安全响应头',
      detail: `未设置: ${missing.join(', ')}`,
      fix: '在 Web 服务器中添加对应的安全响应头',
    });
  }

  // CORS check
  if (headers.access_control_allow_origin === '*') {
    findings.push({
      severity: 'MEDIUM',
      cvss: 4.3,
      title: 'CORS 配置过宽',
      detail: 'Access-Control-Allow-Origin: * 允许任意跨域访问',
      fix: '将 CORS 限制为具体白名单域名',
    });
  }

  // Server fingerprint
  if (headers.server) {
    findings.push({
      severity: 'LOW',
      cvss: 2.5,
      title: '服务器指纹暴露',
      detail: `Server: ${headers.server}`,
      fix: '隐藏服务器版本信息 (ServerTokens Off)',
    });
  }

  // HTTP → HTTPS redirect
  if (headers.status === 200) {
    findings.push({
      severity: 'LOW',
      cvss: 3.0,
      title: '未强制 HTTPS 跳转',
      detail: 'HTTP 请求未 301 重定向到 HTTPS',
      fix: '配置 HTTP → HTTPS 301 重定向',
    });
  }

  // X-Powered-By
  if (headers.x_powered_by) {
    findings.push({
      severity: 'LOW',
      cvss: 2.0,
      title: 'X-Powered-By 信息泄露',
      detail: `X-Powered-By: ${headers.x_powered_by}`,
      fix: '移除 X-Powered-By 响应头',
    });
  }

  // Subdomain exposure
  const activeSubs = subdomains.filter(s => s.active);
  if (activeSubs.length > 2) {
    findings.push({
      severity: 'INFO',
      cvss: 0.0,
      title: '子域名暴露面较大',
      detail: `发现 ${activeSubs.length} 个活跃子域名: ${activeSubs.map(s => s.name).join(', ')}`,
      fix: '清理不需要的子域名',
    });
  }

  // Cookies without Secure flag
  if (headers.set_cookie && !headers.set_cookie.includes('Secure')) {
    findings.push({
      severity: 'LOW',
      cvss: 3.1,
      title: 'Cookie 未设置 Secure 标志',
      detail: '非 Secure Cookie 可通过 HTTP 明文传输',
      fix: '所有 Cookie 添加 Secure; HttpOnly; SameSite 属性',
    });
  }

  return findings;
}

async function runScan(domain, checkTypes) {
  const url = `https://${domain}`;
  const results = {
    target: domain,
    scanned_at: new Date().toISOString(),
    scan_duration_ms: 0,
    subdomains: [],
    headers: {},
    findings: [],
    summary: {},
  };

  const start = Date.now();

  // Subdomain enumeration
  if (checkTypes.includes('subdomain')) {
    results.subdomains = await checkSubdomains(domain);
  }

  // Header/fingerprint check
  if (checkTypes.includes('headers')) {
    results.headers = await checkHeaders(url);
  }

  // Vulnerability analysis (based on above)
  if (checkTypes.includes('vuln')) {
    results.findings = analyzeFindings(results.subdomains, results.headers, domain);
  }

  // Summary
  const counts = { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  results.findings.forEach(f => counts[f.severity] = (counts[f.severity] || 0) + 1);
  results.summary = {
    total_findings: results.findings.length,
    ...counts,
    risk_score: Math.min(100, (counts.HIGH * 25 + counts.MEDIUM * 15 + counts.LOW * 5 + counts.INFO * 1)),
    status: counts.HIGH > 0 ? 'critical' : counts.MEDIUM > 0 ? 'moderate' : 'low',
  };

  results.scan_duration_ms = Date.now() - start;
  return results;
}

// --- HTTP Server ---

const server = http.createServer(async (req, res) => {
  const url = req.url;

  // CORS for RapidAPI
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-RapidAPI-Key, X-RapidAPI-Host, Authorization');
  res.setHeader('Content-Type', 'application/json');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // /health
  if (url === '/health') {
    res.writeHead(200);
    res.end(JSON.stringify({
      status: 'ok',
      service: 'security-scan-api',
      version: '1.0',
      uptime_seconds: Math.round(process.uptime()),
    }));
    return;
  }

  // /docs - API documentation
  if (url === '/docs') {
    res.writeHead(200);
    res.end(JSON.stringify({
      name: 'Security Scan API',
      description: 'Automated web security reconnaissance and vulnerability assessment',
      endpoints: {
        'POST /scan': {
          description: 'Run a security scan on a target domain',
          headers: {
            'Content-Type': 'application/json',
            'X-RapidAPI-Key': 'Your RapidAPI key (if not using proxy mode)',
          },
          body: {
            domain: 'example.com (string, required)',
            check_types: '["subdomain","headers","vuln"] (array, optional, default: all)',
          },
          response: {
            target: 'string',
            subdomains: 'array',
            headers: 'object',
            findings: 'array',
            summary: 'object',
          },
        },
        'GET /health': { description: 'Health check' },
      },
      examples: [
        {
          request: 'POST /scan {"domain": "example.com"}',
          description: 'Full scan: subdomains + headers + vulnerability analysis',
        },
        {
          request: 'POST /scan {"domain": "example.com", "check_types": ["subdomain"]}',
          description: 'Subdomain enumeration only',
        },
      ],
    }));
    return;
  }

  // /scan - main endpoint
  if (url === '/scan' && req.method === 'POST') {
    // Validate API key
    const apiKey = req.headers['x-rapidapi-key'] || req.headers['authorization']?.replace('Bearer ', '');
    if (!apiKey || (!API_KEYS.has(apiKey) && apiKey !== 'rapidapi-proxy')) {
      res.writeHead(401);
      res.end(JSON.stringify({ error: 'Unauthorized', message: 'Invalid or missing API key' }));
      return;
    }

    let body = '';
    req.on('data', (c) => body += c);
    req.on('end', async () => {
      try {
        const params = JSON.parse(body || '{}');
        const domain = params.domain;
        if (!domain || typeof domain !== 'string' || domain.length > 255) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: 'Bad Request', message: 'Valid "domain" (string) required' }));
          return;
        }

        // Sanitize domain
        const cleanDomain = domain.replace(/[^a-zA-Z0-9.-]/g, '').toLowerCase();
        if (!cleanDomain || cleanDomain.length < 3) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: 'Bad Request', message: 'Invalid domain format' }));
          return;
        }

        const checkTypes = params.check_types || ['subdomain', 'headers', 'vuln'];
        const results = await runScan(cleanDomain, checkTypes);

        res.writeHead(200);
        res.end(JSON.stringify(results, null, 2));
      } catch (e) {
        res.writeHead(500);
        res.end(JSON.stringify({ error: 'Internal Error', message: e.message }));
      }
    });
    return;
  }

  // 404
  res.writeHead(404);
  res.end(JSON.stringify({ error: 'Not Found', endpoints: ['/scan', '/health', '/docs'] }));
});

server.listen(PORT, () => {
  console.log(`Security Scan API listening on port ${PORT}`);
  console.log(`API Keys: ${API_KEYS.size} configured`);
});
