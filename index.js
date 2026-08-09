// ============================================================
// AI 马具反向代理网关（Render / Node http-proxy）
//
// 特性清单（针对 ZCode 客户端 + Browser/Computer Use + MCP + Subagents）：
//   1. 路径统一重写：自动补 /zen/go/v1 前缀（HTTP 与 WebSocket 一致），
//      .well-known / ai-plugin.json 原样放行，边界匹配防误判
//   2. 关键头透传：authorization / cookie / 全部 x-* 头，Host 锁定官方域名
//   3. selfHandleResponse 自接管响应流：
//      - 收到上游响应头立即 writeHead（消除慢启动，客户端立刻感知连接建立）
//      - 清理 hop-by-hop 头（Content-Length / Transfer-Encoding 冲突 -> 断流/双写）
//      - SSE 心跳注入：上游静默超过 HEARTBEAT_MS 即向客户端写 ": keepalive"，
//        杜绝"看起来还连着、其实已死"的悬挂订阅 -> 直接消灭 recoveryFailed 的
//        断流诱因
//      - 流式上游不设闲置超时（长推理/排队期不会被代理掐死）
//      - 上游流中断/报错 -> 立即销毁客户端连接，让客户端立刻走恢复流程，
//        而不是傻等超时后恢复失败
//      - 客户端断开（用户停止 / turn 取消）-> 立即销毁上游，止损并释放资源
//   4. WebSocket：路径重写 + TCP 心跳 + 不设闲置超时（MCP 可长时间静默）
//   5. 上游连接池（keepAlive Agent）：复用 TCP，减少握手与冷启动建连失败
//   6. CORS 全通（预检 204 + 响应头注入）
//   7. 301/302 Location 改写，锁死流量走代理链路
//   8. 全局异常兜底（502 结构化 JSON，socket 安全，进程不崩）
//   9. 健康检查 /healthz /health（Render 实例保活探测）
//   10. 请求 ID + 可选访问日志（LOG_REQUESTS=1）
//   11. 优雅停机（SIGTERM/SIGINT：在途 SSE 放行后退出）
//   12. 超时策略分离：流式 = 无闲置超时；普通请求 = IDLE_TIMEOUT_MS
// ============================================================
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const httpProxy = require('http-proxy');

// ---------- 配置 ----------
const TARGET_HOST = process.env.TARGET_HOST || 'https://opencode.ai';
const BASE_PATH = process.env.BASE_PATH || '/zen/go/v1';

const PORT = parseInt(process.env.PORT || '10000', 10);
const LOG_REQUESTS = process.env.LOG_REQUESTS === '1';
const HEARTBEAT_MS = parseInt(process.env.HEARTBEAT_MS || '15000', 10);      // SSE 静默心跳间隔
const KEEPALIVE_MS = parseInt(process.env.KEEPALIVE_MS || '15000', 10);      // TCP 心跳间隔
const IDLE_TIMEOUT_MS = parseInt(process.env.IDLE_TIMEOUT_MS || '600000', 10); // 非流式请求超时

const UPSTREAM_URL = new URL(TARGET_HOST);
const TARGET_HOSTNAME = UPSTREAM_URL.hostname;

// 上游连接池：复用 TCP，减少握手与冷启动期间的建连失败
const AgentCtor = UPSTREAM_URL.protocol === 'https:' ? https.Agent : http.Agent;
const upstreamAgent = new AgentCtor({
    keepAlive: true,
    keepAliveMsecs: 2000,
    maxSockets: 32,
    maxFreeSockets: 8,
});

const proxy = httpProxy.createProxyServer({
    target: TARGET_HOST,
    changeOrigin: true,
    secure: true,
    ws: true,
    xfwd: true,
    autoRewrite: true,
    prependPath: false,           // 路径完全由 rewritePath 手动改写
    agent: upstreamAgent,
    selfHandleResponse: true,     // 响应流由我们接管：心跳注入 / 立即写头 / 异常传播
});

// ---------- 工具函数 ----------

// hop-by-hop 头（RFC 7230 §6.1）：不得透传，由 Node 重新帧编码
const HOP_HEADERS = new Set([
    'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'te', 'trailer', 'transfer-encoding', 'upgrade', 'content-length',
]);

function cleanResponseHeaders(headers) {
    const out = {};
    for (const [k, v] of Object.entries(headers)) {
        if (!HOP_HEADERS.has(k.toLowerCase())) out[k] = v;
    }
    return out;
}

// 路径改写：HTTP 与 WS 共用
function rewritePath(rawPath) {
    const q = rawPath.indexOf('?');
    const pathname = q === -1 ? rawPath : rawPath.slice(0, q);
    const query = q === -1 ? '' : rawPath.slice(q);

    // 静态配置类文件原样放行
    if (pathname.startsWith('/.well-known/') || pathname.includes('ai-plugin.json')) {
        return rawPath;
    }
    // 已带前缀：边界匹配放行（避免 /zen/go/v10/xxx 被误判）
    if (pathname === BASE_PATH || pathname.startsWith(BASE_PATH + '/')) {
        return rawPath;
    }
    // 其余一律补前缀
    const next = (pathname === '/' || pathname === '')
        ? BASE_PATH + '/'
        : BASE_PATH + pathname;
    return next + query;
}

// 潜在流式端点：不设闲置超时，靠心跳保活
function isStreamingRequest(req) {
    const p = (req.url || '').split('?')[0];
    return /\/responses(\/|$)/.test(p) ||
        /\/chat\/completions/.test(p) ||
        /\/mcp\//.test(p) ||
        /\/realtime/.test(p);
}

// SSE 心跳流：透传数据，上游静默时注入 SSE 注释心跳，保持客户端订阅存活
function streamSse(upstream, res, rid) {
    let lastActivity = Date.now();
    const timer = setInterval(() => {
        if (res.writableEnded) { clearInterval(timer); return; }
        if (Date.now() - lastActivity >= HEARTBEAT_MS) {
            lastActivity = Date.now();
            try { res.write(': keepalive\n\n'); }
            catch { clearInterval(timer); }
        }
    }, HEARTBEAT_MS);
    if (timer.unref) timer.unref();

    upstream.on('data', () => { lastActivity = Date.now(); });
    upstream.on('end', () => { clearInterval(timer); res.end(); });
    upstream.on('error', () => { clearInterval(timer); }); // 已在 proxyRes 统一处理
    upstream.pipe(res);
}

// ---------- 请求侧 ----------
proxy.on('proxyReq', (proxyReq, req) => {
    proxyReq.path = rewritePath(req.url);
    proxyReq.setHeader('Host', TARGET_HOSTNAME);

    // 关键头显式透传（http-proxy 默认已全量透传，这里做保险）
    ['authorization', 'cookie'].forEach(h => {
        if (req.headers[h]) proxyReq.setHeader(h, req.headers[h]);
    });
    Object.keys(req.headers).forEach(k => {
        if (k.startsWith('x-') && req.headers[k]) proxyReq.setHeader(k, req.headers[k]);
    });

    // 帧格式必须原样保留：实测 opencode.ai 网关对 chunked 的 POST /responses
    // 直接返回 500 Internal Server Error（只认 Content-Length）。
    // http-proxy 默认原样透传请求头并流式转发 body，这里不要动
    // content-length / transfer-encoding，否则真实调用会全挂。

    // 请求 ID：日志关联 + 回写响应头
    const rid = req.headers['x-request-id'] || crypto.randomUUID();
    req._rid = rid;
    proxyReq.setHeader('x-request-id', rid);

    // 超时策略：流式端点不设闲置超时；普通请求 IDLE_TIMEOUT_MS
    proxyReq.setTimeout(isStreamingRequest(req) ? 0 : IDLE_TIMEOUT_MS);

    // 客户端提前断开（用户停止 / turn 取消）-> 立刻销毁上游，止损并释放资源
    req.on('aborted', () => { if (!proxyReq.destroyed) proxyReq.destroy(); });
});

// ---------- 响应侧（自接管） ----------
proxy.on('proxyRes', (proxyRes, req, res) => {
    const rid = req._rid || '-';

    // 1. 重组响应头：剔除 hop-by-hop，避免 CL/TE 双帧冲突
    const headers = cleanResponseHeaders(proxyRes.headers);

    // 2. 301/302/303：Location 锁回本网关，流量不逃逸
    const loc = headers['location'];
    if (loc && loc.startsWith(TARGET_HOST)) {
        const proto = req.headers['x-forwarded-proto'] || 'http';
        headers['location'] = loc.replace(TARGET_HOST, `${proto}://${req.headers['host']}`);
    }

    // 3. CORS
    headers['access-control-allow-origin'] = '*';
    headers['access-control-allow-methods'] = 'GET, POST, PUT, DELETE, OPTIONS, PATCH';
    const xHeaders = Object.keys(req.headers).filter(k => k.startsWith('x-'));
    headers['access-control-allow-headers'] =
        ['Content-Type', 'Authorization', 'X-Requested-With', ...xHeaders].join(', ');

    // 4. 流式识别 + 禁缓冲
    const ct = (proxyRes.headers['content-type'] || '').toLowerCase();
    const isSse = ct.includes('text/event-stream');
    const isStream = isSse || ct.includes('application/x-ndjson') || isStreamingRequest(req);
    if (isStream) {
        headers['cache-control'] = 'no-cache, no-transform, private';
        headers['x-accel-buffering'] = 'no';
    }

    headers['x-request-id'] = rid;

    // 5. 立即写头（不等第一个数据块，客户端立刻感知连接建立）
    res.writeHead(proxyRes.statusCode, headers);
    if (res.socket) res.socket.setKeepAlive(true, KEEPALIVE_MS);

    // 6. 客户端断开 -> 销毁上游（止损）
    res.on('close', () => {
        if (!proxyRes.complete) proxyRes.destroy();
    });

    // 7. 上游流中断/报错 -> 立即断开客户端，让其立刻走恢复流程，而非悬挂等超时
    proxyRes.on('error', (err) => {
        if (LOG_REQUESTS) console.error(`[proxy] ${rid} upstream stream error: ${err.message}`);
        res.destroy(err);
    });

    // 8. SSE（未压缩）走心跳注入流；其余直接透传
    const enc = String(proxyRes.headers['content-encoding'] || '').toLowerCase();
    if (isSse && !enc.includes('gzip')) {
        streamSse(proxyRes, res, rid);
    } else {
        proxyRes.pipe(res);
    }

    if (LOG_REQUESTS) {
        console.log(`[proxy] ${new Date().toISOString()} ${rid} ${req.method} ${req.url} -> ${proxyRes.statusCode} ${ct}`);
    }
});

// ---------- WebSocket ----------
proxy.on('proxyReqWs', (proxyReqWs, req, socket) => {
    // WS 升级请求同样套用路径前缀（MCP / 自动化控制常走 WS）
    proxyReqWs.path = rewritePath(req.url);
    socket.setKeepAlive(true, KEEPALIVE_MS);
});

// ---------- 全局异常拦截 ----------
proxy.on('error', (err, req, res) => {
    console.error(`[proxy error] ${req.method} ${req.url} -> ${err.code || ''} ${err.message}`);
    // 防止响应对象自身 error 事件未监听导致进程崩溃
    if (res && typeof res.on === 'function') res.on('error', () => {});
    if (res && typeof res.writeHead === 'function' && !res.headersSent) {
        try {
            res.writeHead(502, {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            });
            res.end(JSON.stringify({
                error: {
                    code: 'PROXY_AGENT_ERROR',
                    message: 'AI 代理层转发失败，上游连接或订阅正在尝试恢复。',
                    details: err.message
                }
            }));
        } catch (e) { /* 连接已被客户端关闭时忽略 */ }
    } else if (res && typeof res.destroy === 'function') {
        // 流已开始或为 WS socket：直接断开，避免悬挂
        res.destroy();
    }
});

// ---------- HTTP 服务 ----------
const server = http.createServer((req, res) => {
    // 健康检查：Render 可用 /healthz 探测，防止实例被误判失活
    if (req.url === '/healthz' || req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        return res.end('ok');
    }

    // CORS 预检（Browser Use 调用时高频触发）
    if (req.method === 'OPTIONS') {
        res.writeHead(204, {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH',
            'Access-Control-Allow-Headers': req.headers['access-control-request-headers'] || '*',
            'Access-Control-Max-Age': '86400'
        });
        return res.end();
    }

    proxy.web(req, res);
});

// 客户端侧 TCP 心跳：防止托管平台静默掐断长连接
server.on('connection', (socket) => socket.setKeepAlive(true, KEEPALIVE_MS));

server.on('upgrade', (req, socket, head) => {
    req.headers['host'] = TARGET_HOSTNAME;

    socket.setKeepAlive(true, KEEPALIVE_MS);
    socket.setTimeout(0); // WS 长连接不设闲置超时（MCP 可长时间静默），靠心跳保活

    proxy.ws(req, socket, head, (err) => {
        if (err) console.error('[WebSocket 编排/控制流异常]:', err.message);
        socket.destroy();
    });
});

// 优雅停机：Render 回收实例时尽量放行在途 SSE
function shutdown(sig) {
    console.log(`[AI 网关] ${sig} 收到，正在优雅关闭（在途流放行后退出）...`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 10000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

server.listen(PORT, () => {
    console.log(`[AI 网关] 已上线: :${PORT} -> ${TARGET_HOST}${BASE_PATH}`);
    console.log(`[AI 网关] 心跳=${HEARTBEAT_MS}ms 保活=${KEEPALIVE_MS}ms 闲置超时=${IDLE_TIMEOUT_MS}ms`);
    console.log(`[AI 网关] 适配: Plugin / Skills / MCP / Subagents 并发编排 / Browser & Computer Use`);
});
