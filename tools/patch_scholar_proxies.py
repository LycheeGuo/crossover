from pathlib import Path
import re

path = Path('_worker.js')
text = path.read_text(encoding='utf-8')

# Idempotent: once the batched racing strategy is present, do nothing.
if 'const scholarBatchSize = 4;' in text and 'scholarAttemptTimeoutMs' in text:
    print('Scholar proxy racing is already patched')
    raise SystemExit(0)

pattern = re.compile(
    r"\t\t\t// Prefer the low-latency tier.*?"
    r"\t\t\tif \(!newSocket\) \{\r?\n"
    r"\t\t\t\tthrow new Error\('\[Scholar代理\] 所有Scholar专属代理均连接失败'\);\r?\n"
    r"\t\t\t\}",
    re.DOTALL,
)

replacement = r'''\t\t\t// Scholar proxies are public and can become half-open. Race a small fast tier
\t\t\t// instead of waiting for one proxy at a time. Keep the full validated pool above,
\t\t\t// but only use the fastest candidates during interactive browser traffic.
\t\t\tconst scholarCandidateLimit = Math.min(16, GOOGLE_SCHOLAR_PROXIES.length);
\t\t\tconst scholarFastRandom = GOOGLE_SCHOLAR_PROXIES.slice(0, Math.min(8, scholarCandidateLimit)).sort(() => Math.random() - 0.5);
\t\t\tconst scholarCandidates = scholarFastRandom.concat(GOOGLE_SCHOLAR_PROXIES.slice(8, scholarCandidateLimit));
\t\t\tconst scholarBatchSize = 4;
\t\t\tconst scholarAttemptTimeoutMs = 4500;

\t\t\tconst 连接单个Scholar代理 = async (proxy, batchState) => {
\t\t\t\tconst proxyAddressStr = proxy.replace(/^https?:\\/\\//i, '');
\t\t\t\tconst scholarProxyConfig = await 获取SOCKS5账号(proxyAddressStr);
\t\t\t\tconst scholarProxyIsHTTPS = /^https:\\/\\//i.test(proxy);
\t\t\t\tlet timedOut = false;

\t\t\t\tconst connectPromise = httpConnect(host, portNum, null, scholarProxyIsHTTPS, TCP连接, scholarProxyConfig).then(socket => {
\t\t\t\t\t// A timed-out or losing connection must not stay open in the Worker.
\t\t\t\t\tif (timedOut || batchState.winner) {
\t\t\t\t\t\ttry { socket.close(); } catch (e) { }
\t\t\t\t\t\tthrow new Error('[Scholar代理] 竞速落败');
\t\t\t\t\t}
\t\t\t\t\tbatchState.winner = socket;
\t\t\t\t\treturn { socket, proxy };
\t\t\t\t});

\t\t\t\tconst timeoutPromise = new Promise((_, reject) => {
\t\t\t\t\tsetTimeout(() => {
\t\t\t\t\t\ttimedOut = true;
\t\t\t\t\t\treject(new Error(`[Scholar代理] ${proxy} 超时 ${scholarAttemptTimeoutMs}ms`));
\t\t\t\t\t}, scholarAttemptTimeoutMs);
\t\t\t\t});

\t\t\t\treturn Promise.race([connectPromise, timeoutPromise]);
\t\t\t};

\t\t\tfor (let i = 0; i < scholarCandidates.length && !newSocket; i += scholarBatchSize) {
\t\t\t\tconst batch = scholarCandidates.slice(i, i + scholarBatchSize);
\t\t\t\tconst batchState = { winner: null };
\t\t\t\tlog(`[Scholar代理] 并发尝试第 ${Math.floor(i / scholarBatchSize) + 1} 批: ${batch.join(', ')}`);
\t\t\t\ttry {
\t\t\t\t\tconst winner = await Promise.any(batch.map(proxy => 连接单个Scholar代理(proxy, batchState)));
\t\t\t\t\tnewSocket = winner.socket;
\t\t\t\t\tlog(`[Scholar代理] 竞速连接成功: ${winner.proxy}`);
\t\t\t\t} catch (err) {
\t\t\t\t\tlog(`[Scholar代理] 本批全部失败: ${err?.message || err}`);
\t\t\t\t}
\t\t\t}

\t\t\tif (!newSocket) {
\t\t\t\tthrow new Error('[Scholar代理] 快速代理池均连接失败');
\t\t\t}

\t\t\t// Send the browser's first TLS packet only through the winning proxy. This avoids
\t\t\t// duplicating the same Scholar connection across every racing candidate.
\t\t\tif (本次发送首包 && 有效数据长度(本次首包数据) > 0) {
\t\t\t\tconst scholarWriter = newSocket.writable.getWriter();
\t\t\t\ttry {
\t\t\t\t\tawait scholarWriter.write(数据转Uint8Array(本次首包数据));
\t\t\t\t} finally {
\t\t\t\t\tscholarWriter.releaseLock();
\t\t\t\t}
\t\t\t}'''

text, count = pattern.subn(replacement, text, count=1)
if count != 1:
    raise SystemExit(f'Expected exactly one Scholar sequential proxy block, found {count}')

path.write_text(text, encoding='utf-8')
print('Patched Scholar proxy racing: 4 concurrent, 4.5s hard timeout, 16 fast candidates')
