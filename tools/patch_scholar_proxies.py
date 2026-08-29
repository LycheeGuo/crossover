from pathlib import Path
import re

path = Path('_worker.js')
text = path.read_text(encoding='utf-8')

# Keep only the proxy that is confirmed to work in a real browser session.
proxies = [
    'http://46.30.160.47:7070',
]

pool = '''// Google Scholar proxy pool.
// Browser-verified primary proxy. Keep the exit IP stable during a Scholar session.
const GOOGLE_SCHOLAR_PROXIES = `
%s
`.trim().split(/\\s+/);''' % '\n'.join(proxies)

pool_pattern = re.compile(
    r"// Google Scholar (?:HTTPS CONNECT )?proxy pool\.\s*"
    r"//[^\n]*\n"
    r"const GOOGLE_SCHOLAR_PROXIES\s*=\s*`.*?`\.trim\(\)\.split\(/\\s\+/\);",
    re.DOTALL,
)
text, pool_count = pool_pattern.subn(lambda _: pool, text, count=1)
if pool_count != 1:
    raise SystemExit(f'Expected one Scholar proxy pool, found {pool_count}')

# Route the Scholar front-end regional domains through the dedicated proxy.
new_host_match = "const isScholar = /^scholar\\.google\\.(?:[a-z]{2,63}|(?:com|co)\\.[a-z]{2})$/i.test(host) && GOOGLE_SCHOLAR_PROXIES.length > 0;"
host_pattern = re.compile(
    r"const isScholar\s*=\s*[^;]+&&\s*GOOGLE_SCHOLAR_PROXIES\.length\s*>\s*0;"
)
text, host_count = host_pattern.subn(lambda _: new_host_match, text, count=1)
if host_count != 1:
    raise SystemExit(f'Expected one isScholar matcher, found {host_count}')

# Important: this proxy is known to be slow but usable. Do not impose an application-level
# CONNECT timeout. Wait for it to complete naturally and keep the exit IP stable.
sequential_block = '''\t\t\tconst proxiesToTry = [...GOOGLE_SCHOLAR_PROXIES];

\t\t\tfor (const proxy of proxiesToTry) {
\t\t\t\tconst scholarConnectStartedAt = Date.now();
\t\t\t\ttry {
\t\t\t\t\tlog(`[Scholar代理] 尝试连接到: ${proxy}`);
\t\t\t\t\tconst proxyAddressStr = proxy.replace(/^https?:\\/\\//i, '');
\t\t\t\t\tconst scholarProxyConfig = await 获取SOCKS5账号(proxyAddressStr);
\t\t\t\t\tconst scholarProxyIsHTTPS = /^https:\\/\\//i.test(proxy);
\t\t\t\t\tnewSocket = await httpConnect(
\t\t\t\t\t\thost,
\t\t\t\t\t\tportNum,
\t\t\t\t\t\t本次首包数据,
\t\t\t\t\t\tscholarProxyIsHTTPS,
\t\t\t\t\t\tTCP连接,
\t\t\t\t\t\tscholarProxyConfig
\t\t\t\t\t);
\t\t\t\t\tlog(`[Scholar代理] CONNECT成功: ${proxy}, 耗时 ${Date.now() - scholarConnectStartedAt}ms`);
\t\t\t\t\tbreak;
\t\t\t\t} catch (err) {
\t\t\t\t\tlog(`[Scholar代理] 连接失败: ${proxy}, 耗时 ${Date.now() - scholarConnectStartedAt}ms, 错误: ${err?.message || err}`);
\t\t\t\t}
\t\t\t}

\t\t\tif (!newSocket) {
\t\t\t\tthrow new Error('[Scholar代理] Scholar专属代理连接失败');
\t\t\t}

'''

# Replace any currently installed Scholar connection strategy, including the 6-second
# timeout version, the older racing version, or the older sequential version.
strategy_pattern = re.compile(
    r"\t\t\t(?:const proxiesToTry = \[\.\.\.GOOGLE_SCHOLAR_PROXIES\];|// Scholar proxies are public.*?)"
    r".*?"
    r"\t\t\tif \(!newSocket\) \{\r?\n"
    r"\t\t\t\tthrow new Error\('\[Scholar代理\].*?'\);\r?\n"
    r"\t\t\t\}\r?\n",
    re.DOTALL,
)
text, strategy_count = strategy_pattern.subn(lambda _: sequential_block, text, count=1)
if strategy_count != 1:
    raise SystemExit(f'Expected one Scholar connection strategy block, found {strategy_count}')

path.write_text(text, encoding='utf-8')
print('Scholar configured: only 46.30.160.47:7070, stable exit, no CONNECT timeout, regional Scholar domains retained')
