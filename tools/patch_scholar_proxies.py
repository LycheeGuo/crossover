from pathlib import Path
import re

path = Path('_worker.js')
text = path.read_text(encoding='utf-8')

# Restore the original Scholar proxy pool that was previously working in-browser.
# Keep a stable order: first proxy is primary; the rest are connection-failure fallbacks.
proxies = [
    'http://82.66.253.131:9080',
    'http://46.30.160.47:7070',
    'http://102.134.49.165:6005',
    'http://118.163.198.107:1168',
    'http://211.75.210.107:1168',
]

pool = '''// Google Scholar proxy pool.
// Original browser-verified pool; fixed order, fallback only on connection failure.
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

# Keep regional Scholar hostname support.
new_host_match = "const isScholar = /^(?:scholar\\.google\\.(?:[a-z]{2,63}|(?:com|co)\\.[a-z]{2})|scholar\\.googleusercontent\\.com)$/i.test(host) && GOOGLE_SCHOLAR_PROXIES.length > 0;"
host_pattern = re.compile(
    r"const isScholar\s*=\s*[^;]+&&\s*GOOGLE_SCHOLAR_PROXIES\.length\s*>\s*0;"
)
text, host_count = host_pattern.subn(lambda _: new_host_match, text, count=1)
if host_count != 1:
    raise SystemExit(f'Expected one isScholar matcher, found {host_count}')

# Remove randomization / concurrent racing. Keep one stable Scholar exit IP for normal browsing.
# Only move to the next proxy if the current proxy cannot establish the CONNECT tunnel.
sequential_block = '''\t\t\tconst proxiesToTry = [...GOOGLE_SCHOLAR_PROXIES];

\t\t\tfor (const proxy of proxiesToTry) {
\t\t\t\ttry {
\t\t\t\t\tlog(`[Scholar代理] 尝试连接到: ${proxy}`);
\t\t\t\t\tconst proxyAddressStr = proxy.replace(/^https?:\\/\\//i, '');
\t\t\t\t\tconst scholarProxyConfig = await 获取SOCKS5账号(proxyAddressStr);
\t\t\t\t\tconst scholarProxyIsHTTPS = /^https:\\/\\//i.test(proxy);
\t\t\t\t\tnewSocket = await httpConnect(host, portNum, 本次首包数据, scholarProxyIsHTTPS, TCP连接, scholarProxyConfig);
\t\t\t\t\tlog(`[Scholar代理] 连接成功: ${proxy}`);
\t\t\t\t\tbreak;
\t\t\t\t} catch (err) {
\t\t\t\t\tlog(`[Scholar代理] 连接失败: ${proxy}, 错误: ${err?.message || err}`);
\t\t\t\t}
\t\t\t}

\t\t\tif (!newSocket) {
\t\t\t\tthrow new Error('[Scholar代理] 所有Scholar专属代理均连接失败');
\t\t\t}

'''

race_pattern = re.compile(
    r"\t\t\t// Scholar proxies are public.*?"
    r"(?=\t\t\tif \(本次发送首包\) 已通过代理发送首包 = true;)",
    re.DOTALL,
)
text, race_count = race_pattern.subn(lambda _: sequential_block, text, count=1)

# If an earlier version is already sequential, normalize that block instead.
if race_count == 0:
    old_seq_pattern = re.compile(
        r"\t\t\t(?:const|let) proxiesToTry = .*?"
        r"\t\t\tif \(!newSocket\) \{\r?\n"
        r"\t\t\t\tthrow new Error\('\[Scholar代理\].*?'\);\r?\n"
        r"\t\t\t\}\r?\n",
        re.DOTALL,
    )
    text, seq_count = old_seq_pattern.subn(lambda _: sequential_block, text, count=1)
    if seq_count != 1:
        raise SystemExit('Scholar connection strategy block was not found')

path.write_text(text, encoding='utf-8')
print('Restored original 5 Scholar proxies in fixed fallback order; regional Scholar domains retained')
