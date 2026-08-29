from pathlib import Path
import re

path = Path('_worker.js')
text = path.read_text(encoding='utf-8')

# Keep only the six fastest proxies that passed the second-round
# HTTPS CONNECT + Google Scholar validation on 2026-08-29.
verified = [
    'https://134.209.15.92:443',
    'https://133.242.152.27:443',
    'https://193.49.168.97:443',
    'https://193.49.168.100:443',
    'https://192.126.96.110:443',
    'https://133.167.87.173:443',
]

pool = '''// Google Scholar HTTPS CONNECT proxy pool.
// Six fastest proxies verified on 2026-08-29.
const GOOGLE_SCHOLAR_PROXIES = `
%s
`.trim().split(/\\s+/);''' % '\n'.join(verified)

pool_pattern = re.compile(
    r"// Google Scholar HTTPS CONNECT proxy pool\.\s*"
    r"//[^\n]*\n"
    r"const GOOGLE_SCHOLAR_PROXIES\s*=\s*`.*?`\.trim\(\)\.split\(/\\s\+/\);",
    re.DOTALL,
)
text, pool_count = pool_pattern.subn(pool, text, count=1)
if pool_count != 1:
    raise SystemExit(f'Expected one Scholar proxy pool, found {pool_count}')

# Match Google Scholar regional hostnames without routing all Google traffic.
# Examples: scholar.google.com, scholar.google.de, scholar.google.co.jp,
# scholar.google.com.hk, scholar.google.co.uk, plus Scholar cached-content host.
new_host_match = "const isScholar = /^(?:scholar\\.google\\.(?:[a-z]{2,63}|(?:com|co)\\.[a-z]{2})|scholar\\.googleusercontent\\.com)$/i.test(host) && GOOGLE_SCHOLAR_PROXIES.length > 0;"
host_pattern = re.compile(
    r"const isScholar\s*=\s*[^;]+&&\s*GOOGLE_SCHOLAR_PROXIES\.length\s*>\s*0;"
)
text, host_count = host_pattern.subn(new_host_match, text, count=1)
if host_count != 1:
    raise SystemExit(f'Expected one isScholar matcher, found {host_count}')

# Normalize the runtime strategy to six proxies, racing two at a time.
strategy_pattern = re.compile(
    r"\t\t\tconst scholarCandidateLimit = Math\.min\(16, GOOGLE_SCHOLAR_PROXIES\.length\);\r?\n"
    r"\t\t\tconst scholarFastRandom = .*?;\r?\n"
    r"\t\t\tconst scholarCandidates = .*?;\r?\n"
    r"\t\t\tconst scholarBatchSize = 4;\r?\n"
    r"\t\t\tconst scholarAttemptTimeoutMs = 4500;",
    re.DOTALL,
)
new_strategy = '''\t\t\tconst scholarCandidates = [...GOOGLE_SCHOLAR_PROXIES].sort(() => Math.random() - 0.5);
\t\t\tconst scholarBatchSize = 2;
\t\t\tconst scholarAttemptTimeoutMs = 4000;'''
text, strategy_count = strategy_pattern.subn(new_strategy, text, count=1)

# If the strategy was already reduced by an earlier run, keep it as-is.
if strategy_count == 0:
    already_reduced = (
        'const scholarCandidates = [...GOOGLE_SCHOLAR_PROXIES].sort(() => Math.random() - 0.5);' in text
        and 'const scholarBatchSize = 2;' in text
        and 'const scholarAttemptTimeoutMs = 4000;' in text
    )
    if not already_reduced:
        raise SystemExit('Scholar racing strategy was not found')

path.write_text(text, encoding='utf-8')
print('Scholar patch applied: 6 proxies, 2-way racing, regional scholar.google.* host matching')
