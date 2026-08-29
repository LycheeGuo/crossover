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

# With only six verified proxies, keep the runtime strategy simple:
# shuffle the six, race two at a time, and never wait more than 4 seconds per batch member.
old_candidates = '''\t\t\tconst scholarCandidateLimit = Math.min(16, GOOGLE_SCHOLAR_PROXIES.length);
\t\t\tconst scholarFastRandom = GOOGLE_SCHOLAR_PROXIES.slice(0, Math.min(8, scholarCandidateLimit)).sort(() => Math.random() - 0.5);
\t\t\tconst scholarCandidates = scholarFastRandom.concat(GOOGLE_SCHOLAR_PROXIES.slice(8, scholarCandidateLimit));
\t\t\tconst scholarBatchSize = 4;
\t\t\tconst scholarAttemptTimeoutMs = 4500;'''

new_candidates = '''\t\t\tconst scholarCandidates = [...GOOGLE_SCHOLAR_PROXIES].sort(() => Math.random() - 0.5);
\t\t\tconst scholarBatchSize = 2;
\t\t\tconst scholarAttemptTimeoutMs = 4000;'''

if old_candidates not in text:
    raise SystemExit('Expected current Scholar racing settings were not found')
text = text.replace(old_candidates, new_candidates, 1)

path.write_text(text, encoding='utf-8')
print('Scholar pool reduced to 6 verified proxies; racing 2 at a time with 4s timeout')
