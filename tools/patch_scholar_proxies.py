from pathlib import Path
import re

PROXIES = '''
https://134.209.15.92:443
https://133.242.152.27:443
https://193.49.168.97:443
https://193.49.168.100:443
https://192.126.96.110:443
https://133.167.87.173:443
https://132.208.244.66:443
https://35.247.136.78:443
https://52.140.7.131:443
https://146.189.217.231:443
https://205.178.144.247:8443
https://31.31.78.117:443
https://148.243.232.51:443
https://193.25.2.239:443
https://138.66.66.136:443
https://198.54.223.176:443
https://162.55.97.61:443
https://161.35.159.29:443
https://4.213.225.50:443
https://84.72.72.153:443
https://51.38.179.176:443
https://152.70.202.146:443
https://80.72.39.35:443
https://150.136.9.146:443
https://35.187.237.178:443
https://212.243.240.120:443
https://81.171.24.164:443
https://45.9.61.18:443
https://79.188.239.41:8443
https://146.189.216.139:443
https://157.90.167.183:443
https://152.71.251.13:443
https://209.63.239.148:443
https://80.77.112.216:443
https://46.229.114.132:40000
https://208.169.72.50:443
https://146.189.216.138:443
https://200.23.153.161:443
https://158.195.68.53:443
https://196.21.109.82:443
https://82.196.220.217:443
https://49.50.72.246:443
https://217.160.25.90:443
https://91.227.97.113:443
https://108.60.228.210:443
https://146.48.93.16:443
https://190.113.112.147:443
https://66.70.143.16:443
https://194.195.87.167:8081
https://79.188.239.44:8443
https://201.54.216.54:443
https://104.236.195.215:443
https://79.188.239.40:8443
https://150.136.74.90:443
https://79.133.217.233:443
https://168.138.159.191:443
https://149.210.158.107:5001
https://213.96.140.33:443
https://89.234.183.82:443
https://193.77.81.97:443
https://178.237.108.214:443
https://149.210.243.125:443
https://113.23.216.128:9088
https://194.195.87.167:8080
https://192.154.227.9:3001
https://79.133.217.237:443
https://93.115.26.111:443
https://176.102.64.4:443
https://79.188.239.43:8443
https://51.91.251.117:443
https://181.191.209.142:443
https://196.21.60.44:443
https://87.238.253.66:443
https://165.22.60.108:443
https://35.212.100.37:443
https://46.10.214.92:443
https://195.14.103.106:9090
https://79.188.239.42:8443
https://85.158.220.164:443
https://130.253.2.250:443
https://195.200.166.126:443
https://168.205.255.238:443
https://185.35.199.212:5443
https://130.52.199.50:443
https://194.249.231.22:443
https://5.178.98.214:443
https://168.167.220.27:443
https://79.133.217.232:443
https://140.238.248.0:443
https://41.205.129.179:443
https://46.101.22.14:443
https://104.236.205.59:443
https://129.151.160.199:443
https://147.160.161.12:8081
https://92.242.41.77:443
https://200.133.218.122:443
https://79.133.217.236:443
https://134.0.63.185:443
https://138.108.28.48:443
https://74.103.66.15:443
https://77.81.71.62:443
https://18.169.247.230:443
https://113.23.216.129:9088
https://148.243.232.49:443
https://79.188.239.46:8443
https://45.56.228.8:443
https://79.188.239.47:8443
https://203.193.169.112:443
https://88.197.53.165:443
https://178.115.238.253:443
https://95.110.141.122:8888
https://200.249.205.36:443
https://34.93.103.38:443
https://160.242.47.197:443
https://189.39.119.69:443
https://34.93.13.41:443
https://189.50.88.34:443
'''.strip().splitlines()

path = Path('_worker.js')
text = path.read_text(encoding='utf-8')

pool_body = '\n'.join(PROXIES)
new_pool = f'''// Google Scholar HTTPS CONNECT proxy pool.
// Validated on 2026-08-29 and sorted by measured Scholar latency (fastest first).
const GOOGLE_SCHOLAR_PROXIES = `
{pool_body}
`.trim().split(/\\s+/);'''

pool_pattern = re.compile(
    r"const GOOGLE_SCHOLAR_PROXIES\s*=\s*\[(?:.|\n|\r)*?\];",
    re.MULTILINE,
)
text, pool_count = pool_pattern.subn(lambda _: new_pool, text, count=1)
if pool_count != 1:
    raise SystemExit(f'Expected exactly one GOOGLE_SCHOLAR_PROXIES block, found {pool_count}')

old_call = 'newSocket = await httpConnect(host, portNum, 本次首包数据, false, TCP连接, scholarProxyConfig);'
new_call = "const scholarProxyIsHTTPS = /^https:\\/\\//i.test(proxy);\n\t\t\t\t\tnewSocket = await httpConnect(host, portNum, 本次首包数据, scholarProxyIsHTTPS, TCP连接, scholarProxyConfig);"
if old_call not in text and 'scholarProxyIsHTTPS' not in text:
    raise SystemExit('Scholar httpConnect call was not found')
if old_call in text:
    text = text.replace(old_call, new_call, 1)

old_order = 'let proxiesToTry = [...GOOGLE_SCHOLAR_PROXIES].sort(() => Math.random() - 0.5);'
new_order = '''// Prefer the low-latency tier, but randomize inside it to avoid pinning every request to one public proxy.
\t\t\tconst scholarFastTierSize = Math.min(20, GOOGLE_SCHOLAR_PROXIES.length);
\t\t\tconst scholarFastTier = GOOGLE_SCHOLAR_PROXIES.slice(0, scholarFastTierSize).sort(() => Math.random() - 0.5);
\t\t\tconst scholarFallbackTier = GOOGLE_SCHOLAR_PROXIES.slice(scholarFastTierSize);
\t\t\tlet proxiesToTry = scholarFastTier.concat(scholarFallbackTier);'''
if old_order in text:
    text = text.replace(old_order, new_order, 1)
elif 'scholarFastTierSize' not in text:
    raise SystemExit('Scholar proxy ordering line was not found')

path.write_text(text, encoding='utf-8')
print(f'Patched {len(PROXIES)} Scholar HTTPS proxies')
