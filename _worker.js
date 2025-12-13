import { connect } from "cloudflare:sockets";

// ==============================================================================
// [配置区域]
// ==============================================================================

// 1. 静态资源页面
const Pages静态页面 = 'https://edt-pages.github.io';

// 2. 默认 SOCKS5 白名单
const SOCKS5_WHITELIST_DEFAULT = ['*tapecontent.net', '*cloudatacdn.com', '*loadshare.org', '*cdn-centaurus.com', 'scholar.google.com'];

// 3. 内置学术代理列表 (HTTP) - 你的专用代理池
const CONST_ACADEMIC_PROXIES = [
    'http://208.180.238.40:3390',
    'http://59.127.212.110:4431',
    'http://82.66.253.131:9080',
    'http://46.30.160.47:7070'
];

// 模块级变量
let config_JSON;

// ==============================================================================
// [主程序入口]
// ==============================================================================
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const UA = request.headers.get('User-Agent') || 'null';
        const upgradeHeader = request.headers.get('Upgrade');
        
        // 获取环境变量/密码
        const 管理员密码 = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY;
        const 加密秘钥 = env.KEY || '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';
        
        // 生成 UUID 相关
        const userIDMD5 = await MD5MD5(管理员密码 + 加密秘钥);
        const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
        const envUUID = env.UUID || env.uuid;
        const userID = (envUUID && uuidRegex.test(envUUID)) ? envUUID.toLowerCase() : [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), userIDMD5.slice(16, 20), userIDMD5.slice(20)].join('-');
        
        const host = env.HOST ? env.HOST.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0] : url.hostname;
        
        // 提取 AIP 变量 (备用学术代理，从环境变量获取)
        const AIP_Proxy_List = env.AIP || env.ACADEMIC_PROXY || ''; 

        // 处理普通反代IP
        let 当前反代IP = '';
        if (env.PROXYIP) {
            const proxyIPs = await 整理成数组(env.PROXYIP);
            当前反代IP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
        } else {
            当前反代IP = (request.cf.colo + '.PrOxYIp.CmLiUsSsS.nEt').toLowerCase();
        }
        
        const 访问IP = request.headers.get('X-Real-IP') || request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || request.headers.get('True-Client-IP') || request.headers.get('Fly-Client-IP') || request.headers.get('X-Appengine-Remote-Addr') || request.headers.get('X-Forwarded-For') || request.headers.get('X-Real-IP') || request.headers.get('X-Cluster-Client-IP') || request.cf?.clientTcpRtt || '未知IP';
        
        // ---------------------------------------------------------------
        // Websocket 请求处理 (核心流量转发)
        // ---------------------------------------------------------------
        if (upgradeHeader === 'websocket') {
            return await 处理WS请求(request, userID, 当前反代IP, AIP_Proxy_List);
        }

        // ---------------------------------------------------------------
        // 普通 HTTP 请求处理 (订阅/管理面板)
        // ---------------------------------------------------------------
        if (url.protocol === 'http:') return Response.redirect(url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`), 301);
        if (!管理员密码) return fetch(Pages静态页面 + '/noADMIN').then(r => { const headers = new Headers(r.headers); headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); headers.set('Pragma', 'no-cache'); headers.set('Expires', '0'); return new Response(r.body, { status: 404, statusText: r.statusText, headers }); });
        if (!env.KV) return fetch(Pages静态页面 + '/noKV').then(r => { const headers = new Headers(r.headers); headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); headers.set('Pragma', 'no-cache'); headers.set('Expires', '0'); return new Response(r.body, { status: 404, statusText: r.statusText, headers }); });
        
        const 访问路径 = url.pathname.slice(1).toLowerCase();

        // 快速订阅入口
        if (访问路径 === 加密秘钥 && 加密秘钥 !== '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改') {
            const params = new URLSearchParams(url.search);
            params.set('token', await MD5MD5(host + userID));
            return new Response('重定向中...', { status: 302, headers: { 'Location': `/sub?${params.toString()}` } });
        } 
        
        // 登录页面
        else if (访问路径 === 'login') {
            const cookies = request.headers.get('Cookie') || '';
            const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
            if (authCookie == await MD5MD5(UA + 加密秘钥 + 管理员密码)) return new Response('重定向中...', { status: 302, headers: { 'Location': '/admin' } });
            if (request.method === 'POST') {
                const formData = await request.text();
                const params = new URLSearchParams(formData);
                const 输入密码 = params.get('password');
                if (输入密码 === 管理员密码) {
                    const 响应 = new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    响应.headers.set('Set-Cookie', `auth=${await MD5MD5(UA + 加密秘钥 + 管理员密码)}; Path=/; Max-Age=86400; HttpOnly`);
                    return 响应;
                }
            }
            return fetch(Pages静态页面 + '/login');
        } 
        
        // 管理页面相关
        else if (访问路径 == 'admin' || 访问路径.startsWith('admin/')) {
            const cookies = request.headers.get('Cookie') || '';
            const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
            if (!authCookie || authCookie !== await MD5MD5(UA + 加密秘钥 + 管理员密码)) return new Response('重定向中...', { status: 302, headers: { 'Location': '/login' } });
            
            // 加载配置
            config_JSON = await 读取config_JSON(env, host, userID);
            
            if (访问路径 === 'admin/config.json') {
                 if (request.method === 'POST') {
                     try {
                         const newConfig = await request.json();
                         await env.KV.put('config.json', JSON.stringify(newConfig, null, 2));
                         return new Response(JSON.stringify({ success: true, message: '配置已保存' }), { status: 200 });
                     } catch (e) { return new Response(JSON.stringify({ error: e.message }), { status: 500 }); }
                 }
                 return new Response(JSON.stringify(config_JSON, null, 2), { status: 200 });
            }
            
            if (访问路径 === 'admin/log.json') return new Response(await env.KV.get('log.json') || '[]', { status: 200 });
            
            ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Admin_Login', config_JSON));
            return fetch(Pages静态页面 + '/admin');
        } 
        
        // 登出
        else if (访问路径 === 'logout') {
            const 响应 = new Response('重定向中...', { status: 302, headers: { 'Location': '/login' } });
            响应.headers.set('Set-Cookie', 'auth=; Path=/; Max-Age=0; HttpOnly');
            return 响应;
        } 
        
        // ==============================================================================
        // [订阅处理逻辑]
        // ==============================================================================
        else if (访问路径 === 'sub') {
            const 订阅TOKEN = await MD5MD5(host + userID);
            if (url.searchParams.get('token') === 订阅TOKEN) {
                config_JSON = await 读取config_JSON(env, host, userID);
                ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Get_SUB', config_JSON));
                
                const 节点路径 = config_JSON.启用0RTT ? config_JSON.PATH + '?ed=2560' : config_JSON.PATH;
                
                // [定制] 使用固定规则生成 25 个节点
                const 完整优选列表 = (await 生成定制规则IP(25, -1))[0];
                
                // 构建 VLESS 链接
                let 订阅内容 = 完整优选列表.map(address => {
                     const match = address.match(/^(.*):(\d+)(?:#(.*))?$/) || [null, address, 443, ''];
                     const [_, ip, port, remark] = match;
                     const 节点HOST = 随机替换通配符(host);
                     return `vless://${config_JSON.UUID}@${ip}:${port}?security=tls&type=ws&host=${节点HOST}&sni=${节点HOST}&path=${encodeURIComponent(节点路径)}&encryption=none#${encodeURIComponent(remark)}`;
                }).join('\n');
                
                // [定制] 订阅转换 - 使用您的自建后端
                const ua = UA.toLowerCase();
                if (url.searchParams.has('target') || ua.includes('clash') || ua.includes('meta') || ua.includes('shadowrocket') || ua.includes('surge')) {
                     const target = url.searchParams.get('target') || 'clash';
                     // 您的自建后端地址
                     const 订阅转换URL = `${config_JSON.订阅转换配置.SUBAPI}/sub?target=${target}&url=${encodeURIComponent(url.protocol + '//' + url.host + '/sub?token=' + 订阅TOKEN + '&sub')}&config=${encodeURIComponent(config_JSON.订阅转换配置.SUBCONFIG)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false`;
                     
                     try {
                        const response = await fetch(订阅转换URL, { headers: { 'User-Agent': 'Subconverter' } });
                        if (response.ok) {
                            return new Response(await response.text(), { 
                                status: 200, 
                                headers: { 
                                    "content-type": target.includes('clash') ? "application/x-yaml; charset=utf-8" : "text/plain; charset=utf-8",
                                    "Profile-Update-Interval": "6"
                                } 
                            });
                        }
                     } catch(e) {
                         // console.error('订阅转换失败:', e);
                     }
                }

                return new Response(btoa(订阅内容), { status: 200, headers: { "content-type": "text/plain; charset=utf-8" } });
            }
            return new Response('无效的订阅TOKEN', { status: 403 });
        }

        // 伪装页
        let 伪装页URL = env.URL || 'nginx';
        if (伪装页URL === '1101') return new Response(await html1101(url.host, 访问IP), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
        return new Response(await nginx(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
    }
};

// ==============================================================================
// [WS 传输数据处理核心]
// ==============================================================================
async function 处理WS请求(request, yourUUID, defaultProxyIP, academicProxyStr) {
    const wssPair = new WebSocketPair();
    const [clientSock, serverSock] = Object.values(wssPair);
    serverSock.accept();
    let remoteConnWrapper = { socket: null };
    let isDnsQuery = false;
    const earlyData = request.headers.get('sec-websocket-protocol') || '';
    const readable = makeReadableStr(serverSock, earlyData);
    let 判断是否是木马 = null;

    // 解析备用 AIP 列表 (从环境变量)
    const AIP_List = academicProxyStr ? await 整理成数组(academicProxyStr) : [];

    readable.pipeTo(new WritableStream({
        async write(chunk) {
            if (isDnsQuery) return await forwardataudp(chunk, serverSock, null);
            if (remoteConnWrapper.socket) {
                const writer = remoteConnWrapper.socket.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }
            if (判断是否是木马 === null) {
                const bytes = new Uint8Array(chunk);
                判断是否是木马 = bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a;
            }
            if (remoteConnWrapper.socket) {
                const writer = remoteConnWrapper.socket.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            let parsedInfo;
            if (判断是否是木马) parsedInfo = 解析木马请求(chunk, yourUUID);
            else parsedInfo = 解析魏烈思请求(chunk, yourUUID);

            const { hasError, message, port, hostname, rawIndex, version, isUDP, rawClientData } = parsedInfo;
            if (hasError) return; // 忽略错误
            if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');

            // -----------------------------------------------------------
            // [核心分流逻辑] - 拦截 Scholar
            // -----------------------------------------------------------
            if (hostname.includes('scholar.google.com')) {
                const dataToProxy = 判断是否是木马 ? rawClientData : chunk.slice(rawIndex);
                const headerToClient = 判断是否是木马 ? null : new Uint8Array([version[0], 0]);
                
                // 1. 优先尝试内置的硬编码代理池
                try {
                    const randomProxy = CONST_ACADEMIC_PROXIES[Math.floor(Math.random() * CONST_ACADEMIC_PROXIES.length)];
                    await connectToScholarProxy(hostname, port, dataToProxy, serverSock, headerToClient, remoteConnWrapper, randomProxy);
                    return; // 连接成功，退出后续逻辑
                } catch (e) {
                    console.error(`[Scholar] 内置代理连接失败 (${e.message})，尝试切换到 AIP 备用池...`);
                }

                // 2. 内置失败则尝试 AIP 列表 (ENV变量)
                if (AIP_List.length > 0) {
                    try {
                        const randomAIP = AIP_List[Math.floor(Math.random() * AIP_List.length)];
                        await connectToScholarProxy(hostname, port, dataToProxy, serverSock, headerToClient, remoteConnWrapper, randomAIP);
                        return;
                    } catch (e) {
                        console.error(`[Scholar] AIP 备用代理也连接失败: ${e.message}`);
                    }
                }
                // 3. 如果都失败了，继续走下面的普通流量转发(可能直连或走普通优选)，作为最后的尝试
            }
            // -----------------------------------------------------------

            if (!判断是否是木马 && isUDP) {
                if (port === 53) isDnsQuery = true;
                else throw new Error('UDP is not supported');
            }

            const rawPayload = 判断是否是木马 ? rawClientData : chunk.slice(rawIndex);
            const respHeader = 判断是否是木马 ? null : new Uint8Array([version[0], 0]);

            if (isDnsQuery) return forwardataudp(rawPayload, serverSock, respHeader);
            
            // 普通流量转发 (包含普通优选IP逻辑 + 兜底)
            await forwardataTCP(hostname, port, rawPayload, serverSock, respHeader, remoteConnWrapper, defaultProxyIP);
        },
    })).catch((err) => {});

    return new Response(null, { status: 101, webSocket: clientSock });
}

// -----------------------------------------------------------------------------
// [增强版 Scholar 代理连接]
// -----------------------------------------------------------------------------
async function connectToScholarProxy(targetHost, targetPort, initialData, ws, respHeader, remoteConnWrapper, proxyAddressString) {
    let proxyProtocol = 'http';
    let addressStr = proxyAddressString;

    if (addressStr.startsWith('socks5://')) {
        proxyProtocol = 'socks5';
        addressStr = addressStr.slice(9);
    } else if (addressStr.startsWith('http://')) {
        addressStr = addressStr.slice(7);
    } else if (addressStr.startsWith('https://')) {
        addressStr = addressStr.slice(8);
    }

    const proxyConfig = await 获取SOCKS5账号(addressStr); 
    
    let newSocket;
    if (proxyProtocol === 'socks5') {
        newSocket = await socks5Connect(targetHost, targetPort, initialData, proxyConfig);
    } else {
        newSocket = await httpConnect(targetHost, targetPort, initialData, proxyConfig);
    }

    remoteConnWrapper.socket = newSocket;
    newSocket.closed.catch(() => {}).finally(() => closeSocketQuietly(ws));
    connectStreams(newSocket, ws, respHeader, null);
}

// -----------------------------------------------------------------------------
// [普通流量转发 (包含兜底逻辑)]
// -----------------------------------------------------------------------------
async function forwardataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper, defaultProxyIP) {
    async function connectDirect(address, port, data) {
        const remoteSock = connect({ hostname: address, port: port });
        const writer = remoteSock.writable.getWriter();
        await writer.write(data);
        writer.releaseLock();
        return remoteSock;
    }

    // 1. 尝试使用默认优选 IP
    try {
        let address = host;
        if (defaultProxyIP) {
             try {
                const [ip, p] = await 解析地址端口(defaultProxyIP);
                address = ip;
             } catch(e) {}
        }
        const socket = await connectDirect(address, portNum, rawData);
        remoteConnWrapper.socket = socket;
        connectStreams(socket, ws, respHeader, null);
        return;
    } catch (err) {
        // 优选失败，准备兜底
    }

    // 2. 失败兜底逻辑 (连接备份域名)
    try {
        const fallbackIP = atob('UFJPWFlJUC50cDEuMDkwMjI3Lnh5eg=='); // PROXYIP.tp1.090227.xyz
        const [fbIP, fbPort] = await 解析地址端口(fallbackIP);
        const socket = await connectDirect(fbIP, portNum, rawData);
        remoteConnWrapper.socket = socket;
        connectStreams(socket, ws, respHeader, null);
    } catch (err) {
        ws.close();
    }
}

// -----------------------------------------------------------------------------
// [基础连接函数]
// -----------------------------------------------------------------------------
async function socks5Connect(targetHost, targetPort, initialData, proxyConfig) {
    const { username, password, hostname, port } = proxyConfig;
    const socket = connect({ hostname, port });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    try {
        const authMethods = username && password ? new Uint8Array([0x05, 0x02, 0x00, 0x02]) : new Uint8Array([0x05, 0x01, 0x00]);
        await writer.write(authMethods);
        let response = await reader.read();
        if (response.done || response.value.byteLength < 2) throw new Error('S5 method selection failed');
        const selectedMethod = new Uint8Array(response.value)[1];
        if (selectedMethod === 0x02) {
            const userBytes = new TextEncoder().encode(username);
            const passBytes = new TextEncoder().encode(password);
            const authPacket = new Uint8Array([0x01, userBytes.length, ...userBytes, passBytes.length, ...passBytes]);
            await writer.write(authPacket);
            response = await reader.read();
            if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 authentication failed');
        }
        const hostBytes = new TextEncoder().encode(targetHost);
        const connectPacket = new Uint8Array([0x05, 0x01, 0x00, 0x03, hostBytes.length, ...hostBytes, targetPort >> 8, targetPort & 0xff]);
        await writer.write(connectPacket);
        response = await reader.read();
        if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 connection failed');
        await writer.write(initialData);
        writer.releaseLock(); reader.releaseLock();
        return socket;
    } catch (error) {
        try { writer.releaseLock(); } catch (e) { }
        try { reader.releaseLock(); } catch (e) { }
        try { socket.close(); } catch (e) { }
        throw error;
    }
}

async function httpConnect(targetHost, targetPort, initialData, proxyConfig) {
    const { username, password, hostname, port } = proxyConfig;
    const socket = connect({ hostname, port });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    try {
        const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
        const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
        await writer.write(new TextEncoder().encode(request));
        let responseBuffer = new Uint8Array(0);
        let headerEndIndex = -1;
        while (headerEndIndex === -1) {
            const { done, value } = await reader.read();
            if (done) throw new Error('Closed before HTTP response');
            const newBuffer = new Uint8Array(responseBuffer.length + value.length);
            newBuffer.set(responseBuffer);
            newBuffer.set(value, responseBuffer.length);
            responseBuffer = newBuffer;
            const len = responseBuffer.length;
            if (len >= 4) {
                for (let i = 0; i < len - 3; i++) {
                    if (responseBuffer[i] === 13 && responseBuffer[i+1] === 10 && responseBuffer[i+2] === 13 && responseBuffer[i+3] === 10) {
                        headerEndIndex = i + 4;
                        break;
                    }
                }
            }
            if (responseBuffer.length > 8192) throw new Error('HTTP Header too large');
        }
        
        // 简单校验响应码
        const headerStr = new TextDecoder().decode(responseBuffer.slice(0, headerEndIndex));
        if (!headerStr.includes(' 200 ')) throw new Error('HTTP Proxy Connect Failed: ' + headerStr.split('\r\n')[0]);

        await writer.write(initialData);
        writer.releaseLock(); reader.releaseLock();
        return socket;
    } catch (error) {
        try { writer.releaseLock(); } catch (e) { }
        try { reader.releaseLock(); } catch (e) { }
        try { socket.close(); } catch (e) { }
        throw error;
    }
}

// ---------------------- 辅助函数 ----------------------
async function 获取SOCKS5账号(address) {
    if (address.includes('@')) {
        const lastAtIndex = address.lastIndexOf('@');
        let userPassword = address.substring(0, lastAtIndex).replaceAll('%3D', '=');
        if (/^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i.test(userPassword) && !userPassword.includes(':')) {
             try { userPassword = atob(userPassword); } catch(e){}
        }
        address = `${userPassword}@${address.substring(lastAtIndex + 1)}`;
    }
    const atIndex = address.lastIndexOf("@");
    const [hostPart, authPart] = atIndex === -1 ? [address, undefined] : [address.substring(atIndex + 1), address.substring(0, atIndex)];
    let username, password;
    if (authPart) { [username, password] = authPart.split(":"); }
    let hostname, port;
    if (hostPart.includes("]:")) { [hostname, port] = [hostPart.split("]:")[0] + "]", Number(hostPart.split("]:")[1].replace(/[^\d]/g, ''))]; }
    else if (hostPart.startsWith("[")) { [hostname, port] = [hostPart, 80]; }
    else { const parts = hostPart.split(":"); [hostname, port] = parts.length === 2 ? [parts[0], Number(parts[1].replace(/[^\d]/g, ''))] : [hostPart, 80]; }
    return { username, password, hostname, port };
}

async function 解析地址端口(proxyIP) {
    let 地址 = proxyIP, 端口 = 443;
    if (proxyIP.includes(']:')) { const parts = proxyIP.split(']:'); 地址 = parts[0] + ']'; 端口 = parseInt(parts[1], 10) || 端口; }
    else if (proxyIP.includes(':') && !proxyIP.startsWith('[')) { const colonIndex = proxyIP.lastIndexOf(':'); 地址 = proxyIP.slice(0, colonIndex); 端口 = parseInt(proxyIP.slice(colonIndex + 1), 10) || 端口; }
    return [地址, 端口];
}

function 解析木马请求(buffer, passwordPlainText) {
    const sha224Password = sha224(passwordPlainText);
    if (buffer.byteLength < 56) return { hasError: true, message: "invalid data" };
    let crLfIndex = 56;
    if (new Uint8Array(buffer.slice(56, 57))[0] !== 0x0d || new Uint8Array(buffer.slice(57, 58))[0] !== 0x0a) return { hasError: true, message: "invalid header format" };
    const password = new TextDecoder().decode(buffer.slice(0, crLfIndex));
    if (password !== sha224Password) return { hasError: true, message: "invalid password" };
    const socks5DataBuffer = buffer.slice(crLfIndex + 2);
    if (socks5DataBuffer.byteLength < 6) return { hasError: true, message: "invalid S5 request data" };
    const view = new DataView(socks5DataBuffer);
    const cmd = view.getUint8(0);
    if (cmd !== 1) return { hasError: true, message: "unsupported command, only TCP is allowed" };
    const atype = view.getUint8(1);
    let addressLength = 0; let addressIndex = 2; let address = "";
    switch (atype) {
        case 1: addressLength = 4; address = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)).join("."); break;
        case 3: addressLength = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + 1))[0]; addressIndex += 1; address = new TextDecoder().decode(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)); break;
        case 4: addressLength = 16; const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)); const ipv6 = []; for (let i = 0; i < 8; i++) { ipv6.push(dataView.getUint16(i * 2).toString(16)); } address = ipv6.join(":"); break;
        default: return { hasError: true, message: `invalid addressType is ${atype}` };
    }
    if (!address) return { hasError: true, message: `address is empty, addressType is ${atype}` };
    const portIndex = addressIndex + addressLength;
    const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    return { hasError: false, addressType: atype, port: portRemote, hostname: address, rawClientData: socks5DataBuffer.slice(portIndex + 4) };
}

function 解析魏烈思请求(chunk, token) {
    if (chunk.byteLength < 24) return { hasError: true, message: 'Invalid data' };
    const version = new Uint8Array(chunk.slice(0, 1));
    if (formatIdentifier(new Uint8Array(chunk.slice(1, 17))) !== token) return { hasError: true, message: 'Invalid uuid' };
    const optLen = new Uint8Array(chunk.slice(17, 18))[0];
    const cmd = new Uint8Array(chunk.slice(18 + optLen, 19 + optLen))[0];
    let isUDP = false;
    if (cmd === 1) { } else if (cmd === 2) { isUDP = true; } else { return { hasError: true, message: 'Invalid command' }; }
    const portIdx = 19 + optLen;
    const port = new DataView(chunk.slice(portIdx, portIdx + 2)).getUint16(0);
    let addrIdx = portIdx + 2, addrLen = 0, addrValIdx = addrIdx + 1, hostname = '';
    const addressType = new Uint8Array(chunk.slice(addrIdx, addrValIdx))[0];
    switch (addressType) {
        case 1: addrLen = 4; hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + addrLen)).join('.'); break;
        case 2: addrLen = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + 1))[0]; addrValIdx += 1; hostname = new TextDecoder().decode(chunk.slice(addrValIdx, addrValIdx + addrLen)); break;
        case 3: addrLen = 16; const ipv6 = []; const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx + addrLen)); for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16)); hostname = ipv6.join(':'); break;
        default: return { hasError: true, message: `Invalid address type: ${addressType}` };
    }
    if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
    return { hasError: false, addressType, port, hostname, isUDP, rawIndex: addrValIdx + addrLen, version };
}

async function forwardataudp(udpChunk, webSocket, respHeader) {
    try {
        const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
        let vlessHeader = respHeader;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(udpChunk);
        writer.releaseLock();
        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (webSocket.readyState === WebSocket.OPEN) {
                    if (vlessHeader) {
                        const response = new Uint8Array(vlessHeader.length + chunk.byteLength);
                        response.set(vlessHeader, 0);
                        response.set(chunk, vlessHeader.length);
                        webSocket.send(response.buffer);
                        vlessHeader = null;
                    } else { webSocket.send(chunk); }
                }
            },
        }));
    } catch (error) {}
}

function closeSocketQuietly(socket) { try { if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) { socket.close(); } } catch (error) { } }
function formatIdentifier(arr, offset = 0) { const hex = [...arr.slice(offset, offset + 16)].map(b => b.toString(16).padStart(2, '0')).join(''); return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`; }
async function connectStreams(remoteSocket, webSocket, headerData, retryFunc) { let header = headerData, hasData = false; await remoteSocket.readable.pipeTo(new WritableStream({ async write(chunk, controller) { hasData = true; if (webSocket.readyState !== WebSocket.OPEN) controller.error('ws.readyState is not open'); if (header) { const response = new Uint8Array(header.length + chunk.byteLength); response.set(header, 0); response.set(chunk, header.length); webSocket.send(response.buffer); header = null; } else { webSocket.send(chunk); } }, abort() { }, })).catch((err) => { closeSocketQuietly(webSocket); }); if (!hasData && retryFunc) { await retryFunc(); } }
function makeReadableStr(socket, earlyDataHeader) { let cancelled = false; return new ReadableStream({ start(controller) { socket.addEventListener('message', (event) => { if (!cancelled) controller.enqueue(event.data); }); socket.addEventListener('close', () => { if (!cancelled) { closeSocketQuietly(socket); controller.close(); } }); socket.addEventListener('error', (err) => controller.error(err)); const { earlyData, error } = base64ToArray(earlyDataHeader); if (error) controller.error(error); else if (earlyData) controller.enqueue(earlyData); }, cancel() { cancelled = true; closeSocketQuietly(socket); } }); }
function isSpeedTestSite(hostname) { const speedTestDomains = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')]; if (speedTestDomains.includes(hostname)) return true; for (const domain of speedTestDomains) { if (hostname.endsWith('.' + domain) || hostname === domain) return true; } return false; }
function base64ToArray(b64Str) { if (!b64Str) return { error: null }; try { const binaryString = atob(b64Str.replace(/-/g, '+').replace(/_/g, '/')); const bytes = new Uint8Array(binaryString.length); for (let i = 0; i < binaryString.length; i++) { bytes[i] = binaryString.charCodeAt(i); } return { earlyData: bytes.buffer, error: null }; } catch (error) { return { error }; } }
async function MD5MD5(文本) { const 编码器 = new TextEncoder(); const 第一次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(文本)); const 第一次哈希数组 = Array.from(new Uint8Array(第一次哈希)); const 第一次十六进制 = 第一次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join(''); const 第二次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(第一次十六进制.slice(7, 27))); const 第二次哈希数组 = Array.from(new Uint8Array(第二次哈希)); return 第二次十六进制 = 第二次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('').toLowerCase(); }
function 随机替换通配符(h) { if (!h?.includes('*')) return h; const 字符集 = 'abcdefghijklmnopqrstuvwxyz0123456789'; return h.replace(/\*/g, () => { let s = ''; for (let i = 0; i < Math.floor(Math.random() * 14) + 3; i++) s += 字符集[Math.floor(Math.random() * 36)]; return s; }); }
function 批量替换域名(内容, host, 每组数量 = 2) { let count = 0, currentRandomHost = null; return 内容.replace(/example\.com/g, () => { if (count % 每组数量 === 0) currentRandomHost = 随机替换通配符(host); count++; return currentRandomHost; }); }

async function 读取config_JSON(env, hostname, userID, path, 重置配置 = false) {
    const host = 随机替换通配符(hostname);
    const 初始化开始时间 = performance.now();
    // [定制] 默认配置修改
    const 默认配置JSON = {
        TIME: new Date().toISOString(), HOST: host, UUID: userID, 协议类型: "vless", 传输协议: "ws", 跳过证书验证: true, 启用0RTT: false, TLS分片: null, 随机路径: false,
        优选订阅生成: { local: true, 本地IP库: { 随机IP: true, 随机数量: 16, 指定端口: -1 }, SUB: null, SUBNAME: "edge" + "tunnel", SUBUpdateTime: 6, TOKEN: await MD5MD5(hostname + userID) },
        订阅转换配置: { SUBAPI: "https://subapi.deer.ip-ddns.com", SUBCONFIG: "https://raw.githubusercontent.com/cmliu/ACL4SSR/refs/heads/main/Clash/config/ACL4SSR_Online_Mini_MultiMode_CF.ini", SUBEMOJI: false },
        反代: { PROXYIP: "auto", SOCKS5: { 启用: null, 全局: false, 账号: '', 白名单: [] } }, TG: { 启用: false, BotToken: null, ChatID: null }, CF: { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, Usage: { success: false, pages: 0, workers: 0, total: 0 } }
    };
    try { let configJSON = await env.KV.get('config.json'); if (!configJSON || 重置配置 == true) { await env.KV.put('config.json', JSON.stringify(默认配置JSON, null, 2)); config_JSON = 默认配置JSON; } else { config_JSON = JSON.parse(configJSON); } } catch (error) { config_JSON = 默认配置JSON; }
    config_JSON.HOST = host; config_JSON.UUID = userID; config_JSON.PATH = path ? (path.startsWith('/') ? path : '/' + path) : '/';
    const TLS分片参数 = config_JSON.TLS分片 == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.TLS分片 == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
    config_JSON.LINK = `${config_JSON.协议类型}://${userID}@${host}:443?security=tls&type=${config_JSON.传输协议}&host=${host}&sni=${host}&path=${encodeURIComponent(config_JSON.启用0RTT ? config_JSON.PATH + '?ed=2560' : config_JSON.PATH) + TLS分片参数}&encryption=none${config_JSON.跳过证书验证 ? '&allowInsecure=1' : ''}#${encodeURIComponent(config_JSON.优选订阅生成.SUBNAME)}`;
    config_JSON.优选订阅生成.TOKEN = await MD5MD5(hostname + userID);
    const 初始化TG_JSON = { BotToken: null, ChatID: null }; config_JSON.TG = { 启用: config_JSON.TG.启用 ? config_JSON.TG.启用 : false, ...初始化TG_JSON }; try { const TG_TXT = await env.KV.get('tg.json'); if (!TG_TXT) { await env.KV.put('tg.json', JSON.stringify(初始化TG_JSON, null, 2)); } else { const TG_JSON = JSON.parse(TG_TXT); config_JSON.TG.ChatID = TG_JSON.ChatID ? TG_JSON.ChatID : null; config_JSON.TG.BotToken = TG_JSON.BotToken ? 掩码敏感信息(TG_JSON.BotToken) : null; } } catch (error) {}
    const 初始化CF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null }; config_JSON.CF = { ...初始化CF_JSON, Usage: { success: false, pages: 0, workers: 0, total: 0 } }; try { const CF_TXT = await env.KV.get('cf.json'); if (!CF_TXT) { await env.KV.put('cf.json', JSON.stringify(初始化CF_JSON, null, 2)); } else { const CF_JSON = JSON.parse(CF_TXT); config_JSON.CF.Email = CF_JSON.Email ? CF_JSON.Email : null; config_JSON.CF.GlobalAPIKey = CF_JSON.GlobalAPIKey ? 掩码敏感信息(CF_JSON.GlobalAPIKey) : null; config_JSON.CF.AccountID = CF_JSON.AccountID ? 掩码敏感信息(CF_JSON.AccountID) : null; config_JSON.CF.APIToken = CF_JSON.APIToken ? 掩码敏感信息(CF_JSON.APIToken) : null; const Usage = await getCloudflareUsage(CF_JSON.Email, CF_JSON.GlobalAPIKey, CF_JSON.AccountID, CF_JSON.APIToken); config_JSON.CF.Usage = Usage; } } catch (error) {}
    config_JSON.加载时间 = (performance.now() - 初始化开始时间).toFixed(2) + 'ms';
    return config_JSON;
}

// [定制] 固定规则IP生成逻辑 (25个节点)
async function 生成定制规则IP(count = 25, 指定端口 = -1) {
    const cfport = [443, 2053, 2083, 2087, 2096, 8443];
    const rules = [
        { country: 'HK', cidr: '104.16.0.0/12' },
        { country: 'US', cidr: '172.64.0.0/13' },
        { country: 'SG', cidr: '162.158.0.0/15' },
        { country: 'JP', cidr: '198.41.128.0/17' },
        { country: 'KR', cidr: '188.114.96.0/20' }
    ];

    const generateIP = (cidr) => {
        const [baseIP, prefix] = cidr.split('/');
        const hostBits = 32 - parseInt(prefix);
        const ipParts = baseIP.split('.').map(Number);
        const ipInt = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
        const randomOffset = Math.floor(Math.random() * Math.pow(2, hostBits));
        const randomIPInt = (ipInt + randomOffset) >>> 0;
        return [(randomIPInt >>> 24) & 0xFF, (randomIPInt >>> 16) & 0xFF, (randomIPInt >>> 8) & 0xFF, randomIPInt & 0xFF].join('.');
    };

    const ips = [];
    // 强制生成25个
    for (let i = 0; i < 25; i++) {
        const groupIndex = Math.floor(i / 5) % rules.length;
        const rule = rules[groupIndex];
        const ip = generateIP(rule.cidr);
        const port = 指定端口 === -1 ? cfport[Math.floor(Math.random() * cfport.length)] : 指定端口;
        const num = (i % 5 + 1).toString().padStart(2, '0');
        ips.push(`${ip}:${port}#${rule.country} ${num}`);
    }
    return [ips, ips.join('\n')];
}

async function 整理成数组(内容) {
    if (!内容) return [];
    var 替换后的内容 = 内容.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');
    if (替换后的内容.charAt(0) == ',') 替换后的内容 = 替换后的内容.slice(1);
    if (替换后的内容.charAt(替换后的内容.length - 1) == ',') 替换后的内容 = 替换后的内容.slice(0, 替换后的内容.length - 1);
    return 替换后的内容.split(',');
}

async function 请求优选API(urls, 默认端口 = '443', 超时时间 = 3000) { if (!urls?.length) return []; const results = new Set(); await Promise.allSettled(urls.map(async (url) => { try { const controller = new AbortController(); const timeoutId = setTimeout(() => controller.abort(), 超时时间); const response = await fetch(url, { signal: controller.signal }); clearTimeout(timeoutId); const text = await response.text(); if (text) { const lines = text.trim().split('\n'); lines.forEach(line => { if (line.includes(':')) results.add(line); }); } } catch (e) {} })); return Array.from(results); }

function sha224(s) {
    const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
    const r = (n, b) => ((n >>> b) | (n << (32 - b))) >>> 0;
    s = unescape(encodeURIComponent(s));
    const l = s.length * 8; s += String.fromCharCode(0x80);
    while ((s.length * 8) % 512 !== 448) s += String.fromCharCode(0);
    const h = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
    const hi = Math.floor(l / 0x100000000), lo = l & 0xFFFFFFFF;
    s += String.fromCharCode((hi >>> 24) & 0xFF, (hi >>> 16) & 0xFF, (hi >>> 8) & 0xFF, hi & 0xFF, (lo >>> 24) & 0xFF, (lo >>> 16) & 0xFF, (lo >>> 8) & 0xFF, lo & 0xFF);
    const w = []; for (let i = 0; i < s.length; i += 4)w.push((s.charCodeAt(i) << 24) | (s.charCodeAt(i + 1) << 16) | (s.charCodeAt(i + 2) << 8) | s.charCodeAt(i + 3));
    for (let i = 0; i < w.length; i += 16) {
        const x = new Array(64).fill(0);
        for (let j = 0; j < 16; j++)x[j] = w[i + j];
        for (let j = 16; j < 64; j++) {
            const s0 = r(x[j - 15], 7) ^ r(x[j - 15], 18) ^ (x[j - 15] >>> 3);
            const s1 = r(x[j - 2], 17) ^ r(x[j - 2], 19) ^ (x[j - 2] >>> 10);
            x[j] = (x[j - 16] + s0 + x[j - 7] + s1) >>> 0;
        }
        let [a, b, c, d, e, f, g, h0] = h;
        for (let j = 0; j < 64; j++) {
            const S1 = r(e, 6) ^ r(e, 11) ^ r(e, 25), ch = (e & f) ^ (~e & g), t1 = (h0 + S1 + ch + K[j] + x[j]) >>> 0;
            const S0 = r(a, 2) ^ r(a, 13) ^ r(a, 22), maj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + maj) >>> 0;
            h0 = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
        }
        for (let j = 0; j < 8; j++)h[j] = (h[j] + (j === 0 ? a : j === 1 ? b : j === 2 ? c : j === 3 ? d : j === 4 ? e : j === 5 ? f : j === 6 ? g : h0)) >>> 0;
    }
    let hex = '';
    for (let i = 0; i < 7; i++) {
        for (let j = 24; j >= 0; j -= 8)hex += ((h[i] >>> j) & 0xFF).toString(16).padStart(2, '0');
    }
    return hex;
}

async function surge(content, url, config_JSON) { return content; } 
async function html1101(host, ip) { return `<!DOCTYPE html><html class="no-js" lang="en-US"><head><title>Worker threw exception | ${host} | Cloudflare</title><meta charset="UTF-8" /><meta http-equiv="Content-Type" content="text/html; charset=UTF-8" /><meta http-equiv="X-UA-Compatible" content="IE=Edge" /><meta name="robots" content="noindex, nofollow" /><meta name="viewport" content="width=device-width,initial-scale=1" /><link rel="stylesheet" id="cf_styles-css" href="/cdn-cgi/styles/cf.errors.css" /><style>body{margin:0;padding:0}</style><script>if (!navigator.cookieEnabled) {window.addEventListener('DOMContentLoaded', function () {var cookieEl = document.getElementById('cookie-alert');cookieEl.style.display = 'block';})}</script></head><body><div id="cf-wrapper"><div class="cf-alert cf-alert-error cf-cookie-error" id="cookie-alert" data-translate="enable_cookies">Please enable cookies.</div><div id="cf-error-details" class="cf-error-details-wrapper"><div class="cf-wrapper cf-header cf-error-overview"><h1><span class="cf-error-type" data-translate="error">Error</span><span class="cf-error-code">1101</span><small class="heading-ray-id">Ray ID: ${Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b=>b.toString(16).padStart(2,'0')).join('')} &bull; ${new Date().toISOString()}</small></h1><h2 class="cf-subheadline" data-translate="error_desc">Worker threw exception</h2></div><section></section><div class="cf-section cf-wrapper"><div class="cf-columns two"><div class="cf-column"><h2 data-translate="what_happened">What happened?</h2><p>You've requested a page on a website (${host}) that is on the <a href="https://www.cloudflare.com/5xx-error-landing?utm_source=error_100x" target="_blank">Cloudflare</a> network. An unknown error occurred while rendering the page.</p></div><div class="cf-column"><h2 data-translate="what_can_i_do">What can I do?</h2><p><strong>If you are the owner of this website:</strong><br />refer to <a href="https://developers.cloudflare.com/workers/observability/errors/" target="_blank">Workers - Errors and Exceptions</a> and check Workers Logs for ${host}.</p></div></div></div><div class="cf-error-footer cf-wrapper w-240 lg:w-full py-10 sm:py-4 sm:px-8 mx-auto text-center sm:text-left border-solid border-0 border-t border-gray-300"><p class="text-13"><span class="cf-footer-item sm:block sm:mb-1">Cloudflare Ray ID: <strong class="font-semibold">${Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b=>b.toString(16).padStart(2,'0')).join('')}</strong></span><span class="cf-footer-separator sm:hidden">&bull;</span><span id="cf-footer-item-ip" class="cf-footer-item hidden sm:block sm:mb-1">Your IP:<button type="button" id="cf-footer-ip-reveal" class="cf-footer-ip-reveal-btn">Click to reveal</button><span class="hidden" id="cf-footer-ip">${ip}</span><span class="cf-footer-separator sm:hidden">&bull;</span></span><span class="cf-footer-item sm:block sm:mb-1"><span>Performance &amp; security by</span> <a rel="noopener noreferrer" href="https://www.cloudflare.com/5xx-error-landing" id="brand_link" target="_blank">Cloudflare</a></span></p><script>(function(){function d(){var b=a.getElementById("cf-footer-item-ip"),c=a.getElementById("cf-footer-ip-reveal");b&&"classList"in b&&(b.classList.remove("hidden"),c.addEventListener("click",function(){c.classList.add("hidden");a.getElementById("cf-footer-ip").classList.remove("hidden")}))}var a=document;document.addEventListener&&a.addEventListener("DOMContentLoaded",d)})();</script></div></div></div></body></html>`; }
async function nginx() { return `<!DOCTYPE html><html><head><title>Welcome to nginx!</title><style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif}</style></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working.</p></body></html>`; }
