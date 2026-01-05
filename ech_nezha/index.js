const WebSocket = require('ws');
const net = require('net');
const http = require('http');
const https = require('https');
const dns = require('dns').promises;
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const axios = require('axios');
const { exec } = require('child_process');

const PORT = process.env.PORT || 3000;
const TOKEN = process.env.TOKEN || '';
const CF_FALLBACK_IPS = process.env.PRIP 
  ? process.env.PRIP.split(',') 
  : ['ProxyIP.JP.CMLiussss.net'];

// 哪吒配置
const NEZHA_SERVER = process.env.NSERVER || '';
const NEZHA_PORT = process.env.NPORT || '443';
const NEZHA_KEY = process.env.NKEY || '';
const UUID = process.env.UUID || crypto.randomUUID();

// 哪吒状态管理
let nezhaProcessId = null;
let processCheckInterval = null;
let consecutiveChecks = 0;

// DoH 配置
const DOH_SERVERS = [
  'https://dns.google/dns-query',
  'https://cloudflare-dns.com/dns-query',
  'https://dns.alidns.com/dns-query'
];

// DNS 缓存
const dnsCache = new Map();
const DNS_CACHE_TTL = 300000; // 5分钟

// ======================== 哪吒功能函数 ========================
function detectArchitecture() {
  const arch = os.arch();
  return (arch === 'arm' || arch === 'arm64') ? 'arm64' : 'amd64';
}

function downloadNezhaBinary(binaryName, downloadUrl, callback) {
  const savePath = path.join('/tmp', binaryName);
  const writer = fs.createWriteStream(savePath);
  
  console.log(`[Nezha] 开始下载哪吒客户端: ${binaryName}`);
  
  axios({
    method: 'get',
    url: downloadUrl,
    responseType: 'stream'
  })
    .then(response => {
      response.data.pipe(writer);
      writer.on('finish', () => {
        writer.close();
        console.log(`[Nezha] 下载完成: ${binaryName}`);
        callback(null, binaryName);
      });
    })
    .catch(err => {
      console.error(`[Nezha] 下载失败: ${binaryName} - ${err.message}`);
      callback(err.message);
    });
}

function downloadAllBinaries() {
  const arch = detectArchitecture();
  const binaries = [];
  
  if (arch === 'arm64') {
    binaries.push({ 
      name: 'npm', 
      url: 'https://github.com/dsadsadsss/java-wanju/releases/download/jar/agent2-linux_arm64.bin' 
    });
  } else {
    binaries.push({ 
      name: 'npm', 
      url: 'https://github.com/dsadsadsss/java-wanju/releases/download/jar/agent2-linux_amd64.bin' 
    });
  }

  if (binaries.length === 0) {
    console.log(`[Nezha] 未找到适合架构 (${arch}) 的二进制文件`);
    return;
  }

  binaries.forEach(binary => {
    downloadNezhaBinary(binary.name, binary.url, (err) => {
      if (err) {
        console.log(`[Nezha] ${binary.name} 下载失败`);
      } else {
        console.log(`[Nezha] ${binary.name} 下载成功，准备启动`);
        setupNezhaBinary();
      }
    });
  });
}

function setupNezhaBinary() {
  const binaryPath = '/tmp/npm';
  const configPath = '/tmp/config.yml';
  
  if (!fs.existsSync(binaryPath)) {
    console.error('[Nezha] 二进制文件不存在！');
    return;
  }
  
  if (!fs.existsSync(configPath)) {
    console.error('[Nezha] 配置文件不存在，无法启动！');
    return;
  }
  
  console.log('[Nezha] 准备启动哪吒客户端...');
  
  fs.chmod(binaryPath, '755', (err) => {
    if (err) {
      console.error(`[Nezha] 设置执行权限失败: ${err}`);
    } else {
      startNezhaClient();
    }
  });
}

function startNezhaClient() {
  if (!NEZHA_SERVER || !NEZHA_PORT || !NEZHA_KEY) {
    console.log('[Nezha] 哪吒配置信息不完整，跳过启动');
    return;
  }
  
  console.log('[Nezha] 启动哪吒客户端...');
  
  const command = '/tmp/npm -c /tmp/config.yml';
  
  try {
    const nezhaProcess = exec(command, { detached: true, stdio: 'ignore' });
    
    nezhaProcess.on('spawn', () => {
      nezhaProcessId = nezhaProcess.pid;
      console.log(`[Nezha] 哪吒客户端已启动，进程 ID: ${nezhaProcessId}`);
      startProcessMonitoring();
    });
    
    nezhaProcess.on('error', (err) => {
      console.error(`[Nezha] 哪吒客户端启动失败: ${err.message}`);
      nezhaProcessId = null;
    });
    
    nezhaProcess.on('exit', (code, signal) => {
      console.log(`[Nezha] 哪吒客户端退出，退出码: ${code}, 信号: ${signal}`);
      nezhaProcessId = null;
    });
    
    nezhaProcess.unref();
    
  } catch (e) {
    console.error(`[Nezha] 启动哪吒客户端异常: ${e}`);
  }
}

function startProcessMonitoring() {
  if (processCheckInterval) {
    clearInterval(processCheckInterval);
  }
  
  consecutiveChecks = 0;
  
  processCheckInterval = setInterval(() => {
    checkProcessStatus();
  }, 20000);
}

function checkProcessStatus() {
  if (!nezhaProcessId) {
    console.log('[Nezha] 哪吒客户端未运行，尝试重启...');
    consecutiveChecks = 0;
    startNezhaClient();
    return;
  }
  
  try {
    process.kill(nezhaProcessId, 0);
    consecutiveChecks++;
    console.log(`[Nezha] 哪吒客户端 ${nezhaProcessId} 运行中... (第 ${consecutiveChecks} 次检查)`);
    
    if (consecutiveChecks >= 2) {
      console.log('[Nezha] 哪吒客户端稳定运行，停止监控');
      clearInterval(processCheckInterval);
      processCheckInterval = null;
    }
  } catch (err) {
    if (err.code === 'ESRCH') {
      console.log(`[Nezha] 哪吒客户端 ${nezhaProcessId} 已停止，准备重启...`);
      nezhaProcessId = null;
      consecutiveChecks = 0;
      startNezhaClient();
    } else {
      console.error(`[Nezha] 检查进程状态失败: ${err.message}`);
    }
  }
}

function generateNezhaConfig() {
  const configContent = `client_secret: ${NEZHA_KEY}
debug: false
disable_auto_update: false
disable_command_execute: false
disable_force_update: false
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 3
server: ${NEZHA_SERVER}
skip_connection_count: false
skip_procs_count: false
temperature: false
tls: ${NEZHA_PORT === '443' ? 'true' : 'false'}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${UUID}`;

  const configPath = '/tmp/config.yml';
  
  try {
    fs.writeFileSync(configPath, configContent, 'utf8');
    console.log('[Nezha] 哪吒配置文件已生成: /tmp/config.yml');
    return true;
  } catch (err) {
    console.error(`[Nezha] 生成配置文件失败: ${err.message}`);
    return false;
  }
}

// ======================== DoH 功能 ========================
async function resolveDoH(hostname) {
  const cached = dnsCache.get(hostname);
  if (cached && Date.now() - cached.timestamp < DNS_CACHE_TTL) {
    console.log(`[DoH Cache Hit] ${hostname} -> ${cached.ip}`);
    return cached.ip;
  }

  if (net.isIP(hostname)) {
    return hostname;
  }

  console.log(`[DoH Query] Resolving ${hostname}...`);

  for (const dohServer of DOH_SERVERS) {
    try {
      const ip = await queryDoH(dohServer, hostname);
      if (ip) {
        dnsCache.set(hostname, { ip, timestamp: Date.now() });
        console.log(`[DoH Success] ${hostname} -> ${ip} (via ${dohServer})`);
        return ip;
      }
    } catch (err) {
      console.error(`[DoH Failed] ${dohServer}: ${err.message}`);
    }
  }

  console.log(`[DoH Fallback] Using system DNS for ${hostname}`);
  try {
    const addresses = await dns.resolve4(hostname);
    if (addresses && addresses.length > 0) {
      const ip = addresses[0];
      dnsCache.set(hostname, { ip, timestamp: Date.now() });
      return ip;
    }
  } catch (err) {
    console.error(`[System DNS Failed] ${hostname}: ${err.message}`);
  }

  throw new Error(`Failed to resolve ${hostname}`);
}

function queryDoH(dohServer, hostname) {
  return new Promise((resolve, reject) => {
    const url = `${dohServer}?name=${hostname}&type=A`;
    
    https.get(url, {
      headers: {
        'Accept': 'application/dns-json'
      },
      timeout: 5000
    }, (res) => {
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          
          if (json.Answer && json.Answer.length > 0) {
            for (const answer of json.Answer) {
              if (answer.type === 1) {
                resolve(answer.data);
                return;
              }
            }
          }
          
          reject(new Error('No A record found'));
        } catch (err) {
          reject(err);
        }
      });
    }).on('error', reject).on('timeout', () => {
      reject(new Error('DoH query timeout'));
    });
  });
}

// ======================== HTTP 服务器 ========================
const server = http.createServer((req, res) => {
  if (req.url === '/' || req.url === '/index.html') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Hello-world');
  } else if (req.url === '/stats') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      cacheSize: dnsCache.size,
      dohServers: DOH_SERVERS
    }));
  } else if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'running',
      nezha: nezhaProcessId ? 'active' : 'inactive',
      nezhaProcessId: nezhaProcessId,
      uptime: process.uptime().toFixed(2),
      dnsCacheSize: dnsCache.size,
      timestamp: new Date().toISOString()
    }));
  } else {
    res.writeHead(404);
    res.end('Not Found');
  }
});

// ======================== WebSocket 服务器 ========================
const wss = new WebSocket.Server({ 
  server,
  verifyClient: (info) => {
    const protocol = info.req.headers['sec-websocket-protocol'];
    if (TOKEN && protocol !== TOKEN) {
      return false;
    }
    return true;
  }
});

wss.on('connection', (ws, req) => {
  if (TOKEN && req.headers['sec-websocket-protocol']) {
    ws.protocol = TOKEN;
  }

  handleSession(ws).catch(() => safeCloseWebSocket(ws));
});

async function handleSession(webSocket) {
  let remoteSocket = null;
  let isClosed = false;

  const cleanup = () => {
    if (isClosed) return;
    isClosed = true;
    
    if (remoteSocket) {
      try { remoteSocket.destroy(); } catch {}
      remoteSocket = null;
    }
    
    safeCloseWebSocket(webSocket);
  };

  const pumpRemoteToWebSocket = (socket) => {
    socket.on('data', (data) => {
      if (!isClosed && webSocket.readyState === WebSocket.OPEN) {
        try {
          webSocket.send(data);
        } catch (err) {
          cleanup();
        }
      }
    });

    socket.on('end', () => {
      if (!isClosed) {
        try { webSocket.send('CLOSE'); } catch {}
        cleanup();
      }
    });

    socket.on('error', () => {
      cleanup();
    });
  };

  const parseAddress = (addr) => {
    if (addr[0] === '[') {
      const end = addr.indexOf(']');
      return {
        host: addr.substring(1, end),
        port: parseInt(addr.substring(end + 2), 10)
      };
    }
    const sep = addr.lastIndexOf(':');
    return {
      host: addr.substring(0, sep),
      port: parseInt(addr.substring(sep + 1), 10)
    };
  };

  const isCFError = (err) => {
    const msg = err?.message?.toLowerCase() || '';
    return msg.includes('proxy request') || 
           msg.includes('cannot connect') || 
           msg.includes('econnrefused') ||
           msg.includes('etimedout');
  };

  const connectToRemote = async (targetAddr, firstFrameData) => {
    const { host, port } = parseAddress(targetAddr);
    const attempts = [null, ...CF_FALLBACK_IPS];

    for (let i = 0; i < attempts.length; i++) {
      try {
        const targetHost = attempts[i] || host;
        
        let resolvedHost = targetHost;
        if (!net.isIP(targetHost)) {
          try {
            resolvedHost = await resolveDoH(targetHost);
            console.log(`[Connect] ${targetHost} resolved to ${resolvedHost}`);
          } catch (err) {
            console.error(`[DNS Error] Failed to resolve ${targetHost}: ${err.message}`);
          }
        }
        
        remoteSocket = net.connect({
          host: resolvedHost,
          port: port,
          timeout: 10000
        });

        await new Promise((resolve, reject) => {
          remoteSocket.once('connect', resolve);
          remoteSocket.once('error', reject);
        });

        if (firstFrameData) {
          remoteSocket.write(firstFrameData);
        }

        webSocket.send('CONNECTED');
        pumpRemoteToWebSocket(remoteSocket);
        return;

      } catch (err) {
        if (remoteSocket) {
          try { remoteSocket.destroy(); } catch {}
          remoteSocket = null;
        }

        if (!isCFError(err) || i === attempts.length - 1) {
          throw err;
        }
      }
    }
  };

  webSocket.on('message', async (data) => {
    if (isClosed) return;

    try {
      const message = data.toString();

      if (message.startsWith('CONNECT:')) {
        const sep = message.indexOf('|', 8);
        await connectToRemote(
          message.substring(8, sep),
          message.substring(sep + 1)
        );
      }
      else if (message.startsWith('DATA:')) {
        if (remoteSocket && !remoteSocket.destroyed) {
          remoteSocket.write(message.substring(5));
        }
      }
      else if (message === 'CLOSE') {
        cleanup();
      }
      else if (data instanceof Buffer && remoteSocket && !remoteSocket.destroyed) {
        remoteSocket.write(data);
      }
    } catch (err) {
      try { webSocket.send('ERROR:' + err.message); } catch {}
      cleanup();
    }
  });

  webSocket.on('close', cleanup);
  webSocket.on('error', cleanup);
}

function safeCloseWebSocket(ws) {
  try {
    if (ws.readyState === WebSocket.OPEN || 
        ws.readyState === WebSocket.CLOSING) {
      ws.close(1000, 'Server closed');
    }
  } catch {}
}

// ======================== 优雅退出处理 ========================
const gracefulShutdown = () => {
  console.log('\n[Shutdown] 正在优雅关闭服务器...');
  
  if (processCheckInterval) {
    clearInterval(processCheckInterval);
    processCheckInterval = null;
  }
  
  if (nezhaProcessId) {
    try {
      console.log(`[Shutdown] 停止哪吒客户端进程 ${nezhaProcessId}...`);
      process.kill(nezhaProcessId, 'SIGTERM');
      
      setTimeout(() => {
        try {
          process.kill(nezhaProcessId, 0);
          console.log('[Shutdown] 强制终止哪吒客户端进程...');
          process.kill(nezhaProcessId, 'SIGKILL');
        } catch (e) {
          console.log('[Shutdown] 哪吒客户端进程已停止');
        }
      }, 5000);
    } catch (e) {
      console.log('[Shutdown] 哪吒客户端进程已停止');
    }
  }
  
  wss.clients.forEach(client => {
    try {
      client.close();
    } catch (e) {
      console.error('[Shutdown] 关闭 WebSocket 客户端失败:', e.message);
    }
  });
  
  server.close(() => {
    console.log('[Shutdown] HTTP 服务器已关闭');
    process.exit(0);
  });
  
  setTimeout(() => {
    console.error('[Shutdown] 强制退出超时,强制关闭');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

// ======================== 启动服务 ========================
server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n========================================`);
  console.log(`WebSocket 代理服务器已启动`);
  console.log(`端口: ${PORT}`);
  console.log(`Token 认证: ${TOKEN ? 'enabled' : 'disabled'}`);
  console.log(`DoH 服务器: ${DOH_SERVERS.join(', ')}`);
  console.log(`DNS 缓存 TTL: ${DNS_CACHE_TTL / 1000}s`);
  console.log(`Cloudflare 回退 IP: ${CF_FALLBACK_IPS.join(', ')}`);
  console.log(`========================================\n`);
  
  if (NEZHA_SERVER && NEZHA_PORT && NEZHA_KEY) {
    console.log('[Nezha] 检测到哪吒配置，准备启动哪吒客户端...');
    console.log(`[Nezha] 哪吒服务器: ${NEZHA_SERVER}:${NEZHA_PORT}`);
    console.log(`[Nezha] UUID: ${UUID}\n`);
    
    if (generateNezhaConfig()) {
      downloadAllBinaries();
    }
  } else {
    console.log('[Nezha] 未配置哪吒监控，跳过哪吒客户端启动\n');
  }
});

// ======================== 错误处理 ========================
process.on('uncaughtException', (err) => {
  console.error('[Error] 未捕获的异常:', err);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('[Error] 未处理的 Promise 拒绝:', reason);
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`[Error] 端口 ${PORT} 已被占用`);
    process.exit(1);
  } else {
    console.error('[Error] 服务器错误:', err);
  }
});