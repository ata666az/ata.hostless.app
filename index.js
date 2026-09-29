#!/usr/bin/env node

const os = require('os');
const http = require('http');
const fs = require('fs');
const net = require('net');
const dns = require('dns');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const { Buffer } = require('buffer');
const axios = require('axios');
const si = require('systeminformation');
const grpc = require('@grpc/grpc-js');
const { spawn } = require('child_process');
const protoLoader = require('@grpc/proto-loader');
const { WebSocket, createWebSocketStream } = require('ws');

// ========================== ENV CONFIG ==========================
const UUID = process.env.UUID || 'd1cf4b9c-3e57-085d-b34a-797fcf601381';
const NEZHA_SERVER = process.env.NEZHA_SERVER || '';
const NEZHA_KEY = process.env.NEZHA_KEY || '';
const DOMAIN = process.env.DOMAIN || '';
const AUTO_ACCESS = process.env.AUTO_ACCESS || false;
const SUB_PATH = process.env.SUB_PATH || 'ata';
const NAME = process.env.NAME || 'HOSTLESS';
const PORT = process.env.PORT || 3000;

// Keep-alive
const KEEPALIVE_ENABLE = (process.env.KEEPALIVE_ENABLE || 'true').toLowerCase() === 'true';
const KEEPALIVE_INTERVAL = parseInt(process.env.KEEPALIVE_INTERVAL || '240', 10);
const KEEPALIVE_URL = process.env.KEEPALIVE_URL || '';

// NZ-Agent
const AGENT_VERSION = 'nodejs-9.9.9';
const REPORT_DELAY = 4;
const RETRY_DELAY = 10000;
const IP_REPORT_PERIOD = 1800;
const NETWORK_TIMEOUT = 8000;

const SHOW_LOG = !!(process.env.SHOW_LOG);
function log(...a) { if (SHOW_LOG) console.log(...a); }
function logErr(...a) { if (SHOW_LOG) console.error(...a); }
function logWarn(...a) { if (SHOW_LOG) console.warn(...a); }

const WSPATH = process.env.WSPATH || UUID.slice(0, 8);
const TLS_PORTS = new Set([443, 2053, 2083, 2087, 2096, 8443]);
let uuid = UUID.replace(/-/g, ""), CurrentDomain = DOMAIN, Tls = 'tls', CurrentPort = 443, ISP = '';
const DNS_SERVERS = ['8.8.4.4', '1.1.1.1'];
const BLOCKED_DOMAINS = [
  'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
  'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org'
];

function shouldUseTLS(server) {
  const p = server.split(':');
  if (p.length < 2) return false;
  return TLS_PORTS.has(parseInt(p[p.length - 1], 10));
}
function isBlockedDomain(host) {
  if (!host) return false;
  const h = host.toLowerCase();
  return BLOCKED_DOMAINS.some(b => h === b || h.endsWith('.' + b));
}

async function getisp() {
  try {
    const r = await axios.get('https://api.ip.sb/geoip', { headers: { 'User-Agent': 'Mozilla/5.0' }, timeout: 3000 });
    ISP = `${r.data.country_code}-${r.data.isp}`.replace(/ /g, '_');
  } catch (e) {
    try {
      const r2 = await axios.get('http://ip-api.com/json', { headers: { 'User-Agent': 'Mozilla/5.0' }, timeout: 3000 });
      ISP = `${r2.data.countryCode}-${r2.data.org}`.replace(/ /g, '_');
    } catch { ISP = 'Unknown'; }
  }
}

async function getip() {
  if (!DOMAIN) {
    try {
      const r = await axios.get('https://api-ipv4.ip.sb/ip', { timeout: 5000 });
      CurrentDomain = r.data.trim(); Tls = 'none'; CurrentPort = PORT;
    } catch { CurrentDomain = 'change-your-domain.com'; Tls = 'tls'; CurrentPort = 443; }
  } else {
    CurrentDomain = DOMAIN; Tls = 'tls'; CurrentPort = 443;
  }
}

// ========================== HTTP SERVER ==========================
const httpServer = http.createServer(async (req, res) => {
  // Keepalive endpoint
  if (req.url === '/keepalive') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end('OK');
  }

  if (req.url === '/') {
    const filePath = path.join(__dirname, 'index.html');
    fs.readFile(filePath, 'utf8', (err, content) => {
      if (err) { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end('Hello world!'); }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(content);
    });
    return;
  }

  if (req.url === `/${SUB_PATH}`) {
    await getisp(); await getip();
    const namePart = NAME ? `${NAME}-${ISP}` : ISP;
    const tlsParam = Tls === 'tls' ? 'tls' : 'none';
    const ssTls = Tls === 'tls' ? 'tls;' : '';
    const vlsURL = `vless://${UUID}@${CurrentDomain}:${CurrentPort}?encryption=none&security=${tlsParam}&sni=${CurrentDomain}&fp=chrome&type=ws&host=${CurrentDomain}&path=%2F${WSPATH}#${namePart}`;
    const troURL = `trojan://${UUID}@${CurrentDomain}:${CurrentPort}?security=${tlsParam}&sni=${CurrentDomain}&fp=chrome&type=ws&host=${CurrentDomain}&path=%2F${WSPATH}#${namePart}`;
    const ssPwd = Buffer.from(`none:${UUID}`).toString('base64');
    const ssURL = `ss://${ssPwd}@${CurrentDomain}:${CurrentPort}?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D${CurrentDomain};path%3D%2F${WSPATH};${ssTls}sni%3D${CurrentDomain};skip-cert-verify%3Dtrue;mux%3D0#${namePart}`;
    const sub = vlsURL + '\n' + troURL + '\n' + ssURL;
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end(Buffer.from(sub).toString('base64') + '\n');
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found\n');
});

// ========================== KEEP-ALIVE ==========================
function startKeepAlive() {
  if (!KEEPALIVE_ENABLE) { console.log('[KeepAlive] Disabled'); return; }
  const target = KEEPALIVE_URL || `http://127.0.0.1:${PORT}/keepalive`;
  console.log(`[KeepAlive] Active -> ${target} every ${KEEPALIVE_INTERVAL}s`);

  const ping = () => {
    const lib = target.startsWith('https://') ? https : http;
    const req = lib.get(target, { timeout: 10000 }, (res) => {
      res.resume();
      log(`[KeepAlive] OK ${res.statusCode} @ ${new Date().toISOString()}`);
    });
    req.on('error', e => logErr(`[KeepAlive] Error: ${e.message}`));
    req.on('timeout', () => { req.destroy(); logErr('[KeepAlive] Timeout'); });
  };
  setTimeout(ping, 10 * 1000);
  setInterval(ping, KEEPALIVE_INTERVAL * 1000);
}

// ========================== DNS RESOLVER ==========================
function resolveHost(host) {
  return new Promise((resolve, reject) => {
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(host)) return resolve(host);
    let attempts = 0;
    const tryNext = () => {
      if (attempts >= DNS_SERVERS.length) return reject(new Error(`DNS fail: ${host}`));
      attempts++;
      axios.get(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`, { timeout: 5000, headers: { 'Accept': 'application/dns-json' } })
        .then(r => {
          if (r.data.Status === 0 && r.data.Answer) {
            const ip = r.data.Answer.find(x => x.type === 1);
            if (ip) return resolve(ip.data);
          }
          tryNext();
        }).catch(() => tryNext());
    };
    tryNext();
  });
}

// ========================== PROXY HANDLERS ==========================
function handleVlsConnection(ws, msg) {
  const [VERSION] = msg;
  const id = msg.slice(1, 17);
  if (!id.every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16))) return false;

  let i = msg.slice(17, 18).readUInt8() + 19;
  const port = msg.slice(i, i += 2).readUInt16BE(0);
  const ATYP = msg.slice(i, i += 1).readUInt8();
  const host = ATYP == 1 ? msg.slice(i, i += 4).join('.') :
    (ATYP == 2 ? new TextDecoder().decode(msg.slice(i + 1, i += 1 + msg.slice(i, i + 1).readUInt8())) :
      (ATYP == 3 ? msg.slice(i, i += 16).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':') : ''));

  if (isBlockedDomain(host)) { ws.close(); return false; }
  ws.send(new Uint8Array([VERSION, 0]));
  const duplex = createWebSocketStream(ws);
  resolveHost(host).then(ip => {
    net.connect({ host: ip, port }, function () {
      this.write(msg.slice(i));
      duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);
    }).on('error', () => {});
  }).catch(() => {
    net.connect({ host, port }, function () {
      this.write(msg.slice(i));
      duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);
    }).on('error', () => {});
  });
  return true;
}

function handleTrojConnection(ws, msg) {
  try {
    if (msg.length < 58) return false;
    const hash = msg.slice(0, 56).toString();
    if (crypto.createHash('sha224').update(UUID).digest('hex') !== hash) return false;
    let offset = 56;
    if (msg[offset] === 0x0d && msg[offset + 1] === 0x0a) offset += 2;
    if (msg[offset] !== 0x01) return false;
    offset += 1;
    const atyp = msg[offset]; offset += 1;
    let host, port;
    if (atyp === 0x01) { host = msg.slice(offset, offset + 4).join('.'); offset += 4; }
    else if (atyp === 0x03) { const l = msg[offset]; offset += 1; host = msg.slice(offset, offset + l).toString(); offset += l; }
    else if (atyp === 0x04) { host = msg.slice(offset, offset + 16).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':'); offset += 16; }
    else return false;
    port = msg.readUInt16BE(offset); offset += 2;
    if (offset < msg.length && msg[offset] === 0x0d && msg[offset + 1] === 0x0a) offset += 2;
    if (isBlockedDomain(host)) { ws.close(); return false; }
    const duplex = createWebSocketStream(ws);
    resolveHost(host).then(ip => {
      net.connect({ host: ip, port }, function () {
        if (offset < msg.length) this.write(msg.slice(offset));
        duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);
      }).on('error', () => {});
    }).catch(() => {
      net.connect({ host, port }, function () {
        if (offset < msg.length) this.write(msg.slice(offset));
        duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);
      }).on('error', () => {});
    });
    return true;
  } catch { return false; }
}

function handleSsConnection(ws, msg) {
  try {
    let offset = 0;
    const atyp = msg[offset]; offset += 1;
    let host, port;
    if (atyp === 0x01) { host = msg.slice(offset, offset + 4).join('.'); offset += 4; }
    else if (atyp === 0x03) { const l = msg[offset]; offset += 1; host = msg.slice(offset, offset + l).toString(); offset += l; }
    else if (atyp === 0x04) { host = msg.slice(offset, offset + 16).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':'); offset += 16; }
    else return false;
    port = msg.readUInt16BE(offset); offset += 2;
    if (isBlockedDomain(host)) { ws.close(); return false; }
    const duplex = createWebSocketStream(ws);
    resolveHost(host).then(ip => {
      net.connect({ host: ip, port }, function () {
        if (offset < msg.length) this.write(msg.slice(offset));
        duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);
      }).on('error', () => {});
    }).catch(() => {
      net.connect({ host, port }, function () {
        if (offset < msg.length) this.write(msg.slice(offset));
        duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);
      }).on('error', () => {});
    });
    return true;
  } catch { return false; }
}

// ========================== WEBSOCKET ==========================
const wss = new WebSocket.Server({ server: httpServer });
wss.on('connection', (ws, req) => {
  const url = req.url || '';
  if (!url.startsWith(`/${WSPATH}`)) { ws.close(); return; }

  ws.once('message', msg => {
    if (msg.length > 17 && msg[0] === 0) {
      const id = msg.slice(1, 17);
      if (id.every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16))) {
        if (!handleVlsConnection(ws, msg)) ws.close();
        return;
      }
    }
    if (msg.length >= 58 && handleTrojConnection(ws, msg)) return;
    if (msg.length > 0 && (msg[0] === 0x01 || msg[0] === 0x03 || msg[0] === 0x04)) {
      if (handleSsConnection(ws, msg)) return;
    }
    ws.close();
  }).on('error', () => {});
});

// ========================== AUTO ACCESS ==========================
async function addAccessTask() {
  if (!AUTO_ACCESS || !DOMAIN) return;
  try {
    await axios.post("https://oooo.serv00.net/add-url", { url: `https://${DOMAIN}/${SUB_PATH}` }, { headers: { 'Content-Type': 'application/json' } });
    console.log('Auto access added');
  } catch {}
}

// ========================== NZ AGENT ==========================
const PROTO_CONTENT = `
syntax = "proto3";
option go_package = "./proto";
package proto;
service NezhaService {
  rpc ReportSystemState(stream State) returns (stream Receipt) {}
  rpc ReportSystemInfo(Host) returns (Receipt) {}
  rpc RequestTask(stream TaskResult) returns (stream Task) {}
  rpc IOStream(stream IOStreamData) returns (stream IOStreamData) {}
  rpc ReportGeoIP(GeoIP) returns (GeoIP) {}
  rpc ReportSystemInfo2(Host) returns (Uint64Receipt) {}
}
message Host { string platform=1; string platform_version=2; repeated string cpu=3; uint64 mem_total=4; uint64 disk_total=5; uint64 swap_total=6; string arch=7; string virtualization=8; uint64 boot_time=9; string version=10; repeated string gpu=11; }
message State { double cpu=1; uint64 mem_used=2; uint64 swap_used=3; uint64 disk_used=4; uint64 net_in_transfer=5; uint64 net_out_transfer=6; uint64 net_in_speed=7; uint64 net_out_speed=8; uint64 uptime=9; double load1=10; double load5=11; double load15=12; uint64 tcp_conn_count=13; uint64 udp_conn_count=14; uint64 process_count=15; repeated State_SensorTemperature temperatures=16; repeated double gpu=17; }
message State_SensorTemperature { string name=1; double temperature=2; }
message Task { uint64 id=1; uint64 type=2; string data=3; }
message TaskResult { uint64 id=1; uint64 type=2; float delay=3; string data=4; bool successful=5; }
message Receipt { bool proced=1; }
message Uint64Receipt { uint64 data=1; }
message IOStreamData { bytes data=1; }
message GeoIP { bool use6=1; IP ip=2; string country_code=3; uint64 dashboard_boot_time=4; }
message IP { string ipv4=1; string ipv6=2; }
`;

function loadProto() {
  const tmp = path.join(os.tmpdir(), `nezha_${process.pid}.proto`);
  fs.writeFileSync(tmp, PROTO_CONTENT);
  try {
    const pkg = protoLoader.loadSync(tmp, { keepCase: false, longs: Number, enums: Number, defaults: true, oneofs: true });
    return grpc.loadPackageDefinition(pkg).proto;
  } finally { try { fs.unlinkSync(tmp); } catch {} }
}

function buildMetadata() {
  const m = new grpc.Metadata();
  m.add('client-secret', NEZHA_KEY);
  m.add('client-uuid', UUID);
  m.add('client_secret', NEZHA_KEY);
  m.add('client_uuid', UUID);
  return m;
}

let netInTransfer = 0, netOutTransfer = 0, netInSpeed = 0, netOutSpeed = 0, lastNetUpdate = 0;
let activeIOStreams = 0, lastReportedIP = null;

const EXCLUDE_IF = ['lo', 'tun', 'docker', 'veth', 'br-', 'vmbr', 'vnet', 'kube', 'Meta', 'tailscale', 'fw', 'tap'];
const EXPECT_FS = new Set(['apfs','ext4','ext3','ext2','f2fs','reiserfs','jfs','bcachefs','btrfs','fuseblk','zfs','simfs','ntfs','fat32','exfat','xfs','fuse.rclone']);
const shouldExcludeIf = n => EXCLUDE_IF.some(e => n.includes(e));

function getArch() {
  return { x64: 'x86_64', arm64: 'aarch64', ia32: 'i386' }[process.arch] || process.arch;
}

async function getHost() {
  const [osInfo, cpuInfo, memInfo, fsSize] = await Promise.all([si.osInfo(), si.cpu(), si.mem(), si.fsSize()]);
  let diskTotal = 0;
  for (const fs of fsSize) if (EXPECT_FS.has((fs.type || '').toLowerCase())) diskTotal += fs.size || 0;
  return {
    platform: osInfo.distro || process.platform,
    platformVersion: osInfo.release || '',
    cpu: [`${cpuInfo.manufacturer} ${cpuInfo.brand} ${cpuInfo.cores} Physical Core`],
    memTotal: memInfo.total, diskTotal, swapTotal: memInfo.swaptotal || 0,
    arch: getArch(), virtualization: '', bootTime: Math.floor(Date.now() / 1000 - os.uptime()),
    version: AGENT_VERSION, gpu: []
  };
}

async function trackNetworkSpeed() {
  try {
    const stats = await si.networkStats();
    let inB = 0, outB = 0;
    for (const s of stats) {
      if (shouldExcludeIf(s.iface)) continue;
      inB += s.rx_bytes || 0; outB += s.tx_bytes || 0;
    }
    const now = Math.floor(Date.now() / 1000);
    if (lastNetUpdate > 0) {
      const d = now - lastNetUpdate;
      if (d > 0) { netInSpeed = Math.max(0, (inB - netInTransfer) / d); netOutSpeed = Math.max(0, (outB - netOutTransfer) / d); }
    }
    netInTransfer = inB; netOutTransfer = outB; lastNetUpdate = now;
  } catch {}
}

function getConnCount() {
  if (process.platform !== 'linux') return [0, 0];
  try {
    const c = f => Math.max(0, fs.readFileSync(f, 'utf8').split('\n').length - 2);
    return [c('/proc/net/tcp') + c('/proc/net/tcp6'), c('/proc/net/udp') + c('/proc/net/udp6')];
  } catch { return [0, 0]; }
}

function getProcCount() {
  if (process.platform !== 'linux') return -1;
  try { return fs.readdirSync('/proc').filter(x => /^\d+$/.test(x)).length; } catch { return 0; }
}

async function getState() {
  const [load, mem, fsSize] = await Promise.all([si.currentLoad(), si.mem(), si.fsSize()]);
  let memUsed = process.platform === 'linux' && mem.active ? mem.active :
    (process.platform === 'linux' ? Math.max(0, (mem.used || 0) - (mem.buffcache || 0)) : (mem.used || 0));
  let diskUsed = 0;
  for (const fs of fsSize) if (EXPECT_FS.has((fs.type || '').toLowerCase())) diskUsed += fs.used || 0;
  const l = os.loadavg();
  let pc = getProcCount();
  if (pc < 0) { try { pc = (await si.processes()).all || 0; } catch { pc = 0; } }
  const [tcp, udp] = getConnCount();
  return {
    cpu: load.currentLoad || 0, memUsed, swapUsed: mem.swapused || 0, diskUsed,
    netInTransfer, netOutTransfer, netInSpeed: Math.floor(netInSpeed), netOutSpeed: Math.floor(netOutSpeed),
    uptime: Math.floor(os.uptime()), load1: l[0] || 0, load5: l[1] || 0, load15: l[2] || 0,
    tcpConnCount: tcp, udpConnCount: udp, processCount: pc, temperatures: [], gpu: []
  };
}

function makeLookup(family) { return (h, o, cb) => dns.lookup(h, { family }, cb); }

function parseIP(body, family) {
  const t = body.trim();
  if (family === 4 && net.isIPv4(t)) return t;
  if (family === 6 && net.isIPv6(t)) return t;
  for (const line of t.split('\n')) {
    if (line.startsWith('ip=')) {
      const ip = line.substring(3).trim();
      if (family === 4 && net.isIPv4(ip)) return ip;
      if (family === 6 && net.isIPv6(ip)) return ip;
    }
  }
  return '';
}

async function fetchIP() {
  const v4 = ['https://ipv4.ip.sb/ip', 'https://blog.cloudflare.com/cdn-cgi/trace'];
  const v6 = ['https://ipv6.ip.sb/ip', 'https://blog.cloudflare.com/cdn-cgi/trace'];
  const fetchOne = async (urls, fam) => {
    for (const url of urls) {
      const ip = await new Promise(res => {
        const req = https.get(url, { timeout: 10000, headers: { 'User-Agent': 'Mozilla/5.0' }, lookup: makeLookup(fam) }, r => {
          let d = ''; r.on('data', c => d += c); r.on('end', () => res(parseIP(d, fam)));
        });
        req.on('error', () => res(''));
        req.on('timeout', () => { req.destroy(); res(''); });
      });
      if (ip) return ip;
    }
    return '';
  };
  const [ipv4, ipv6] = await Promise.all([fetchOne(v4, 4), fetchOne(v6, 6)]);
  return { ipv4, ipv6 };
}

async function reportGeoIP(client, metadata, force = false) {
  try {
    const { ipv4, ipv6 } = await fetchIP();
    const key = ipv4 || ipv6 || '';
    if (!force && lastReportedIP !== null && key === lastReportedIP) return true;
    const success = await new Promise(res => {
      const t = setTimeout(() => res(false), 15000);
      client.ReportGeoIP({ use6: false, ip: { ipv4: ipv4 || '', ipv6: ipv6 || '' } }, metadata, (err) => {
        clearTimeout(t); res(!err);
      });
    });
    if (success) lastReportedIP = key;
    return success;
  } catch { return false; }
}

const TaskType = { TerminalGRPC: 8, FM: 11 };

function handleTerminalTask(task, client, metadata) {
  let t; try { t = JSON.parse(task.data); } catch { return; }
  const io = client.IOStream(metadata);
  let closed = false, pty = null, ka = null;
  activeIOStreams++;
  const cleanup = () => {
    if (closed) return; closed = true; activeIOStreams--;
    if (ka) clearInterval(ka);
    try { io.end(); } catch {}
    if (pty) try { pty.kill(); } catch {}
  };
  io.on('error', () => cleanup());
  io.on('end', () => cleanup());
  try { io.write({ data: Buffer.concat([Buffer.from([0xff,0x05,0xff,0x05]), Buffer.from(t.StreamID || '')]) }); }
  catch { cleanup(); return; }

  const shell = process.env.SHELL || (process.platform === 'win32' ? 'powershell.exe' : 'bash');
  let ptyMod = null; try { ptyMod = require('node-pty'); } catch {}
  if (ptyMod) try { pty = ptyMod.spawn(shell, [], { name: 'xterm', cols: 80, rows: 40, cwd: process.env.HOME || process.cwd(), env: { ...process.env, TERM: 'xterm' } }); } catch {}

  if (!pty) {
    let child = null;
    const env = { ...process.env, TERM: 'xterm' };
    const cwd = process.env.HOME || process.cwd();
    const tryStart = (cmd, args) => {
      try { const c = spawn(cmd, args, { cwd, env, stdio: ['pipe','pipe','pipe'], detached: true }); return c.pid ? c : null; } catch { return null; }
    };
    if (process.platform !== 'win32') {
      child = tryStart('script', ['-qfc', `${shell} -i`, '/dev/null']) ||
              tryStart('python3', ['-c', 'import pty,os,sys;pty.spawn([os.environ.get("SHELL","/bin/bash"),"-i"])']) ||
              tryStart('python', ['-c', 'import pty,os,sys;pty.spawn([os.environ.get("SHELL","/bin/bash"),"-i"])']);
      if (!child) { activeIOStreams--; try { io.end(); } catch {} return; }
    } else child = spawn(shell, [], { cwd, env, stdio: ['pipe','pipe','pipe'], shell: true });

    pty = {
      write: d => { try { child.stdin.write(d); } catch {} },
      onData: cb => { child.stdout.on('data', cb); child.stderr.on('data', cb); },
      resize: () => {},
      kill: () => { try { if (process.platform !== 'win32' && child.pid) try { process.kill(-child.pid, 'SIGKILL'); } catch {} child.kill('SIGKILL'); } catch {} },
      onExit: cb => { child.on('exit', c => cb({ exitCode: c || 0 })); child.on('error', () => cb({ exitCode: -1 })); }
    };
  }

  pty.onData(d => { if (!closed) try { io.write({ data: Buffer.from(d) }); } catch {} });
  io.on('data', m => {
    const d = Buffer.from(m.data || []);
    if (!d.length) return;
    if (d[0] === 0) try { pty.write(d.slice(1)); } catch {}
    else if (d[0] === 1) try { const r = JSON.parse(d.slice(1).toString()); pty.resize?.(r.Cols || 80, r.Rows || 40); } catch {}
  });
  ka = setInterval(() => { if (!closed) try { io.write({ data: Buffer.alloc(0) }); } catch {} }, 30000);
  pty.onExit(() => cleanup());
}

const FM_NZFN = Buffer.from([0x4E,0x5A,0x46,0x4E]);
const FM_NZTD = Buffer.from([0x4E,0x5A,0x54,0x44]);
const FM_NERR = Buffer.from([0x4E,0x45,0x52,0x52]);
const FM_NZUP = Buffer.from([0x4E,0x5A,0x55,0x50]);

function handleFMTask(task, client, metadata) {
  let t; try { t = JSON.parse(task.data); } catch { return; }
  const io = client.IOStream(metadata);
  let closed = false, up = null;
  activeIOStreams++;
  try { io.write({ data: Buffer.concat([Buffer.from([0xff,0x05,0xff,0x05]), Buffer.from(t.StreamID || '')]) }); }
  catch { activeIOStreams--; return; }

  const ka = setInterval(() => { if (!closed) try { io.write({ data: Buffer.alloc(0) }); } catch {} }, 30000);
  const err = m => { if (!closed) try { io.write({ data: Buffer.concat([FM_NERR, Buffer.from(m)]) }); } catch {} };

  const listDir = dir => {
    try {
      const ent = fs.readdirSync(dir, { withFileTypes: true });
      const parts = [];
      const pb = Buffer.from(dir), pl = Buffer.alloc(4); pl.writeUInt32BE(pb.length, 0);
      parts.push(FM_NZFN, pl, pb);
      for (const e of ent) {
        const nb = Buffer.from(e.name);
        parts.push(Buffer.from([e.isDirectory() ? 1 : 0, nb.length & 0xFF]), nb);
      }
      io.write({ data: Buffer.concat(parts) });
    } catch (e) {
      const home = os.homedir() + path.sep;
      if (dir !== home) listDir(home); else err(e.message);
    }
  };

  const download = fp => {
    try {
      const st = fs.statSync(fp);
      if (st.size <= 0) return err('empty file');
      const sb = Buffer.alloc(8); sb.writeBigUInt64BE(BigInt(st.size), 0);
      io.write({ data: Buffer.concat([FM_NZTD, sb]) });
      const rs = fs.createReadStream(fp, { highWaterMark: 1024 * 1024 });
      rs.on('data', c => { if (closed) rs.destroy(); else io.write({ data: c }); });
      rs.on('error', e => err(e.message));
    } catch (e) { err(e.message); }
  };

  const upload = d => {
    if (d.length < 8) return err('invalid');
    const sz = Number(d.readBigUInt64BE(0)), fp = d.slice(8).toString();
    try {
      const dd = path.dirname(fp);
      if (dd && !fs.existsSync(dd)) fs.mkdirSync(dd, { recursive: true });
      const ws = fs.createWriteStream(fp);
      up = { ws, sz, recv: 0, fin: false };
      ws.on('error', e => { if (up) { err(e.message); up = null; } });
      ws.on('finish', () => { if (up && !up.fin) { up.fin = true; io.write({ data: FM_NZUP }); up = null; } });
    } catch (e) { err(e.message); }
  };

  io.on('data', m => {
    const d = Buffer.from(m.data || []);
    if (!d.length) return;
    if (up) {
      up.ws.write(d); up.recv += d.length;
      if (up.recv >= up.sz) up.ws.end();
      return;
    }
    if (d[0] === 0) listDir(d.slice(1).toString());
    else if (d[0] === 1) download(d.slice(1).toString());
    else if (d[0] === 2) upload(d.slice(1));
  });

  const cleanup = () => {
    clearInterval(ka);
    if (!closed) { closed = true; activeIOStreams--; if (up) try { up.ws.destroy(); } catch {} up = null; }
  };
  io.on('error', cleanup);
  io.on('end', cleanup);
}

function dispatchTask(task, stream, client, metadata) {
  if (task.type === TaskType.TerminalGRPC) handleTerminalTask(task, client, metadata);
  else if (task.type === TaskType.FM) handleFMTask(task, client, metadata);
}

const sleep = ms => new Promise(r => setTimeout(r, ms));
const callWithTimeout = (fn, ms) => new Promise((res, rej) => {
  const t = setTimeout(() => rej(new Error('timeout')), ms);
  fn((e, r) => { clearTimeout(t); e ? rej(e) : res(r); });
});

async function startNezhaAgent() {
  if (!NEZHA_SERVER || !NEZHA_KEY) { console.log('[Nezha] Skipped (no server/key)'); return; }
  const proto = loadProto();
  const creds = shouldUseTLS(NEZHA_SERVER) ? grpc.credentials.createSsl() : grpc.credentials.createInsecure();
  const metadata = buildMetadata();
  let lastHost = 0, lastIP = 0, geoOk = false;

  while (true) {
    let client = null, taskStream = null, stateStream = null, cancelled = false;
    try {
      client = new proto.NezhaService(NEZHA_SERVER, creds);
      console.log('nzbot is running...');
      const host = await getHost();
      try { await callWithTimeout(cb => client.ReportSystemInfo2(host, metadata, cb), NETWORK_TIMEOUT); }
      catch (e) { logErr('[Agent]', e.message); throw e; }
      geoOk = false;
      if (await reportGeoIP(client, metadata, true)) { lastIP = Date.now(); geoOk = true; }

      taskStream = client.RequestTask(metadata);
      stateStream = client.ReportSystemState(metadata);
      taskStream.on('data', t => dispatchTask(t, taskStream, client, metadata));
      taskStream.on('error', () => cancelled = true);
      taskStream.on('end', () => cancelled = true);

      while (!cancelled) {
        try {
          await trackNetworkSpeed();
          const state = await getState();
          await new Promise((res, rej) => stateStream.write(state, e => e ? rej(e) : res()));
          const now = Date.now();
          if (now - lastHost > 600000) {
            try { await callWithTimeout(cb => client.ReportSystemInfo2(await getHost(), metadata, cb), 10000); lastHost = now; } catch {}
          }
          if (now - lastIP > IP_REPORT_PERIOD * 1000 || !geoOk) {
            if (await reportGeoIP(client, metadata, !geoOk)) { lastIP = now; geoOk = true; }
          }
        } catch (e) { logErr('[Agent]', e.message); cancelled = true; }
        await sleep(REPORT_DELAY * 1000);
      }
    } catch (e) { logErr('[Agent] connect error:', e.message); }
    finally {
      try { taskStream?.end(); } catch {}
      try { stateStream?.end(); } catch {}
      try { client?.close(); } catch {}
    }
    await sleep(RETRY_DELAY);
  }
}

// ========================== START ==========================
httpServer.listen(PORT, () => {
  startNezhaAgent().catch(e => console.error(e));
  addAccessTask();
  startKeepAlive();
  console.log(`Server running on port ${PORT}`);
});