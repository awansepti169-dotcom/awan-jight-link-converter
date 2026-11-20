const dns = require("node:dns").promises;
const net = require("node:net");

const ALLOWED_HOSTS = [
  "sfl.gl", "sub4unlock.com", "sub4unlock.io", "sub2unlock.com",
  "sub2unlock.io", "linkvertise.com", "linkvertise.net", "ouo.io", "ouo.press",
  "mediafire.com", "www.mediafire.com"
];

function isPrivate(ip) {
  if (net.isIPv4(ip)) {
    const p = ip.split(".").map(Number);
    return p[0] === 10 || p[0] === 127 || p[0] === 0 ||
      (p[0] === 169 && p[1] === 254) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) || p[0] >= 224;
  }
  if (net.isIPv6(ip)) {
    const x = ip.toLowerCase();
    return x === "::1" || x === "::" || x.startsWith("fc") || x.startsWith("fd") ||
      x.startsWith("fe80:") || x.startsWith("::ffff:127.");
  }
  return true;
}
async function validatePublicHost(host) {
  if (host === "localhost" || host.endsWith(".local")) throw new Error("Host lokal tidak diizinkan.");
  const records = await dns.lookup(host, {all:true});
  if (!records.length || records.some(r => isPrivate(r.address))) throw new Error("Alamat tujuan tidak diizinkan.");
}
function isMediafire(url) {
  try { const h = new URL(url).hostname.toLowerCase(); return h === "mediafire.com" || h.endsWith(".mediafire.com"); }
  catch { return false; }
}
exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return {statusCode:405,body:JSON.stringify({error:"Method not allowed"})};
  try {
    const body = JSON.parse(event.body || "{}");
    let current = new URL(body.url);
    if (!["http:","https:"].includes(current.protocol)) throw new Error("Gunakan tautan http atau https.");
    if (current.username || current.password) throw new Error("URL dengan kredensial tidak diizinkan.");
    const startHost = current.hostname.toLowerCase();
    const supported = ALLOWED_HOSTS.some(h => startHost === h || startHost.endsWith("." + h));
    if (!supported) throw new Error("Domain ini belum termasuk daftar layanan yang didukung.");
    let hops = 0;
    const seen = new Set();
    while (hops < 8) {
      if (seen.has(current.href)) break;
      seen.add(current.href);
      await validatePublicHost(current.hostname);
      const response = await fetch(current.href, {
        method:"GET", redirect:"manual",
        headers:{"User-Agent":"AwanJightLinkChecker/1.0","Accept":"text/html,application/xhtml+xml"}
      });
      if ([301,302,303,307,308].includes(response.status)) {
        const location = response.headers.get("location");
        if (!location) break;
        current = new URL(location, current);
        if (!["http:","https:"].includes(current.protocol)) throw new Error("Redirect dengan protokol tidak diizinkan.");
        hops++;
        continue;
      }
      break;
    }
    const finalUrl = current.href;
    const found = isMediafire(finalUrl);
    return {statusCode:200,headers:{"Content-Type":"application/json","Cache-Control":"no-store"},body:JSON.stringify({
      finalUrl, mediafireUrl:found ? finalUrl : null, hops,
      message:found ? "Tujuan redirect publik mengarah ke MediaFire." :
        "Redirect publik berhasil diperiksa, tetapi tujuan MediaFire belum terdeteksi. Jika ada halaman CAPTCHA, login, subscribe, atau JavaScript gate, pemeriksaan berhenti di sana."
    })};
  } catch (e) {
    return {statusCode:400,headers:{"Content-Type":"application/json"},body:JSON.stringify({error:e.message || "Invalid request"})};
  }
};
