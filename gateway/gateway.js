// Claude cookie-injecting gateway
// Root path (/foo) -> claude.ai/foo  (relative URLs work!)
// /p/<host>/<path> -> <host>/<path>   (asset domains)
const http=require("http"),https=require("https"),fs=require("fs");
const COOKIES_FILE=process.env.COOKIES_FILE||"/cookies/claude.json";
const PORT=parseInt(process.env.PORT||"8088",10);
const LISTEN=process.env.LISTEN||"0.0.0.0";
const PUBLIC_HOST=process.env.PUBLIC_HOST||"claude.jft-foruse.com";
const FIXED_UA=process.env.FIXED_UA||"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36";
const UPSTREAM_TIMEOUT_MS=parseInt(process.env.UPSTREAM_TIMEOUT_MS||"30000",10);
const ALLOWED_HOSTS=new Set(["claude.ai","www.claude.ai","assets.claude.ai","assets-proxy.anthropic.com"]);
const COOKIE_HOSTS=new Set(["claude.ai","www.claude.ai"]);
const UPSTREAMS={}; ALLOWED_HOSTS.forEach(h=>UPSTREAMS[h]=h);
let cookieHeader="",cookieMtime=0;
function loadCookies(){try{const st=fs.statSync(COOKIES_FILE);if(st.mtimeMs===cookieMtime)return;cookieMtime=st.mtimeMs;const d=JSON.parse(fs.readFileSync(COOKIES_FILE,"utf8"));cookieHeader=(d.cookies||[]).map(c=>c.name+"="+c.value).join("; ");console.log("[cookies] loaded "+(d.cookies||[]).length);}catch(e){console.error("[cookies] "+e.message);}}
loadCookies();setInterval(loadCookies,15000);
function pub(h,p){return "https://"+PUBLIC_HOST+(h==="claude.ai"?"":"/p/"+h)+p;}
function rewriteBody(buf,ct){
  if(!ct||!(ct.includes("text/html")||ct.includes("text/css")||ct.includes("javascript")))return buf;
  let s=buf.toString("utf8");
  for(const h of ALLOWED_HOSTS){ if(h==="claude.ai")continue; s=s.replace(new RegExp("https?://"+h.replace(/\./g,"\\."),"g"),pub(h,"")); }
  return Buffer.from(s,"utf8");
}
function rewriteCsp(csp){
  if(!csp) return csp;
  const hosts=["assets-proxy.anthropic.com","assets.claude.ai","a-cdn.claude.ai","a.claude.ai","a-cdn.anthropic.com","s-cdn.anthropic.com"];
  let out=csp;
  for(const h of hosts){ out=out.split(h).join(PUBLIC_HOST); }
  out=out.replace(/\*\.anthropic\.com/g, "*."+PUBLIC_HOST+" *.anthropic.com");
  out=out.replace(/\*\.claude\.ai/g, "*."+PUBLIC_HOST+" *.claude.ai");
  out=out.replace(/\*\.claude\.com/g, "*."+PUBLIC_HOST+" *.claude.com");
  return out;
}
const server=http.createServer((req,res)=>{
  if(req.url==="/__health"){res.writeHead(200,{"content-type":"application/json"});return res.end(JSON.stringify({ok:true,cookies:cookieHeader?"loaded":"empty"}));}
  let host,urlPath;
  const m=req.url.match(/^\/p\/([^\/]+)(\/.*)?$/);
  if(m){host=m[1];urlPath=m[2]||"/";if(!ALLOWED_HOSTS.has(host)){res.writeHead(403);return res.end("host not allowed");}}
  else{host="claude.ai";urlPath=req.url;}
  const chunks=[];req.on("data",c=>chunks.push(c));
  req.on("end",()=>{
    const body=Buffer.concat(chunks);
    const headers={...req.headers};
    ["host","cookie","origin","referer","x-forwarded-for","x-forwarded-host","x-forwarded-proto","true-client-ip","accept-encoding","authorization","proxy-authorization"].forEach(k=>delete headers[k]);
    headers["host"]=host;
    if(COOKIE_HOSTS.has(host))headers["cookie"]=cookieHeader;
    headers["accept-language"]="en-US,en;q=0.9";
    headers["user-agent"]=FIXED_UA;
    if(COOKIE_HOSTS.has(host)){headers["origin"]="https://"+host;headers["referer"]="https://"+host+"/";}
    if(urlPath.startsWith("/v1/")||urlPath.startsWith("/api/")){
      const ah=Object.keys(headers).filter(k=>k.startsWith("anthropic"));
      console.log("[api] "+req.method+" "+urlPath+" anthropic-headers:["+ah.join(",")+"]");
    }
    const proxyReq=https.request({hostname:host,port:443,path:urlPath,method:req.method,headers},(proxyRes)=>{
      const rh={...proxyRes.headers};delete rh["set-cookie"];
      if(rh["content-security-policy"])rh["content-security-policy"]=rewriteCsp(rh["content-security-policy"]);
      if(rh["location"]){for(const h of ALLOWED_HOSTS){rh["location"]=rh["location"].replace(new RegExp("https?://"+h,"g"),pub(h,""));}}
      const ct=rh["content-type"]||"";
      if(ct.includes("text/html")||ct.includes("text/css")||ct.includes("javascript")){
        const bc=[];proxyRes.on("data",c=>bc.push(c));proxyRes.on("end",()=>{
          const rb=rewriteBody(Buffer.concat(bc),ct);
          delete rh["content-length"];rh["content-length"]=rb.length;
          if(ct.includes("text/html")){rh["cache-control"]="no-cache, no-store, must-revalidate";}
          else{rh["cache-control"]="public, max-age=86400";}
          console.log("[resp] "+host+" "+urlPath+" -> "+proxyRes.statusCode+" (rewritten)");
          res.writeHead(proxyRes.statusCode,rh);res.end(rb);
        });
      } else {
      console.log("[resp] "+host+" "+urlPath+" -> "+proxyRes.statusCode);
      res.writeHead(proxyRes.statusCode,rh);proxyRes.pipe(res);
      }
    });
    proxyReq.setTimeout(UPSTREAM_TIMEOUT_MS,()=>proxyReq.destroy(new Error("timeout")));
    proxyReq.on("error",e=>{console.error("[upstream "+host+"] "+e.message);if(!res.headersSent){res.writeHead(502);res.end("bad gateway");}else res.end();});
    if(body.length)proxyReq.write(body);proxyReq.end();
  });
  req.on("error",()=>{});
});
server.listen(PORT,LISTEN,()=>console.log("[gateway] listening on "+LISTEN+":"+PORT));
