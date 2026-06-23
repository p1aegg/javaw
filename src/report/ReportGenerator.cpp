#include "report/ReportGenerator.hpp"

#include <Windows.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <vector>

namespace report {

namespace {

const char* SeverityClass(scanner::Severity s) {
    switch (s) {
        case scanner::Severity::Detect: return "detect";
        case scanner::Severity::Warning: return "warning";
        case scanner::Severity::Suspicious: return "suspicious";
        default: return "detect";
    }
}

bool IsSystemIntegrityDetection(const std::string& message) {
    std::string lower = message;
    for (auto& ch : lower) ch = static_cast<char>(tolower(static_cast<unsigned char>(ch)));
    return lower.find("(system integrity)") != std::string::npos ||
           lower.find("(system tampering)") != std::string::npos;
}

bool IsBypassDetection(const std::string& message) {
    std::string lower = message;
    for (auto& ch : lower) ch = static_cast<char>(tolower(static_cast<unsigned char>(ch)));
    static const std::vector<std::string> patterns = {
        "-dfabric.", "-dforge.", "-dfml.", "-dquilt.",
        "-djava.security.manager=", "-djava.security.policy=", "-xbootclasspath",
        "-xx:+enabledynamicagentloading", "-dclient.brand=", "-dlauncher.brand=",
        "-dfabric.launcher.brand=", "-dfabric.launcher.name="
    };
    for (const auto& pattern : patterns) {
        if (lower.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

static std::string EscapeHtml(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char ch : s) {
        switch (ch) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out += ch; break;
        }
    }
    return out;
}

static std::string ToHex(uintptr_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << value;
    return oss.str();
}

static std::string JoinAddresses(const std::vector<uintptr_t>& addresses) {
    std::ostringstream oss;
    for (std::size_t i = 0; i < addresses.size(); ++i) {
        if (i > 0) oss << ", ";
        oss << ToHex(addresses[i]);
    }
    return oss.str();
}

} // end anonymous namespace

std::string GenerateHtmlReport(const scanner::ScanSummary& summary, const std::string& outPath) {
    std::ostringstream detectsRows;
    std::ostringstream bypassRows;
    std::ostringstream warningRows;
    std::ostringstream suspiciousRows;
    std::ostringstream systemIntegrityRows;
    std::ostringstream highlights;

    struct UniqueDetection {
        scanner::Severity severity;
        std::string message;
        int totalHits = 0;
        std::string timestamp;
        uintptr_t address = 0;
        uintptr_t baseAddress = 0;
        std::vector<uintptr_t> hitAddresses;
    };

    std::map<std::pair<scanner::Severity, std::string>, UniqueDetection> uniqueDetections;

    for (const auto& d : summary.detections) {
        const auto key = std::make_pair(d.severity, d.message);
        if (uniqueDetections.find(key) == uniqueDetections.end()) {
            UniqueDetection ud;
            ud.severity = d.severity;
            ud.message = d.message;
            ud.totalHits = d.hits;
            ud.timestamp = d.timestamp;
            ud.address = d.address;
            ud.baseAddress = d.baseAddress;
            ud.hitAddresses = d.hitAddresses;
            uniqueDetections[key] = ud;
        } else {
            uniqueDetections[key].totalHits += d.hits;
            for (const auto& addr : d.hitAddresses) {
                if (std::find(uniqueDetections[key].hitAddresses.begin(),
                              uniqueDetections[key].hitAddresses.end(), addr) ==
                    uniqueDetections[key].hitAddresses.end()) {
                    uniqueDetections[key].hitAddresses.push_back(addr);
                }
            }
        }
    }

    std::vector<UniqueDetection> sortedDetections;
    for (const auto& [key, detection] : uniqueDetections) {
        sortedDetections.push_back(detection);
    }

    std::sort(sortedDetections.begin(), sortedDetections.end(),
              [](const UniqueDetection& a, const UniqueDetection& b) {
                  if (a.severity != b.severity) return static_cast<int>(a.severity) < static_cast<int>(b.severity);
                  std::string aLower = a.message, bLower = b.message;
                  for (auto& ch : aLower) ch = static_cast<char>(tolower(static_cast<unsigned char>(ch)));
                  for (auto& ch : bLower) ch = static_cast<char>(tolower(static_cast<unsigned char>(ch)));
                  return aLower < bLower;
              });

    int detectionId = 1;
    for (const auto& d : sortedDetections) {
        std::string categoryClass;
        if (d.severity == scanner::Severity::Detect)      categoryClass = "cat-detect";
        else if (IsBypassDetection(d.message))             categoryClass = "cat-bypass";
        else if (IsSystemIntegrityDetection(d.message))    categoryClass = "cat-system";
        else if (d.severity == scanner::Severity::Warning) categoryClass = "cat-warning";
        else                                               categoryClass = "cat-suspicious";

        std::ostringstream row;
        row << "<div class='log-row " << SeverityClass(d.severity) << " " << categoryClass << "'"
            << " data-id='" << detectionId << "'"
            << " data-sev='" << SeverityClass(d.severity) << "'"
            << " data-hits='" << d.totalHits << "'"
            << " data-time='" << EscapeHtml(d.timestamp) << "'"
            << " data-msg='" << EscapeHtml(d.message) << "'"
            << " data-addr='" << ToHex(d.address) << "'"
            << " data-base='" << ToHex(d.baseAddress) << "'"
            << " data-all-addrs='" << EscapeHtml(JoinAddresses(d.hitAddresses)) << "'>"
            << "<span class='time'>[" << EscapeHtml(d.timestamp) << "]</span>"
            << "<span class='dot'></span>"
            << "<span class='msg'>" << EscapeHtml(d.message) << " (" << d.totalHits << " times)</span>"
            << "</div>\n";

        if (d.severity == scanner::Severity::Detect) detectsRows << row.str();
        else if (IsBypassDetection(d.message)) bypassRows << row.str();
        else if (d.severity == scanner::Severity::Warning) warningRows << row.str();
        else if (IsSystemIntegrityDetection(d.message)) systemIntegrityRows << row.str();
        else suspiciousRows << row.str();

        std::string low = d.message;
        for (auto& ch : low) ch = static_cast<char>(tolower(static_cast<unsigned char>(ch)));
        if (low.find("doomsday") != std::string::npos) {
            highlights << "<div class='critical'><div class='critical-title'>Doomsday Found</div><div class='critical-body'>"
                       << EscapeHtml(d.message) << "</div></div>\n";
        }
        ++detectionId;
    }

    int bypassCount = 0;
    int suspiciousCountExcludingSystem = 0;
    for (const auto& d : sortedDetections) {
        if (IsBypassDetection(d.message)) bypassCount += d.totalHits;
        if (d.severity == scanner::Severity::Suspicious && !IsSystemIntegrityDetection(d.message))
            suspiciousCountExcludingSystem += d.totalHits;
    }
    int systemIntegrityCount = 0;
    for (const auto& d : sortedDetections) {
        if (IsSystemIntegrityDetection(d.message)) systemIntegrityCount += d.totalHits;
    }
    int warningCountExcludingBypass = std::max<int>(0, static_cast<int>(summary.warningCount) - bypassCount);

    const std::string html =
        "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'/>"
        "<title>P1AE javaw - Detection Results</title>"
        "<style>"
        ":root{--bg0:#000000;--bg1:#0a0a0a;--glass:rgba(10,10,10,.88);--glass2:rgba(6,6,6,.82);"
        "--border:rgba(255,255,255,.25);--border2:rgba(255,255,255,.08);"
        "--text:#ebeaf8;--muted:#8888a0;--accent:#d0d0e0;--accent2:#e8e8f0;"
        "--red:#e05555;--yellow:#c8b040;--blue:#5588d8;--green:#40c070;}"
        "html,body{height:100%;margin:0;}"
        "body{color:var(--text);font-family:Segoe UI,Arial,sans-serif;overflow:hidden;background:#000000;}"
        "#bg{position:fixed;inset:0;z-index:0;}"
        ".vignette{position:fixed;inset:0;z-index:1;pointer-events:none;background:radial-gradient(1100px 750px at 50% 30%, rgba(0,0,0,0) 0%, rgba(0,0,0,.35) 60%, rgba(0,0,0,.82) 100%);}"
        ".app{position:relative;z-index:2;height:100%;display:flex;flex-direction:column;}"
        ".top{display:flex;align-items:center;justify-content:space-between;padding:22px 30px;}"
        ".brand-center{font-weight:800;letter-spacing:7px;font-size:44px;color:var(--accent2);text-shadow:0 0 22px rgba(255,255,255,.25),0 0 45px rgba(180,180,200,.18);}"
        ".top-right,.top-left{color:var(--accent);font-weight:700;opacity:.95;}"
        ".wrap{flex:1;display:flex;align-items:flex-start;gap:18px;padding:0 22px 22px 22px;min-height:0;}"
        ".card{background:linear-gradient(180deg,var(--glass),var(--glass2));border:1px solid var(--border);border-radius:16px;backdrop-filter:blur(12px);box-shadow:0 0 0 1px var(--border2), 0 0 40px rgba(255,255,255,.06);}"
        ".left{width:295px;padding:18px;display:flex;flex-direction:column;gap:10px;align-self:flex-start;height:max-content;}"
        ".left h2{margin:4px 0 0 0;font-size:18px;letter-spacing:.2px;}"
        ".sub{color:var(--muted);font-size:12.5px;line-height:1.35;}"
        ".tabs{margin-top:6px;display:flex;flex-direction:column;gap:10px;}"
        ".tab{cursor:pointer;user-select:none;display:flex;align-items:center;justify-content:space-between;padding:12px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.12);background:rgba(14,14,14,.72);transition:all .18s;}"
        ".tab:hover{transform:scale(1.01);box-shadow:0 0 18px rgba(255,255,255,.10);border-color:rgba(255,255,255,.22);}"
        ".tab.active{background:rgba(28,28,28,.82);border-color:rgba(255,255,255,.30);box-shadow:0 0 26px rgba(255,255,255,.12);}"
        ".tab .label{display:flex;align-items:center;gap:10px;font-size:13px;}"
        ".pill{min-width:34px;text-align:center;font-weight:800;border-radius:10px;padding:3px 8px;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.16);}"
        ".ico{width:10px;height:10px;border-radius:50%;}"
        ".ico.detect{background:var(--red);}.ico.warning{background:var(--yellow);}.ico.suspicious{background:var(--blue);}.ico.system{background:var(--green);}.ico.bypass{background:#9f7bff;}"
        ".main{flex:1;min-width:0;align-self:flex-start;height:max-content;padding:18px;display:flex;flex-direction:column;gap:10px;}"
        ".main-header{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;}"
        ".main h2{margin:0;font-size:18px;letter-spacing:.2px;}"
        ".meta{color:var(--muted);font-size:12.5px;line-height:1.35;}"
        ".logs{display:flex;flex-direction:column;gap:12px;max-height:58vh;overflow:auto;padding:20px 12px;}"
        ".logs::-webkit-scrollbar{width:10px;}.logs::-webkit-scrollbar-thumb{background:rgba(255,255,255,.18);border-radius:999px;border:2px solid rgba(4,4,4,.75);}.logs::-webkit-scrollbar-track{background:rgba(0,0,0,.25);border-radius:999px;}"
        ".log-row{"
        "display:flex;align-items:center;gap:14px;padding:14px 24px;"
        "border-radius:9999px;border:1px solid rgba(255,255,255,.12);"
        "background:rgba(12,12,12,.90);"
        "cursor:pointer;transition:all .25s ease;"
        "position:relative;overflow:hidden;"
        "margin-bottom:6px;"
        "}"
        ".log-row:hover{"
        "background:rgba(28,28,28,.96);"
        "border-color:rgba(255,255,255,.35);"
        "}"
        ".log-row::before{"
        "content:'';position:absolute;inset:0;"
        "background:linear-gradient(90deg, transparent, rgba(255,255,255,.06), transparent);"
        "opacity:0;transition:opacity .3s;pointer-events:none;border-radius:9999px;"
        "}"
        ".log-row:hover::before{opacity:1;}"
        ".time{color:#b0b0c8;font-family:Consolas,ui-monospace,Menlo,monospace;font-size:12px;opacity:.9;}"
        ".dot{width:11px;height:11px;border-radius:50%;display:inline-block;box-shadow:0 0 14px rgba(0,0,0,.3);}"
        ".log-row.cat-detect .dot{background:var(--red);box-shadow:0 0 20px rgba(200,80,80,.5);}"
        ".log-row.cat-warning .dot{background:var(--yellow);box-shadow:0 0 18px rgba(200,180,60,.4);}"
        ".log-row.cat-suspicious .dot{background:var(--blue);box-shadow:0 0 18px rgba(80,140,220,.4);}"
        ".log-row.cat-system .dot{background:var(--green);box-shadow:0 0 18px rgba(60,190,100,.4);}"
        ".log-row.cat-bypass .dot{background:#9f7bff;box-shadow:0 0 18px rgba(159,123,255,.4);}"
        ".msg{flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:13px;}"
        ".critical{margin-top:8px;padding:14px 14px;border-radius:14px;border:1px solid rgba(255,255,255,.22);background:linear-gradient(180deg, rgba(22,22,22,.92), rgba(12,12,12,.78));box-shadow:0 0 32px rgba(255,255,255,.06), inset 0 0 0 1px rgba(255,255,255,.06);}"
        ".critical-title{font-weight:900;color:#e8e8f8;letter-spacing:.7px;margin-bottom:6px;}"
        ".critical-body{color:#c8c8d8;font-size:13px;}"
        ".detail-page{display:none;flex:1;min-height:0;overflow:auto;padding:6px 2px 2px 2px;}"
        ".detail-header{display:flex;align-items:center;justify-content:space-between;gap:10px;}"
        ".back-btn{cursor:pointer;border:1px solid rgba(255,255,255,.22);background:rgba(255,255,255,.05);color:#d8d8e8;border-radius:10px;padding:7px 14px;font-weight:700;transition:all .2s ease;}"
        ".back-btn:hover{background:rgba(255,255,255,.12);border-color:rgba(255,255,255,.45);}"
        ".detail-grid{margin-top:12px;display:grid;grid-template-columns:180px 1fr;gap:10px;}"
        ".detail-k{color:var(--muted);font-size:12px;}"
        ".detail-v{font-size:13px;color:#e8e8f0;word-break:break-word;}"
        ".detail-box{margin-top:10px;border:1px solid rgba(255,255,255,.14);background:rgba(16,16,16,.55);border-radius:12px;padding:12px;}"
        ".footer{position:fixed;right:22px;bottom:18px;color:rgba(200,200,220,.75);font-size:12px;z-index:3;}"
        "</style></head><body>"
        "<canvas id='bg'></canvas><div class='vignette'></div>"
        "<div class='app'>"
        "<div class='top'>"
        "<div class='top-left'>discord.gg/aRGFyn2ZHH</div>"
        "<div class='brand-center'>P1AE javaw</div>"
        "<div class='top-right'></div>"
        "</div>"
        "<div class='wrap'>"
        "<aside class='left card'>"
        "<h2>Detection Results</h2>"
        "<div class='sub'>" + std::to_string(summary.detections.size()) + " events across 5 categories</div>"
        "<div class='tabs'>"
        "<div class='tab active' data-tab='detects'><div class='label'><span class='ico detect'></span>Detects Logs</div><div class='pill'>" + std::to_string(summary.detectCount) + "</div></div>"
        "<div class='tab' data-tab='system'><div class='label'><span class='ico system'></span>System Integrity</div><div class='pill'>" + std::to_string(systemIntegrityCount) + "</div></div>"
        "<div class='tab' data-tab='bypass'><div class='label'><span class='ico bypass'></span>Bypass Logs</div><div class='pill'>" + std::to_string(bypassCount) + "</div></div>"
        "<div class='tab' data-tab='warnings'><div class='label'><span class='ico warning'></span>Warnings Logs</div><div class='pill'>" + std::to_string(warningCountExcludingBypass) + "</div></div>"
        "<div class='tab' data-tab='suspicious'><div class='label'><span class='ico suspicious'></span>Suspicious Logs</div><div class='pill'>" + std::to_string(suspiciousCountExcludingSystem) + "</div></div>"
        "</div>"
        "</aside>"
        "<main class='main card'>"
        "<div class='main-header'>"
        "<div><h2 id='tabTitle'>Detects Logs</h2></div>"
        "<div class='meta'>PID " + std::to_string(summary.pid) + " • Scan " + EscapeHtml(summary.scanType) + "</div>"
        "</div>"
        + highlights.str() +
        "<div class='logs' id='logs_detects'>" + detectsRows.str() + "</div>"
        "<div class='logs' id='logs_system' style='display:none'>" + systemIntegrityRows.str() + "</div>"
        "<div class='logs' id='logs_bypass' style='display:none'>" + bypassRows.str() + "</div>"
        "<div class='logs' id='logs_warnings' style='display:none'>" + warningRows.str() + "</div>"
        "<div class='logs' id='logs_suspicious' style='display:none'>" + suspiciousRows.str() + "</div>"
        "<div class='detail-page' id='detailPage'>"
        "<div class='detail-header'><h2 id='detailTitle'>Detection Details</h2><button class='back-btn' id='backToLogs'>Back to logs</button></div>"
        "<div class='detail-grid'>"
        "<div class='detail-k'>Detection ID</div><div class='detail-v' id='d_id'>-</div>"
        "<div class='detail-k'>Severity</div><div class='detail-v' id='d_sev'>-</div>"
        "<div class='detail-k'>Hits</div><div class='detail-v' id='d_hits'>-</div>"
        "<div class='detail-k'>Address</div><div class='detail-v' id='d_addr'>-</div>"
        "<div class='detail-k'>Base Address</div><div class='detail-v' id='d_base'>-</div>"
        "<div class='detail-k'>Timestamp</div><div class='detail-v' id='d_time'>-</div>"
        "<div class='detail-k'>PID</div><div class='detail-v'>" + std::to_string(summary.pid) + "</div>"
        "<div class='detail-k'>Scan Type</div><div class='detail-v'>" + EscapeHtml(summary.scanType) + "</div>"
        "</div>"
        "<div class='detail-box'><div class='detail-k' style='margin-bottom:5px'>Message</div><div class='detail-v' id='d_msg'>-</div></div>"
        "<div class='detail-box'><div class='detail-k' style='margin-bottom:5px'>All Hit Addresses</div><div class='detail-v' id='d_all_addrs'>-</div></div>"
        "</div>"
        "</main></div>"
        "<div class='footer'></div></div>"

        "<script>"
        "(function(){"
        "const tabs=[...document.querySelectorAll('.tab')];"
        "const title=document.getElementById('tabTitle');"
        "const detailPage=document.getElementById('detailPage');"
        "const backBtn=document.getElementById('backToLogs');"
        "const logsByTab={detects:document.getElementById('logs_detects'),system:document.getElementById('logs_system'),bypass:document.getElementById('logs_bypass'),warnings:document.getElementById('logs_warnings'),suspicious:document.getElementById('logs_suspicious')};"
        "let activeTab='detects';"
        "function showLogsOnly(){detailPage.style.display='none';Object.keys(logsByTab).forEach(k=>{logsByTab[k].style.display=(k===activeTab)?'block':'none';});}"
        "function show(tab){activeTab=tab;tabs.forEach(t=>t.classList.toggle('active',t.dataset.tab===tab));showLogsOnly();"
        "title.textContent=tab==='detects'?'Detects Logs':tab==='system'?'System Integrity':tab==='bypass'?'Bypass Logs':tab==='warnings'?'Warnings Logs':'Suspicious Logs';}"
        "tabs.forEach(t=>t.addEventListener('click',()=>show(t.dataset.tab)));"
        "if(backBtn)backBtn.addEventListener('click',showLogsOnly);"
        "document.querySelectorAll('.log-row').forEach(row=>{row.addEventListener('click',()=>{"
        "document.getElementById('d_id').textContent=row.dataset.id||'-';"
        "document.getElementById('d_sev').textContent=row.dataset.sev||'-';"
        "document.getElementById('d_hits').textContent=row.dataset.hits||'-';"
        "document.getElementById('d_addr').textContent=row.dataset.addr||'-';"
        "document.getElementById('d_base').textContent=row.dataset.base||'-';"
        "document.getElementById('d_time').textContent=row.dataset.time||'-';"
        "document.getElementById('d_msg').textContent=row.dataset.msg||'-';"
        "document.getElementById('d_all_addrs').textContent=row.dataset.allAddrs||'-';"
        "Object.values(logsByTab).forEach(el=>{if(el)el.style.display='none';});"
        "detailPage.style.display='block';});});"
        "})();"
        "</script>"

        "<script>(function(){"
        "const c=document.getElementById('bg');const ctx=c.getContext('2d');"
        "let w=0,h=0;"
        "function resize(){w=c.width=window.innerWidth;h=c.height=window.innerHeight;}window.addEventListener('resize',resize);resize();"
        "let seed=1337;"
        "function srnd(){seed=(seed*1664525+1013904223)>>>0;return seed/4294967296;}"
        "function srng(a,b){return a+srnd()*(b-a);}"
        "const stars=Array.from({length:220},()=>({x:srng(0,1),y:srng(0,1),r:srng(0.7,2.2),tw:srng(0.5,2.5),sp:srng(0.1,0.5)}));"
        "const snow=Array.from({length:180},(_,i)=>{"
        "const sA=((i*37)%1000)/1000,sB=((i*83+19)%1000)/1000,sC=((i*29+7)%1000)/1000;"
        "return{sA,sB,sC,v:20+sA*35,d:5+sB*10,r:0.6+sB*1.2,a:200+Math.floor(sC*55)};"
        "});"
        "function frame(t){t/=1000;"
        "ctx.fillStyle='rgb(0,0,0)';ctx.fillRect(0,0,w,h);"
        "for(let i=0;i<260;i++){"
        "const x=(i*97+t*(0.4+(i%7)*0.03))%w;"
        "const y=(i*53+t*(0.2+(i%5)*0.02))%h;"
        "const a=(8+(i%9)+8)/255;"
        "ctx.fillStyle=`rgba(200,200,210,${a})`;ctx.beginPath();ctx.arc(x,y,0.8+(i%3)*0.35,0,Math.PI*2);ctx.fill();"
        "}"
        "for(let i=0;i<stars.length;i+=5){"
        "if(i+1>=stars.length)break;"
        "const s=stars[i],n=stars[i+1];"
        "const sx=(s.x*w+t*s.sp*7)%w,sy=(s.y*h+Math.sin(t*0.2+s.tw)*3)%h;"
        "const nx=(n.x*w+t*n.sp*7)%w,ny=(n.y*h)%h;"
        "ctx.strokeStyle='rgba(220,220,230,0.118)';ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(sx,sy);ctx.lineTo(nx,ny);ctx.stroke();"
        "}"
        "for(const s of stars){"
        "const pulse=0.55+0.45*Math.sin(t*(0.9+s.sp)+s.tw);"
        "const alpha=Math.floor(95+150*pulse)/255;"
        "const x=(s.x*w+t*s.sp*7)%w,y=(s.y*h+Math.sin(t*0.2+s.tw)*3)%h;"
        "ctx.fillStyle=`rgba(255,255,255,${alpha})`;ctx.beginPath();ctx.arc(x,y,s.r,0,Math.PI*2);ctx.fill();"
        "}"
        "for(let i=0;i<snow.length;i++){const p=snow[i];"
        "const y=(p.sA*h+t*p.v)%(h+16)-8;"
        "const x=(p.sC*w+Math.sin(t*(0.9+p.sB)+p.sC*6.28)*p.d+w)%w;"
        "const ao=p.a/255;"
        "ctx.fillStyle=`rgba(255,255,255,${ao/3})`;ctx.beginPath();ctx.arc(x,y,p.r+0.8,0,Math.PI*2);ctx.fill();"
        "ctx.fillStyle=`rgba(255,255,255,${ao})`;ctx.beginPath();ctx.arc(x,y,p.r,0,Math.PI*2);ctx.fill();"
        "if(i%4===0){ctx.strokeStyle=`rgba(255,255,255,${ao/2})`;ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(x,y-3);ctx.lineTo(x,y+3);ctx.stroke();}"
        "}"
        "requestAnimationFrame(frame);}"
        "requestAnimationFrame(frame);"
        "})();</script></body></html>";

    std::ofstream out(outPath, std::ios::trunc);
    out << html;
    return std::filesystem::absolute(std::filesystem::path(outPath)).string();
}

void OpenInDefaultBrowser(const std::string& path) {
    ShellExecuteA(nullptr, "open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

} // end of namespace report