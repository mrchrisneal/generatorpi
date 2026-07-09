(function(){
"use strict";
var $=function(id){return document.getElementById(id);};
var panel=$('panel');
var state=null, clockOffset=0, busy=false, confirmOpen=false;
var newestSeq=0, oldestSeq=null, loadingOlder=false, totalEvents=0;

/* ---------- fetch helpers ---------- */
/* Build request URLs from location.origin (which never includes userinfo) rather
   than a bare relative path: if the page was opened via a credentials-in-URL
   bookmark (http://user:pass@host/), a relative fetch would resolve against that
   document URL and the Fetch API rejects constructing a Request from a URL that
   embeds credentials. location.origin strips them, so fetch works either way. */
/* Central TIMED fetch: every request flows through here so the bottom status bar can show
   live connection health, rough latency (time-to-complete), and pending activity -- the
   signal that matters most on the flaky Pi link. */
var NET={pending:0,lastOk:0,lastErr:0,samples:[]};
function _nowMs(){return (window.performance&&performance.now)?performance.now():Date.now();}
function netFetch(path,opts){
  if(NET.pending===0){                     // first request in flight -> arm the slow-line timer
    clearTimeout(NET._slowTimer);
    NET._slowTimer=setTimeout(function(){  // still pending after 1s -> reveal the last-ditch line
      if(NET.pending>0){var h=$('stickyHdr');if(h)h.classList.add('slow');
        var p=$('placard');if(p)p.classList.add('slow');}   // same line on the top placard
    },1000);
  }
  NET.pending++;netRender();
  var t0=_nowMs();
  function settle(){                       // shared teardown (success + error)
    NET.pending--;
    if(NET.pending===0){                   // nothing in flight -> disarm timer + hide the line
      clearTimeout(NET._slowTimer);
      var h=$('stickyHdr');if(h)h.classList.remove('slow');
      var p=$('placard');if(p)p.classList.remove('slow');   // clear the placard line too
    }
    netRender();
  }
  return fetch(location.origin+path,opts||{}).then(function(r){
    NET.samples.push(_nowMs()-t0);if(NET.samples.length>8)NET.samples.shift(); // rolling avg of last 8
    NET.lastOk=Date.now();settle();return r;
  },function(e){NET.lastErr=Date.now();settle();throw e;});
}
function api(path,opts){return netFetch(path,opts).then(function(r){return r.json().catch(function(){return {};});});}
function post(path,body){return api(path,{method:'POST',headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});}
/* GLOBAL SERIAL poll queue for the flaky Pi link: at most ONE poll request is ever in
   flight at a time across ALL pollers (state / events / history) -- a laggy link is never
   asked to juggle concurrent requests competing for the same starved bandwidth. Coalesced
   per key: re-requesting a poll whose previous is still QUEUED just refreshes that queued
   entry (with the freshest path, e.g. history's ?since=), so nothing piles up -- the queue
   holds at most one job per key. A job that hangs past `ms` is aborted so the queue can't
   wedge. Resolves to parsed JSON, or null when coalesced/failed/aborted. */
var _pollQ=[], _pollActive=false;
// Lower number = higher priority when several jobs are queued. The control-critical
// polls (state, then events) always jump ahead of a large history ('sys') fetch in the
// QUEUE -- so history waiting to run never delays the generator status. It still can't
// preempt a request already IN FLIGHT (that's the one-at-a-time contract), it just loses
// its place in line. Unknown keys default to lowest priority.
var _pollPrio={state:0,events:1,logs:1,sys:2};
// While an update is running we pause the HEAVY routine polls (events / logs / system history) so
// the Pi isn't hammered -- but we KEEP the lightweight 'state' poll so the header bar (ONLINE +
// latency) stays live even with the modal open / parked at the go/no-go. Only 'state' gets through.
var updateActive=false;
// User-controllable poll cadence (localStorage-backed, clamped 1-30s, default 3s). Everything that
// polls the Pi uses this ONE rate -- incl. the update-status poll -- so we never hammer the link.
// (The Settings slider that writes gp_refresh_secs is task #37; the plumbing is here now.)
var refreshMs=Math.max(1000,Math.min(30000,(parseInt(localStorage.getItem('gp_refresh_secs'),10)||3)*1000));
// Central client request-timeout: the flaky Pi link can take 10-20s+, so give every request
// generous headroom before it's aborted. ONE place to tweak; all poll requests obey it (any
// pollFetch caller that passes no explicit ms uses this). Fuller central-timeout work = roadmap.
var REQ_TIMEOUT_MS=45000;
// The update / result modal covers the log windows, so while EITHER is open we pause the heavy
// polls too (only 'state' keeps the header live) -- even before the update itself has started.
function _updModalShown(){var a=document.getElementById('updModal'),b=document.getElementById('updResultModal');
  return (a&&a.classList.contains('show'))||(b&&b.classList.contains('show'));}
function pollFetch(key,path,ms){
  return new Promise(function(resolve){
    if((updateActive||_updModalShown())&&key!=='state'){resolve(null);return;}   // update running OR modal open -> only 'state'
    for(var i=0;i<_pollQ.length;i++){          // coalesce a still-queued same-key job
      if(_pollQ[i].key===key){_pollQ[i].resolve(null);_pollQ[i].path=path;_pollQ[i].ms=ms;_pollQ[i].resolve=resolve;return;}
    }
    _pollQ.push({key:key,path:path,ms:ms,resolve:resolve,t:Date.now()});
    _drainPollQ();
  });
}
function _drainPollQ(){
  // No updateActive gate here: pollFetch already blocks every key EXCEPT 'state' during an
  // update, so the only jobs that reach the queue are the state polls we WANT to keep draining
  // (they keep the header's ONLINE + latency live while the modal is open / parked).
  if(_pollActive||!_pollQ.length)return;
  _pollActive=true;
  // Pick the most-urgent job by EFFECTIVE priority, with anti-starvation aging. A job's effective
  // priority improves (its number drops) by one level for each full refresh interval it has waited,
  // so a constantly re-fired high-prio 'state' can NEVER perpetually starve 'events'/'logs'/'sys':
  // whatever has waited long enough ages to the front and gets its turn. Ties break FIFO (earliest
  // enqueued). When the link is fast (nothing waits long) this behaves exactly like strict priority.
  var _now=Date.now(), _age=Math.max(1000,refreshMs);
  var bi=0,_beff=null,_bt=null;
  for(var i=0;i<_pollQ.length;i++){
    var _base=(_pollPrio[_pollQ[i].key]==null?9:_pollPrio[_pollQ[i].key]);
    var _t=_pollQ[i].t||_now;
    var _eff=_base-Math.floor((_now-_t)/_age);   // one priority level gained per interval waited
    if(_beff===null||_eff<_beff||(_eff===_beff&&_t<_bt)){_beff=_eff;_bt=_t;bi=i;}
  }
  var job=_pollQ.splice(bi,1)[0];
  var ctrl=('AbortController' in window)?new AbortController():null;
  var to=setTimeout(function(){if(ctrl)ctrl.abort();},job.ms||REQ_TIMEOUT_MS);
  netFetch(job.path,ctrl?{signal:ctrl.signal}:{})
    .then(function(r){return r.json().catch(function(){return {};});})
    .catch(function(){return null;})
    .then(function(d){clearTimeout(to);job.resolve(d);_pollActive=false;_drainPollQ();});
}
function fetchState(cb){pollFetch('state','/api/state').then(cb);}

/* ---------- clocks / formatting ---------- */
function nowSec(){return (Date.now()+clockOffset)/1000;}
var MON=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
function clock12(d){var h=d.getHours(),m=d.getMinutes(),ap=h<12?'am':'pm';h=h%12;if(h===0)h=12;return h+':'+(m<10?'0':'')+m+ap;}
function fmtStamp(d,withYear){var s=MON[d.getMonth()]+' '+d.getDate();if(withYear){s+=' '+String(d.getFullYear()).slice(-2);}return s+' '+clock12(d);}
function parseISO(s){if(!s)return null;var d=new Date(s);return isNaN(d.getTime())?null:d;}
function pad2(n){return (n<10?'0':'')+n;}
function fmtClock(secs){secs=Math.max(0,Math.floor(secs));var d=Math.floor(secs/86400);secs-=d*86400;var h=Math.floor(secs/3600);secs-=h*3600;var m=Math.floor(secs/60);var s=secs-m*60;var base=pad2(h)+':'+pad2(m)+':'+pad2(s);return d>0?d+'d '+base:base;}
var DASH='\u2014';
function fmtDur(hours){if(hours==null||!isFinite(hours))return DASH;var m=Math.round(hours*60);var d=Math.floor(m/1440);m-=d*1440;var h=Math.floor(m/60);m-=h*60;if(d>0)return d+'d '+h+'h';if(h>0)return h+'h '+m+'m';return m+'m';}

/* ---------- live derived values ---------- */
function liveTotalHours(){if(!state)return 0;var t=state.total_run_hours||0;if(state.running&&state.current_run_started_at){t+=Math.max(0,(nowSec()-state.current_run_started_at)/3600);}return t;}
function uptimeSecs(){if(state&&state.running&&state.current_run_started_at){return Math.max(0,nowSec()-state.current_run_started_at);}return 0;}
function fuel(){return state?state.fuel:null;}
function alertCfg(){return state&&state.alerts?state.alerts:{alerts_on:true,alert_threshold:20};}
function projectedLevel(){var f=fuel();if(!f)return null;var run=Math.max(0,liveTotalHours()-f.fill_run_hours);return Math.max(0,Math.min(100,f.fill_level-f.drain_rate*run));}
function hoursTo(target){var f=fuel();if(!f||!state.running)return null;var lvl=projectedLevel();if(f.drain_rate>0&&lvl>target)return (lvl-target)/f.drain_rate;return null;}

/* ---------- odometer wheels ---------- */
var odoReels=[];var ODO_CELL=46;
function buildOdometer(){var odo=$('odometer');odo.innerHTML='';
  // Each wheel is a .reel of 11 .cells (0..9 then a DUPLICATE 0 at index 10).
  // The 11th cell is the seamless-wrap landing pad: on a 9->0 rollover we roll
  // FORWARD onto it, then invisibly snap back to the real 0 -- never backward.
  function wheel(cls,dur){var w=document.createElement('div');w.className='wheel '+cls;var reel=document.createElement('div');reel.className='reel';for(var i=0;i<=10;i++){var c=document.createElement('div');c.className='cell';c.textContent=i%10;reel.appendChild(c);}w.appendChild(reel);odo.appendChild(w);
    // Per-reel animation state: pos = current -translateY() magnitude in px;
    // dur = this wheel's CSS transition duration (ms, must match the stylesheet);
    // wrapping = true while a rollover roll+snap is in flight (re-entrancy guard);
    // pending = latest requested target px queued while that wrap runs.
    return {el:reel,pos:0,dur:dur,wrapping:false,pending:null};}
  odoReels=[];for(var i=0;i<4;i++)odoReels.push(wheel('wheel-int',700));
  var dot=document.createElement('span');dot.className='odo-dot';dot.textContent='.';odo.appendChild(dot);
  odoReels.push(wheel('wheel-tenths',1000));}
// Move one reel toward a target px magnitude. total_run_hours only ever INCREASES
// within a session, so a target that is LOWER than the current position is always a
// wrap-past-9-to-0, never a real decrease -- handle it as a forward roll, not a
// backward spin.
function setReel(r,target){
  // A wrap animation is already running for this reel: don't disturb it -- just
  // record the newest target so the snap step lands on the latest value.
  if(r.wrapping){r.pending=target;return;}
  if(target>=r.pos){
    // Forward (or no) motion: the reel climbs up the strip; the CSS transition
    // animates it normally. Record the new resting position.
    r.pos=target;r.el.style.transform='translateY(-'+target+'px)';return;}
  // WRAP: target moved back toward 0. Roll FORWARD onto the duplicate 0 (11th cell
  // at 10*ODO_CELL) using the wheel's normal transition, so it reads 9 -> 0 upward.
  r.wrapping=true;r.pending=target;
  r.el.style.transform='translateY(-'+(10*ODO_CELL)+'px)';
  // After that roll finishes, snap (no animation) to the equivalent low position so
  // the next real forward move continues cleanly. Timer matched to the wheel's
  // transition duration (+ small buffer to guarantee the roll has landed).
  setTimeout(function(){
    var t=(r.pending==null?target:r.pending); // apply the freshest queued value
    r.el.style.transition='none';
    r.el.style.transform='translateY(-'+t+'px)';
    void r.el.offsetHeight;                    // force reflow so the snap commits
    r.el.style.transition='';                  // restore the stylesheet transition
    r.pos=t;r.wrapping=false;r.pending=null;
  },r.dur+40);
}
var _lastOdoHours=null;
function updateOdometer(hours){
  // The lifetime odometer only ever INCREMENTS. Ignore any lower value (e.g. the live
  // uptime tick overshooting, then a delayed/slow state response pulling it back) so the
  // wheels never spin backward or roll all the way around -- they only climb forward.
  if(_lastOdoHours!=null && hours <= _lastOdoHours) return;   /* #40: also skip when UNCHANGED (no redundant transform write) */
  _lastOdoHours=hours;
  var intPart=Math.min(9999,Math.floor(hours));var ds=('0000'+intPart).slice(-4);
  for(var i=0;i<4;i++){setReel(odoReels[i],parseInt(ds.charAt(i),10)*ODO_CELL);}
  var frac=hours-Math.floor(hours);setReel(odoReels[4],frac*10*ODO_CELL);
}

/* ---------- state render ---------- */
/* Idempotent DOM writers -- write ONLY when the value actually changes. The state poll
   fires every few seconds and re-renders the whole panel; on WebKit (no scroll anchoring)
   even a NO-OP mutation (rewriting a text node to the same string, re-setting an attribute
   to its current value) triggers a style/layout recalc that nudges the scroll position when
   the user is parked at the footer -- the #40 jump. Skipping identical writes removes the
   mutation entirely (and saves DOM work on the single-core Pi). Every poll-path write goes
   through these. */
function txt(el,v){ if(el&&el.textContent!==v)el.textContent=v; }               // textContent read-back is exact
function clsIf(el,v){ if(el&&el.className!==v)el.className=v; }                    // className read-back is exact
function attrIf(el,k,v){ if(el&&el.getAttribute(k)!==v)el.setAttribute(k,v); }   // getAttribute read-back is exact
/* style + innerHTML READ-BACK is normalized by the browser ('#ff5a4a' -> 'rgb(...)', HTML re-serialized),
   so comparing against the live property would never match and we'd write every time -- defeating the guard.
   Cache the RAW value we last set on the element and compare against that instead. */
function styIf(el,k,v){ if(el){var kk='_gs_'+k; if(el[kk]!==v){el[kk]=v;el.style[k]=v;} } }
function htmlIf(el,v){ if(el&&el._gh!==v){el._gh=v;el.innerHTML=v;} }
function propIf(el,k,v){ if(el&&el[k]!==v)el[k]=v; }
function cmdLabel(c){return {start:'START',stop:'STOP',mark_run:'MARK RUN',mark_stop:'MARK STOP'}[c]||DASH;}
function applyState(s){
  if(!s)return; state=s; clockOffset=s.server_now*1000-Date.now();
  attrIf(panel,'data-running',s.running?'true':'false');
  txt($('statusWord'),s.running?'RUNNING':'STOPPED');
  var sub=$('shSub');if(sub){txt(sub,s.running?'Generator ON':'Generator OFF');clsIf(sub,'sh-sub '+(s.running?'on':'off'));}
  txt($('detailMsg'),s.running?('Start sequence completed '+DASH+' verify the unit is running.'):('System idle '+DASH+' generator stopped. Flip switch up to start.'));
  txt($('regLastCmd'),cmdLabel(s.last_command));
  txt($('regAttempts'),''+s.start_attempts);
  var ls=parseISO(s.last_start_time),lp=parseISO(s.last_stop_time);
  txt($('regLastStart'),ls?fmtStamp(ls,false):DASH);
  txt($('regLastStop'),lp?fmtStamp(lp,false):DASH);
  if(!busy&&!confirmOpen){propIf($('powerSwitch'),'checked',s.running);}
  if(s.fuel){propIf($('rateInput'),'placeholder',s.fuel.drain_rate+' %/hr');}
  var a=s.alerts||{}; setToggle(a.alerts_on!==false);
  if(document.activeElement!==$('threshSlider')){var _tv=(a.alert_threshold||20);
    if(+$('threshSlider').value!==_tv)$('threshSlider').value=_tv;txt($('threshVal'),_tv+'%');}
  // Fuel feature enable/disable: hide the whole Fuel drawer + reflect the toggle.
  var fEnabled=s.fuel_enabled!==false;
  styIf($('fuelDrawer'),'display',fEnabled?'':'none');
  setTog('fuelToggle',fEnabled);
  // Web push server state (vapid key + whether the server can send).
  pushApplyState(s.push||{});
  // SYSTEM drawer FACE stat (1m load + optional temp) -- driven here from the state poll so
  // it stays live even while the drawer is collapsed and history isn't being polled.
  setSysFaceStat(s.sys||{});
  tick();
}
// Paint the SYSTEM drawer face stat: a SINGLE glanceable value -- CPU% (amber, matching the
// COMPUTE chart's CPU line). Hidden entirely when unavailable (no sample yet) so no bare
// "--" ever. One value only -- two looked cluttered on the face.
function setSysFaceStat(sys){
  var el=$('sysFaceStat');if(!el)return;
  var c=sys.cpu;
  if(c==null){styIf(el,'display','none');htmlIf(el,'');return;}
  styIf(el,'display','');
  htmlIf(el,'<span style="color:#ffb347">CPU '+Math.round(c)+'%</span>');
}
function setTog(id,on){var el=$(id),v=on?'true':'false';if(el&&el.getAttribute('aria-checked')!==v)el.setAttribute('aria-checked',v);}   /* idempotent: skip identical aria writes (#40) */
function tick(){if(!state)return;txt($('uptime'),fmtClock(uptimeSecs()));updateOdometer(liveTotalHours());renderFuel();}
function renderFuel(){
  var f=fuel();if(!f)return;var lvl=projectedLevel();var thr=alertCfg().alert_threshold;var running=state.running;
  var col=lvl<=thr?'#ff5a4a':(lvl<=thr+15?'#ffb347':'#7ce0b0');
  var levelEl=$('fLevel');txt(levelEl,Math.round(lvl)+'%');styIf(levelEl,'color',col);
  var faceLvl=$('fuelFaceLevel');txt(faceLvl,Math.round(lvl)+'%');styIf(faceLvl,'color',col);
  txt($('fRate'),f.drain_rate.toFixed(1)+' %/hr');
  txt($('fReachesLabel'),'REACHES '+thr+'%');
  var toThr=hoursTo(thr),toEmpty=hoursTo(0);
  txt($('fReaches'),running?(toThr!=null?fmtDur(toThr):DASH):'PAUSED');
  txt($('fEmptyIn'),running?(toEmpty!=null?fmtDur(toEmpty):DASH):'PAUSED');
  txt($('fLowAt'),(running&&toThr!=null)?clock12(new Date(Date.now()+toThr*3600000)):(running?DASH:'STOPPED'));
  txt($('fEmptyAt'),(running&&toEmpty!=null)?clock12(new Date(Date.now()+toEmpty*3600000)):(running?DASH:'STOPPED'));
  styIf($('tankFill'),'height',lvl+'%');clsIf($('tank'),'tank'+(lvl<=thr?' low':''));styIf($('tankLine'),'bottom',thr+'%');
  clsIf($('alertBanner'),'alert-banner'+((alertCfg().alerts_on!==false&&lvl<=thr)?' show':''));
}

/* ---------- event log ---------- */
function tagLabel(t){return '['+({startup:'BOOT',start:'START',start_complete:'START',start_rejected:'ERR',stop:'STOP',set_running:'MANUAL',fuel:'FUEL'}[t]||'LOG')+']';}
function evtEl(e){var row=document.createElement('div');row.className='evt';
  var t=document.createElement('span');t.className='t';t.textContent=fmtStamp(new Date(e.ts*1000),true);
  var g=document.createElement('span');g.className='g';g.textContent=tagLabel(e.type);
  var m=document.createElement('span');m.className='m';m.textContent=e.message;
  row.appendChild(t);row.appendChild(g);row.appendChild(m);return row;}
function setCount(n){totalEvents=n;$('logCount').textContent=n+' EVENT'+(n===1?'':'S');}
// Every events render guards on logView==='events': a late /api/events response must
// NOT paint after the user has switched to APP LOG (it would wipe the app-log lines).
function loadInitialEvents(){var lg=$('log');if(lg&&!lg.children.length)lg.classList.add('loading');   // spinner while the empty log loads
  return pollFetch('events','/api/events?limit=100').then(function(d){if(!d||logView!=='events')return;var log=$('log');log.classList.remove('loading');log.innerHTML='';var evs=d.events||[];evs.forEach(function(e){log.appendChild(evtEl(e));});if(evs.length){newestSeq=evs[0].seq;oldestSeq=evs[evs.length-1].seq;}setCount(d.latest_seq||evs.length);});}
// Delta poll: only pull events AFTER the newest sequence we already hold.
function loadNewEvents(){if(!newestSeq){loadInitialEvents();return;}pollFetch('events','/api/events?after='+newestSeq+'&limit=100').then(function(d){if(!d||logView!=='events')return;var evs=d.events||[];var log=$('log');for(var i=evs.length-1;i>=0;i--){log.insertBefore(evtEl(evs[i]),log.firstChild);}if(evs.length){newestSeq=evs[0].seq;}if(d.latest_seq)setCount(d.latest_seq);});}
function loadOlderEvents(){if(logView!=='events'||loadingOlder||oldestSeq==null)return;loadingOlder=true;api('/api/events?before='+oldestSeq+'&limit=100').then(function(d){var evs=d.events||[];var log=$('log');evs.forEach(function(e){log.appendChild(evtEl(e));});if(evs.length){oldestSeq=evs[evs.length-1].seq;}loadingOlder=false;}).catch(function(){loadingOlder=false;});}

/* ---------- application-log view (raw log-file tail) ---------- */
// The EVENT LOG panel toggles between the curated event store and the raw application
// log file. logView is the current mode ('events'|'log'), persisted so the panel comes
// back the way you left it. Both feeds render into the same #log element.
var LS_LOGVIEW='gp.logview';
var logView='events';
try{if(localStorage.getItem(LS_LOGVIEW)==='log')logView='log';}catch(e){}
// Parse one app-log line into the same 3-column shape the EVENT rows use. The stdlib
// format is "YYYY-MM-DD HH:MM:SS [LEVEL] message". A match yields time/level/message
// columns tinted by severity; a non-match (blank line, multi-line traceback) renders
// as a single full-width message so nothing is lost.
var _logRe=/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] ([\s\S]*)$/;
var _lvlTag={INFO:'INFO',WARNING:'WARN',ERROR:'ERR',CRITICAL:'CRIT',DEBUG:'DBG'};
function _span(cls,txt){var e=document.createElement('span');e.className=cls;e.textContent=txt;return e;}
function logLnEl(s){var d=document.createElement('div');d.className='logln';
  var m=s.match(_logRe);
  if(m){var lvl=m[2].toUpperCase();
    if(lvl==='ERROR'||lvl==='CRITICAL')d.classList.add('err');
    else if(lvl==='WARNING'||lvl==='WARN')d.classList.add('warn');
    d.appendChild(_span('lt',m[1]));
    d.appendChild(_span('lg','['+(_lvlTag[lvl]||lvl.slice(0,4))+']'));
    d.appendChild(_span('lm',m[3]));
  }else{d.classList.add('raw');d.appendChild(_span('lm',s));}   // continuation / non-standard line
  return d;}
// Fetch + render the log-file tail through the SINGLE serial poll queue (key 'logs',
// events-tier priority). Guarded so a late response can't paint after switching to
// EVENTS. Oldest-first (file/tail order); keeps the view pinned to the newest line
// only when the user is already scrolled to the bottom (so reading history isn't
// yanked away on the 4s refresh).
var _logOffset=null;   // byte cursor into the log file; null forces a full (reset) fetch
// "Hide routine HTTP traffic" display filter (per-browser pref, persisted to localStorage).
// When on, routine SUCCESSFUL access lines are hidden from the APP LOG so real events aren't
// drowned out; errors (4xx/5xx) and non-access lines are ALWAYS shown. The server still logs
// everything -- this is display-only. Access lines read "<who>@<ip> -> <METHOD> <path> <status>".
var LS_HIDEHTTP='gp.hidehttp';
var _hideHttp=true;   // DEFAULT: hide routine 2xx/3xx traffic so real events aren't buried
try{var _hh=localStorage.getItem(LS_HIDEHTTP);if(_hh!=null)_hideHttp=(_hh==='1');}catch(e){}
var _accessRe=/ -> (?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) \S+ ([0-9]{3})(?:\s|$)/;
function _isRoutineHttp(line){var m=line.match(_accessRe);return !!m&&(+m[1])<400;}   // 2xx/3xx only
function _logHidden(line){return _hideHttp&&_isRoutineHttp(line);}                    // filter predicate
function _setLogCount(){var n=$('log').querySelectorAll('.logln').length;$('logCount').textContent=n+' LINE'+(n===1?'':'S');}
// INCREMENTAL app-log fetch: pass our byte cursor so the server returns ONLY the newly
// appended lines (an idle poll is a few bytes, not ~70KB). reset=true (initial load or a
// server-side log rotation) replaces the view; otherwise the lines are strictly-new and
// get PREPENDED newest-first. We only reach here while scrolled to the top (paused
// otherwise), so prepending never yanks text the user is reading.
function loadAppLog(){var lg=$('log');if(!lg.children.length)lg.classList.add('loading');
  var q='/api/logs?lines=1000';if(_logOffset!=null)q+='&since='+_logOffset;
  return pollFetch('logs',q,REQ_TIMEOUT_MS).then(function(d){if(!d||logView!=='log')return;
    var log=$('log');log.classList.remove('loading');
    var lines=d.lines||[];
    if(typeof d.offset==='number')_logOffset=d.offset;   // advance the delta cursor
    var atTop=(log.scrollTop<=4);
    if(d.reset){   // full tail -> rebuild newest-first (top = most recent)
      log.innerHTML='';for(var i=lines.length-1;i>=0;i--){if(_logHidden(lines[i]))continue;log.appendChild(logLnEl(lines[i]));}
      _setLogCount();if(atTop)log.scrollTop=0;return;
    }
    if(!lines.length)return;                              // nothing new -> leave view as-is
    // Delta: insert oldest->newest before the current top so the newest ends up on top.
    for(var j=0;j<lines.length;j++){if(_logHidden(lines[j]))continue;log.insertBefore(logLnEl(lines[j]),log.firstChild);}
    while(log.children.length>1000)log.removeChild(log.lastChild);   // cap rendered rows
    _setLogCount();if(atTop)log.scrollTop=0;});}
// True only when the panel is scrolled to the very top (newest end, both panes).
function logAtTop(){var l=$('log');return l.scrollTop<=4;}
// One dispatch point for the ongoing 4s refresh + post-action settle: pull whichever
// feed is currently shown so we never render the wrong one into #log. PAUSE the feed
// whenever the user has scrolled DOWN to read older lines -- both panes insert/repaint
// at the top, which would shove the text they're reading around. Scrolling back to the
// top resumes automatically on the next tick. (Initial load + view-switch bypass this;
// they go straight through setLogView, not here.)
function loadLogFeed(){if(!logAtTop())return;if(logView==='log')loadAppLog();else loadNewEvents();}
// Switch views: persist, light the active segment, clear + reload the panel NOW (don't
// wait for the next 4s tick). Resetting the event cursors forces a fresh initial event
// load when returning to EVENTS so the list rebuilds cleanly.
function setLogView(v){logView=(v==='log')?'log':'events';
  try{localStorage.setItem(LS_LOGVIEW,logView);}catch(e){}
  var seg=$('logViewToggle');
  if(seg){var bs=seg.querySelectorAll('button');for(var i=0;i<bs.length;i++){bs[i].classList.toggle('on',bs[i].getAttribute('data-view')===logView);}}
  var log=$('log');log.innerHTML='';log.scrollTop=0;
  // Reset the byte cursor: we just cleared the panel, so the next loadAppLog must do a
  // full (reset) fetch and rebuild rather than trying to append a delta onto nothing.
  _logOffset=null;
  // Spinner on the SELECTED segment until its feed finishes loading (matches the button/
  // iotoggle spinners). The loaders return their pollFetch promise so we can clear it.
  var actBtn=seg?seg.querySelector('button[data-view="'+logView+'"]'):null;
  if(actBtn)actBtn.classList.add('loading');
  var p;
  if(logView==='log'){log.classList.add('applog');p=loadAppLog();}
  else{log.classList.remove('applog');newestSeq=0;oldestSeq=null;p=loadInitialEvents();}
  if(actBtn){if(p&&p.then){p.then(function(){actBtn.classList.remove('loading');});}else{actBtn.classList.remove('loading');}}}

/* ---------- actions ---------- */
function refresh(){fetchState(function(s){if(s)applyState(s);});loadLogFeed();}
function settle(target){var n=0;(function step(){setTimeout(function(){fetchState(function(s){if(s)applyState(s);if((s&&s.running===target)||++n>20){busy=false;sw.disabled=false;if(s)applyState(s);loadLogFeed();}else step();});},600);})();}
var sw=$('powerSwitch');
var confirmOverlayEl=$('confirmOverlay');
/* Element focused before the dialog opened (normally #powerSwitch) so we can
   restore focus to it on close for keyboard/AT users. */
var confirmPrevFocus=null;
/* Toggle the `inert` attribute on the two regions that hold every background
   control (.body + footer). inert makes them non-interactive AND hides them from
   assistive tech while the modal is up. We deliberately do NOT inert #panel or
   #confirmOverlay: the overlay is a CHILD of #panel and must stay interactive. */
function setBackgroundInert(on){
  var body=panel.querySelector('.body'),foot=panel.querySelector('footer');
  if(body){if(on){body.setAttribute('inert','');}else{body.removeAttribute('inert');}}
  if(foot){if(on){foot.setAttribute('inert','');}else{foot.removeAttribute('inert');}}
}
/* GENERIC confirmation dialog. The START flow (power switch) and the destructive
   Settings actions (restart / factory reset) all drive this one modal. opts:
   {title, body, confirmLabel, confirmClass('red'=warning start | 'danger'=destructive),
    onConfirm:()=>Promise|void, onCancel:()=>void}. onConfirm's promise keeps the modal
   open with a spinner until it settles; onCancel runs on cancel/Escape/backdrop. */
var _cfConfirm=null,_cfCancel=null;
function showConfirm(o){
  confirmOpen=true;
  $('confirmTitle').textContent=o.title||'CONFIRM';
  $('confirmBody').textContent=o.body||'';
  var cb=$('confirmStart');
  cb.textContent=o.confirmLabel||'CONFIRM';
  cb.className='btn3d '+(o.confirmClass||'red');      /* red=start warning, danger=destructive */
  cb.classList.remove('loading');
  $('confirmCancel').disabled=false;
  _cfConfirm=o.onConfirm||null;_cfCancel=o.onCancel||null;
  confirmPrevFocus=document.activeElement;            /* remember where focus was */
  confirmOverlayEl.className='confirm-overlay show';
  setBackgroundInert(true);                           /* trap: bg non-interactive */
  cb.focus();                                         /* move focus into the dialog */
}
/* Power switch -> START confirm (warning orange button; cancel reverts the switch). */
sw.addEventListener('change',function(){
  if(sw.checked){showConfirm({title:'START GENERATOR?',
    body:'This cranks the real engine. Confirm the area around the unit is clear and it is safe to start.',
    confirmLabel:'START',confirmClass:'red',onConfirm:doStart,onCancel:function(){sw.checked=false;}});}
  else{doStop();}
});
function closeConfirm(runCancel){
  confirmOpen=false;
  confirmOverlayEl.className='confirm-overlay';
  setBackgroundInert(false);                          /* restore bg BEFORE focusing */
  var onCancel=_cfCancel;_cfConfirm=null;_cfCancel=null;
  if(runCancel&&onCancel){onCancel();}               /* e.g. revert the power switch */
  /* Restore focus to the pre-open element, falling back to the power switch. */
  var restore=confirmPrevFocus||$('powerSwitch');
  confirmPrevFocus=null;
  if(restore&&typeof restore.focus==='function'){restore.focus();}
}
$('confirmCancel').addEventListener('click',function(){closeConfirm(true);});
$('confirmStart').addEventListener('click',function(){
  var cb=$('confirmStart');
  if(cb.classList.contains('loading'))return;                      // anti-double-click
  var act=_cfConfirm;
  cb.classList.add('loading');$('confirmCancel').disabled=true;    // spinner; hold the modal open
  Promise.resolve(act?act():null).catch(function(){}).then(function(){
    cb.classList.remove('loading');$('confirmCancel').disabled=false;closeConfirm(false);});
});
/* Escape cancels the dialog (running the cancel callback) while it is open. */
document.addEventListener('keydown',function(e){if(confirmOpen&&(e.key==='Escape'||e.key==='Esc')){e.preventDefault();closeConfirm(true);}});
/* Backdrop click cancels — only when the click lands on the overlay itself,
   not on anything inside the confirm card. */
confirmOverlayEl.addEventListener('click',function(e){if(e.target===confirmOverlayEl){closeConfirm(true);}});
/* RESET section server actions -> reuse the generic confirm (true-red destructive button). */
$('restartBtn').addEventListener('click',function(){showConfirm({title:'RESTART APP?',
  body:'Restarts the GeneratorPi service on the server. The page will reconnect in a few seconds. The generator and relay are not affected.',
  confirmLabel:'RESTART',confirmClass:'danger',
  onConfirm:function(){return post('/api/restart').catch(function(){});}});});   // server re-execs; poller auto-reconnects
$('factoryBtn').addEventListener('click',function(){showConfirm({title:'FACTORY RESET?',
  body:'Wipes the event log, application logs, lifetime run-hours, and fuel/alert settings back to defaults. Your login and server config are NOT touched. This cannot be undone.',
  confirmLabel:'FACTORY RESET',confirmClass:'danger',
  onConfirm:function(){return post('/api/factory-reset').then(function(){_logOffset=null;refresh();}).catch(function(){});}});});
/* Disable the switch for the whole in-flight start/stop so a mid-settle flip
   can't kick off a second concurrent settle() loop. Re-enabled wherever busy is
   cleared (settle completion + every failure/reject path). */
function doStart(){busy=true;sw.disabled=true;return post('/api/start').then(function(d){if(d&&d.success===false){busy=false;sw.disabled=false;sw.checked=false;refresh();}else{settle(true);}}).catch(function(){busy=false;sw.disabled=false;sw.checked=false;refresh();});}
/* /api/stop returns {success:false} when the relay is busy with an in-progress
   start; honor it (like doStart) instead of settling to OFF and flipping back. */
function doStop(){busy=true;sw.disabled=true;sw.checked=false;post('/api/stop').then(function(d){if(d&&d.success===false){busy=false;sw.disabled=false;refresh();return;}settle(false);}).catch(function(){busy=false;sw.disabled=false;refresh();});}
// Wrap an async button action with a spinner: on click, disable + hide the label + show a
// spinner in its place (the button keeps its width); restore on settle. The factory returns
// the action's promise, or a falsy value to skip (e.g. invalid input) so no spinner shows.
function btnBusy(id,factory){
  var b=$(id);if(!b)return;
  b.addEventListener('click',function(){
    if(b.classList.contains('loading'))return;          // anti-double-click
    var p=factory();
    if(!p||!p.then)return;                               // nothing async happened (bad input, etc.)
    b.classList.add('loading');
    p.catch(function(){}).then(function(){b.classList.remove('loading');});
  });
}
btnBusy('markRunBtn',function(){return post('/api/set_running',{running:true}).then(refresh);});
btnBusy('markStopBtn',function(){return post('/api/set_running',{running:false}).then(refresh);});

/* ---------- fuel controls ---------- */
function numVal(id){var v=parseFloat($(id).value);return isFinite(v)?v:null;}
btnBusy('setRateBtn',function(){var v=numVal('rateInput');if(v==null)return;return post('/api/fuel/rate',{rate:v}).then(function(){$('rateInput').value='';refresh();});});
btnBusy('resetRateBtn',function(){return post('/api/fuel/rate/reset').then(function(){$('rateInput').value='';refresh();});});
/* TOTAL RUNTIME override: POST the entered hours, then clear the field and refresh. The
   odometer only ever rolls FORWARD (updateOdometer skips any value <= _lastOdoHours), so a
   correction to a LOWER value would otherwise be ignored; reset _lastOdoHours to null so the
   next render re-seeds the wheels to the new value (up OR down) cleanly.
   RACE FIX: we must fold the confirmed new total into `state` BEFORE re-seeding, because
   refresh() fetches /api/state asynchronously and the 1s tick() keeps running meanwhile. On
   the slow Pi link a tick can land in that window and, with _lastOdoHours just nulled, re-seed
   it from the STALE (old, higher) state -- then the real lower value arrives and is skipped as
   "backward", leaving the wheels stuck until reload. Applying d.total_run_hours (and, when
   running, re-stamping the run clock to now like the server does) makes any intervening tick
   compute the new value. Guarded on a numeric field so a degraded/empty response is a no-op. */
btnBusy('setRunHoursBtn',function(){var v=numVal('runHoursInput');if(v==null||v<0)return;return post('/api/runtime/hours',{hours:v}).then(function(d){$('runHoursInput').value='';if(state&&d&&typeof d.total_run_hours==='number'){state.total_run_hours=d.total_run_hours;if(state.running)state.current_run_started_at=nowSec();}_lastOdoHours=null;refresh();});});
btnBusy('recordBtn',function(){var v=numVal('readingInput');if(v==null)return;return post('/api/fuel/reading',{level:v}).then(function(){$('readingInput').value='';refresh();});});
btnBusy('fillBtn',function(){var v=numVal('fillInput');if(v==null)return;return post('/api/fuel/fill',{level:v}).then(function(){$('fillInput').value='';refresh();});});

/* ---------- alert toggle + threshold ---------- */
// Show a spinner on the toggle half being switched TO (I=on, O=off) while the request is
// in flight; clear on settle. `on` = the NEW state. Returns the promise unchanged.
function toggleSpin(id,on,p){
  var t=$(id);if(!t||!p||!p.then)return p;
  var half=t.querySelector(on?'.half.i':'.half.o');
  if(half)half.classList.add('loading');
  p.catch(function(){}).then(function(){if(half)half.classList.remove('loading');});
  return p;
}
function setToggle(on){attrIf($('alertToggle'),'aria-checked',on?'true':'false');}
function toggleAlerts(){var on=$('alertToggle').getAttribute('aria-checked')==='true';toggleSpin('alertToggle',!on,post('/api/alerts',{enabled:!on}).then(refresh));}
$('alertToggle').addEventListener('click',toggleAlerts);
$('alertToggle').addEventListener('keydown',function(e){if(e.key===' '||e.key==='Enter'){e.preventDefault();toggleAlerts();}});
$('threshSlider').addEventListener('input',function(){$('threshVal').textContent=this.value+'%';if(state){state.alerts=state.alerts||{};state.alerts.alert_threshold=parseInt(this.value,10);renderFuel();}});
$('threshSlider').addEventListener('change',function(){post('/api/alerts',{threshold:parseInt(this.value,10)}).then(refresh);});

/* ---------- drawers ---------- */
// Drawer open/closed state persists across launches (localStorage key gp.drawer.<id>), so
// the panels come back the way you left them. onToggle(open) fires on every state change
// (click AND restore) -- the SYSTEM drawer uses it to start/stop history polling.
function initDrawer(id,cls,onToggle){
  var d=$(id),face=d.querySelector('.drawer-face'),clip=d.querySelector('.drawer-clip');
  var LSK='gp.drawer.'+id;
  // Slide open/closed by animating max-height. We animate to the content's ACTUAL
  // scrollHeight (never a fixed cap -- a fixed cap clips a tall drawer like Settings),
  // then drop the cap to 'none' once open so later content growth can't clip either.
  function setOpen(open,save){
    d.className='drawer '+cls+(open?' open':'');
    face.setAttribute('aria-expanded',open?'true':'false');
    if(open){
      clip.style.maxHeight=clip.scrollHeight+'px';   // animate 0 -> content height
    }else{
      // Collapsing: pin the current height first (in case it's 'none'), reflow, then 0
      // so the transition has two concrete endpoints to animate between.
      clip.style.maxHeight=clip.scrollHeight+'px';void clip.offsetHeight;clip.style.maxHeight='0';
    }
    if(save){try{localStorage.setItem(LSK,open?'1':'0');}catch(e){}}
    if(onToggle)onToggle(open);
  }
  // After an EXPAND transition settles, remove the cap so a later height change (e.g. the
  // push-help line wrapping) is never clipped. Only when still open.
  clip.addEventListener('transitionend',function(e){
    if(e.propertyName==='max-height'&&d.className.indexOf('open')>=0){clip.style.maxHeight='none';}
  });
  face.addEventListener('click',function(){setOpen(d.className.indexOf('open')<0,true);});
  // Restore persisted open state on load. Suppress the slide transition for the restore so
  // the drawer doesn't animate open on every page load -- it should just already be open.
  var saved=null;try{saved=localStorage.getItem(LSK);}catch(e){}
  if(saved==='1'){var prev=clip.style.transition;clip.style.transition='none';setOpen(true,false);clip.style.maxHeight='none';void clip.offsetHeight;clip.style.transition=prev;}
}

/* ---------- event-log infinite scroll ---------- */
$('log').addEventListener('scroll',function(){if(this.scrollTop+this.clientHeight>=this.scrollHeight-24){loadOlderEvents();}});

/* ---------- fuel feature toggle ---------- */
function toggleFuel(){var on=$('fuelToggle').getAttribute('aria-checked')==='true';toggleSpin('fuelToggle',!on,post('/api/alerts',{fuel_enabled:!on}).then(refresh));}
$('fuelToggle').addEventListener('click',toggleFuel);
$('fuelToggle').addEventListener('keydown',function(e){if(e.key===' '||e.key==='Enter'){e.preventDefault();toggleFuel();}});

/* ---------- LOG VIEWER: routine-HTTP display filter (Settings) ---------- */
// Client-only pref: the httpToggle's I(on)=SHOW routine traffic, so aria-checked === !_hideHttp.
// Flipping it persists to localStorage and, if the APP LOG is showing, forces a full re-fetch so
// the 1000-line window is re-filtered (a delta alone couldn't retroactively hide/show old rows).
function setHideHttp(hide){_hideHttp=!!hide;
  try{localStorage.setItem(LS_HIDEHTTP,_hideHttp?'1':'0');}catch(e){}
  setTog('httpToggle',!_hideHttp);
  // Flipping the filter re-fetches the app-log to re-filter the 1000-line window, so the
  // toggle DOES make a request -> spin the selected half until that reload settles.
  if(logView==='log'){_logOffset=null;$('log').innerHTML='';toggleSpin('httpToggle',!_hideHttp,loadAppLog());}}
function toggleHttp(){setHideHttp($('httpToggle').getAttribute('aria-checked')==='true');}
$('httpToggle').addEventListener('click',toggleHttp);
$('httpToggle').addEventListener('keydown',function(e){if(e.key===' '||e.key==='Enter'){e.preventDefault();toggleHttp();}});

/* ---------- RESET local preferences (Settings) ---------- */
// Escape hatch: wipe THIS browser's gp.* preference keys (open panels, chart layout, log
// source + filters) and reload so everything restores to defaults. Local-only -- never
// touches the generator or server. Scoped to gp.* so any unrelated keys are left alone.
$('resetPrefsBtn').addEventListener('click',function(){
  var b=$('resetPrefsBtn');if(b.classList.contains('loading'))return;b.classList.add('loading');
  try{var ks=[];for(var i=0;i<localStorage.length;i++){var k=localStorage.key(i);if(k&&k.indexOf('gp.')===0)ks.push(k);}
    for(var j=0;j<ks.length;j++)localStorage.removeItem(ks[j]);}catch(e){}
  location.reload();});

/* ---------- web push ---------- */
/* Requires a service worker + PushManager + a SECURE CONTEXT. On a self-signed cert the
   origin may not be secure until the client trusts it, so this degrades gracefully:
   the toggle shows an "unavailable" helper and the in-page banner still covers alerts. */
var swReg=null;
var pushSupported=('serviceWorker' in navigator)&&('PushManager' in window)&&('Notification' in window)&&(window.isSecureContext===true);
var serverPush={supported:false,vapidKey:'',reason:''};
// Wiki base for "how to enable" deep-links surfaced when push can't be turned on.
var WIKI='https://github.com/mrchrisneal/generatorpi/wiki';
// Set the push helper text. With a wikiPage, append a "Setup guide" link so the user can
// learn how to enable push successfully. Built via DOM nodes (not innerHTML) so the message
// can never inject markup, and a plain textContent fast-path for the no-link (success) cases.
function setPushHelp(t,wikiPage){var el=$('pushHelp');
  if(!wikiPage){if(el.textContent!==t)el.textContent=t;el._ph=null;return;}   /* idempotent no-link path (#40) */
  /* Idempotent LINK path: cache the (message+page) signature and skip the rebuild when it's
     unchanged, so the per-poll refreshPushUI() never re-mutates the DOM for a steady state --
     that redundant rewrite was exactly the #40 WebKit scroll-jump trigger, and the broken-push
     state (which hits this path) refreshes on every poll. */
  var sig=t+'\u0000'+wikiPage;
  if(el._ph===sig)return;
  el._ph=sig;
  el.textContent=t+' ';
  var a=document.createElement('a');a.href=WIKI+'/'+wikiPage;a.target='_blank';a.rel='noopener';
  a.textContent='Setup guide \u2197';el.appendChild(a);}
function urlB64ToUint8(base64){
  var pad='='.repeat((4-base64.length%4)%4);
  var b64=(base64+pad).replace(/-/g,'+').replace(/_/g,'/');
  var raw=atob(b64),out=new Uint8Array(raw.length);
  for(var i=0;i<raw.length;i++)out[i]=raw.charCodeAt(i);
  return out;
}
function pushApplyState(p){serverPush.supported=!!p.supported;serverPush.vapidKey=p.vapid_public_key||'';serverPush.reason=p.reason||'';refreshPushUI();}
function refreshPushUI(){
  // A push flow just settled -> clear any spinner on the push-toggle halves.
  var _pt=$('pushToggle');if(_pt){var _hl=_pt.querySelectorAll('.half.loading');for(var _i=0;_i<_hl.length;_i++)_hl[_i].classList.remove('loading');}
  var testBtn=$('testPushBtn');
  if(!pushSupported){setTog('pushToggle',false);
    // Surface WHY it's unavailable (the two real causes) + a link to the enable guide.
    var why=(window.isSecureContext!==true)?'Push needs a secure (HTTPS) connection on this device.':'This browser doesn\u2019t support web push.';
    setPushHelp(why+' In-page alerts still work.','Web-Push-Notifications');testBtn.disabled=true;return;}
  if(!serverPush.supported){setTog('pushToggle',false);
    /* Cause-specific reason from the server (push_status) instead of a misleading blanket
       "no VAPID keys": distinguish the missing library, un-generated keys, and bad keys. */
    var r=serverPush.reason,sm;
    if(r==='library_missing') sm='Server push support isn\u2019t installed \u2014 the py-vapid / http-ece libraries are missing on the server.';
    else if(r==='no_keys') sm='The server has push support but no VAPID keys yet \u2014 they auto-generate on startup, so check the server log and that the settings file is writable.';
    else if(r==='invalid_keys') sm='The server\u2019s VAPID keys are invalid \u2014 clear the VAPID_* lines in the settings file and restart to regenerate them.';
    else sm='Push isn\u2019t configured on the server.';
    setPushHelp(sm+' In-page alerts still work.','Web-Push-Notifications');testBtn.disabled=true;return;}
  if(Notification.permission==='denied'){setTog('pushToggle',false);setPushHelp('Notifications are blocked in this browser\u2019s site settings \u2014 allow them to enable push.','Web-Push-Notifications');testBtn.disabled=true;return;}
  if(swReg){
    swReg.pushManager.getSubscription().then(function(sub){
      var on=!!sub;setTog('pushToggle',on);
      setPushHelp(on?'Push enabled on this device.':'Push available \u2014 flip to enable on this device.');
      testBtn.disabled=!on;
    }).catch(function(){setTog('pushToggle',false);setPushHelp('Push state unavailable \u2014 using in-page alerts.');testBtn.disabled=true;});
  }else{setTog('pushToggle',false);setPushHelp('Push available \u2014 flip to enable on this device.');testBtn.disabled=true;}
}
function registerSW(){
  if(!pushSupported){refreshPushUI();return;}
  navigator.serviceWorker.register('/sw.js').then(function(reg){
    swReg=reg;
    /* If this browser already has a subscription from a prior visit, make sure the
       SERVER has it too -- the browser's local subscription and the server's stored
       record can drift (server db reset, subscription pruned, different instance).
       This idempotent upsert re-syncs it so the test button + pushes actually work. */
    reg.pushManager.getSubscription().then(function(sub){if(sub){post('/api/push/subscribe',sub.toJSON());}}).catch(function(){setTog('pushToggle',false);setPushHelp('Push state unavailable \u2014 using in-page alerts.');refreshPushUI();});
    refreshPushUI();
  }).catch(function(){pushSupported=false;refreshPushUI();});
}
function enablePush(){
  if(!pushSupported||!serverPush.supported||!serverPush.vapidKey||!swReg){refreshPushUI();return;}
  /* Promise.resolve() tolerates BOTH a returned promise (modern) and undefined
     (legacy callback-only requestPermission that would otherwise throw on .then). */
  Promise.resolve(Notification.requestPermission()).then(function(perm){
    if(perm!=='granted'){refreshPushUI();return;}
    swReg.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:urlB64ToUint8(serverPush.vapidKey)})
      .then(function(sub){post('/api/push/subscribe',sub.toJSON()).then(function(){refreshPushUI();refresh();});})
      .catch(function(){setPushHelp('Could not subscribe (is the cert trusted?). In-page alerts still work.');refreshPushUI();});
  });
}
function disablePush(){
  if(!swReg){refreshPushUI();return;}
  swReg.pushManager.getSubscription().then(function(sub){
    if(!sub){refreshPushUI();return;}
    var ep=sub.endpoint;
    /* Catch an out-of-band unsubscribe rejection so it doesn't become an
       unhandled rejection or leave the toggle stale. */
    sub.unsubscribe().then(function(){post('/api/push/unsubscribe',{endpoint:ep}).then(function(){refreshPushUI();refresh();});}).catch(function(){setTog('pushToggle',false);setPushHelp('Push state unavailable \u2014 using in-page alerts.');refreshPushUI();});
  }).catch(function(){setTog('pushToggle',false);setPushHelp('Push state unavailable \u2014 using in-page alerts.');refreshPushUI();});
}
function togglePush(){var on=$('pushToggle').getAttribute('aria-checked')==='true';
  var tgt=$('pushToggle').querySelector(!on?'.half.i':'.half.o');if(tgt)tgt.classList.add('loading');  // spinner on the target half; refreshPushUI clears it when the flow settles
  if(on)disablePush();else enablePush();}
$('pushToggle').addEventListener('click',togglePush);
$('pushToggle').addEventListener('keydown',function(e){if(e.key===' '||e.key==='Enter'){e.preventDefault();togglePush();}});
btnBusy('testPushBtn',function(){return post('/api/push/test').then(function(d){setPushHelp((d&&d.success)?'Test sent \u2014 check your notifications.':((d&&d.message)||'Test failed.'));});});

/* ---------- SYSTEM charts (hand-rolled inline SVG, no libs) ---------- */
var SYS=(function(){
  var SVGNS="http://www.w3.org/2000/svg";
  var W=300,H=100;                 // viewBox units (preserveAspectRatio=none stretches)
  var points=[];                   // full fetched buffer (up to ~1h)
  var view=[];                     // slice of points within the selected time window
  var windowSec=3600;              // duration selector: 300 / 900 / 3600 (default 60m)
  var capacity=240;                // server ring-buffer size (from endpoint); caps our buffer
  // Field order MUST match the backend SYS_FIELDS tuple (minus "t", handled separately).
  var COLKEYS=["cpu","mem","load1","load5","temp","volt","thr","rssi","qual"];
  // Rebuild row objects {t,cpu,mem,...} from the columnar payload {cols:{t:[...],...}}.
  // The charts consume row objects, so we reconstruct them here rather than reworking
  // every consumer to read columns. Returns [] if the payload is empty/malformed.
  function colsToRows(d){
    var c=d&&d.cols;if(!c||!c.t)return [];
    var n=c.t.length,out=new Array(n);
    for(var i=0;i<n;i++){var row={t:c.t[i]};
      for(var k=0;k<COLKEYS.length;k++){var col=c[COLKEYS[k]];row[COLKEYS[k]]=col?col[i]:null;}
      out[i]=row;}
    return out;}
  // Per-chart definitions: which series, colors, axis behavior.
  var CHARTS={
    compute:{series:[{k:"cpu",c:"#ffb347"},{k:"mem",c:"#6fd3e0"}],min:0,max:100},
    load:{series:[{k:"load1",c:"#9fb5ff"},{k:"load5",c:"#eb9fd0"}],min:0,max:"auto"},
    vitals:{series:[{k:"temp",c:"#ff8a6a",axis:"l"},{k:"volt",c:"#6fd3e0",axis:"r"}],
            dual:true,bands:true},
    link:{series:[{k:"rssi",c:"#7ce0b0",axis:"l"},{k:"qual",c:"#ffb347",axis:"r"}],dual:true}
  };
  var hidden={};                   // series key -> true when legend-toggled off

  function el(name,attrs){var e=document.createElementNS(SVGNS,name);
    for(var a in attrs)e.setAttribute(a,attrs[a]);return e;}
  function svgOf(chart){return document.querySelector('#sysChart-'+chart+' .sysgraph');}

  // Restrict the full buffer to the selected time window (relative to the newest point).
  function computeView(){
    if(!points.length){view=[];return;}
    var cut=points[points.length-1].t-windowSec;
    view=points.filter(function(p){return p.t>=cut;});}

  // Value range for a set of series keys across the VISIBLE points (nulls skipped).
  function rangeOf(keys){var lo=Infinity,hi=-Infinity;
    for(var i=0;i<view.length;i++){for(var j=0;j<keys.length;j++){
      var v=view[i][keys[j]];if(v==null)continue;if(v<lo)lo=v;if(v>hi)hi=v;}}
    if(lo===Infinity)return null;return [lo,hi];}

  // Build "x,y x,y" polyline segments for one series, splitting on nulls so gaps
  // aren't drawn as straight lines through missing data.
  function segs(key,ymin,ymspan){
    var n=view.length,out=[],cur=[];
    for(var i=0;i<n;i++){
      var v=view[i][key];
      if(v==null){if(cur.length){out.push(cur);cur=[];}continue;}
      var x=n<2?0:(i/(n-1))*W;
      var y=H-((v-ymin)/(ymspan||1))*H;
      cur.push(x.toFixed(1)+","+y.toFixed(1));
    }
    if(cur.length)out.push(cur);return out;}

  // Scale helper for a chart+series: returns [ymin, yspan] honoring fixed/auto/dual.
  function scaleFor(def,key){
    if(def.dual){var r=rangeOf([key]);if(!r)return [0,1];
      var pad=(r[1]-r[0])*0.15||1;return [r[0]-pad,(r[1]-r[0])+2*pad];}
    if(def.max==="auto"){var rr=rangeOf(def.series.map(function(s){return s.k;}));
      var top=rr?Math.max(1.0,rr[1]*1.2):1.0;return [def.min,top-def.min];}
    return [def.min,def.max-def.min];}

  function draw(chart){
    var def=CHARTS[chart],svg=svgOf(chart);if(!svg)return;
    while(svg.firstChild)svg.removeChild(svg.firstChild);
    // faint horizontal grid
    for(var g=1;g<4;g++)svg.appendChild(el("line",
      {x1:0,y1:g*H/4,x2:W,y2:g*H/4,"class":"grid"}));
    if(!view.length)return;
    // throttle/undervolt alert bands behind VITALS
    if(def.bands){var n=view.length,run=null;
      for(var i=0;i<=n;i++){
        var bad=i<n&&view[i].thr!=null&&((view[i].thr&0x1)||(view[i].thr&0x4));
        if(bad&&run===null)run=i;
        else if(!bad&&run!==null){
          var x0=(run/(n-1))*W,x1=((i-1)/(n-1))*W;
          svg.appendChild(el("rect",{x:x0,y:0,width:Math.max(1,x1-x0),height:H,"class":"band"}));
          run=null;}}}
    // series polylines
    def.series.forEach(function(s){
      if(hidden[s.k])return;
      var sc=scaleFor(def,s.k);
      segs(s.k,sc[0],sc[1]).forEach(function(seg){
        var pl=el("polyline",{points:seg.join(" ")});
        pl.style.stroke=s.c;pl.style.color=s.c;svg.appendChild(pl);});});
    // y-axis corner labels for EVERY chart (crisp HTML overlay; SVG text would distort
    // under the non-uniform viewBox scale). A series with NO data (all null -- e.g.
    // voltage off-Pi) gets a BLANK axis rather than a phantom 0..1 scale.
    var lk=def.series[0].k,tl="",bl="",tr="",br="";
    if(rangeOf([lk])){var l=scaleFor(def,lk);tl=axfmt(l[0]+l[1]);bl=axfmt(l[0]);}
    if(def.dual){var rk=def.series[1].k;
      if(rangeOf([rk])){var r=scaleFor(def,rk);tr=axfmt(r[0]+r[1]);br=axfmt(r[0]);}}
    // Colour axes by SCALE, not just by series: DUAL-scale charts (vitals/link) tint each
    // axis to ITS own line (left=series[0], right=series[1]); SAME-scale charts (compute/load),
    // where a SINGLE shared y-axis serves BOTH lines, use neutral WHITE so the axis isn't
    // misread as belonging to only one of the two series.
    var leftC=def.dual?def.series[0].c:"#e8e8ea";
    setAx(chart,tl,bl,tr,br,leftC,def.dual?def.series[1].c:null);
  }
  function axfmt(v){return v===0?"0":(Math.abs(v)<10?v.toFixed(2):v.toFixed(0));}
  function setAx(chart,tl,bl,tr,br,lc,rc){
    var s=document.querySelectorAll('#sysChart-'+chart+' .sys-ax');
    if(s.length<4)return;
    s[0].textContent=tl;s[1].textContent=bl;s[2].textContent=tr;s[3].textContent=br;
    if(lc){s[0].style.color=lc;s[1].style.color=lc;}
    if(rc){s[2].style.color=rc;s[3].style.color=rc;}}

  // Toggle the loading spinner on every chart screen (shown until data lands).
  function setScreensLoading(on){
    for(var c in CHARTS){var scr=document.querySelector('#sysChart-'+c+' .sys-screen');
      if(scr)scr.classList.toggle('loading',on);}}
  function render(){
    computeView();
    setScreensLoading(!points.length);   // clears the spinner once the first data is in
    for(var c in CHARTS){
      if(!document.getElementById('sysChart-'+c).classList.contains('collapsed'))draw(c);}
    if(window.SYS_afterRender)window.SYS_afterRender();}

  function load(){
    // History goes through the SAME single serial poll queue as state/events (key 'sys')
    // -- only ONE request is ever in flight across the whole app. The columnar payload +
    // ?since= delta keep history small enough that it doesn't monopolize the lane: the
    // first open ships the (now-compact) buffer once, then every poll ships only the NEW
    // points. pollFetch coalesces a still-queued 'sys' job (freshest ?since=) and handles
    // the abort-timeout, so nothing stacks and the queue can't wedge.
    var q='/api/system/history';
    if(points.length)q+='?since='+points[points.length-1].t;
    else setScreensLoading(true);          // first load: show the spinners right away
    return pollFetch('sys',q,REQ_TIMEOUT_MS).then(function(d){
        if(!d)return;                       // coalesced / failed / aborted -- nothing to merge
        if(d.capacity)capacity=d.capacity;
        var fresh=colsToRows(d);
        if(!points.length){points=fresh;}
        else if(fresh.length){
          var lastT=points[points.length-1].t;
          for(var i=0;i<fresh.length;i++){if(fresh[i].t>lastT)points.push(fresh[i]);}
          if(points.length>capacity)points=points.slice(points.length-capacity);
        }
        render();
      });
  }

  return {load:load,render:render,draw:draw,CHARTS:CHARTS,hidden:hidden,
          setWindow:function(s){windowSec=s;render();},
          getWindow:function(){return windowSec;},
          get points(){return points;},set points(v){points=v;},
          get view(){return view;}};
})();

/* ---------- connection / latency indicator (sticky header) ---------- */
/* Paint the header's net indicator from NET (fed by netFetch on every request). Colour +
   state by rough latency; RECONNECTING when the last request failed or nothing has
   succeeded for a while; a shimmer runs while requests are pending. */
function netRender(){
  var ind=$('netInd');if(!ind)return;
  var now=Date.now();
  var stale=NET.lastOk&&(now-NET.lastOk>32000);
  var reconnecting=(NET.pending===0&&NET.lastErr>NET.lastOk)||stale;
  var n=NET.samples.length;
  var ms=n?Math.round(NET.samples.reduce(function(a,b){return a+b;},0)/n):null; // avg of last 8
  var cls='ok',state='ONLINE';
  if(reconnecting){cls='bad';state='RECONNECTING';}   // red reserved for no-connection
  else if(ms==null){state='CONNECTING';}
  else if(ms>=5000){cls='vslow';state='VERY SLOW';}    // orange: very slow
  else if(ms>=1000){cls='slow';state='SLOW';}          // yellow: connected but slow
  else{cls='ok';state='ONLINE';}                        // green: under 1s
  clsIf(ind,'sh-net '+cls);
  var hdr=$('stickyHdr');if(hdr)hdr.classList.toggle('syncing',NET.pending>0);
  txt($('nbState'),state);
  txt($('nbMs'),(ms!=null&&!reconnecting)?(ms+' ms'):'');
  // Mirror the same state onto the top placard indicator so the top-of-page header shows
  // ONLINE + ms + the pending spinner too (kept in sync from the one NET source).
  var indTop=$('netIndTop');
  if(indTop){clsIf(indTop,'ph-net '+cls);
    txt($('nbStateTop'),state);
    txt($('nbMsTop'),(ms!=null&&!reconnecting)?(ms+' ms'):'');}
  var pc=$('placard');if(pc)pc.classList.toggle('syncing',NET.pending>0);
}
// Reveal the sticky header once scrolled past the placard.
(function(){var hdr=$('stickyHdr');if(!hdr)return;
  function onScroll(){var y=window.pageYOffset||document.documentElement.scrollTop||0;
    hdr.classList.toggle('show',y>110);}
  window.addEventListener('scroll',onScroll,{passive:true});onScroll();})();
// Refresh the indicator on a timer too, so RECONNECTING/staleness shows even when no
// request has completed to trigger a repaint.
setInterval(netRender,2000);netRender();

/* ---------- boot ---------- */
buildOdometer();initDrawer('fuelDrawer','fuel');initDrawer('advDrawer','adv');
// EVENT LOG view toggle: wire the segmented buttons + restore the persisted view. In
// APP-LOG mode we set the class + light the segment here; the initial fetch is driven
// by the first refresh() below (loadLogFeed -> loadAppLog), which shows the spinner.
(function(){var seg=$('logViewToggle');if(!seg)return;
  seg.addEventListener('click',function(e){var b=e.target.closest('button[data-view]');if(!b)return;setLogView(b.getAttribute('data-view'));});
  var bs=seg.querySelectorAll('button');for(var i=0;i<bs.length;i++){bs[i].classList.toggle('on',bs[i].getAttribute('data-view')===logView);}
  if(logView==='log')$('log').classList.add('applog');
  setTog('httpToggle',!_hideHttp);})();   // reflect the persisted routine-HTTP filter pref
// SYSTEM drawer: poll history only while open (zero cost when closed). Its persisted open
// state is restored by initDrawer, which fires this callback -- so a drawer left open
// resumes polling immediately on load (no more re-opening it every launch).
var _sysTimer=null;
initDrawer('sysDrawer','sys',function(open){
  if(open){SYS.load();if(!_sysTimer)_sysTimer=setInterval(function(){SYS.load();},15000);}
  else if(_sysTimer){clearInterval(_sysTimer);_sysTimer=null;}
});

/* ---------- SYSTEM interaction: hover, strips, collapse, legend, status ---------- */
(function(){
  var LS_C="gp.sys.collapsed",LS_H="gp.sys.hidden";
  function relTime(t){var s=Math.max(0,Math.round(Date.now()/1000)-t);
    if(s<60)return "-"+s+"s";if(s<3600)return "-"+Math.round(s/60)+"m";
    return "-"+(s/3600).toFixed(1)+"h";}
  function num(v,suf,dp){return v==null?"--":((dp!=null?v.toFixed(dp):v)+(suf||""));}

  function esc(s){return String(s).replace(/[<>&]/g,function(c){
    return c==="<"?"&lt;":c===">"?"&gt;":"&amp;";});}
  function seg(text,color){return '<span style="color:'+color+'">'+esc(text)+'</span>';}
  function thrWord(thr){if(thr==null)return "";
    if(thr&0x1)return "\u26d4undervolt";if(thr&0x4)return "\u26a0throttle";
    if((thr&0x10000)||(thr&0x40000))return "\u26a0since-boot";return "\u2713nominal";}
  function thrColor(thr){if(thr&0x1)return "#ff8a6a";
    if((thr&0x4)||(thr&0x10000)||(thr&0x40000))return "#ffb347";return "#7ce0b0";}
  // Build the hover strip: time LEFT, colour-matched values RIGHT. Each value's colour
  // matches its chart line.
  // Colour-matched value segments for a point -- shared by the hover strip AND the
  // collapsed-chart header readout, so both always agree.
  function valsHTML(chart,p){
    if(!p)return "";
    if(chart==="compute")return seg("CPU "+num(p.cpu,"%"),"#ffb347")+seg("MEM "+num(p.mem,"%"),"#6fd3e0");
    if(chart==="load")return seg("1m "+num(p.load1,"",2),"#9fb5ff")+seg("5m "+num(p.load5,"",2),"#eb9fd0");
    if(chart==="vitals"){var v=seg(num(p.temp,"\u00b0C",1),"#ff8a6a")+seg(num(p.volt,"V",2),"#6fd3e0");
      var w=thrWord(p.thr);if(w)v+=seg(w,thrColor(p.thr));return v;}
    if(chart==="link")return seg(num(p.rssi,"dBm"),"#7ce0b0")+seg("q"+num(p.qual,""),"#ffb347");
    return "";}
  function stripHTML(chart,p){
    if(!p)return '<span class="t">\u2014</span>';
    // The LEFT time indicator is only meaningful while hovering a point; at rest it's just
    // "-Ns" of the latest sample (noise). Show it only on hover -- keep an empty .t span so
    // the values stay right-aligned via the strip's space-between layout.
    var tstr=hoverIdx>=0?esc(relTime(p.t)):"";
    return '<span class="t">'+tstr+'</span><span class="v">'+valsHTML(chart,p)+'</span>';}

  var hoverIdx=-1;                 // -1 => show latest
  function updateStatus(){
    var pts=SYS.view,p=null;
    if(pts.length)p=hoverIdx>=0&&hoverIdx<pts.length?pts[hoverIdx]:pts[pts.length-1];
    var last=pts.length?pts[pts.length-1]:null;   // latest sample: collapsed-header readout + chip
    for(var c in SYS.CHARTS){
      var strip=document.querySelector('#sysChart-'+c+' .sys-strip');
      if(strip)strip.innerHTML=stripHTML(c,p);
      // collapsed chart shows its LATEST values in the header (cross-fades with the legend)
      var hv=document.querySelector('#sysChart-'+c+' .sys-head-vals');
      if(hv)hv.innerHTML=valsHTML(c,last);}
    // The throttle/undervolt chip reflects the LATEST sample; it lives in the drawer body
    // (visible only when the drawer is open). Off a Pi there's no throttle data -> HIDE the
    // chip entirely rather than show a useless "--". (The FACE stat -- CPU% -- is driven by
    // applyState from the state poll, so it stays live even when the drawer is collapsed.)
    var chip=$('sysThrChip');
    if(chip){var t=last?last.thr:null;
      if(t==null){chip.style.display="none";}
      else{chip.style.display="";
        if(t&0x1){chip.className="sys-chip uv";chip.textContent="UNDERVOLTING";}
        else if((t&0x10000)||(t&0x40000)){chip.className="sys-chip thr";chip.textContent="THROTTLED";}
        else{chip.className="sys-chip clean";chip.textContent="NOMINAL";}}}
  }

  // Synced crosshair: pointer x over any screen -> nearest index -> all strips.
  function showAt(idx){hoverIdx=idx;
    document.querySelectorAll('#sysDrawer .sysgraph .cross,#sysDrawer .sysgraph .dot')
      .forEach(function(n){n.remove();});
    var pts=SYS.view;
    if(idx>=0&&pts.length>1){var x=(idx/(pts.length-1))*300;
      for(var c in SYS.CHARTS){var svg=document.querySelector('#sysChart-'+c+' .sysgraph');
        if(!svg||document.getElementById('sysChart-'+c).classList.contains('collapsed'))continue;
        var ln=document.createElementNS("http://www.w3.org/2000/svg","line");
        ln.setAttribute("x1",x);ln.setAttribute("y1",0);ln.setAttribute("x2",x);
        ln.setAttribute("y2",100);ln.setAttribute("class","cross");svg.appendChild(ln);}}
    updateStatus();}

  function bindHover(){
    document.querySelectorAll('#sysDrawer .sys-screen').forEach(function(scr){
      scr.addEventListener('mousemove',function(e){move(e.clientX,scr);});
      scr.addEventListener('touchmove',function(e){
        if(e.touches[0])move(e.touches[0].clientX,scr);},{passive:true});
      scr.addEventListener('mouseleave',function(){showAt(-1);});});}
  function move(clientX,scr){var r=scr.getBoundingClientRect();
    var pts=SYS.view;if(!pts.length)return;
    var frac=Math.min(1,Math.max(0,(clientX-r.left)/r.width));
    showAt(Math.round(frac*(pts.length-1)));}

  // Per-chart collapse (eye) with localStorage persistence.
  function loadSet(k){try{return JSON.parse(localStorage.getItem(k))||[];}catch(e){return [];}}
  function saveSet(k,arr){try{localStorage.setItem(k,JSON.stringify(arr));}catch(e){}}
  function applyCollapsed(){var cs=loadSet(LS_C);
    for(var c in SYS.CHARTS){$('sysChart-'+c).classList.toggle('collapsed',cs.indexOf(c)>=0);}}
  // The whole chart header toggles collapse/expand, EXCEPT clicks that land on a legend
  // series chip (those toggle that series' visibility instead). The caret on the right is
  // just a visual state indicator now -- driven purely by the .collapsed class via CSS.
  function bindFaces(){
    document.querySelectorAll('#sysDrawer .sys-panel-face').forEach(function(face){
      var panel=face.closest('.sys-panel'),c=panel.getAttribute('data-chart');
      face.setAttribute('role','button');face.setAttribute('tabindex','0');
      face.setAttribute('aria-label','Collapse or expand the '+c+' chart');
      function syncAria(){face.setAttribute('aria-expanded',panel.classList.contains('collapsed')?'false':'true');}
      syncAria();
      function toggle(){
        panel.classList.toggle('collapsed');
        var cs=loadSet(LS_C),i=cs.indexOf(c);
        if(panel.classList.contains('collapsed')){if(i<0)cs.push(c);}else if(i>=0)cs.splice(i,1);
        saveSet(LS_C,cs);syncAria();SYS.render();}
      face.addEventListener('click',function(e){
        if(e.target.closest('.sys-leg'))return;   // legend chip handles its own click
        toggle();});
      face.addEventListener('keydown',function(e){
        if(e.target.closest('.sys-leg'))return;
        if(e.key==='Enter'||e.key===' '){e.preventDefault();toggle();}});});}

  // Legend series toggles (persisted).
  function applyHidden(){var hs=loadSet(LS_H);hs.forEach(function(k){SYS.hidden[k]=true;});
    document.querySelectorAll('#sysDrawer .sys-leg').forEach(function(l){
      l.classList.toggle('off',!!SYS.hidden[l.getAttribute('data-series')]);});}
  function bindLegend(){
    document.querySelectorAll('#sysDrawer .sys-leg').forEach(function(l){
      l.addEventListener('click',function(){var k=l.getAttribute('data-series');
        SYS.hidden[k]=!SYS.hidden[k];l.classList.toggle('off',!!SYS.hidden[k]);
        var hs=loadSet(LS_H),i=hs.indexOf(k);
        if(SYS.hidden[k]){if(i<0)hs.push(k);}else if(i>=0)hs.splice(i,1);
        saveSet(LS_H,hs);SYS.render();});});}

  // Re-apply strips after every data render.
  window.SYS_afterRender=function(){updateStatus();};

  // Duration selector (5m/15m/60m), persisted. Filters the visible window client-side;
  // the buffer already holds up to an hour, so no refetch is needed.
  var LS_W="gp.sys.window";
  function bindWindow(){
    var saved=parseInt(localStorage.getItem(LS_W))||3600;
    var btns=document.querySelectorAll('#sysWin button');
    btns.forEach(function(b){
      var sec=parseInt(b.getAttribute('data-sec'));
      b.classList.toggle('on',sec===saved);
      b.addEventListener('click',function(){
        btns.forEach(function(x){x.classList.remove('on');});
        b.classList.add('on');
        try{localStorage.setItem(LS_W,String(sec));}catch(e){}
        hoverIdx=-1;SYS.setWindow(sec);});});
    SYS.setWindow(saved);}

  applyCollapsed();applyHidden();bindFaces();bindLegend();bindHover();bindWindow();updateStatus();
})();
registerSW();
refresh();
setInterval(function(){if(!busy)refresh();},refreshMs);

/* iOS/Safari scroll-anchor net (#40, v1.3.1). WebKit has no `overflow-anchor`, so a genuine
   above-the-fold height change while the user is parked at the footer would jump + clip the page.
   Chrome/Firefox anchor natively -> install ONLY where it's absent so we never double-compensate.
   A ResizeObserver on <body> catches a height change and shifts scroll by the delta to hold the
   visual position. SECONDARY net only: the actual #40 jump was root-caused to spurious NO-OP DOM
   writes on the state poll (WebKit reacts to a re-write even when the value is unchanged) and fixed
   by the idempotent render helpers (txt/clsIf/attrIf/styIf/htmlIf/propIf) above -- that jump had NO
   height change, so this observer never fired for it. This stays as belt-and-suspenders for any
   real future above-fold height change on WebKit. */
(function(){
  if(!window.ResizeObserver) return;
  try{ if(window.CSS && CSS.supports && CSS.supports('overflow-anchor','auto')) return; }catch(e){}
  var de=document.documentElement, lastH=de.scrollHeight;
  new ResizeObserver(function(){
    var h=de.scrollHeight, dh=h-lastH; lastH=h;
    if(Math.abs(dh)<1) return;
    var y=window.scrollY||window.pageYOffset||0;
    if(y>0) window.scrollTo(0, y+dh);
  }).observe(document.body);
})();
/* ---------- footer update check ---------- */
/* Ask the server (which can reach GitHub; the page's CSP can't) for the latest published
   version. ONLY when a newer one exists do we reveal the footer update banner (+ pulse the
   version yellow); otherwise the banner stays hidden. Runs once on load; the server ALSO
   checks hourly and pushes a notification (once per run) when no browser is open. */
/* Populate the contextual update line. text = the status; actionLabel/actionMode/href set
   the trailing " · <link>" (omitted when actionLabel is falsy). Always reveals the row. */
function _updSet(text,actionLabel,actionMode,textHtml){
  var row=$('updRow'),a=$('updAction'),sep=$('updSep'),tx=$('updText');
  // #updText is a plain <span> LABEL (dim, footer colour). The optional textHtml lets a caller
  // embed ONE link inside it (e.g. the version string "v1.1.0" linking to GitHub releases) while
  // the rest of the status text stays a plain dim label; otherwise the escaped text is used.
  if(textHtml!=null){tx.innerHTML=textHtml;}else{tx.textContent=text;}
  if(actionLabel){
    // The ACTION is never a GitHub link -- it only opens the in-app modal (update/forceupdate) or
    // re-checks (recheck). href='#' + the click handler preventDefaults and routes by dataset.mode.
    a.textContent=actionLabel;a.dataset.mode=actionMode||'';a.href='#';a.removeAttribute('target');
    // Arrow separator points toward the "Update now" action; a dot for other actions.
    sep.textContent=(actionMode==='update')?' \u2192 ':' \u00b7 ';
    a.style.display='';sep.style.display='';
  }else{a.style.display='none';sep.style.display='none';}
  row.style.display='';
}
/* Check for a newer release. `manual` (version click / "Check again") shows a spinner +
   "Checking…" and, when UP TO DATE, reports "Version up-to-date" as feedback. An AUTOMATIC
   (on-load) check stays silent when up to date -- the line only surfaces for
   available/failed. Both reveal the line for an available update (+ pulse) or a failure. */
function checkUpdate(manual,passive){
  var row=$('updRow'),v=$('verLink');if(!row)return;
  if(updateActive)return;                                    // never poll while an update runs
  if(manual){row.classList.add('checking');_updSet('Checking for updates\u2026');if(v)v.classList.remove('out-of-date');}
  // Manual + on-load do a LIVE repo check (?fresh=1); the passive 5-min refresh reads the
  // server's CACHED last-known result so an open page never hammers GitHub.
  api('/api/check-update'+(passive?'':'?fresh=1')).then(function(d){
    row.classList.remove('checking');
    if(d&&d.update_available&&d.latest){                      // update available
      // Only the VERSION STRING links to GitHub releases (target=_blank); " available!" stays a
      // plain dim label, and the "Update now" action opens the in-app modal (never a GitHub link).
      _updSet('','Update now','update',
        '<a href="https://github.com/mrchrisneal/generatorpi/releases" target="_blank" rel="noopener">v'+d.latest+'</a> available!');
      if(v)v.classList.add('out-of-date');
    }else if(!d||d.latest==null){                             // couldn't reach the repo
      _updSet('Update check failed','Check again','recheck');
      if(v)v.classList.remove('out-of-date');
    }else{                                                    // up to date
      if(v)v.classList.remove('out-of-date');
      // Up-to-date: show the status + a "Force update" action (dev/power feature) that re-runs the
      // full update flow against the CURRENT release without needing a version bump -- handy for
      // testing. The status text is a dim label; only "Force update" is a bright link.
      if(manual){_updSet('Version up-to-date','Force update','forceupdate');}
      else{row.style.display='none';}                        // silent on a normal load
    }
  }).catch(function(){row.classList.remove('checking');_updSet('Update check failed','Check again','recheck');if(v)v.classList.remove('out-of-date');});
}
/* The action link opens the in-app UPDATE modal in the update state; re-checks otherwise. */
$('updAction').addEventListener('click',function(e){
  e.preventDefault();
  var m=this.dataset.mode;
  if(m==='update'||m==='forceupdate'){openUpdateModal();}else{checkUpdate(true);}
});
/* Clicking the version (v1.0.0) runs a MANUAL check instead of navigating -- the title
   tooltip says so on hover. */
(function(){var vl=$('verLink');if(!vl)return;
  vl.addEventListener('click',function(e){e.preventDefault();checkUpdate(true);});})();
checkUpdate();                                               // on-load: one live check
// Keep the footer in sync on a 5-minute timer via the server's CACHED result (no GitHub hit).
setInterval(function(){checkUpdate(false,true);},300000);

/* ---------- self-update flow (changelog -> progress -> restart -> reload) ---------- */
var _updPoll=null;
function _ovShow(id){$(id).className='confirm-overlay show';setBackgroundInert(true);}
function _ovHide(id){$(id).className='confirm-overlay';setBackgroundInert(false);}
// Colour + structure the terminal: bright [SECTION] headers, green "ok", red [ERROR], amber
// [WARNING]/[REVERTED]/[ROLLBACK], dim indented child lines. Text is escaped first (log content
// includes exception messages), so building innerHTML from it is XSS-safe.
var _termFollow=true;
function _esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function _fmtLogLine(line){
  // Server severity markers (\u0001 warn / \u0002 err) colour a WHOLE line that carries no text
  // label (e.g. the copy-clean install command). Stripped here so they never render or get copied.
  var mk=line.charCodeAt(0);
  if(mk===1||mk===2){return '<span class="'+(mk===1?'tl-warn-b':'tl-err-b')+'">'+_esc(line.slice(1))+'</span>';}
  var m=line.match(/^\[([^\]]+)\]\s?(.*)$/);           // [SECTION] optional-rest
  if(m){
    var tag=m[1],rest=m[2]||'',tu=tag.toUpperCase(),cls='tl-hdr',bcls='tl-msg';
    if(tu==='ERROR'){cls='tl-err';bcls='tl-err-b';}
    else if(tu==='WARNING'||tu==='REVERTED'||tu==='ROLLBACK'){cls='tl-warn';bcls='tl-warn-b';}
    // BRIGHT shade on the [TAG]; the rest of the line in the matching NORMAL shade (an "ok" tail
    // stays green) -- mirrors the green [SECTION]+body scheme, in amber / red.
    var out='<span class="'+cls+'">['+_esc(tag)+']</span>';
    if(rest){var rc=/^ok\b/i.test(rest)?'tl-ok':bcls;
      out+=' <span class="'+rc+'">'+_esc(rest)+'</span>';}
    return out;
  }
  // Inline "WARNING:" / "ERROR:" label (possibly indented): bright label + normal-shade remainder,
  // so a whole warning/error DETAIL line reads in its colour with the label brightest.
  var w=line.match(/^(\s*)(WARNING|ERROR):\s?(.*)$/);
  if(w){var lead=w[1],lbl=w[2],body=w[3]||'',er=(lbl==='ERROR');
    return _esc(lead)+'<span class="'+(er?'tl-err':'tl-warn')+'">'+lbl+':</span>'+
      (body?' <span class="'+(er?'tl-err-b':'tl-warn-b')+'">'+_esc(body)+'</span>':'');}
  if(/^\s/.test(line))return '<span class="tl-sub">'+_esc(line)+'</span>';   // indented child
  return '<span class="tl-msg">'+_esc(line)+'</span>';                        // plain line
}
function _termHTML(lines){return lines.map(function(l){return '<div class="tl">'+_fmtLogLine(l)+'</div>';}).join('');}
var _termSig='';
function _renderTerm(el,logArr){
  // Skip the DOM rewrite when the log is unchanged (length + last line identical) -- rewriting
  // innerHTML would wipe the user's text selection, so an idle/parked terminal stays selectable.
  var sig=(logArr?logArr.length:0)+'|'+(logArr&&logArr.length?logArr[logArr.length-1]:'');
  if(sig===_termSig)return;
  _termSig=sig;
  var prev=el.scrollTop;
  el.innerHTML=(logArr&&logArr.length)?_termHTML(logArr):'';
  el.scrollTop=_termFollow?el.scrollHeight:prev;   // follow only while pinned to the bottom
}
// Any scroll away from the bottom stops the auto-follow; returning to the bottom resumes it.
$('updChangelog').addEventListener('scroll',function(){
  var el=this;_termFollow=(el.scrollHeight-el.scrollTop-el.clientHeight)<6;
});
// One-time scroll-to-bottom at each STAGE END so the colored warning/error summary lines (the last
// log lines of the stage) are visible even if the user had scrolled up mid-stage. _lastUpdPhase
// makes it fire once per stage-boundary transition, not on every poll.
var _lastUpdPhase='';
function _updScrollEnd(el){if(el){el.scrollTop=el.scrollHeight;_termFollow=true;}}
// Title spinner while actively working; caution banner (error/abort) or success banner (staged
// ok) beneath the log. Only one banner shows at a time.
function _updWorking(on){var c=$('updCard');if(c)c.classList.toggle('working',!!on);}
function _updWarn(on,text){var w=$('updWarn');if(w)w.classList.toggle('show',!!on);
  if(on&&text){var t=$('updWarnText');if(t)t.textContent=text;}
  if(on){_updOk(false);}}
function _updOk(on){var o=$('updOk');if(o)o.classList.toggle('show',!!on);if(on){var w=$('updWarn');if(w)w.classList.remove('show');}}
// Copy any log/terminal window to the clipboard (the COPY button top-right of a .log-wrap).
// innerText keeps the rendered line breaks; falls back to textarea+execCommand off secure ctx.
document.addEventListener('click',function(e){
  var b=e.target&&e.target.closest?e.target.closest('.log-copy'):null;if(!b)return;
  var el=$(b.dataset.copy);if(!el)return;
  var txt=el.innerText||el.textContent||'';
  // On success, swap the copy glyph for a checkmark (green), then revert after a moment.
  var CHECK='<svg viewBox="0 0 256 256" fill="currentColor" aria-hidden="true"><path d="M229.66,77.66l-128,128a8,8,0,0,1-11.32,0l-56-56a8,8,0,0,1,11.32-11.32L96,188.69,218.34,66.34a8,8,0,0,1,11.32,11.32Z"/></svg>';
  var done=function(){var o=b.innerHTML;b.innerHTML=CHECK;b.classList.add('done');
    setTimeout(function(){b.innerHTML=o;b.classList.remove('done');},1200);};
  var fb=function(){var ta=document.createElement('textarea');ta.value=txt;ta.style.position='fixed';ta.style.opacity='0';
    document.body.appendChild(ta);ta.focus();ta.select();var ok=false;try{ok=document.execCommand('copy');}catch(_e){}
    document.body.removeChild(ta);if(ok)done();};
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(txt).then(done,fb);}
  else{fb();}
});
function openUpdateModal(){
  var cl=$('updChangelog'),doBtn=$('updDoBtn'),cancel=$('updCancelBtn');
  // Reset any leftover restart state: a prior run hides the log box + shows the "Restarting"
  // spinner panel, so restore them (and clear the _waiting guard) so a re-opened / FORCED update
  // starts clean. This is what makes "Force update" / gpForceUpdate() re-runnable without a reload.
  _waiting=false;
  var _w=$('updWaiting'); if(_w)_w.style.display='none';
  if(cl.parentElement)cl.parentElement.style.display='';
  var _cb=$('updCard').querySelector('.confirm-btns'); if(_cb)_cb.style.display='';
  cl.innerHTML='<span class="upd-inline-spin" aria-hidden="true"></span>Loading changelog\u2026';cl.style.display='';
  var note=$('updBackupNote');note.textContent='';note.style.display='';
  $('updProgressWrap').style.display='none';
  doBtn.className='btn3d danger';doBtn.textContent='PROCEED';doBtn.dataset.role='';doBtn.disabled=false;doBtn.style.display='';
  cancel.className='btn3d steel';cancel.textContent='CANCEL';cancel.dataset.role='';cancel.disabled=false;cancel.style.display='';
  _updWorking(false);_updWarn(false);_updOk(false);_showImportant(null);_lastUpdPhase='';
  _ovShow('updModal');doBtn.focus();
  api('/api/update/changelog').then(function(d){
    if(d&&d.changelog){cl.textContent=d.changelog;}
    else{cl.textContent='Changelog unavailable'+((d&&d.error)?(' — '+d.error):'')+'.';}
    note.textContent='All files are backed up to '+((d&&d.backup_dir)||'backups/')+' before updating.';
  }).catch(function(e){cl.textContent='Changelog unavailable — request failed'+(e?(' ('+e+')'):'')+'.';});
}
// Dev/testing convenience: force the update flow from the browser console at any time (even when
// up-to-date) via gpForceUpdate() -- re-runs the whole update against the current release, so we
// don't have to bump/cut a version just to exercise the flow. Same as clicking "Force update".
window.gpForceUpdate=openUpdateModal;
// CANCEL doubles as REVERT while the run is parked on a decision; else it only closes when idle.
$('updCancelBtn').addEventListener('click',function(){
  var b=$('updCancelBtn');
  if(b.dataset.role==='revert'){_decide('revert');return;}
  if(_updPoll||updateActive)return;                      // no closing mid-run
  _ovHide('updModal');
});
$('updDoBtn').addEventListener('click',function(){
  var b=$('updDoBtn');
  if(b.dataset.role==='proceed'){_decide('proceed');return;}   // PROCEED past a warning
  if(b.classList.contains('loading'))return;
  b.classList.add('loading');$('updCancelBtn').disabled=true;
  post('/api/update/start').then(function(){
    updateActive=true;                                   // PAUSE all routine polling now
    _termFollow=true;_termSig='';                        // follow + force a fresh first render
    _updWorking(true);_updWarn(false);_updOk(false);     // spinner on, no banners yet
    var cl=$('updChangelog');cl.style.display='';cl.textContent='Starting…';
    $('updBackupNote').style.display='none';
    b.classList.remove('loading');b.style.display='none';   // progress is automatic
    $('updCancelBtn').textContent='CLOSE';$('updCancelBtn').disabled=true;
    _pollUpdate();
  }).catch(function(){
    b.classList.remove('loading');$('updCancelBtn').disabled=false;
    $('updChangelog').textContent='Could not start the update.';
  });
});
// Answer a REVERT/PROCEED prompt, then resume polling the terminal.
function _decide(choice){
  var doBtn=$('updDoBtn'),cancel=$('updCancelBtn');
  doBtn.style.display='none';doBtn.dataset.role='';
  cancel.dataset.role='';cancel.textContent='CLOSE';cancel.disabled=true;cancel.className='btn3d steel';
  _updWorking(true);_updWarn(false);_updOk(false);_showImportant(null);  // resuming work after the decision
  if(choice==='proceed'){
    // Proceeding = Stage 2 (swap + restart). The moment the decision is accepted, hand the modal
    // over to the "Restarting" spinner (the server is about to go down, so live log streaming would
    // just freeze). The full detailed log is preserved for the result modal. Fire the spinner
    // whether or not the decide response arrives -- the server may restart before it can reply.
    if(_updPoll){clearTimeout(_updPoll);_updPoll=null;}
    post('/api/update/decide',{choice:choice}).then(_waitBackAndReload).catch(_waitBackAndReload);
    return;
  }
  post('/api/update/decide',{choice:choice}).catch(function(){});
  _pollUpdate();
}
// Build + show the dedicated IMPORTANT note box for a release the web updater refuses to install.
// `notes` = the operator note list from the manifest: a NON-EMPTY list -> the intro line, the note(s),
// a fading divider, then the release/repo links (Case A); an EMPTY list -> the single-sentence fallback
// with the links (Case B). `notes === null` -> hide the box (any normal decision / non-blocked state).
// Note text is escaped; the links are a fixed repo + encodeURIComponent(version), so no injection.
var GH_REPO='https://github.com/mrchrisneal/generatorpi';
function _showImportant(notes,version){
  var box=$('updImportant'),body=$('updImportantBody');
  if(notes===null){box.className='upd-important';body.textContent='';return;}
  var rel=GH_REPO+'/releases/tag/v'+encodeURIComponent(version||'');
  var links='the <a href="'+rel+'" target="_blank" rel="noopener noreferrer">release page</a> or '
           +'<a href="'+GH_REPO+'" target="_blank" rel="noopener noreferrer">GitHub repo</a>';
  if(notes.length){
    body.innerHTML='<p>This release cannot be installed by the web updater:</p>'
      +notes.map(function(n){return '<p>'+_esc(n)+'</p>';}).join('')
      +'<div class="drawer-divider"></div>'
      +'<p>For more information, see '+links+'.</p>';
  }else{
    body.innerHTML='<p>This release cannot be installed by the web updater. For more information, see '+links+'.</p>';
  }
  box.className='upd-important show';
}
// Parked on a go/no-go (stage gate) OR an error/warning: offer REVERT (always) + PROCEED (only when the
// step allows it). A NON-proceedable park = a real error/warning -> the amber banner. A NOT-web-installable
// park = the greyed (disabled) apply button + the IMPORTANT box (which carries the message; no amber banner).
function _showDecision(s){
  var doBtn=$('updDoBtn'),cancel=$('updCancelBtn');
  var allow=s.decide&&s.decide.allow_proceed;
  var blocked=s.decide&&s.decide.proceed_disabled;      // release NOT web-installable -> greyed apply btn + IMPORTANT box
  // When blocked there is nothing staged to revert, so the cancel button reads CLOSE (it just dismisses).
  cancel.className='btn3d steel';cancel.textContent=blocked?'CLOSE':'REVERT';cancel.dataset.role='revert';cancel.disabled=false;cancel.style.display='';
  if(allow){
    doBtn.className='btn3d danger';doBtn.textContent=(s.decide.proceed_label)||'PROCEED';doBtn.dataset.role='proceed';doBtn.disabled=false;doBtn.style.display='';
  }else if(blocked){
    // SHOW the apply button but GREYED + disabled so the refused action is visible (not hidden). The
    // IMPORTANT box below says why + how to install manually; dataset.role cleared + the button's
    // `disabled` triggers .btn3d:disabled greying, so a click is inert (backend also refuses proceed).
    doBtn.className='btn3d danger';doBtn.textContent=(s.decide.proceed_label)||'UPDATE';doBtn.dataset.role='';doBtn.disabled=true;doBtn.style.display='';
  }else{doBtn.style.display='none';}
  _showImportant(blocked?(s.important_notes||[]):null,s.version);   // dedicated IMPORTANT box (blocked only)
  _updWorking(false);                                   // not actively working while parked
  if(allow){_updOk(true);}                              // clean staged go/no-go -> green ready banner
  else if(blocked){_updWarn(false);_updOk(false);}      // not-installable: the IMPORTANT box carries the message
  else{_updWarn(true,'A warning or error occurred during the update — review the log above before proceeding.');}
}
function _pollUpdate(){
  if(_updPoll)clearTimeout(_updPoll);
  api('/api/update/status').then(function(s){
    if(!s){_updPoll=setTimeout(_pollUpdate,refreshMs);return;}
    var cl=$('updChangelog');cl.style.display='';_renderTerm(cl,s.log);
    if(s.phase!==_lastUpdPhase){                            // a stage boundary was crossed
      if(s.phase==='awaiting'||s.phase==='restarting'){_updScrollEnd(cl);}   // end of Stage 1 / Stage 2
      _lastUpdPhase=s.phase;
    }
    var working=['checking','downloading','verifying','backing_up','swapping','restarting'].indexOf(s.phase)>=0;
    _updWorking(working);
    if(working){_updWarn(false);_updOk(false);_showImportant(null);}   // no banners/box while actively working
    // Parked on a decision -> STOP polling entirely (zero network traffic while we wait on the
    // human). The REVERT/UPDATE click (_decide) resumes _pollUpdate; nothing changes until then.
    if(s.phase==='awaiting'){_showDecision(s);_updPoll=null;return;}
    if(s.phase==='failed'){                              // reverted / failed -> allow closing
      updateActive=false;                               // resume routine polling (old version runs)
      _updWorking(false);_updOk(false);
      // Contextual banner: a real error vs. a user-initiated revert of a clean staged update.
      if(s.error){_updWarn(true,'A warning or error occurred during the update — review the log above before proceeding.');}
      else{_updWarn(true,'Update aborted by user.');}
      $('updCancelBtn').textContent='CLOSE';$('updCancelBtn').dataset.role='';$('updCancelBtn').disabled=false;
      $('updDoBtn').style.display='none';_updPoll=null;return;
    }
    if(s.phase==='restarting'){_updPoll=null;_waitBackAndReload();return;}
    _updPoll=setTimeout(_pollUpdate,refreshMs);
  }).catch(function(){_updPoll=setTimeout(_pollUpdate,refreshMs);});
}
var _waiting=false;
function _waitBackAndReload(){
  if(_waiting)return; _waiting=true;                     // guard against a double invocation
  // Stage-2 downtime: HIDE the whole log box + note/banners/buttons and show the dedicated waiting
  // panel -- a large rotating spinner + "Restarting" + an elapsed timer. The full detailed log is
  // preserved for the post-restart result modal.
  var card=$('updCard');
  var cl=$('updChangelog'); if(cl&&cl.parentElement)cl.parentElement.style.display='none';   // .log-wrap
  ['updBackupNote','updWarn','updOk','updProgressWrap'].forEach(function(id){var e=$(id);if(e)e.style.display='none';});
  var cb=card.querySelector('.confirm-btns'); if(cb)cb.style.display='none';
  _updWorking(false);
  $('updWaiting').style.display='';
  var banner=$('updWaitBanner'); banner.className='upd-banner';        // hidden until it escalates
  var timerEl=$('updWaitTimer'), t0=Date.now(), dots=0;
  // 1s tick: elapsed timer + escalating INLINE notification banner (same style/size as the result
  // "Update completed" banner) -- orange "Still updating" with animated dots (. .. ... looping) once
  // past 2 min, red "may be unresponsive" past 5 min.
  var render=function(){
    var s=Math.floor((Date.now()-t0)/1000);
    timerEl.textContent=Math.floor(s/60)+':'+('0'+(s%60)).slice(-2);
    if(s>=300){banner.className='upd-banner show upd-banner-err';
      banner.textContent='GeneratorPi may be unresponsive. Please try reloading the page manually.';}
    else if(s>=120){dots=(dots%3)+1;banner.className='upd-banner show upd-banner-warn';
      banner.textContent='Still updating'+new Array(dots+1).join('.');}
  };
  var timer=setInterval(render,1000); render();
  // ROBUST restart detection via the API (the proven auth path, unlike a raw fetch): /api/state now
  // reports started_at (this process's start unix ts). Baseline it from the FIRST (pre-restart)
  // poll -- the re-exec is delayed ~1.5s so the app is still up -- then when started_at CHANGES the
  // app has fully restarted on the new version -> cache-bust reload to the fresh UI (result modal).
  var base=null, tries=0;
  (function poll(){
    tries++;
    api('/api/state').then(function(s){
      if(s&&s.started_at!=null){
        if(base===null){base=s.started_at;}                       // old process (still up)
        else if(s.started_at!==base){clearInterval(timer);        // NEW process -> restarted -> done
          location.replace(location.pathname+'?u='+Date.now());return;}
      }
      if(tries<330)setTimeout(poll,2000);                         // ~11 min ceiling (outlasts the 10m watchdog)
    }).catch(function(){if(tries<330)setTimeout(poll,2000);});    // app down mid-restart -> keep waiting
  })();
}
/* Post-restart result modal: the SAME terminal look, showing the FULL captured log; DISMISS
   clears it server-side so it never reappears until the next update. */
function checkUpdateResult(tries){
  tries=tries||0;
  // After a post-update cache-bust reload (the ?u= param), the systemd bootstrap writes its
  // success/fail marker a few seconds AFTER the app first answers, so retry briefly to catch it
  // rather than miss the result modal (audit M-4). A normal load checks once.
  var retry=function(){if(tries<7&&location.search.indexOf('u=')>=0)setTimeout(function(){checkUpdateResult(tries+1);},2000);};
  api('/api/update/result').then(function(d){
    if(!d||!d.pending){retry();return;}
    var ok=(d.status==='success');
    $('updResultTitle').textContent=ok?'UPDATE COMPLETE':'UPDATE FAILED';
    // Success/failure notice as a prominent banner ABOVE the DISMISS button (the old reddish top
    // note was removed per design). Checkmark for success, caution triangle for a failed update.
    var ban=$('updResultBanner');
    ban.className='upd-banner show '+(ok?'upd-banner-ok':'upd-banner-warn');
    ban.innerHTML=ok
      ?'<span class="upd-ico">\u2713</span><span>The update completed successfully!</span>'
      :'<span class="upd-ico">\u26a0</span><span>The update did not complete.</span>';
    // Same colourised terminal as the live view, showing the FULL captured log; start at the
    // TOP so the reader can follow it from the beginning.
    var lg=$('updResultLog');lg.innerHTML=_termHTML(String(d.log||'(no log captured)').split('\n'));lg.scrollTop=0;
    _ovShow('updResultModal');
  }).catch(function(){retry();});
}
$('updResultDismiss').addEventListener('click',function(){
  var b=$('updResultDismiss');if(b.classList.contains('loading'))return;
  b.classList.add('loading');
  post('/api/update/result/ack').catch(function(){}).then(function(){
    b.classList.remove('loading');_ovHide('updResultModal');});
});
checkUpdateResult();
setInterval(function(){tick();},1000);
})();
