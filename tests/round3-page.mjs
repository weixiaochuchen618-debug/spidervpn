// TradeChannelRs（Rust 版）第三轮 · 界面导入「端口」控件核验
//
// 目的：核验 item1（界面导入加端口选择）。四条要求必须同时成立：
//   ① 表单有端口输入框，留空 = 17890；
//   ② 填合法端口 → 命令里带上 port=n；
//   ③ 填非法（0 / 65533 / 非数字）→ 页面**提示**且**不发命令**；
//   ④ .imp 改成 flex-wrap，多控件不挤坏「线路名」。
//
// 口径按主理人拍板的 **B 方案（加 validity.badInput 判断）**：
//     pt = el.value            // number 控件遇到非数字，value 回 ""
//     if (el.validity.badInput)                 → 提示、不发命令
//     else if (pt === '')                        → 留空，用 17890，**不带 port 字段**
//     else if (!整数 || <1 || >65532)            → 提示、不发命令
//     else                                       → 发命令，带 port
// 为什么非加不可：`<input type="number">` 会把用户打的非数字清成空串，只留 badInput=true。
// 不判 badInput 时，"用户以为填了端口、实际悄悄用了 17890 且一声不吭" —— 静默回落。
//
// 为什么要从 exe 里抽 HTML：测的必须是**交付物**，不是仓库里那份源码。
// HTML 以明文存在于产物中（`<!DOCTYPE html>` / `</html>` 各唯一 1 处）。
//
// 三层证据，缺一不可：
//   A. 静态：控件属性、CSS、守卫与发命令的**代码次序**；
//   B. Node vm + DOM 桩：直接执行产物里的那段 JS，对「点导入」做行为断言
//      （提示文案 / postMessage 调用次数 / 命令里有没有 port）。"提示"与"不发命令"必须**同时**断言。
//   C. 无头浏览器（Chrome/Edge）：`<input type="number">` 的 value sanitization 与 badInput
//      是**浏览器**行为，Node 桩只是个模型。P5b 那类（非数字）的真值只有真浏览器能给。
//   D. 同一份 HTML 在 380/460/700px 下量矩形：flex-wrap 真的折行、线路名不被挤没。
//
// 不起产品进程、不占任何端口、不写注册表、不碰数据根。
//
// 用法：node tests\round3-page.mjs [exe] [chrome]
//       TC_NO_BROWSER=1 → 只跑 A/B 两段（调试脚本用，不出结论）
// 退出码：0 全通过 / 1 有 FAIL / 2 有 SKIP（缺浏览器等）

import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const EXE = process.argv[2] || 'C:\\TradeChannelRs\\bin\\tradechannel-rs.exe';
const CANDIDATES = [
  process.argv[3],
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
].filter(Boolean);

let pass = 0, fail = 0, skip = 0;
const log = [];
function okMsg(id, desc) { pass++; log.push(`PASS  ${id}  ${desc}`); }
function badMsg(id, desc, detail) { fail++; log.push(`FAIL  ${id}  ${desc} :: ${detail}`); }
function skipMsg(id, desc, why) { skip++; log.push(`SKIP  ${id}  ${desc} :: ${why}`); }
function check(id, desc, cond, detail) { cond ? okMsg(id, desc) : badMsg(id, desc, detail); }
const PROMPT = '端口要填 1~65532 的整数，留空即用 17890';

// ---------------------------------------------------------------- 抽 HTML
const buf = readFileSync(EXE);
const at = (needle, from = 0) => buf.indexOf(Buffer.from(needle, 'utf8'), from);
const i1 = at('<!DOCTYPE html>');
const i2 = at('</html>', i1);
if (i1 < 0 || i2 < 0) {
  console.log('FAIL  E0  产物里找不到内嵌 HTML（<!DOCTYPE html> 起，</html> 止）');
  process.exit(1);
}
const PAGE = buf.slice(i1, i2 + '</html>'.length).toString('utf8');
log.push(`INFO  产物：${EXE}（${buf.length} 字节）`);
log.push(`INFO  从产物抽出页面：${PAGE.length} 字符`);

// ---------------------------------------------------------------- P0 同源：产物里的页面 == 仓库源码里的 PAGE
// 为什么要比：这一条把"我抽出来测的那段 HTML"钉在"实现方真正写的那段"上。
// 若产物是别的构建、或源码在构建后又被改过，这里立刻红——比"测了一个来路不明的页面"强。
{
  const SRC_UI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src', 'ui.rs');
  let srcPage = null;
  try {
    const s = readFileSync(SRC_UI, 'utf8');
    const head = 'const PAGE: &str = r#"';
    const a = s.indexOf(head);
    const b = a < 0 ? -1 : s.indexOf('"#;', a + head.length);
    if (a >= 0 && b > a) srcPage = s.slice(a + head.length, b).replace(/\r\n/g, '\n'); // Rust 会把字面量里的 CRLF 规范成 LF
  } catch {}
  if (srcPage === null) {
    skipMsg('P0', '产物与源码同源（页面部分逐字节一致）', `读不到 ${SRC_UI} 或没找到 PAGE 常量`);
  } else {
    check('P0', '产物内嵌页面与仓库当前源码的 PAGE 逐字节一致（装的是这一份构建）',
      srcPage === PAGE, `源码侧 ${srcPage.length} 字符 vs 产物侧 ${PAGE.length} 字符`);
  }
}

// ---------------------------------------------------------------- A. 静态
const tagOf = (id) => {
  const k = PAGE.indexOf(`id="${id}"`);
  if (k < 0) return '';
  const s = PAGE.lastIndexOf('<', k), e = PAGE.indexOf('>', k);
  return PAGE.slice(s, e + 1);
};
const portTag = tagOf('port');
const profAt = PAGE.indexOf('id="profile"'), portAt = PAGE.indexOf('id="port"'), btnAt = PAGE.indexOf('id="doImport"');

check('P1a', '表单里有端口输入框', portAt > 0, `id="port" 位置=${portAt}`);
check('P1b', '端口框是 type="number" 且 1..65532', /type="number"/.test(portTag) && /min="1"/.test(portTag) && /max="65532"/.test(portTag), portTag);
check('P1c', '端口框占位符写着 17890（留空即用它）', /placeholder="17890"/.test(portTag), portTag);
check('P1d', '端口框在「导入线路」按钮之前', portAt > 0 && btnAt > portAt, `port=${portAt} 按钮=${btnAt}`);
check('P1e', '端口框在路径框之后（profile < port）', profAt > 0 && portAt > profAt, `profile=${profAt} port=${portAt}`);

const impRule = (PAGE.match(/\.imp\{[^}]*\}/) || [''])[0];
check('P1f', '.imp 是 flex-wrap:wrap（多控件折行而不是挤成一团）', /display:flex/.test(impRule) && /flex-wrap:wrap/.test(impRule), impRule);
check('P1g', '端口框宽度固定 flex:0 0 88px（不会被挤没）', /#port\{flex:0 0 88px\}/.test(PAGE), (PAGE.match(/#port\{[^}]*\}/) || [''])[0]);
check('P1h', '线路名框 flex:1 1 140px（可伸缩但有 140px 基准）', /#linename\{flex:1 1 140px\}/.test(PAGE), (PAGE.match(/#linename\{[^}]*\}/) || [''])[0]);

const gAt = PAGE.indexOf('Number.isInteger(n)');
const pAt = PAGE.indexOf('cmd.port=n');
const postAt = PAGE.indexOf('postMessage(JSON.stringify(cmd))');
const badAt = PAGE.indexOf('badInput');
check('P1i', '端口校验（整数/范围）写在发命令之前（代码次序）', gAt > 0 && pAt > gAt && postAt > pAt, `整数校验=${gAt} port赋值=${pAt} postMessage=${postAt}`);
check('P1j', '非法时给的文案是定稿那句', PAGE.includes(PROMPT), '未找到该文案');
const guardBlock = gAt >= 0 ? PAGE.slice(gAt, gAt + 120) : '';
check('P1k', '校验分支里确实 return（不是只提示还继续发）', /return;/.test(guardBlock), guardBlock);
check('P1l', '页面会把宿主回包的 detail 显示出来（宿主那句「请换一个线路端口」才到得了用户）',
  PAGE.includes('id="detail"') && /getElementById\('detail'\)\.textContent=s\.detail/.test(PAGE),
  (PAGE.match(/getElementById\('detail'\)[^;]*/) || [''])[0]);

// B 方案的两条结构钉子（真正的证明在 P5b 的行为断言与 §C）
check('P1m', 'B 方案：页面读了 validity.badInput（非数字那条路存在）', badAt > 0, '页面里找不到 badInput');
check('P1n', 'badInput 的判断发生在发命令之前', badAt > 0 && postAt > badAt, `badInput=${badAt} postMessage=${postAt}`);

// ---------------------------------------------------------------- B. Node 桩：执行产物里的真 JS
const scriptStart = PAGE.indexOf('<script>');
const scriptEnd = PAGE.lastIndexOf('</script>');
const SRC = PAGE.slice(scriptStart + '<script>'.length, scriptEnd);

function makeSandbox() {
  const els = new Map();
  const posts = [];
  const el = (id) => {
    if (!els.has(id)) els.set(id, {
      id, value: '', textContent: '', innerHTML: '', disabled: false, checked: false,
      className: '', title: '', placeholder: '', type: '', style: {}, dataset: {},
      validity: { badInput: false, valid: true },
      setCustomValidity() {}, checkValidity() { return !this.validity.badInput; },
      _l: {},
      addEventListener(t, fn) { (this._l[t] = this._l[t] || []).push(fn); },
      click() { (this._l.click || []).forEach((fn) => fn.call(this, { target: this, preventDefault() {} })); },
      closest() { return null; },
      getBoundingClientRect() { return { top: 0, left: 0, width: 0, height: 0 }; },
    });
    return els.get(id);
  };
  const sandbox = {
    console, JSON, Math, Number, String, Object, Array, Boolean, Date,
    parseInt, parseFloat, isNaN, isFinite,
    document: { getElementById: el, querySelector: () => null, querySelectorAll: () => [], body: {} },
    window: { ipc: { postMessage: (m) => posts.push(m) } },
  };
  sandbox.window.window = sandbox.window;
  sandbox.globalThis = sandbox;
  return { sandbox, el, posts };
}

const { sandbox, el, posts } = makeSandbox();
let loadErr = null;
try {
  vm.createContext(sandbox);
  vm.runInContext(SRC, sandbox, { filename: 'page-from-exe.js', timeout: 5000 });
} catch (e) { loadErr = e; }
check('P2a', '产物里的页面脚本能在 Node 里加载（注册监听不报错）', !loadErr, loadErr && (loadErr.stack || String(loadErr)));
if (loadErr) { dump(); process.exit(1); }

// 按 HTML 规范给 number 控件建模（真值由 §C 的真浏览器给）：
//   · 空串/纯空格 → value=""，badInput=false（用户没打字，或只敲了空格）
//   · 合法浮点数 → value 原样保留，badInput=false
//   · 其它（字母、0x、全角）→ value=""，badInput=true
const isFloat = (s) => /^-?(\d+(\.\d+)?|\.\d+)([eE][-+]?\d+)?$/.test(s);
function browserModel(raw) {
  if (raw.trim() === '') return { value: '', badInput: false };
  if (!isFloat(raw)) return { value: '', badInput: true };
  return { value: raw, badInput: false };
}

// 一个用例：设好输入 → 点导入 → 看「提示」和「发了什么命令」
function clickImport(rawPort, model = 'browser') {
  posts.length = 0;
  el('profile').value = 'C:\\tmp\\dual-mode.json';
  el('engine').value = 'C:\\tmp\\sing-box.exe';
  el('linename').value = '核验线路';
  el('mode').value = 'proxy';
  el('msg').textContent = '';
  el('doImport').disabled = false;
  const m = model === 'browser' ? browserModel(rawPort) : { value: rawPort, badInput: false };
  el('port').value = m.value;
  el('port').validity.badInput = m.badInput;
  el('doImport').click();
  const sent = posts.slice();
  let parsed = null;
  try { parsed = JSON.parse(sent[0]); } catch {}
  return { msg: el('msg').textContent, sent, parsed, disabled: el('doImport').disabled, model: m };
}

// 断言模板：非法 ⇒ 有提示 且 一次命令都不发 且 按钮没被禁死 且 没有进入"导入中…"
function illegalCase(id, label, raw) {
  const r = clickImport(raw);
  check(id, `${label}「${raw}」→ 提示且**不发命令**`,
    r.sent.length === 0 && r.msg === PROMPT && r.disabled === false && r.msg !== '导入中…',
    `发命令次数=${r.sent.length} 提示="${r.msg}" 按钮disabled=${r.disabled} 模型=${JSON.stringify(r.model)}`);
}
function legalCase(id, raw) {
  const r = clickImport(raw);
  check(id, `合法「${raw}」→ 发 1 次命令且 port=${raw}`,
    r.sent.length === 1 && r.parsed && r.parsed.port === Number(raw) && Number.isInteger(r.parsed.port),
    `次数=${r.sent.length} 命令=${r.sent[0]}`);
}

// B1 留空：不填端口也必须能导入，且**不带 port 键**（回落逻辑只写在宿主一处）
{
  const r = clickImport('');
  check('P2b', '留空 → 发 1 次导入命令且 JSON 里没有 port 键',
    r.sent.length === 1 && r.parsed && r.parsed.cmd === 'import' && !('port' in r.parsed),
    `次数=${r.sent.length} 命令=${r.sent[0]}`);
}
// B2 纯空格：number 控件里 value 回 ""、badInput=false → 必须按**留空**处理（单列，别和 abc 混）
{
  const r = clickImport('   ');
  check('P2c', '只填空格 → 按留空处理（value=""、badInput=false），不带 port 键',
    r.model.value === '' && r.model.badInput === false && r.sent.length === 1 && r.parsed && !('port' in r.parsed),
    `模型=${JSON.stringify(r.model)} 次数=${r.sent.length} 命令=${r.sent[0]}`);
}
// B3 范围类：控件能装进去，走整数/范围校验
illegalCase('P2d1', '范围外', '0');
illegalCase('P2d2', '范围外', '65533');
// B4 P5a：控件能装进去（合法浮点数）→ 整数/范围校验必须挡住
illegalCase('P5a1', '负数', '-1');
illegalCase('P5a2', '非整数', '1.5');
illegalCase('P5a3', '科学计数', '1e5');
// B5 P5b：控件装不进去 → value 被清成 ""、badInput=true → B 方案新增的那条路必须挡住
illegalCase('P5b1', '非数字', 'abc');
illegalCase('P5b2', '数字+字母', '12abc');
illegalCase('P5b3', '十六进制写法', '0x10');
illegalCase('P5b4', '全角数字', '１２３');
// B6 合法值
legalCase('P2e1', '17890');
legalCase('P2e2', '48600');
legalCase('P2e3', '65532');
legalCase('P2e4', '1');
// B7 对照：同一串 abc，在"原样传入"模型下会被整数校验挡住——
// 说明 B 方案不是多余的：不加 badInput 时，真浏览器给的是空串，会走"留空"那条路。
{
  const rawModel = (() => {
    const r = clickImport('abc', 'raw');
    return r;
  })();
  const browser = clickImport('abc', 'browser');
  log.push(`INFO  「abc」两种模型：原样传入 → 提示"${rawModel.msg}"、发命令 ${rawModel.sent.length} 次；` +
    `浏览器（value="" + badInput）→ 提示"${browser.msg}"、发命令 ${browser.sent.length} 次`);
  check('P2f', '传进来的非数字一定被挡住（不论 value 是否已被清空）',
    rawModel.sent.length === 0 && browser.sent.length === 0,
    `原样模型发命令=${rawModel.sent.length} 浏览器模型发命令=${browser.sent.length}`);
}

// ---------------------------------------------------------------- C. 真浏览器
function findBrowser() {
  if (process.env.TC_NO_BROWSER === '1') return null;   // 只跑 A/B 两段
  for (const c of CANDIDATES) { try { readFileSync(c, { flag: 'r' }); return c; } catch {} }
  return null;
}
const BROWSER = findBrowser();

function runHeadless(html, extraArgs) {
  const dir = mkdtempSync(path.join(tmpdir(), 'tc-page-'));
  const file = path.join(dir, 'page.html');
  writeFileSync(file, html, 'utf8');
  const args = [
    '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
    '--disable-extensions', '--disable-sync', '--no-sandbox',
    `--user-data-dir=${path.join(dir, 'ud')}`,
    '--virtual-time-budget=4000',
    ...extraArgs,
    'file:///' + file.replace(/\\/g, '/'),
  ];
  let out = '';
  try { out = execFileSync(BROWSER, args, { encoding: 'utf8', timeout: 90000, stdio: ['ignore', 'pipe', 'pipe'] }); }
  catch (e) { out = (e.stdout || '') + (e.stderr || ''); }
  return { out: String(out), dir };
}
const unescapeHtml = (s) => s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
const grabPre = (dom, id) => {
  const m = dom.match(new RegExp(`<pre id="${id}">([\\s\\S]*?)</pre>`));
  if (!m) return null;
  try { return JSON.parse(unescapeHtml(m[1])); } catch { return null; }
};

if (!BROWSER) {
  skipMsg('P3a', '真浏览器里「非数字」的 .value 与 badInput', '本机没有 Chrome/Edge');
  skipMsg('P5b-浏览器', '真浏览器下的非法输入拦截矩阵', '同上');
  skipMsg('P4a', 'flex-wrap 折行与线路名宽度（380/460/700px）', '同上');
} else {
  log.push(`INFO  浏览器：${BROWSER}`);
  const spy = `<script>window.ipc={postMessage:function(m){(window.__sent=window.__sent||[]).push(m);}};</script>`;
  const runner = `<script>(function(){
    var raws=['',' ','0','65533','65532','17890','48600','-1','1.5','1e5','.5','abc','12abc','0x10','abc123','１２３'];
    var out=[];
    for(var i=0;i<raws.length;i++){
      var v=raws[i], pe=document.getElementById('port');
      pe.value=''; pe.value=v;                       // setter 同样走 value sanitization
      var got=pe.value, bad=!!(pe.validity&&pe.validity.badInput);
      window.__sent=[];
      document.getElementById('msg').textContent='';
      var b=document.getElementById('doImport'); b.disabled=false;
      document.getElementById('profile').value='C:\\\\tmp\\\\a.json';
      document.getElementById('engine').value='C:\\\\tmp\\\\s.exe';
      b.click();
      out.push({raw:v,value:got,badInput:bad,msg:document.getElementById('msg').textContent,
                sent:window.__sent.length,cmd:window.__sent[0]||null,disabled:b.disabled});
    }
    var pre=document.createElement('pre'); pre.id='tcresult';
    pre.textContent=JSON.stringify(out); document.body.appendChild(pre);
  })();</script>`;

  const html = PAGE.replace('<script>', spy + '<script>').replace('</body>', runner + '</body>');
  const { out: dom, dir } = runHeadless(html, ['--dump-dom']);
  try { rmSync(dir, { recursive: true, force: true }); } catch {}
  const rows = grabPre(dom, 'tcresult');
  if (!rows) {
    skipMsg('P3a', '真浏览器下的端口拦截矩阵', '没拿到结果（dump-dom 解析失败）');
  } else {
    const by = (raw) => rows.find((r) => r.raw === raw);
    const abc = by('abc');
    check('P3a', '真浏览器里「非数字」进不了 .value（被清成空串，只留 badInput）',
      abc && abc.value === '' && abc.badInput === true,
      abc ? `value="${abc.value}" badInput=${abc.badInput}` : '缺用例');
    log.push(`INFO  「abc」实测：value="${abc ? abc.value : '?'}" badInput=${abc ? abc.badInput : '?'} ` +
      `→ 点导入后发命令 ${abc ? abc.sent : '?'} 次，提示="${abc ? abc.msg : '?'}"`);
    // 非数字（P5b）：真浏览器里 value 是空串，只有 badInput 能救——B 方案的正面证据
    for (const v of ['abc', '12abc', '0x10', '１２３']) {
      const r = by(v);
      check(`P5b-${v}`, `真浏览器：非数字「${v}」（value="" badInput=true）→ 有提示且不发命令`,
        r && r.value === '' && r.badInput === true && r.sent === 0 && r.msg === PROMPT,
        r ? `value="${r.value}" badInput=${r.badInput} 提示="${r.msg}" 发命令=${r.sent}` : '缺用例');
    }
    // 控件能装进去的非法值（P2d/P5a）：走整数/范围校验
    for (const v of ['0', '65533', '-1', '1.5', '1e5']) {
      const r = by(v);
      check(`P3b-${v}`, `真浏览器：非法「${v}」→ 有提示且不发命令`,
        r && r.sent === 0 && r.msg === PROMPT,
        r ? `value="${r.value}" 提示="${r.msg}" 发命令=${r.sent}` : '缺用例');
    }
    for (const v of ['17890', '48600', '65532']) {
      const r = by(v);
      check(`P3c-${v}`, `真浏览器：合法「${v}」→ 命令里带 port`,
        r && r.sent === 1 && r.cmd && JSON.parse(r.cmd).port === Number(v),
        r ? `value="${r.value}" 发命令=${r.sent} 命令=${r.cmd}` : '缺用例');
    }
    // 留空与纯空格：两条都必须走"留空"，不能因为加了 badInput 就一起被挡掉
    for (const v of ['', ' ']) {
      const r = by(v);
      check(`P3d-${JSON.stringify(v)}`, `真浏览器：${v === '' ? '留空' : '纯空格'} → 按留空处理、发命令且不带 port`,
        r && r.value === '' && r.badInput === false && r.sent === 1 && r.cmd && !('port' in JSON.parse(r.cmd)),
        r ? `value="${r.value}" badInput=${r.badInput} 发命令=${r.sent} 命令=${r.cmd}` : '缺用例');
    }
  }

  // 布局：同一个 .imp 在三种宽度下的矩形
  const layoutRunner = `<script>(function(){
    function r(id){var e=document.getElementById(id);if(!e)return null;var b=e.getBoundingClientRect();
      return {id:id,x:Math.round(b.left),y:Math.round(b.top),w:Math.round(b.width),h:Math.round(b.height)};}
    var ids=['profile','engine','linename','port','mode','doImport'];
    var boxes=ids.map(r);
    var rows={}; boxes.forEach(function(b){ if(b){ rows[b.y]=(rows[b.y]||0)+1; } });
    var ov=[];
    for(var i=0;i<boxes.length;i++)for(var j=i+1;j<boxes.length;j++){
      var a=boxes[i],c=boxes[j]; if(!a||!c)continue;
      var x=Math.min(a.x+a.w,c.x+c.w)-Math.max(a.x,c.x);
      var y=Math.min(a.y+a.h,c.y+c.h)-Math.max(a.y,c.y);
      if(x>1&&y>1) ov.push(a.id+'×'+c.id+'('+x+'×'+y+')');
    }
    var pre=document.createElement('pre'); pre.id='tclayout';
    pre.textContent=JSON.stringify({boxes:boxes,rows:Object.keys(rows).length,overlaps:ov,
      docW:document.documentElement.clientWidth});
    document.body.appendChild(pre);
  })();</script>`;
  const lhtml = PAGE.replace('</body>', layoutRunner + '</body>');

  for (const w of [380, 460, 700]) {
    const { out: wdom, dir: wdir } = runHeadless(lhtml, [`--window-size=${w},900`, '--dump-dom']);
    const lay = grabPre(wdom, 'tclayout');
    try { rmSync(wdir, { recursive: true, force: true }); } catch {}
    if (!lay) { skipMsg(`P4a-${w}`, `${w}px 下的布局测量`, '没拿到结果'); continue; }
    const name = lay.boxes.find((b) => b.id === 'linename');
    const portB = lay.boxes.find((b) => b.id === 'port');
    check(`P4a-${w}`, `${w}px：控件不重叠、线路名不被挤没（行数=${lay.rows} 线路名宽=${name && name.w}）`,
      lay.overlaps.length === 0 && name && name.w >= 60 && portB && portB.w >= 60,
      JSON.stringify(lay));
    log.push(`INFO  ${w}px 布局：${lay.boxes.map((b) => `${b.id}@(${b.x},${b.y})w=${b.w}`).join(' ')} 行数=${lay.rows} 重叠=[${lay.overlaps.join(',')}]`);
  }

  // 截图留证（380px 最窄）。只留导入区：整页太高，.imp 会被挤到视口外拍不到。
  try {
    const shotDir = mkdtempSync(path.join(tmpdir(), 'tc-shot-'));
    const shot = path.join(shotDir, 'imp-380.png');
    const shotHtml = PAGE.replace('</head>',
      '<style>.lines,.split,.opts,.check,dl,.line,.tag{display:none}</style></head>');
    writeFileSync(path.join(shotDir, 'p.html'), shotHtml, 'utf8');
    execFileSync(BROWSER, ['--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run',
      `--user-data-dir=${path.join(shotDir, 'ud')}`, '--virtual-time-budget=3000',
      '--window-size=380,900', `--screenshot=${shot}`,
      'file:///' + path.join(shotDir, 'p.html').replace(/\\/g, '/')], { timeout: 60000, stdio: 'ignore' });
    log.push(`INFO  380px 截图：${shot}`);
  } catch (e) { log.push(`INFO  截图没成功：${e.message}`); }
}

// ---------------------------------------------------------------- 汇总
function dump() { console.log(log.join('\n')); }
dump();
console.log(`\nTOTAL PASS=${pass} FAIL=${fail} SKIP=${skip}`);
if (fail > 0) process.exit(1);
if (skip > 0) process.exit(2);
process.exit(0);
