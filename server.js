// FaceAttend backend - Node 18+, zero dependencies. JSON-file storage (set DATA_DIR to a persistent disk).
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const E=process.env,PORT=+E.PORT||3100,DATA=path.join(E.DATA_DIR||__dirname,'data');fs.mkdirSync(DATA,{recursive:true});
const F=path.join(DATA,'db.json');let db;
try{db=JSON.parse(fs.readFileSync(F,'utf8'))}catch{db={seq:1,users:[],depts:[],classes:[],assigns:[],tt:[],sessions:[],marks:[],fixes:[]}}
const save=()=>{fs.writeFileSync(F+'.tmp',JSON.stringify(db));fs.renameSync(F+'.tmp',F)};
db.faces=db.faces||{};let SECRET=E.JWT_SECRET;if(!SECRET){const f=path.join(DATA,'secret');try{SECRET=fs.readFileSync(f,'utf8')}catch{SECRET=crypto.randomBytes(32).toString('hex');fs.writeFileSync(f,SECRET,{mode:0o600})}}
const b64=o=>Buffer.from(JSON.stringify(o)).toString('base64url'),sig=s=>crypto.createHmac('sha256',SECRET).update(s).digest('base64url');
const sign=id=>{const s=b64({alg:'HS256'})+'.'+b64({sub:id,exp:Date.now()+12*36e5});return s+'.'+sig(s)};
const verify=t=>{try{const[h,p,s]=String(t).split('.'),m=sig(h+'.'+p);if(!s||s.length!==m.length||!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(m)))return;const o=JSON.parse(Buffer.from(p,'base64url'));return o.exp>Date.now()?o.sub:undefined}catch{}};
const hpw=(pw,salt)=>crypto.scryptSync(pw,salt,64).toString('hex');
const mkUser=(role,d,pw)=>{const salt=crypto.randomBytes(16).toString('hex');return{id:db.seq++,role,...d,email:d.email.toLowerCase(),salt,hash:hpw(pw,salt),must:true}};
if(!db.users.length){db.users.push(mkUser('admin',{name:'Administrator',email:E.ADMIN_EMAIL||'admin@college.edu'},E.ADMIN_PASSWORD||'Admin@123'));save()}
const bad=(c,m,x)=>{throw{c,m,x}};
const strip=u=>({id:u.id,role:u.role,name:u.name,email:u.email,must:u.must,classId:u.classId,collegeId:u.collegeId,regNo:u.regNo});
const roster=cid=>db.users.filter(u=>u.role==='student'&&u.classId===cid).map(u=>({id:u.id,name:u.name,collegeId:u.collegeId,regNo:u.regNo,face:!!db.faces[u.id]}));
const nmU=id=>(db.users.find(u=>u.id===id)||{}).name;
const r1=x=>Math.round(x*10)/10;
// attended = PRESENT + LATE + OD
const summary=s=>{const n=roster(s.cid).length,m=db.marks.filter(x=>x.sid===s.id),c=k=>m.filter(x=>x.st===k).length;return{total:n,present:c('PRESENT'),absent:c('ABSENT'),od:c('OD'),late:c('LATE'),unmarked:n-m.length,pct:n?r1((c('PRESENT')+c('LATE')+c('OD'))/n*100):0}};
const report=id=>{const h=db.marks.filter(m=>m.stu===id).map(m=>{const s=db.sessions.find(x=>x.id===m.sid);return{date:s.date,period:s.period,st:m.st}}).sort((a,b)=>b.date.localeCompare(a.date)||b.period-a.period),c=k=>h.filter(x=>x.st===k).length;return{total:h.length,present:c('PRESENT'),absent:c('ABSENT'),od:c('OD'),late:c('LATE'),pct:h.length?r1((c('PRESENT')+c('LATE')+c('OD'))/h.length*100):0,history:h}};
const hits=new Map(),limited=ip=>{const n=Date.now(),a=(hits.get(ip)||[]).filter(t=>n-t<6e4);a.push(n);hits.set(ip,a);return a.length>10};
const ST=['PRESENT','ABSENT','OD','LATE'],TM=/^([01]\d|2[0-3]):[0-5]\d$/;
async function route(req,p,b){const M=req.method;
 if(p==='/api/ping')return{ok:1};
 if(p==='/api/login'&&M==='POST'){if(limited(String(req.headers['x-forwarded-for']||req.socket.remoteAddress).split(',')[0].trim()))bad(429,'Too many attempts. Wait a minute.');
  const u=db.users.find(x=>x.email===String(b.email||'').trim().toLowerCase()),h=hpw(String(b.password||''),u?u.salt:'0');
  if(!u||!crypto.timingSafeEqual(Buffer.from(h),Buffer.from(u.hash)))bad(401,'Wrong email or password.');return{token:sign(u.id),user:strip(u)}}
 const id=verify((req.headers.authorization||'').slice(7)),u=id&&db.users.find(x=>x.id===id);if(!u)bad(401,'Please sign in again.');
 if(p==='/api/me')return{user:strip(u)};
 if(p==='/api/password'&&M==='POST'){const pw=String(b.new||'');if(hpw(String(b.old||''),u.salt)!==u.hash)bad(400,'Current password is wrong.');
  if(pw.length<8||!/[A-Za-z]/.test(pw)||!/\d/.test(pw))bad(400,'New password needs 8+ characters with a letter and a number.');if(pw===b.old)bad(400,'Choose a different password.');
  u.salt=crypto.randomBytes(16).toString('hex');u.hash=hpw(pw,u.salt);u.must=false;save();return{ok:1}}
 if(u.must)bad(403,'Password change required.',{must:1});
 const[,,area,a,c]=p.split('/'),need=r=>{if(u.role!==r)bad(403,'Forbidden')};
 if(area==='admin'){need('admin');
  if(a==='data')return{depts:db.depts,classes:db.classes,teachers:db.users.filter(x=>x.role==='teacher').map(strip),students:db.users.filter(x=>x.role==='student').map(strip),assigns:db.assigns,tt:db.tt};
  if(M!=='POST')bad(404,'Not found');
  const s=k=>String(b[k]||'').trim(),n=k=>parseInt(b[k],10),cls=k=>db.classes.some(x=>x.id===n(k)),tch=k=>db.users.some(x=>x.id===n(k)&&x.role==='teacher');
  if(a==='dept'){if(!s('name'))bad(400,'Department name required.');if(db.depts.some(d=>d.name.toLowerCase()===s('name').toLowerCase()))bad(409,'Department exists.');db.depts.push({id:db.seq++,name:s('name').slice(0,80)})}
  else if(a==='class'){if(!s('name')||!db.depts.some(d=>d.id===n('deptId'))||!(n('semester')>0))bad(400,'Enter class name, department and semester.');db.classes.push({id:db.seq++,name:s('name').slice(0,80),deptId:n('deptId'),semester:n('semester')})}
  else if(a==='teacher'||a==='student'){const em=s('email').toLowerCase();if(!s('name')||!/^\S+@\S+\.\S+$/.test(em))bad(400,'Valid name and email required.');if(db.users.some(x=>x.email===em))bad(409,'Email already registered.');
   const d={name:s('name').slice(0,60),email:em};
   if(a==='student'){if(!cls('classId')||!s('collegeId')||!s('regNo'))bad(400,'Class, College ID and Registration No. required.');if(db.users.some(x=>x.role==='student'&&(x.collegeId===s('collegeId')||x.regNo===s('regNo'))))bad(409,'College ID or Registration No. already used.');Object.assign(d,{classId:n('classId'),collegeId:s('collegeId'),regNo:s('regNo')})}
   const temp='Tmp@'+crypto.randomBytes(3).toString('hex');db.users.push(mkUser(a,d,temp));save();return{ok:1,temp}}
  else if(a==='assign'){if(!tch('teacherId')||!cls('classId'))bad(400,'Choose a teacher and class.');if(db.assigns.some(x=>x.tid===n('teacherId')&&x.cid===n('classId')))bad(409,'Already assigned.');db.assigns.push({tid:n('teacherId'),cid:n('classId')})}
  else if(a==='tt'){const cid=n('classId'),tid=n('teacherId'),day=n('day'),per=n('period'),st=s('start'),en=s('end');
   if(!cls('classId')||!tch('teacherId')||!s('subject')||!(day>=1&&day<=6)||!(per>=1&&per<=12)||!TM.test(st)||!TM.test(en)||st>=en)bad(400,'Fill all timetable fields; end time must be after start.');
   if(!db.assigns.some(x=>x.tid===tid&&x.cid===cid))bad(400,'Assign this teacher to the class first.');
   if(db.tt.some(t=>t.day===day&&(t.tid===tid||t.cid===cid)&&(t.period===per||(t.start<en&&st<t.end))))bad(409,'Timetable conflict: the teacher or class already has an overlapping entry.');
   db.tt.push({id:db.seq++,cid,tid,subject:s('subject').slice(0,60),day,period:per,start:st,end:en})}
  else bad(404,'Not found');save();return{ok:1}}
 if(area==='t'){need('teacher');
  const mine=cid=>db.assigns.some(x=>x.tid===u.id&&x.cid===cid)||bad(403,'You are not assigned to this class.'),cn=cid=>(db.classes.find(x=>x.id===cid)||{}).name;
  const own=i=>{const s=db.sessions.find(x=>x.id===i);if(!s)bad(404,'Session not found.');if(s.tid!==u.id)bad(403,'This session belongs to another teacher.');return s};
  if(a==='classes')return db.assigns.filter(x=>x.tid===u.id).map(x=>db.classes.find(k=>k.id===x.cid)).filter(Boolean);
  if(a==='tt')return db.tt.filter(x=>x.tid===u.id).map(x=>({...x,className:cn(x.cid)})).sort((x,y)=>x.day-y.day||x.period-y.period);
  if(a==='faces')return mine(+c),roster(+c).filter(r=>db.faces[r.id]).map(r=>({id:r.id,name:r.name,d:db.faces[r.id]}));
  if(a==='face'&&M==='POST'){const stu=db.users.find(x=>x.id===parseInt(b.studentId,10)&&x.role==='student');if(!stu)bad(404,'Student not found.');mine(stu.classId);const ds=b.descriptors;if(!Array.isArray(ds)||ds.length<1||ds.length>5||!ds.every(d=>Array.isArray(d)&&d.length===128&&d.every(Number.isFinite)))bad(400,'Invalid face data.');db.faces[stu.id]=ds;save();return{ok:1}}
  if(a==='roster')return mine(+c),roster(+c);
  if(a==='sessions')return db.sessions.filter(x=>x.tid===u.id).map(x=>({...x,className:cn(x.cid)})).reverse();
  if(a==='session'&&M==='POST'){const cid=parseInt(b.classId,10),per=parseInt(b.period,10),d=String(b.date||'');mine(cid);
   if(!/^\d{4}-\d{2}-\d{2}$/.test(d)||isNaN(Date.parse(d))||!(per>=1&&per<=12))bad(400,'Enter a valid date and period (1-12).');
   if(db.sessions.some(x=>x.cid===cid&&x.date===d&&x.period===per))bad(409,'A session already exists for this class, date and period.');
   const s={id:db.seq++,cid,tid:u.id,date:d,period:per,closed:false};db.sessions.push(s);save();return{id:s.id}}
  if(a==='session'){const s=own(+c),ms=db.marks.filter(x=>x.sid===s.id);
   return{session:{...s,className:cn(s.cid)},roster:roster(s.cid).map(r=>({...r,st:(ms.find(x=>x.stu===r.id)||{}).st})),summary:summary(s),fixes:db.fixes.filter(x=>x.sid===s.id).map(x=>({...x,student:nmU(x.stu),by:nmU(x.by)}))}}
  if(a==='mark'&&M==='POST'){const s=own(parseInt(b.sessionId,10)),stu=parseInt(b.studentId,10),st=b.status;
   if(s.closed)bad(409,'Session is closed.');if(!ST.includes(st))bad(400,'Invalid status.');if(!roster(s.cid).some(r=>r.id===stu))bad(403,'Student is not in this class.');
   const ex=db.marks.find(x=>x.sid===s.id&&x.stu===stu);
   if(ex){if(ex.st===st)return{ok:1};const why=String(b.reason||'').trim();if(why.length<3)bad(400,'A reason is required to correct attendance.');db.fixes.push({sid:s.id,stu,prev:ex.st,next:st,reason:why.slice(0,200),by:u.id,at:Date.now()});ex.st=st}
   else db.marks.push({sid:s.id,stu,st});save();return{ok:1}}
  if(a==='close'&&M==='POST'){const s=own(+c);s.closed=true;save();return{ok:1}}
  if(a==='student'){const s=db.users.find(x=>x.id===+c&&x.role==='student');if(!s)bad(404,'Student not found.');mine(s.classId);return{name:s.name,...report(s.id)}}
 }
 if(area==='s'){need('student');if(a==='report')return report(u.id)}
 bad(404,'Not found')}
const body=req=>new Promise(ok=>{let b='';req.on('data',c=>{b+=c;if(b.length>1e5)req.destroy()});req.on('end',()=>{try{ok(b?JSON.parse(b):{})}catch{ok({})}})});
http.createServer(async(req,res)=>{res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');
 const p=new URL(req.url,'http://x').pathname;
 if(!p.startsWith('/api/')){if(p==='/'||p==='/index.html'){res.writeHead(200,{'content-type':'text/html; charset=utf-8','cache-control':'no-cache'});return fs.createReadStream(path.join(__dirname,'public','index.html')).pipe(res)}res.writeHead(404);return res.end('Not found')}
 const send=(c,o)=>{res.writeHead(c,{'content-type':'application/json','cache-control':'no-store'});res.end(JSON.stringify(o))};
 try{send(200,await route(req,p,await body(req)))}catch(x){if(x&&x.c)send(x.c,{error:x.m,...x.x});else{console.error(x);send(500,{error:'Server error'})}}
}).listen(PORT,'0.0.0.0',()=>console.log('FaceAttend running on port '+PORT));
