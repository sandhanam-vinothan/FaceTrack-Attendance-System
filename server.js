// FaceTrack backend - Node 18+ + Neon PostgreSQL
require('dotenv').config();
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { Pool } = require('pg');

const E = process.env, PORT = +E.PORT || 3100;
if (!E.DATABASE_URL) throw new Error('DATABASE_URL is required');
const pool = new Pool({
  connectionString: E.DATABASE_URL,
  ssl: E.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined
});

let SECRET = E.JWT_SECRET;
if (!SECRET) {
  if (E.NODE_ENV === 'production') throw new Error('JWT_SECRET is required in production');
  SECRET = crypto.randomBytes(32).toString('hex');
  console.warn('JWT_SECRET not set; generated temporary development secret.');
}

const b64=o=>Buffer.from(JSON.stringify(o)).toString('base64url');
const sig=s=>crypto.createHmac('sha256',SECRET).update(s).digest('base64url');
const sign=id=>{const s=b64({alg:'HS256'})+'.'+b64({sub:id,exp:Date.now()+12*36e5});return s+'.'+sig(s)};
const verify=t=>{try{const[h,p,s]=String(t).split('.'),m=sig(h+'.'+p);if(!s||s.length!==m.length||!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(m)))return;const o=JSON.parse(Buffer.from(p,'base64url'));return o.exp>Date.now()?+o.sub:undefined}catch{}};
const signKiosk=()=>{const x=b64({alg:'HS256'})+'.'+b64({kiosk:1,exp:Date.now()+12*36e5});return x+'.'+sig(x)};
const verifyKiosk=t=>{try{const[h,p,z]=String(t).split('.'),m=sig(h+'.'+p);if(!z||z.length!==m.length||!crypto.timingSafeEqual(Buffer.from(z),Buffer.from(m)))return false;const o=JSON.parse(Buffer.from(p,'base64url'));return !!(o.kiosk&&o.exp>Date.now())}catch{return false}};
const hpw=(pw,salt)=>crypto.scryptSync(pw,salt,64).toString('hex');
const bad=(c,m,x)=>{throw{c,m,x}};
const r1=x=>Math.round(x*10)/10;
const ST=['PRESENT','ABSENT','OD','LATE'], TM=/^([01]\d|2[0-3]):[0-5]\d$/;
const strip=u=>({id:+u.id,role:u.role,name:u.name,email:u.email,must:u.must_change_password,classId:u.class_id==null?undefined:+u.class_id,collegeId:u.college_id||undefined,regNo:u.reg_no||undefined});
const q=(text,params=[])=>pool.query(text,params);
const one=async(text,params=[]) => (await q(text,params)).rows[0];

async function ensureAdmin(){
  const n=await one("SELECT COUNT(*)::int AS n FROM users");
  if(n.n) return;
  const email=(E.ADMIN_EMAIL||'admin@college.edu').toLowerCase();
  const pw=E.ADMIN_PASSWORD||'Admin@123';
  const salt=crypto.randomBytes(16).toString('hex');
  await q(`INSERT INTO users(role,name,email,salt,password_hash,must_change_password)
           VALUES('admin','Administrator',$1,$2,$3,true)`,[email,salt,hpw(pw,salt)]);
  console.log('Initial admin account created:',email);
}

async function roster(cid){
  const {rows}=await q(`SELECT u.id,u.name,u.college_id,u.reg_no,
    EXISTS(SELECT 1 FROM face_descriptors f WHERE f.student_id=u.id) AS face
    FROM users u WHERE u.role='student' AND u.class_id=$1 ORDER BY u.id`,[cid]);
  return rows.map(x=>({id:+x.id,name:x.name,collegeId:x.college_id,regNo:x.reg_no,face:x.face}));
}
async function nmU(id){const x=await one('SELECT name FROM users WHERE id=$1',[id]);return x?.name}
async function summary(s){
  const n=(await roster(s.cid)).length;
  const {rows:m}=await q('SELECT status FROM attendance_marks WHERE session_id=$1',[s.id]);
  const c=k=>m.filter(x=>x.status===k).length;
  return {total:n,present:c('PRESENT'),absent:c('ABSENT'),od:c('OD'),late:c('LATE'),unmarked:n-m.length,pct:n?r1((c('PRESENT')+c('LATE')+c('OD'))/n*100):0};
}
async function report(id){
  const {rows}=await q(`SELECT s.attendance_date::text AS date,s.period,m.status AS st
    FROM attendance_marks m JOIN attendance_sessions s ON s.id=m.session_id
    WHERE m.student_id=$1 ORDER BY s.attendance_date DESC,s.period DESC`,[id]);
  const h=rows.map(x=>({date:String(x.date).slice(0,10),period:x.period,st:x.st})),c=k=>h.filter(x=>x.st===k).length;
  return {total:h.length,present:c('PRESENT'),absent:c('ABSENT'),od:c('OD'),late:c('LATE'),pct:h.length?r1((c('PRESENT')+c('LATE')+c('OD'))/h.length*100):0,history:h};
}
const hits=new Map(),limited=ip=>{const n=Date.now(),a=(hits.get(ip)||[]).filter(t=>n-t<6e4);a.push(n);hits.set(ip,a);return a.length>10};

async function route(req,p,b){
  const M=req.method;
  if(p==='/api/ping')return{ok:1};

  if(p==='/api/login'&&M==='POST'){
    if(limited(String(req.headers['x-forwarded-for']||req.socket.remoteAddress).split(',')[0].trim()))bad(429,'Too many attempts. Wait a minute.');
    const u=await one('SELECT * FROM users WHERE email=$1',[String(b.email||'').trim().toLowerCase()]);
    const h=hpw(String(b.password||''),u?u.salt:'0');
    if(!u||!crypto.timingSafeEqual(Buffer.from(h),Buffer.from(u.password_hash)))bad(401,'Wrong email or password.');
    return{token:sign(u.id),user:strip(u)}
  }

  // Dedicated classroom kiosk: separate from teacher/student accounts.
  if(p==='/api/kiosk/login'&&M==='POST'){
    const expected=String(E.KIOSK_PIN||'2468');
    if(String(b.pin||'')!==expected)bad(401,'Incorrect scanner PIN.');
    return{token:signKiosk()};
  }
  if(p.startsWith('/api/kiosk/')){
    if(!verifyKiosk((req.headers.authorization||'').slice(7)))bad(401,'Scanner authorization required.');
    const parts=p.split('/'),a=parts[3],c=parts[4];
    if(a==='tt'&&M==='GET'){
      const {rows}=await q(`SELECT t.id,t.class_id AS cid,t.teacher_id AS tid,t.subject,t.day,t.period,
        to_char(t.start_time,'HH24:MI') AS start,to_char(t.end_time,'HH24:MI') AS "end",
        c.name AS "className",u.name AS "teacherName" FROM timetable t
        JOIN classes c ON c.id=t.class_id JOIN users u ON u.id=t.teacher_id ORDER BY t.day,t.period,c.name`);
      return rows.map(x=>({...x,id:+x.id,cid:+x.cid,tid:+x.tid}));
    }
    if(a==='session'&&M==='POST'){
      const tt=await one(`SELECT id,class_id AS cid,teacher_id AS tid,period FROM timetable WHERE id=$1`,[parseInt(b.timetableId,10)]);
      const date=String(b.date||''); if(!tt||!/^\\d{4}-\\d{2}-\\d{2}$/.test(date))bad(400,'Choose a valid scheduled class and date.');
      let x=await one(`SELECT id,closed FROM attendance_sessions WHERE class_id=$1 AND attendance_date=$2 AND period=$3`,[tt.cid,date,tt.period]);
      if(!x)x=await one(`INSERT INTO attendance_sessions(class_id,teacher_id,attendance_date,period,closed) VALUES($1,$2,$3,$4,false) RETURNING id,closed`,[tt.cid,tt.tid,date,tt.period]);
      return{id:+x.id,closed:x.closed};
    }
    if(a==='session'&&M==='GET'){
      const ss=await one(`SELECT s.id,s.class_id AS cid,s.teacher_id AS tid,s.attendance_date::text AS date,s.period,s.closed,c.name AS "className" FROM attendance_sessions s JOIN classes c ON c.id=s.class_id WHERE s.id=$1`,[+c]);
      if(!ss)bad(404,'Session not found.'); ss.id=+ss.id;ss.cid=+ss.cid;ss.tid=+ss.tid;ss.date=String(ss.date).slice(0,10);
      const {rows:ms}=await q('SELECT student_id AS stu,status AS st FROM attendance_marks WHERE session_id=$1',[ss.id]);
      return{session:ss,roster:(await roster(ss.cid)).map(r=>({...r,st:(ms.find(x=>+x.stu===r.id)||{}).st})),summary:await summary(ss)};
    }
    if(a==='faces'&&M==='GET'){
      const rs=(await roster(+c)).filter(r=>r.face),out=[];for(const r of rs){const {rows}=await q('SELECT descriptor FROM face_descriptors WHERE student_id=$1 ORDER BY id',[r.id]);out.push({id:r.id,name:r.name,d:rows.map(x=>x.descriptor)})}return out;
    }
    if(a==='mark'&&M==='POST'){
      const ss=await one(`SELECT id,class_id AS cid,closed FROM attendance_sessions WHERE id=$1`,[parseInt(b.sessionId,10)]);if(!ss)bad(404,'Session not found.');if(ss.closed)bad(409,'Session is closed.');
      const stu=parseInt(b.studentId,10);if(!(await roster(+ss.cid)).some(r=>r.id===stu))bad(403,'Student is not in this class.');
      await q(`INSERT INTO attendance_marks(session_id,student_id,status) VALUES($1,$2,'PRESENT') ON CONFLICT(session_id,student_id) DO NOTHING`,[ss.id,stu]);return{ok:1};
    }
    bad(404,'Scanner endpoint not found.');
  }

  const id=verify((req.headers.authorization||'').slice(7));
  const u=id&&await one('SELECT * FROM users WHERE id=$1',[id]);
  if(!u)bad(401,'Please sign in again.');
  if(p==='/api/me')return{user:strip(u)};

  if(p==='/api/password'&&M==='POST'){
    const pw=String(b.new||'');
    if(hpw(String(b.old||''),u.salt)!==u.password_hash)bad(400,'Current password is wrong.');
    if(pw.length<8||!/[A-Za-z]/.test(pw)||!/\d/.test(pw))bad(400,'New password needs 8+ characters with a letter and a number.');
    if(pw===b.old)bad(400,'Choose a different password.');
    const salt=crypto.randomBytes(16).toString('hex');
    await q('UPDATE users SET salt=$1,password_hash=$2,must_change_password=false WHERE id=$3',[salt,hpw(pw,salt),u.id]);
    return{ok:1}
  }
  if(u.must_change_password)bad(403,'Password change required.',{must:1});

  if(p==='/api/ai'&&M==='POST'){
    const question=String(b.question||'').trim().slice(0,2000); if(!question)bad(400,'Ask a question.');
    let appContext={user:{name:u.name,role:u.role},today:new Date().toISOString().slice(0,10)};
    if(u.role==='teacher'){
      const {rows:tt}=await q(`SELECT t.subject,t.day,t.period,to_char(t.start_time,'HH24:MI') AS start,to_char(t.end_time,'HH24:MI') AS "end",c.name AS class FROM timetable t JOIN classes c ON c.id=t.class_id WHERE t.teacher_id=$1 ORDER BY t.day,t.period`,[u.id]);
      const {rows:ss}=await q(`SELECT s.id,s.attendance_date::text AS date,s.period,c.name AS class,s.closed FROM attendance_sessions s JOIN classes c ON c.id=s.class_id WHERE s.teacher_id=$1 ORDER BY s.attendance_date DESC,s.period DESC LIMIT 30`,[u.id]);
      const {rows:classes}=await q(`SELECT c.id,c.name,c.semester,(SELECT count(*)::int FROM users st WHERE st.role='student' AND st.class_id=c.id) AS students FROM teacher_assignments ta JOIN classes c ON c.id=ta.class_id WHERE ta.teacher_id=$1 ORDER BY c.name`,[u.id]);
      appContext.timetable=tt;appContext.recentSessions=ss.map(x=>({...x,date:String(x.date).slice(0,10)}));appContext.assignedClasses=classes;
    } else if(u.role==='student') appContext.attendance=await report(u.id);
    else if(u.role==='admin'){
      const counts=await one(`SELECT (SELECT count(*) FROM departments)::int departments,(SELECT count(*) FROM classes)::int classes,(SELECT count(*) FROM users WHERE role='teacher')::int teachers,(SELECT count(*) FROM users WHERE role='student')::int students,(SELECT count(*) FROM attendance_sessions)::int sessions`);appContext.systemCounts=counts;
    }
    const context=`You are FaceAttend AI inside a college face-attendance application. Answer using LIVE APP CONTEXT when the question is about this user's timetable, classes, attendance, sessions or system. Today is ${appContext.today}. Weekly timetable day uses 1=Monday through 6=Saturday. If a requested fact is not in the context, say that clearly; do not invent it. User role: ${u.role}. Never reveal secrets, API keys, biometric face descriptors, password hashes, or private data belonging to unrelated users. Keep answers concise and useful. LIVE APP CONTEXT: ${JSON.stringify(appContext)}`;
    try{
      if(E.OPENAI_API_KEY){
        const rr=await fetch('https://api.openai.com/v1/responses',{method:'POST',headers:{'content-type':'application/json','authorization':'Bearer '+E.OPENAI_API_KEY},body:JSON.stringify({model:E.OPENAI_MODEL||'gpt-6-luna',instructions:context,input:question,max_output_tokens:500})});
        const j=await rr.json(); if(!rr.ok)bad(502,j.error?.message||'AI service error.');
        return{answer:j.output_text||j.output?.flatMap(x=>x.content||[]).map(x=>x.text||'').join('')||'No response.'};
      }
      if(E.OLLAMA_BASE_URL){
        const rr=await fetch(E.OLLAMA_BASE_URL.replace(/\/$/,'')+'/api/chat',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({model:E.OLLAMA_MODEL||'llama3.2',stream:false,messages:[{role:'system',content:context},{role:'user',content:question}]})});
        const j=await rr.json(); if(!rr.ok)bad(502,j.error||'Ollama service error.'); return{answer:j.message?.content||'No response.'};
      }
      bad(503,'AI is not configured. Add OPENAI_API_KEY on Render, or set OLLAMA_BASE_URL for a reachable Ollama server.');
    }catch(x){if(x&&x.c)throw x;bad(502,'AI service is temporarily unavailable.')}
  }

  const[,,area,a,c]=p.split('/'),need=r=>{if(u.role!==r)bad(403,'Forbidden')};

  if(area==='admin'){
    need('admin');
    if(a==='data'){
      const [depts,classes,teachers,students,assigns,tt]=await Promise.all([
        q('SELECT id,name FROM departments ORDER BY id'),
        q('SELECT id,name,dept_id AS "deptId",semester FROM classes ORDER BY id'),
        q("SELECT * FROM users WHERE role='teacher' ORDER BY id"),
        q("SELECT * FROM users WHERE role='student' ORDER BY id"),
        q('SELECT teacher_id AS tid,class_id AS cid FROM teacher_assignments ORDER BY teacher_id,class_id'),
        q(`SELECT id,class_id AS cid,teacher_id AS tid,subject,day,period,
           to_char(start_time,'HH24:MI') AS start,to_char(end_time,'HH24:MI') AS "end" FROM timetable ORDER BY id`)
      ]);
      return{depts:depts.rows,classes:classes.rows,teachers:teachers.rows.map(strip),students:students.rows.map(strip),assigns:assigns.rows,tt:tt.rows};
    }
    if(a==='delete'&&M==='POST'){
      const type=String(b.type||''),id=parseInt(b.id,10); if(!id)bad(400,'Invalid item.');
      if(type==='department')await q('DELETE FROM departments WHERE id=$1',[id]);
      else if(type==='class')await q('DELETE FROM classes WHERE id=$1',[id]);
      else if(type==='teacher')await q("DELETE FROM users WHERE id=$1 AND role='teacher'",[id]);
      else if(type==='student')await q("DELETE FROM users WHERE id=$1 AND role='student'",[id]);
      else if(type==='timetable')await q('DELETE FROM timetable WHERE id=$1',[id]);
      else if(type==='assignment')await q('DELETE FROM teacher_assignments WHERE teacher_id=$1 AND class_id=$2',[parseInt(b.teacherId,10),parseInt(b.classId,10)]);
      else bad(400,'Unsupported item.'); return{ok:1};
    }
    if(a==='clear-attendance'&&M==='POST'){
      await q('DELETE FROM attendance_sessions'); return{ok:1};
    }
    if(M!=='POST')bad(404,'Not found');
    const s=k=>String(b[k]||'').trim(),n=k=>parseInt(b[k],10);
    const cls=async k=>!!await one('SELECT 1 FROM classes WHERE id=$1',[n(k)]);
    const tch=async k=>!!await one("SELECT 1 FROM users WHERE id=$1 AND role='teacher'",[n(k)]);

    if(a==='dept'){
      if(!s('name'))bad(400,'Department name required.');
      if(await one('SELECT 1 FROM departments WHERE lower(name)=lower($1)',[s('name')]))bad(409,'Department exists.');
      await q('INSERT INTO departments(name) VALUES($1)',[s('name').slice(0,80)]);
    } else if(a==='class'){
      if(!s('name')||!await one('SELECT 1 FROM departments WHERE id=$1',[n('deptId')])||!(n('semester')>0))bad(400,'Enter class name, department and semester.');
      await q('INSERT INTO classes(name,dept_id,semester) VALUES($1,$2,$3)',[s('name').slice(0,80),n('deptId'),n('semester')]);
    } else if(a==='teacher'||a==='student'){
      const em=s('email').toLowerCase();
      if(!s('name')||!/^\S+@\S+\.\S+$/.test(em))bad(400,'Valid name and email required.');
      if(await one('SELECT 1 FROM users WHERE email=$1',[em]))bad(409,'Email already registered.');
      if(a==='student'){
        if(!await cls('classId')||!s('collegeId')||!s('regNo'))bad(400,'Class, College ID and Registration No. required.');
        if(await one("SELECT 1 FROM users WHERE role='student' AND (college_id=$1 OR reg_no=$2)",[s('collegeId'),s('regNo')]))bad(409,'College ID or Registration No. already used.');
      }
      const temp='Tmp@'+crypto.randomBytes(3).toString('hex'),salt=crypto.randomBytes(16).toString('hex');
      await q(`INSERT INTO users(role,name,email,class_id,college_id,reg_no,salt,password_hash,must_change_password)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,true)`,[
          a,s('name').slice(0,60),em,a==='student'?n('classId'):null,a==='student'?s('collegeId'):null,a==='student'?s('regNo'):null,salt,hpw(temp,salt)
        ]);
      return{ok:1,temp};
    } else if(a==='assign'){
      if(!await tch('teacherId')||!await cls('classId'))bad(400,'Choose a teacher and class.');
      if(await one('SELECT 1 FROM teacher_assignments WHERE teacher_id=$1 AND class_id=$2',[n('teacherId'),n('classId')]))bad(409,'Already assigned.');
      await q('INSERT INTO teacher_assignments(teacher_id,class_id) VALUES($1,$2)',[n('teacherId'),n('classId')]);
    } else if(a==='tt'){
      const cid=n('classId'),tid=n('teacherId'),day=n('day'),per=n('period'),st=s('start'),en=s('end');
      if(!await cls('classId')||!await tch('teacherId')||!s('subject')||!(day>=1&&day<=6)||!(per>=1&&per<=12)||!TM.test(st)||!TM.test(en)||st>=en)bad(400,'Fill all timetable fields; end time must be after start.');
      if(!await one('SELECT 1 FROM teacher_assignments WHERE teacher_id=$1 AND class_id=$2',[tid,cid]))bad(400,'Assign this teacher to the class first.');
      if(await one(`SELECT 1 FROM timetable WHERE day=$1 AND (teacher_id=$2 OR class_id=$3)
        AND (period=$4 OR (start_time<$5::time AND $6::time<end_time)) LIMIT 1`,[day,tid,cid,per,en,st]))bad(409,'Timetable conflict: the teacher or class already has an overlapping entry.');
      await q('INSERT INTO timetable(class_id,teacher_id,subject,day,period,start_time,end_time) VALUES($1,$2,$3,$4,$5,$6,$7)',
        [cid,tid,s('subject').slice(0,60),day,per,st,en]);
    } else bad(404,'Not found');
    return{ok:1};
  }

  if(area==='t'){
    need('teacher');
    const mine=async cid=>{if(!await one('SELECT 1 FROM teacher_assignments WHERE teacher_id=$1 AND class_id=$2',[u.id,cid]))bad(403,'You are not assigned to this class.')};
    const cn=async cid=>(await one('SELECT name FROM classes WHERE id=$1',[cid]))?.name;
    const own=async i=>{const x=await one(`SELECT id,class_id AS cid,teacher_id AS tid,attendance_date::text AS date,period,closed FROM attendance_sessions WHERE id=$1`,[i]);if(!x)bad(404,'Session not found.');if(+x.tid!==+u.id)bad(403,'This session belongs to another teacher.');x.id=+x.id;x.cid=+x.cid;x.tid=+x.tid;x.date=String(x.date).slice(0,10);return x};

    if(a==='classes'){const {rows}=await q(`SELECT c.id,c.name,c.dept_id AS "deptId",c.semester FROM teacher_assignments ta JOIN classes c ON c.id=ta.class_id WHERE ta.teacher_id=$1 ORDER BY c.id`,[u.id]);return rows}
    if(a==='tt'){const {rows}=await q(`SELECT t.id,t.class_id AS cid,t.teacher_id AS tid,t.subject,t.day,t.period,to_char(t.start_time,'HH24:MI') AS start,to_char(t.end_time,'HH24:MI') AS "end",c.name AS "className" FROM timetable t JOIN classes c ON c.id=t.class_id WHERE t.teacher_id=$1 ORDER BY t.day,t.period`,[u.id]);return rows}
    if(a==='faces'){
      await mine(+c); const rs=(await roster(+c)).filter(r=>r.face);
      for(const r of rs){const {rows}=await q('SELECT descriptor FROM face_descriptors WHERE student_id=$1 ORDER BY id',[r.id]);r.d=rows.map(x=>x.descriptor)}
      return rs.map(r=>({id:r.id,name:r.name,d:r.d}));
    }
    if(a==='face'&&M==='POST'){
      const stu=await one("SELECT id,class_id FROM users WHERE id=$1 AND role='student'",[parseInt(b.studentId,10)]);
      if(!stu)bad(404,'Student not found.'); await mine(+stu.class_id);
      const ds=b.descriptors;
      if(!Array.isArray(ds)||ds.length<1||ds.length>5||!ds.every(d=>Array.isArray(d)&&d.length===128&&d.every(Number.isFinite)))bad(400,'Invalid face data.');
      const client=await pool.connect();try{await client.query('BEGIN');await client.query('DELETE FROM face_descriptors WHERE student_id=$1',[stu.id]);for(const d of ds)await client.query('INSERT INTO face_descriptors(student_id,descriptor) VALUES($1,$2::jsonb)',[stu.id,JSON.stringify(d)]);await client.query('COMMIT')}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
      return{ok:1};
    }
    if(a==='roster'){await mine(+c);return roster(+c)}
    if(a==='sessions'){const {rows}=await q(`SELECT s.id,s.class_id AS cid,s.teacher_id AS tid,s.attendance_date::text AS date,s.period,s.closed,c.name AS "className" FROM attendance_sessions s JOIN classes c ON c.id=s.class_id WHERE s.teacher_id=$1 ORDER BY s.id DESC`,[u.id]);return rows.map(x=>({...x,date:String(x.date).slice(0,10)}))}
    if(a==='session'&&M==='POST'){
      const cid=parseInt(b.classId,10),per=parseInt(b.period,10),d=String(b.date||'');await mine(cid);
      if(!/^\d{4}-\d{2}-\d{2}$/.test(d)||isNaN(Date.parse(d))||!(per>=1&&per<=12))bad(400,'Enter a valid date and period (1-12).');
      if(await one('SELECT 1 FROM attendance_sessions WHERE class_id=$1 AND attendance_date=$2 AND period=$3',[cid,d,per]))bad(409,'A session already exists for this class, date and period.');
      const x=await one('INSERT INTO attendance_sessions(class_id,teacher_id,attendance_date,period,closed) VALUES($1,$2,$3,$4,false) RETURNING id',[cid,u.id,d,per]);return{id:+x.id};
    }
    if(a==='session'){
      const s=await own(+c),{rows:ms}=await q('SELECT student_id AS stu,status AS st FROM attendance_marks WHERE session_id=$1',[s.id]);
      const rr=(await roster(s.cid)).map(r=>({...r,st:(ms.find(x=>+x.stu===r.id)||{}).st}));
      const {rows:fx}=await q(`SELECT session_id AS sid,student_id AS stu,previous_status AS prev,new_status AS next,reason,changed_by AS "by",changed_at AS at FROM attendance_corrections WHERE session_id=$1 ORDER BY id`,[s.id]);
      for(const x of fx){x.student=await nmU(x.stu);x.by=await nmU(x.by)}
      return{session:{...s,className:await cn(s.cid)},roster:rr,summary:await summary(s),fixes:fx};
    }
    if(a==='mark'&&M==='POST'){
      const s=await own(parseInt(b.sessionId,10)),stu=parseInt(b.studentId,10),st=b.status;
      if(s.closed)bad(409,'Session is closed.');if(!ST.includes(st))bad(400,'Invalid status.');
      if(!(await roster(s.cid)).some(r=>r.id===stu))bad(403,'Student is not in this class.');
      const ex=await one('SELECT status FROM attendance_marks WHERE session_id=$1 AND student_id=$2',[s.id,stu]);
      if(ex){
        if(ex.status===st)return{ok:1};
        const why=String(b.reason||'').trim();if(why.length<3)bad(400,'A reason is required to correct attendance.');
        const client=await pool.connect();try{await client.query('BEGIN');await client.query(`INSERT INTO attendance_corrections(session_id,student_id,previous_status,new_status,reason,changed_by,changed_at) VALUES($1,$2,$3,$4,$5,$6,$7)`,[s.id,stu,ex.status,st,why.slice(0,200),u.id,Date.now()]);await client.query('UPDATE attendance_marks SET status=$1 WHERE session_id=$2 AND student_id=$3',[st,s.id,stu]);await client.query('COMMIT')}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
      } else await q('INSERT INTO attendance_marks(session_id,student_id,status) VALUES($1,$2,$3)',[s.id,stu,st]);
      return{ok:1};
    }
    if(a==='close'&&M==='POST'){const s=await own(+c);await q('UPDATE attendance_sessions SET closed=true WHERE id=$1',[s.id]);return{ok:1}}
    if(a==='delete-session'&&M==='POST'){const s=await own(+c);await q('DELETE FROM attendance_sessions WHERE id=$1',[s.id]);return{ok:1}}
    if(a==='student'){const stu=await one("SELECT id,name,class_id FROM users WHERE id=$1 AND role='student'",[+c]);if(!stu)bad(404,'Student not found.');await mine(+stu.class_id);return{name:stu.name,...await report(+stu.id)}}
  }

  if(area==='s'){need('student');if(a==='report')return report(+u.id)}
  bad(404,'Not found');
}

const body=req=>new Promise(ok=>{let b='';req.on('data',c=>{b+=c;if(b.length>1e5)req.destroy()});req.on('end',()=>{try{ok(b?JSON.parse(b):{})}catch{ok({})}})});
const server=http.createServer(async(req,res)=>{
  res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');
  const p=new URL(req.url,'http://x').pathname;
  if(!p.startsWith('/api/')){
    if(p==='/'||p==='/index.html'){res.writeHead(200,{'content-type':'text/html; charset=utf-8','cache-control':'no-cache'});return fs.createReadStream(path.join(__dirname,'public','index.html')).pipe(res)}
    res.writeHead(404);return res.end('Not found')
  }
  const send=(c,o)=>{res.writeHead(c,{'content-type':'application/json','cache-control':'no-store'});res.end(JSON.stringify(o))};
  try{send(200,await route(req,p,await body(req)))}catch(x){if(x&&x.c)send(x.c,{error:x.m,...x.x});else{console.error(x);send(500,{error:'Server error'})}}
});

(async()=>{
  try{
    await q('SELECT 1');
    await ensureAdmin();
    server.listen(PORT,'0.0.0.0',()=>console.log('FaceTrack running on port '+PORT+' with Neon PostgreSQL'));
  }catch(e){console.error('Database startup failed:',e);process.exit(1)}
})();
