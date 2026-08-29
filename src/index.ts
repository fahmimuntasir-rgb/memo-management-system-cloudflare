interface Env{DB:D1Database;ASSETS:Fetcher;APP_NAME:string;SESSION_HOURS:string;RESEND_API_KEY?:string;RESET_FROM_EMAIL?:string}
type User={id:string;organization_id:string;organization_name:string;department_id?:string|null;name:string;email:string;role:"admin"|"user";status:string};
const enc=new TextEncoder();
const json=(data:unknown,status=200,headers:HeadersInit={})=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store",...headers}});
const b64=(a:ArrayBuffer|Uint8Array)=>{let s="";for(const b of new Uint8Array(a))s+=String.fromCharCode(b);return btoa(s)};
const unb64=(s:string)=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const random=(n=32)=>{const a=new Uint8Array(n);crypto.getRandomValues(a);return b64(a).replace(/[+/=]/g,"")};
async function sha(v:string){return b64(await crypto.subtle.digest("SHA-256",enc.encode(v)))}
async function hashPassword(password:string,salt=random(18),iterations=100000){const key=await crypto.subtle.importKey("raw",enc.encode(password),"PBKDF2",false,["deriveBits"]);const bits=await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:typeof salt==="string"?enc.encode(salt):salt,iterations},key,256);return `pbkdf2_sha256$${iterations}$${b64(enc.encode(salt))}$${b64(bits)}`}
async function verifyPassword(password:string,stored:string){try{const[,i,s,h]=stored.split("$");const salt=new TextDecoder().decode(unb64(s));const actual=(await hashPassword(password,salt,Number(i))).split("$")[3];const a=unb64(actual),b=unb64(h);if(a.length!==b.length)return false;let d=0;for(let x=0;x<a.length;x++)d|=a[x]^b[x];return d===0}catch{return false}}
function cookie(req:Request,name:string){return req.headers.get("cookie")?.split(";").map(x=>x.trim()).find(x=>x.startsWith(name+"="))?.slice(name.length+1)}
function sessionCookie(value:string,maxAge:number){return `mf_session=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`}
function validOrigin(req:Request){if(["GET","HEAD","OPTIONS"].includes(req.method))return true;const origin=req.headers.get("origin");return !origin||origin===new URL(req.url).origin}
async function currentUser(req:Request,env:Env):Promise<User|null>{const token=cookie(req,"mf_session");if(!token)return null;const row=await env.DB.prepare(`SELECT u.id,u.organization_id,o.name organization_name,u.department_id,u.name,u.email,u.role,u.status FROM sessions s JOIN users u ON u.id=s.user_id JOIN organizations o ON o.id=u.organization_id WHERE s.id_hash=? AND s.expires_at>? AND u.status='active'`).bind(await sha(token),new Date().toISOString()).first<User>();return row||null}
async function audit(env:Env,u:User,type:string,entity:string|null,desc:string){await env.DB.prepare("INSERT INTO audit_logs(id,organization_id,user_id,event_type,entity_type,entity_id,description,created_at) VALUES(?,?,?,?,?,?,?,?)").bind(crypto.randomUUID(),u.organization_id,u.id,type,entity?"user":null,entity,desc,new Date().toISOString()).run()}
async function body(req:Request){try{return await req.json() as Record<string,string>}catch{return {}}}
function passwordOK(p:string){return p.length>=12&&/[A-Z]/.test(p)&&/[a-z]/.test(p)&&/[0-9]/.test(p)&&/[^A-Za-z0-9]/.test(p)}

async function event(env:Env,u:User,memoId:string,type:string,description:string,comment:string|null=null){
 const now=new Date().toISOString();
 await env.DB.batch([
  env.DB.prepare("INSERT INTO memo_events(id,organization_id,memo_id,user_id,event_type,description,comment,created_at) VALUES(?,?,?,?,?,?,?,?)").bind(crypto.randomUUID(),u.organization_id,memoId,u.id,type,description,comment,now),
  env.DB.prepare("INSERT INTO audit_logs(id,organization_id,user_id,event_type,entity_type,entity_id,description,created_at) VALUES(?,?,?,?,?,?,?,?)").bind(crypto.randomUUID(),u.organization_id,u.id,type,"memo",memoId,description,now)
 ]);
}
async function canReadMemo(env:Env,u:User,id:string){
 const sql=u.role==="admin"
  ?"SELECT id FROM memos WHERE id=? AND organization_id=?"
  :"SELECT DISTINCT m.id FROM memos m LEFT JOIN workflow_steps w ON w.memo_id=m.id AND w.organization_id=m.organization_id WHERE m.id=? AND m.organization_id=? AND (m.author_id=? OR w.participant_id=? OR EXISTS(SELECT 1 FROM delegations d WHERE d.organization_id=m.organization_id AND d.delegator_id=w.participant_id AND d.delegate_id=? AND d.status='active' AND d.start_at<=? AND d.end_at>=?))";
 return u.role==="admin"
  ?await env.DB.prepare(sql).bind(id,u.organization_id).first()
  :await env.DB.prepare(sql).bind(id,u.organization_id,u.id,u.id,u.id,new Date().toISOString(),new Date().toISOString()).first();
}
async function v2(req:Request,env:Env,path:string,u:User):Promise<Response|null>{
 const url=new URL(req.url);
 if(path==="/api/v2/options"&&req.method==="GET"){
  const [users,depts,cats,templates,templateSteps]=await Promise.all([
   env.DB.prepare("SELECT id,name,email,designation,department_id FROM users WHERE organization_id=? AND status='active' ORDER BY name").bind(u.organization_id).all(),
   env.DB.prepare("SELECT id,name,active FROM departments WHERE organization_id=? AND active=1 ORDER BY name").bind(u.organization_id).all(),
   env.DB.prepare("SELECT id,name,description,active FROM categories WHERE organization_id=? AND active=1 ORDER BY name").bind(u.organization_id).all(),
   env.DB.prepare("SELECT id,name,description FROM workflow_templates WHERE organization_id=? AND active=1 ORDER BY name").bind(u.organization_id).all(),
   env.DB.prepare("SELECT s.template_id,s.position,s.label,s.action_type FROM workflow_template_steps s JOIN workflow_templates t ON t.id=s.template_id WHERE t.organization_id=? AND t.active=1 ORDER BY s.template_id,s.position").bind(u.organization_id).all()
  ]);
  return json({users:users.results,departments:depts.results,categories:cats.results,templates:(templates.results as any[]).map(t=>({...t,steps:(templateSteps.results as any[]).filter(s=>s.template_id===t.id)}))});
 }
 if(path==="/api/v2/dashboard"&&req.method==="GET"){
  const [mine,inbox,complete,urgent,unread]=await Promise.all([
   env.DB.prepare("SELECT COUNT(*) n FROM memos WHERE organization_id=? AND author_id=?").bind(u.organization_id,u.id).first<{n:number}>(),
   env.DB.prepare("SELECT COUNT(*) n FROM workflow_steps WHERE organization_id=? AND participant_id=? AND status='Current'").bind(u.organization_id,u.id).first<{n:number}>(),
   env.DB.prepare("SELECT COUNT(*) n FROM memos WHERE organization_id=? AND status='Approved' AND (author_id=? OR ?='admin')").bind(u.organization_id,u.id,u.role).first<{n:number}>(),
   env.DB.prepare("SELECT COUNT(*) n FROM memos WHERE organization_id=? AND priority='Urgent' AND (author_id=? OR ?='admin')").bind(u.organization_id,u.id,u.role).first<{n:number}>(),
   env.DB.prepare("SELECT COUNT(*) n FROM notifications WHERE organization_id=? AND user_id=? AND read_at IS NULL").bind(u.organization_id,u.id).first<{n:number}>()
  ]);
  return json({mine:mine?.n||0,inbox:inbox?.n||0,completed:complete?.n||0,urgent:urgent?.n||0,unread:unread?.n||0});
 }
 if(path==="/api/v2/memos"&&req.method==="GET"){
  const view=url.searchParams.get("view")||"mine",q="%"+(url.searchParams.get("q")||"").trim()+"%",filters:string[]=[],filterArgs:any[]=[];
  const add=(column:string,param:string)=>{const value=(url.searchParams.get(param)||"").trim();if(value){filters.push(column+"=?");filterArgs.push(value)}};
  add("m.status","status");add("m.priority","priority");add("m.department_id","department_id");add("m.category_id","category_id");add("m.author_id","author_id");
  const from=url.searchParams.get("date_from"),to=url.searchParams.get("date_to");if(from){filters.push("m.updated_at>=?");filterArgs.push(from+"T00:00:00.000Z")}if(to){filters.push("m.updated_at<=?");filterArgs.push(to+"T23:59:59.999Z")}
  const sortColumns:Record<string,string>={reference:"m.reference_no",subject:"m.subject",author:"u.name",status:"m.status",priority:"CASE m.priority WHEN 'Urgent' THEN 3 WHEN 'High' THEN 2 ELSE 1 END",submitted:"m.submitted_at",updated:"m.updated_at"},sort=sortColumns[url.searchParams.get("sort")||""]||"m.updated_at",direction=url.searchParams.get("order")==="asc"?"ASC":"DESC";
  const extra=filters.length?" AND "+filters.join(" AND "):"";let sql="",args:any[]=[];
  if(view==="inbox"){sql="SELECT DISTINCT m.id,m.reference_no,m.subject,m.status,m.priority,m.submitted_at,m.updated_at,u.name author,w.required_action,CASE WHEN w.participant_id=? THEN 0 ELSE 1 END delegated FROM memos m JOIN users u ON u.id=m.author_id JOIN workflow_steps w ON w.memo_id=m.id AND w.organization_id=m.organization_id WHERE m.organization_id=? AND w.status='Current' AND (w.participant_id=? OR EXISTS(SELECT 1 FROM delegations d WHERE d.organization_id=m.organization_id AND d.delegator_id=w.participant_id AND d.delegate_id=? AND d.status='active' AND d.start_at<=? AND d.end_at>=?)) AND (m.reference_no LIKE ? OR m.subject LIKE ? OR m.body LIKE ?)"+extra+" ORDER BY "+sort+" "+direction;const now=new Date().toISOString();args=[u.id,u.organization_id,u.id,u.id,now,now,q,q,q,...filterArgs]}
  else if(view==="completed"){sql="SELECT DISTINCT m.id,m.reference_no,m.subject,m.status,m.priority,m.submitted_at,m.updated_at,u.name author FROM memos m JOIN users u ON u.id=m.author_id LEFT JOIN workflow_steps w ON w.memo_id=m.id WHERE m.organization_id=? AND m.status IN('Approved','Rejected','Cancelled') AND (?='admin' OR m.author_id=? OR w.participant_id=?) AND (m.reference_no LIKE ? OR m.subject LIKE ? OR m.body LIKE ?)"+extra+" ORDER BY "+sort+" "+direction;args=[u.organization_id,u.role,u.id,u.id,q,q,q,...filterArgs]}
  else{sql="SELECT m.id,m.reference_no,m.subject,m.status,m.priority,m.submitted_at,m.updated_at,u.name author FROM memos m JOIN users u ON u.id=m.author_id WHERE m.organization_id=? AND m.author_id=? AND (m.reference_no LIKE ? OR m.subject LIKE ? OR m.body LIKE ?)"+extra+" ORDER BY "+sort+" "+direction;args=[u.organization_id,u.id,q,q,q,...filterArgs]}
  const rows=await env.DB.prepare(sql).bind(...args).all();return json({memos:rows.results,total:rows.results.length,filters:{view}});
 }
 if(path==="/api/v2/memos"&&req.method==="POST"){
  const b:any=await req.json().catch(()=>({}));if(!b.subject?.trim()||!b.body?.trim())return json({error:"Subject and body are required."},400);
  const participants=Array.isArray(b.participants)?b.participants.filter((x:any)=>x&&x.user_id):[];
  if(b.submit&&participants.length===0)return json({error:"Add at least one workflow participant before submission."},400);
  const allowed=participants.length?await env.DB.prepare("SELECT COUNT(*) n FROM users WHERE organization_id=? AND status='active' AND id IN ("+participants.map(()=>"?").join(",")+")").bind(u.organization_id,...participants.map((x:any)=>x.user_id)).first<{n:number}>():{n:0};
  if(participants.length&&allowed?.n!==participants.length)return json({error:"A workflow participant is invalid."},400);
  const count=await env.DB.prepare("SELECT COUNT(*) n FROM memos WHERE organization_id=?").bind(u.organization_id).first<{n:number}>(),id=crypto.randomUUID(),now=new Date().toISOString();
  const ref="MEM-"+new Date().getUTCFullYear()+"-"+String((count?.n||0)+1).padStart(4,"0"),status=b.submit?"Pending Approval":"Draft";
  const stmts:any[]=[env.DB.prepare("INSERT INTO memos(id,organization_id,author_id,department_id,reference_no,subject,body,status,priority,created_at,updated_at,category_id,submitted_at,current_step,version_no) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(id,u.organization_id,u.id,b.department_id||null,ref,b.subject.trim(),b.body.trim(),status,["Normal","High","Urgent"].includes(b.priority)?b.priority:"Normal",now,now,b.category_id||null,b.submit?now:null,b.submit?1:null,1),env.DB.prepare("INSERT INTO memo_versions(id,organization_id,memo_id,version_no,editor_id,subject,body,created_at,submission_note) VALUES(?,?,?,?,?,?,?,?,?)").bind(crypto.randomUUID(),u.organization_id,id,1,u.id,b.subject.trim(),b.body.trim(),now,b.submit?"Initial submission":"Draft created"),env.DB.prepare("INSERT INTO memo_events(id,organization_id,memo_id,user_id,event_type,description,created_at) VALUES(?,?,?,?,?,?,?)").bind(crypto.randomUUID(),u.organization_id,id,u.id,b.submit?"MEMO_SUBMITTED":"MEMO_CREATED",b.submit?"Memo submitted":"Draft created",now)];
  participants.forEach((p:any,i:number)=>{stmts.push(env.DB.prepare("INSERT INTO workflow_steps(id,organization_id,memo_id,position,participant_id,label,required_action,status,started_at) VALUES(?,?,?,?,?,?,?,?,?)").bind(crypto.randomUUID(),u.organization_id,id,i+1,p.user_id,p.label||null,p.action||"Approve",b.submit&&i===0?"Current":"Future",b.submit&&i===0?now:null));if(b.submit&&i===0)stmts.push(env.DB.prepare("INSERT INTO notifications(id,organization_id,user_id,memo_id,type,message,created_at) VALUES(?,?,?,?,?,?,?)").bind(crypto.randomUUID(),u.organization_id,p.user_id,id,"ACTION_REQUIRED",ref+" requires your action",now))});
  await env.DB.batch(stmts);await audit(env,u,b.submit?"MEMO_SUBMITTED":"MEMO_CREATED",id,ref+" "+status.toLowerCase());return json({id,reference_no:ref},201);
 }
 const detail=path.match(/^\/api\/v2\/memos\/([^/]+)$/);
 if(detail&&req.method==="PATCH"){
  const id=detail[1],b:any=await req.json().catch(()=>({}));
  const memo:any=await env.DB.prepare("SELECT * FROM memos WHERE id=? AND organization_id=? AND author_id=?").bind(id,u.organization_id,u.id).first();
  if(!memo)return json({error:"Memo not found or access denied."},404);
  if(!["Draft","Changes Requested"].includes(memo.status))return json({error:"Only drafts or memos returned for changes can be edited."},409);
  if(!b.subject?.trim()||!b.body?.trim())return json({error:"Subject and body are required."},400);
  const now=new Date().toISOString();
  if(memo.status==="Draft"){
   await env.DB.batch([
    env.DB.prepare("UPDATE memos SET subject=?,body=?,department_id=?,category_id=?,priority=?,updated_at=? WHERE id=? AND organization_id=? AND author_id=? AND status='Draft'").bind(b.subject.trim(),b.body.trim(),b.department_id||null,b.category_id||null,["Normal","High","Urgent"].includes(b.priority)?b.priority:"Normal",now,id,u.organization_id,u.id),
    env.DB.prepare("UPDATE memo_versions SET subject=?,body=?,created_at=?,submission_note='Draft updated' WHERE memo_id=? AND organization_id=? AND version_no=?").bind(b.subject.trim(),b.body.trim(),now,id,u.organization_id,memo.version_no)
   ]);
   await event(env,u,id,"MEMO_MODIFIED","Draft updated");
  }else{
   await env.DB.batch([
    env.DB.prepare("UPDATE memos SET subject=?,body=?,department_id=?,category_id=?,priority=?,version_no=version_no+1,updated_at=? WHERE id=? AND organization_id=? AND author_id=? AND status='Changes Requested'").bind(b.subject.trim(),b.body.trim(),b.department_id||null,b.category_id||null,["Normal","High","Urgent"].includes(b.priority)?b.priority:"Normal",now,id,u.organization_id,u.id),
    env.DB.prepare("INSERT INTO memo_versions(id,organization_id,memo_id,version_no,editor_id,subject,body,created_at,submission_note) VALUES(?,?,?,?,?,?,?,?,?)").bind(crypto.randomUUID(),u.organization_id,id,memo.version_no+1,u.id,b.subject.trim(),b.body.trim(),now,"Revision after requested changes")
   ]);
   await event(env,u,id,"MEMO_REVISED","Memo revised as version "+(memo.version_no+1));
  }
  return json({ok:true});
 }
 if(detail&&req.method==="DELETE"){
  const id=detail[1],memo:any=await env.DB.prepare("SELECT reference_no FROM memos WHERE id=? AND organization_id=? AND author_id=? AND status='Draft'").bind(id,u.organization_id,u.id).first();
  if(!memo)return json({error:"Only the author can delete a draft."},403);
  await event(env,u,id,"DRAFT_DELETED",memo.reference_no+" draft deleted");
  await env.DB.prepare("DELETE FROM memos WHERE id=? AND organization_id=? AND author_id=? AND status='Draft'").bind(id,u.organization_id,u.id).run();
  return json({ok:true});
 }
 const submit=path.match(/^\/api\/v2\/memos\/([^/]+)\/submit$/);
 if(submit&&req.method==="POST"){
  const id=submit[1],memo:any=await env.DB.prepare("SELECT * FROM memos WHERE id=? AND organization_id=? AND author_id=?").bind(id,u.organization_id,u.id).first();
  if(!memo)return json({error:"Memo not found or access denied."},404);
  if(!["Draft","Changes Requested"].includes(memo.status))return json({error:"This memo cannot be submitted from its current status."},409);
  const now=new Date().toISOString();
  let step:any;
  if(memo.status==="Draft")step=await env.DB.prepare("SELECT * FROM workflow_steps WHERE memo_id=? AND organization_id=? ORDER BY position LIMIT 1").bind(id,u.organization_id).first();
  else step=await env.DB.prepare("SELECT * FROM workflow_steps WHERE memo_id=? AND organization_id=? AND status='Changes Requested' ORDER BY position LIMIT 1").bind(id,u.organization_id).first();
  if(!step)return json({error:"The memo requires at least one workflow participant."},409);
  await env.DB.batch([
   env.DB.prepare("UPDATE workflow_steps SET status='Current',started_at=?,completed_at=NULL,acted_by=NULL,acted_on_behalf_of=NULL,action=NULL,comment=NULL WHERE id=? AND organization_id=?").bind(now,step.id,u.organization_id),
   env.DB.prepare("UPDATE memos SET status='Pending Approval',submitted_at=COALESCE(submitted_at,?),current_step=?,updated_at=? WHERE id=? AND organization_id=? AND author_id=?").bind(now,step.position,now,id,u.organization_id,u.id),
   env.DB.prepare("INSERT INTO notifications(id,organization_id,user_id,memo_id,type,message,created_at) VALUES(?,?,?,?,?,?,?)").bind(crypto.randomUUID(),u.organization_id,step.participant_id,id,memo.status==="Draft"?"ACTION_REQUIRED":"MEMO_RESUBMITTED",memo.reference_no+" requires your action",now)
  ]);
  await event(env,u,id,memo.status==="Draft"?"MEMO_SUBMITTED":"MEMO_RESUBMITTED",memo.status==="Draft"?"Memo submitted":"Revised memo resubmitted");
  return json({ok:true});
 }
 const attachmentList=path.match(/^\/api\/v2\/memos\/([^/]+)\/attachments$/);
 if(attachmentList&&req.method==="POST"){
  const id=attachmentList[1],memo:any=await env.DB.prepare("SELECT id,status,author_id FROM memos WHERE id=? AND organization_id=?").bind(id,u.organization_id).first();
  if(!memo||memo.author_id!==u.id)return json({error:"Only the memo author can upload attachments."},403);
  if(!["Draft","Changes Requested"].includes(memo.status))return json({error:"Attachments can only be changed before submission or while revising a memo."},409);
  const form=await req.formData().catch(()=>null),file=form?.get("file");
  if(!(file instanceof File))return json({error:"Choose a file to upload."},400);
  if(file.size<1||file.size>750000)return json({error:"The file must be between 1 byte and 750 KB."},400);
  const allowed=new Set(["application/pdf","image/png","image/jpeg","text/plain","application/vnd.openxmlformats-officedocument.wordprocessingml.document","application/msword"]);
  if(!allowed.has(file.type))return json({error:"Allowed file types: PDF, PNG, JPG, TXT, DOC and DOCX."},415);
  const attachmentId=crypto.randomUUID(),now=new Date().toISOString(),safeName=file.name.replace(/[\\/\r\n]/g,"_").slice(0,180)||"attachment";
  await env.DB.prepare("INSERT INTO attachments(id,organization_id,memo_id,uploaded_by,file_name,content_type,size,content,created_at) VALUES(?,?,?,?,?,?,?,?,?)").bind(attachmentId,u.organization_id,id,u.id,safeName,file.type,file.size,await file.arrayBuffer(),now).run();
  await event(env,u,id,"ATTACHMENT_ADDED","Attachment added: "+safeName);
  return json({id:attachmentId,file_name:safeName,size:file.size},201);
 }
 const attachment=path.match(/^\/api\/v2\/memos\/([^/]+)\/attachments\/([^/]+)$/);
 if(attachment&&req.method==="GET"){
  const [memoId,attachmentId]=[attachment[1],attachment[2]];
  if(!await canReadMemo(env,u,memoId))return json({error:"Attachment not found or access denied."},404);
  const file:any=await env.DB.prepare("SELECT file_name,content_type,size,content FROM attachments WHERE id=? AND memo_id=? AND organization_id=?").bind(attachmentId,memoId,u.organization_id).first();
  if(!file)return json({error:"Attachment not found or access denied."},404);
  const safeName=String(file.file_name).replace(/[\"\\\r\n]/g,"_");
  return new Response(file.content,{headers:{"content-type":file.content_type||"application/octet-stream","content-length":String(file.size),"content-disposition":`attachment; filename="${safeName}"`,"cache-control":"private, no-store","x-content-type-options":"nosniff"}});
 }
 if(attachment&&req.method==="DELETE"){
  const [memoId,attachmentId]=[attachment[1],attachment[2]],memo:any=await env.DB.prepare("SELECT status,author_id FROM memos WHERE id=? AND organization_id=?").bind(memoId,u.organization_id).first();
  if(!memo||memo.author_id!==u.id)return json({error:"Only the memo author can remove attachments."},403);
  if(!["Draft","Changes Requested"].includes(memo.status))return json({error:"Attachments can only be removed before submission or while revising a memo."},409);
  const file:any=await env.DB.prepare("SELECT file_name FROM attachments WHERE id=? AND memo_id=? AND organization_id=?").bind(attachmentId,memoId,u.organization_id).first();
  if(!file)return json({error:"Attachment not found."},404);
  await env.DB.prepare("DELETE FROM attachments WHERE id=? AND memo_id=? AND organization_id=?").bind(attachmentId,memoId,u.organization_id).run();
  await event(env,u,memoId,"ATTACHMENT_REMOVED","Attachment removed: "+file.file_name);
  return json({ok:true});
 }
 if(detail&&req.method==="GET"){
  const id=detail[1];if(!await canReadMemo(env,u,id))return json({error:"Memo not found or access denied."},404);
  const [memo,steps,comments,events,versions,files]=await Promise.all([
   env.DB.prepare("SELECT m.*,a.name author,d.name department,c.name category FROM memos m JOIN users a ON a.id=m.author_id LEFT JOIN departments d ON d.id=m.department_id LEFT JOIN categories c ON c.id=m.category_id WHERE m.id=? AND m.organization_id=?").bind(id,u.organization_id).first(),
   env.DB.prepare("SELECT w.*,p.name participant,ab.name acted_by_name FROM workflow_steps w JOIN users p ON p.id=w.participant_id LEFT JOIN users ab ON ab.id=w.acted_by WHERE w.memo_id=? AND w.organization_id=? ORDER BY w.position").bind(id,u.organization_id).all(),
   env.DB.prepare("SELECT c.*,u.name author FROM comments c JOIN users u ON u.id=c.user_id WHERE c.memo_id=? AND c.organization_id=? ORDER BY c.created_at").bind(id,u.organization_id).all(),
   env.DB.prepare("SELECT e.*,u.name actor FROM memo_events e LEFT JOIN users u ON u.id=e.user_id WHERE e.memo_id=? AND e.organization_id=? ORDER BY e.created_at").bind(id,u.organization_id).all(),
   env.DB.prepare("SELECT id,version_no,editor_id,subject,created_at,submission_note FROM memo_versions WHERE memo_id=? AND organization_id=? ORDER BY version_no DESC").bind(id,u.organization_id).all(),
   env.DB.prepare("SELECT id,file_name,content_type,size,uploaded_by,created_at FROM attachments WHERE memo_id=? AND organization_id=? ORDER BY created_at").bind(id,u.organization_id).all()
  ]);const current=(steps.results as any[]).find(s=>s.status==="Current");let can_act=current?.participant_id===u.id,acting_on_behalf_of:string|null=null;if(current&&!can_act){const delegated:any=await env.DB.prepare("SELECT delegator_id FROM delegations WHERE organization_id=? AND delegator_id=? AND delegate_id=? AND status='active' AND start_at<=? AND end_at>=?").bind(u.organization_id,current.participant_id,u.id,new Date().toISOString(),new Date().toISOString()).first();can_act=!!delegated;acting_on_behalf_of=delegated?.delegator_id||null}return json({memo,steps:steps.results,comments:comments.results,events:events.results,versions:versions.results,attachments:files.results,can_act,acting_on_behalf_of});
 }
 const action=path.match(/^\/api\/v2\/memos\/([^/]+)\/action$/);
 if(action&&req.method==="POST"){
  const id=action[1],b:any=await req.json().catch(()=>({})),kind=String(b.action||"");
  if(!["Approve","Reject","Request Changes","Comment"].includes(kind))return json({error:"Unsupported workflow action."},400);
  if(!await canReadMemo(env,u,id))return json({error:"Memo not found or access denied."},404);
  if(kind==="Comment"){if(!b.comment?.trim())return json({error:"Comment is required."},400);const now=new Date().toISOString();await env.DB.prepare("INSERT INTO comments(id,organization_id,memo_id,user_id,comment_type,text,created_at) VALUES(?,?,?,?,?,?,?)").bind(crypto.randomUUID(),u.organization_id,id,u.id,"General",b.comment.trim(),now).run();await event(env,u,id,"COMMENT_ADDED",u.name+" added a comment",b.comment.trim());return json({ok:true})}
  const step:any=await env.DB.prepare("SELECT * FROM workflow_steps WHERE memo_id=? AND organization_id=? AND status='Current'").bind(id,u.organization_id).first();
  if(!step)return json({error:"No workflow action is currently available."},409);
  let actingFor:string|null=null;if(step.participant_id!==u.id){const d:any=await env.DB.prepare("SELECT delegator_id FROM delegations WHERE organization_id=? AND delegator_id=? AND delegate_id=? AND status='active' AND start_at<=? AND end_at>=?").bind(u.organization_id,step.participant_id,u.id,new Date().toISOString(),new Date().toISOString()).first();if(!d)return json({error:"Only the current workflow participant may perform this action."},403);actingFor=d.delegator_id}
  if((kind==="Reject"||kind==="Request Changes")&&!b.comment?.trim())return json({error:"A reason or comment is required."},400);
  const now=new Date().toISOString();
  if(kind==="Approve"){
   const next:any=await env.DB.prepare("SELECT id,participant_id,position FROM workflow_steps WHERE memo_id=? AND organization_id=? AND position>? ORDER BY position LIMIT 1").bind(id,u.organization_id,step.position).first();
   const stmts:any[]=[env.DB.prepare("UPDATE workflow_steps SET status='Completed',acted_by=?,acted_on_behalf_of=?,action='Approve',comment=?,completed_at=? WHERE id=? AND organization_id=?").bind(u.id,actingFor,b.comment||null,now,step.id,u.organization_id)];
   if(next){stmts.push(env.DB.prepare("UPDATE workflow_steps SET status='Current',started_at=? WHERE id=? AND organization_id=?").bind(now,next.id,u.organization_id),env.DB.prepare("UPDATE memos SET status='Pending Approval',current_step=?,updated_at=? WHERE id=? AND organization_id=?").bind(next.position,now,id,u.organization_id),env.DB.prepare("INSERT INTO notifications(id,organization_id,user_id,memo_id,type,message,created_at) VALUES(?,?,?,?,?,?,?)").bind(crypto.randomUUID(),u.organization_id,next.participant_id,id,"ACTION_REQUIRED","A memo requires your action",now))}
   else stmts.push(env.DB.prepare("UPDATE memos SET status='Approved',completed_at=?,updated_at=? WHERE id=? AND organization_id=?").bind(now,now,id,u.organization_id));
   await env.DB.batch(stmts);await event(env,u,id,next?"WORKFLOW_ADVANCED":"WORKFLOW_COMPLETED",(next?"Memo moved to the next participant":"Memo approved and completed")+(actingFor?" under delegated authority":""),b.comment||null);
  }else{const status=kind==="Reject"?"Rejected":"Changes Requested";await env.DB.batch([env.DB.prepare("UPDATE workflow_steps SET status=?,acted_by=?,acted_on_behalf_of=?,action=?,comment=?,completed_at=? WHERE id=? AND organization_id=?").bind(status,u.id,actingFor,kind,b.comment.trim(),now,step.id,u.organization_id),env.DB.prepare("UPDATE memos SET status=?,updated_at=? WHERE id=? AND organization_id=?").bind(status,now,id,u.organization_id)]);await event(env,u,id,kind==="Reject"?"MEMO_REJECTED":"CHANGES_REQUESTED","Memo "+status.toLowerCase()+(actingFor?" under delegated authority":""),b.comment.trim())}
  return json({ok:true});
 }
 if(path==="/api/v2/notifications"&&req.method==="GET"){const rows=await env.DB.prepare("SELECT * FROM notifications WHERE organization_id=? AND user_id=? ORDER BY created_at DESC LIMIT 50").bind(u.organization_id,u.id).all();return json({notifications:rows.results})}
 if(path==="/api/v2/notifications/read"&&req.method==="POST"){await env.DB.prepare("UPDATE notifications SET read_at=? WHERE organization_id=? AND user_id=? AND read_at IS NULL").bind(new Date().toISOString(),u.organization_id,u.id).run();return json({ok:true})}
 if(path==="/api/v2/delegations"&&req.method==="GET"){
  const [outgoing,incoming]=await Promise.all([env.DB.prepare("SELECT d.*,x.name delegate_name,x.email delegate_email FROM delegations d JOIN users x ON x.id=d.delegate_id WHERE d.organization_id=? AND d.delegator_id=? ORDER BY d.created_at DESC").bind(u.organization_id,u.id).all(),env.DB.prepare("SELECT d.*,x.name delegator_name,x.email delegator_email FROM delegations d JOIN users x ON x.id=d.delegator_id WHERE d.organization_id=? AND d.delegate_id=? ORDER BY d.created_at DESC").bind(u.organization_id,u.id).all()]);return json({outgoing:outgoing.results,incoming:incoming.results});
 }
 if(path==="/api/v2/delegations"&&req.method==="POST"){
  const b:any=await req.json().catch(()=>({})),start=new Date(b.start_at),end=new Date(b.end_at);if(!b.delegate_id||b.delegate_id===u.id||isNaN(start.getTime())||isNaN(end.getTime())||end<=start)return json({error:"Choose another user and a valid start/end period."},400);const delegate=await env.DB.prepare("SELECT id FROM users WHERE id=? AND organization_id=? AND status='active'").bind(b.delegate_id,u.organization_id).first();if(!delegate)return json({error:"The selected delegate is unavailable."},400);const overlap=await env.DB.prepare("SELECT id FROM delegations WHERE organization_id=? AND delegator_id=? AND status='active' AND start_at<? AND end_at>?").bind(u.organization_id,u.id,end.toISOString(),start.toISOString()).first();if(overlap)return json({error:"You already have an overlapping active delegation."},409);const id=crypto.randomUUID(),now=new Date().toISOString();await env.DB.batch([env.DB.prepare("INSERT INTO delegations(id,organization_id,delegator_id,delegate_id,start_at,end_at,reason,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)").bind(id,u.organization_id,u.id,b.delegate_id,start.toISOString(),end.toISOString(),String(b.reason||"").trim()||null,"active",now),env.DB.prepare("INSERT INTO notifications(id,organization_id,user_id,type,message,created_at) VALUES(?,?,?,?,?,?)").bind(crypto.randomUUID(),u.organization_id,b.delegate_id,"DELEGATION_ASSIGNED",u.name+" delegated workflow authority to you",now)]);await audit(env,u,"DELEGATION_CREATED",id,"Workflow authority delegated");return json({id},201);
 }
 const delegation=path.match(/^\/api\/v2\/delegations\/([^/]+)$/);
 if(delegation&&req.method==="PATCH"){
  const id=delegation[1],row=await env.DB.prepare("SELECT id FROM delegations WHERE id=? AND organization_id=? AND delegator_id=?").bind(id,u.organization_id,u.id).first();if(!row)return json({error:"Delegation not found or access denied."},404);await env.DB.prepare("UPDATE delegations SET status='cancelled' WHERE id=? AND organization_id=? AND delegator_id=?").bind(id,u.organization_id,u.id).run();await audit(env,u,"DELEGATION_CANCELLED",id,"Workflow delegation cancelled");return json({ok:true});
 }
 if(path==="/api/v2/admin/reports"&&req.method==="GET"){if(u.role!=="admin")return json({error:"Administrator authority required."},403);const rows=await env.DB.prepare("SELECT status,COUNT(*) count FROM memos WHERE organization_id=? GROUP BY status ORDER BY status").bind(u.organization_id).all();return json({by_status:rows.results})}
 if(path==="/api/v2/admin/setup"&&req.method==="GET"){
  if(u.role!=="admin")return json({error:"Administrator authority required."},403);
  const [departments,categories,templates,steps]=await Promise.all([env.DB.prepare("SELECT * FROM departments WHERE organization_id=? ORDER BY name").bind(u.organization_id).all(),env.DB.prepare("SELECT * FROM categories WHERE organization_id=? ORDER BY name").bind(u.organization_id).all(),env.DB.prepare("SELECT * FROM workflow_templates WHERE organization_id=? ORDER BY name").bind(u.organization_id).all(),env.DB.prepare("SELECT s.* FROM workflow_template_steps s JOIN workflow_templates t ON t.id=s.template_id WHERE t.organization_id=? ORDER BY s.template_id,s.position").bind(u.organization_id).all()]);
  return json({departments:departments.results,categories:categories.results,templates:(templates.results as any[]).map(t=>({...t,steps:(steps.results as any[]).filter(s=>s.template_id===t.id)}))});
 }
 if(path==="/api/v2/admin/departments"&&req.method==="POST"){
  if(u.role!=="admin")return json({error:"Administrator authority required."},403);const b:any=await req.json().catch(()=>({})),name=String(b.name||"").trim();if(name.length<2)return json({error:"Department name is required."},400);try{const id=crypto.randomUUID();await env.DB.prepare("INSERT INTO departments(id,organization_id,name,active) VALUES(?,?,?,1)").bind(id,u.organization_id,name).run();await audit(env,u,"DEPARTMENT_CREATED",id,"Department created: "+name);return json({id},201)}catch{return json({error:"That department already exists."},409)}
 }
 if(path==="/api/v2/admin/categories"&&req.method==="POST"){
  if(u.role!=="admin")return json({error:"Administrator authority required."},403);const b:any=await req.json().catch(()=>({})),name=String(b.name||"").trim();if(name.length<2)return json({error:"Category name is required."},400);try{const id=crypto.randomUUID();await env.DB.prepare("INSERT INTO categories(id,organization_id,name,description,active,created_at) VALUES(?,?,?,?,1,?)").bind(id,u.organization_id,name,String(b.description||"").trim()||null,new Date().toISOString()).run();await audit(env,u,"CATEGORY_CREATED",id,"Category created: "+name);return json({id},201)}catch{return json({error:"That category already exists."},409)}
 }
 if(path==="/api/v2/admin/templates"&&req.method==="POST"){
  if(u.role!=="admin")return json({error:"Administrator authority required."},403);const b:any=await req.json().catch(()=>({})),name=String(b.name||"").trim(),steps=Array.isArray(b.steps)?b.steps.filter((s:any)=>String(s.label||"").trim()):[];if(name.length<2||!steps.length)return json({error:"Template name and at least one step are required."},400);const id=crypto.randomUUID(),now=new Date().toISOString(),stmts:any[]=[env.DB.prepare("INSERT INTO workflow_templates(id,organization_id,name,description,active,created_at) VALUES(?,?,?,?,1,?)").bind(id,u.organization_id,name,String(b.description||"").trim()||null,now)];steps.forEach((s:any,i:number)=>stmts.push(env.DB.prepare("INSERT INTO workflow_template_steps(id,template_id,position,label,action_type) VALUES(?,?,?,?,?)").bind(crypto.randomUUID(),id,i+1,String(s.label).trim(),s.action_type==="Review"?"Review":"Approve")));try{await env.DB.batch(stmts);await audit(env,u,"TEMPLATE_CREATED",id,"Workflow template created: "+name);return json({id},201)}catch{return json({error:"That template already exists."},409)}
 }
 const setupItem=path.match(/^\/api\/v2\/admin\/(departments|categories|templates)\/([^/]+)$/);
 if(setupItem&&req.method==="PATCH"){
  if(u.role!=="admin")return json({error:"Administrator authority required."},403);const table=setupItem[1]==="templates"?"workflow_templates":setupItem[1],id=setupItem[2],b:any=await req.json().catch(()=>({})),active=b.active?1:0;const found=await env.DB.prepare(`SELECT id FROM ${table} WHERE id=? AND organization_id=?`).bind(id,u.organization_id).first();if(!found)return json({error:"Setup item not found."},404);await env.DB.prepare(`UPDATE ${table} SET active=? WHERE id=? AND organization_id=?`).bind(active,id,u.organization_id).run();await audit(env,u,"SETUP_ITEM_UPDATED",id,setupItem[1]+" status updated");return json({ok:true});
 }
 return null;
}

async function api(req:Request,env:Env,path:string){
 if(!validOrigin(req))return json({error:"Invalid request origin."},403);
 if(path==="/api/login"&&req.method==="POST"){const b=await body(req);const email=(b.email||"").trim().toLowerCase();const row=await env.DB.prepare(`SELECT u.id,u.organization_id,o.name organization_name,u.name,u.email,u.password_hash,u.role,u.status FROM users u JOIN organizations o ON o.id=u.organization_id WHERE u.email=? AND u.status='active'`).bind(email).first<User&{password_hash:string}>();if(!row||!await verifyPassword(b.password||"",row.password_hash))return json({error:"Invalid email or password."},401);const token=random(36),now=new Date(),expires=new Date(now.getTime()+Number(env.SESSION_HOURS||12)*3600000);await env.DB.prepare("INSERT INTO sessions(id_hash,user_id,organization_id,expires_at,created_at,last_seen_at,user_agent) VALUES(?,?,?,?,?,?,?)").bind(await sha(token),row.id,row.organization_id,expires.toISOString(),now.toISOString(),now.toISOString(),req.headers.get("user-agent")).run();await audit(env,row,"USER_LOGIN",row.id,"Successful login");return json({user:{id:row.id,name:row.name,email:row.email,role:row.role,organization:row.organization_name}},200,{"set-cookie":sessionCookie(token,Number(env.SESSION_HOURS||12)*3600)})}
 if(path==="/api/logout"&&req.method==="POST"){const token=cookie(req,"mf_session");if(token)await env.DB.prepare("DELETE FROM sessions WHERE id_hash=?").bind(await sha(token)).run();return json({ok:true},200,{"set-cookie":sessionCookie("",0)})}
 if(path==="/api/forgot-password"&&req.method==="POST"){const b=await body(req);const row=await env.DB.prepare("SELECT id,email FROM users WHERE email=? AND status='active'").bind((b.email||"").trim().toLowerCase()).first<{id:string,email:string}>();let demoToken:string|undefined;if(row){const token=random(36);await env.DB.prepare("DELETE FROM password_resets WHERE user_id=?").bind(row.id).run();await env.DB.prepare("INSERT INTO password_resets(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)").bind(await sha(token),row.id,new Date(Date.now()+30*60000).toISOString(),new Date().toISOString()).run();if(env.RESEND_API_KEY&&env.RESET_FROM_EMAIL){await fetch("https://api.resend.com/emails",{method:"POST",headers:{"authorization":`Bearer ${env.RESEND_API_KEY}`,"content-type":"application/json"},body:JSON.stringify({from:env.RESET_FROM_EMAIL,to:[row.email],subject:"MemoFlow password reset",html:`<p>Reset your password: <a href="${new URL(req.url).origin}/?reset=${encodeURIComponent(token)}">Reset password</a>. This link expires in 30 minutes.</p>`})})}else demoToken=token}return json({message:"If that account exists, reset instructions have been created.",demoToken})}
 if(path==="/api/reset-password"&&req.method==="POST"){const b=await body(req);if(!passwordOK(b.password||""))return json({error:"Use 12+ characters with upper, lower, number and symbol."},400);const tokenHash=await sha(b.token||"");const reset=await env.DB.prepare("SELECT user_id FROM password_resets WHERE token_hash=? AND used_at IS NULL AND expires_at>?").bind(tokenHash,new Date().toISOString()).first<{user_id:string}>();if(!reset)return json({error:"Reset link is invalid or expired."},400);const now=new Date().toISOString();await env.DB.batch([env.DB.prepare("UPDATE users SET password_hash=?,updated_at=? WHERE id=?").bind(await hashPassword(b.password),now,reset.user_id),env.DB.prepare("UPDATE password_resets SET used_at=? WHERE token_hash=?").bind(now,tokenHash),env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(reset.user_id)]);return json({message:"Password changed. Please sign in."})}
 const u=await currentUser(req,env);if(!u)return json({error:"Authentication required."},401);
 const upgraded=await v2(req,env,path,u);if(upgraded)return upgraded;
 if(path==="/api/me")return json({user:{...u,password_hash:undefined}});
 if(path==="/api/profile"&&req.method==="PATCH"){
  const b:any=await req.json().catch(()=>({})),name=String(b.name||"").trim(),email=String(b.email||"").trim().toLowerCase();
  if(name.length<2||name.length>100||!/^\S+@\S+\.\S+$/.test(email))return json({error:"Enter a valid name and email address."},400);
  const department=b.department_id?await env.DB.prepare("SELECT id FROM departments WHERE id=? AND organization_id=? AND active=1").bind(b.department_id,u.organization_id).first():null;
  if(b.department_id&&!department)return json({error:"The selected department is unavailable."},400);
  try{await env.DB.prepare("UPDATE users SET name=?,email=?,department_id=?,updated_at=? WHERE id=? AND organization_id=?").bind(name,email,b.department_id||null,new Date().toISOString(),u.id,u.organization_id).run();await audit(env,u,"PROFILE_UPDATED",u.id,"Profile updated");return json({ok:true,name,email})}catch{return json({error:"That email address is already in use."},409)}
 }
 if(path==="/api/change-password"&&req.method==="POST"){
  const b:any=await req.json().catch(()=>({}));if(!passwordOK(String(b.new_password||"")))return json({error:"Use 12+ characters with upper, lower, number and symbol."},400);
  const row:any=await env.DB.prepare("SELECT password_hash FROM users WHERE id=? AND organization_id=?").bind(u.id,u.organization_id).first();
  if(!row||!await verifyPassword(String(b.current_password||""),row.password_hash))return json({error:"The current password is incorrect."},403);
  const now=new Date().toISOString();await env.DB.batch([env.DB.prepare("UPDATE users SET password_hash=?,updated_at=? WHERE id=? AND organization_id=?").bind(await hashPassword(b.new_password),now,u.id,u.organization_id),env.DB.prepare("DELETE FROM sessions WHERE user_id=? AND id_hash<>?").bind(u.id,await sha(cookie(req,"mf_session")||""))]);await audit(env,u,"PASSWORD_CHANGED",u.id,"Password changed");return json({ok:true});
 }
 if(path==="/api/memos"&&req.method==="GET"){const rows=await env.DB.prepare(`SELECT m.id,m.reference_no,m.subject,m.status,m.priority,m.created_at,u.name author FROM memos m JOIN users u ON u.id=m.author_id WHERE m.organization_id=? ORDER BY m.created_at DESC`).bind(u.organization_id).all();return json({memos:rows.results})}
 if(path==="/api/memos"&&req.method==="POST"){const b=await body(req);if(!b.subject?.trim()||!b.body?.trim())return json({error:"Subject and body are required."},400);const count=await env.DB.prepare("SELECT COUNT(*) n FROM memos WHERE organization_id=?").bind(u.organization_id).first<{n:number}>();const ref=`MEM-${new Date().getUTCFullYear()}-${String((count?.n||0)+1).padStart(4,"0")}`,id=crypto.randomUUID(),now=new Date().toISOString();await env.DB.prepare("INSERT INTO memos(id,organization_id,author_id,department_id,reference_no,subject,body,status,priority,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)").bind(id,u.organization_id,u.id,null,ref,b.subject.trim(),b.body.trim(),b.status==="Draft"?"Draft":"Pending Approval",["Normal","High","Urgent"].includes(b.priority)?b.priority:"Normal",now,now).run();await audit(env,u,"MEMO_CREATED",id,`${ref} created`);return json({id,reference_no:ref},201)}
 if(path==="/api/admin/users"&&req.method==="GET"){if(u.role!=="admin")return json({error:"Administrator authority required."},403);const rows=await env.DB.prepare("SELECT u.id,u.name,u.email,u.role,u.status,u.department_id,d.name department,u.created_at FROM users u LEFT JOIN departments d ON d.id=u.department_id WHERE u.organization_id=? ORDER BY u.name").bind(u.organization_id).all();return json({users:rows.results})}
 if(path==="/api/admin/users"&&req.method==="POST"){if(u.role!=="admin")return json({error:"Administrator authority required."},403);const b=await body(req);if(!b.name||!b.email||!passwordOK(b.password||""))return json({error:"Name, email and a strong password are required."},400);const id=crypto.randomUUID(),now=new Date().toISOString();try{await env.DB.prepare("INSERT INTO users(id,organization_id,department_id,name,email,password_hash,role,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)").bind(id,u.organization_id,null,b.name.trim(),b.email.trim().toLowerCase(),await hashPassword(b.password),b.role==="admin"?"admin":"user","active",now,now).run();await audit(env,u,"USER_CREATED",id,`${b.email} created as ${b.role==="admin"?"admin":"user"}`);return json({id},201)}catch{return json({error:"A user with that email already exists in this organization."},409)}}
 const managedUser=path.match(/^\/api\/admin\/users\/([^/]+)$/);
 if(managedUser&&req.method==="PATCH"){
  if(u.role!=="admin")return json({error:"Administrator authority required."},403);const id=managedUser[1],b:any=await req.json().catch(()=>({}));
  const target:any=await env.DB.prepare("SELECT id,role,status FROM users WHERE id=? AND organization_id=?").bind(id,u.organization_id).first();if(!target)return json({error:"User not found."},404);
  const status=b.status==="inactive"?"inactive":"active",role=b.role==="admin"?"admin":"user";
  if(id===u.id&&(status!=="active"||role!=="admin"))return json({error:"You cannot deactivate or remove administrator access from your own account."},409);
  if(target.role==="admin"&&(status!=="active"||role!=="admin")){const admins=await env.DB.prepare("SELECT COUNT(*) n FROM users WHERE organization_id=? AND role='admin' AND status='active'").bind(u.organization_id).first<{n:number}>();if((admins?.n||0)<=1)return json({error:"The organization must retain at least one active administrator."},409)}
  const department=b.department_id?await env.DB.prepare("SELECT id FROM departments WHERE id=? AND organization_id=? AND active=1").bind(b.department_id,u.organization_id).first():null;if(b.department_id&&!department)return json({error:"The selected department is unavailable."},400);
  await env.DB.batch([env.DB.prepare("UPDATE users SET role=?,status=?,department_id=?,updated_at=? WHERE id=? AND organization_id=?").bind(role,status,b.department_id||null,new Date().toISOString(),id,u.organization_id),...(status==="inactive"?[env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(id)]:[])]);await audit(env,u,"USER_UPDATED",id,"User role/status updated");return json({ok:true});
 }
 if(path==="/api/audit"&&req.method==="GET"){if(u.role!=="admin")return json({error:"Administrator authority required."},403);const rows=await env.DB.prepare("SELECT event_type,description,created_at,user_id FROM audit_logs WHERE organization_id=? ORDER BY created_at DESC LIMIT 50").bind(u.organization_id).all();return json({events:rows.results})}
 return json({error:"Not found."},404)
}
export default{async fetch(req:Request,env:Env){const url=new URL(req.url);if(url.pathname.startsWith("/api/"))return api(req,env,url.pathname);return env.ASSETS.fetch(req)}};
export{hashPassword,verifyPassword,passwordOK};
