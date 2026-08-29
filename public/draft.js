const baseMemoDetail=detail;
detail=async function(id){
 await baseMemoDetail(id);
 const d=await api("/api/v2/memos/"+id),m=d.memo;
 if(m.author_id!==me.id||!["Draft","Changes Requested"].includes(m.status))return;
 document.querySelector(".heading").insertAdjacentHTML("afterend",'<section class="panel draft-actions"><div class="padded"><div class="top-actions"><button class="btn" id="editMemo">'+(m.status==="Draft"?"Edit draft":"Edit revision")+'</button><button class="btn secondary" id="submitMemo">'+(m.status==="Draft"?"Submit draft":"Resubmit revision")+'</button>'+(m.status==="Draft"?'<button class="btn danger-btn" id="deleteMemo">Delete draft</button>':"")+'</div></div></section>');
 document.querySelector("#editMemo").onclick=()=>editDraft(id,m);
 document.querySelector("#submitMemo").onclick=async()=>{try{await api("/api/v2/memos/"+id+"/submit",{method:"POST",body:"{}"});await detail(id)}catch(x){alert(x.message)}};
 document.querySelector("#deleteMemo")?.addEventListener("click",async()=>{if(!confirm("Delete this draft permanently?"))return;try{await api("/api/v2/memos/"+id,{method:"DELETE"});await go("mine")}catch(x){alert(x.message)}});
};
function editDraft(id,m){
 const cats=opt.categories.map(x=>'<option value="'+e(x.id)+'" '+(x.id===m.category_id?"selected":"")+'>'+e(x.name)+'</option>').join("");
 const deps=opt.departments.map(x=>'<option value="'+e(x.id)+'" '+(x.id===m.department_id?"selected":"")+'>'+e(x.name)+'</option>').join("");
 const d=document.createElement("div");d.className="modal";
 d.innerHTML='<div class="card wide"><h2>'+(m.status==="Draft"?"Edit draft":"Revise memo")+'</h2><form class="form" id="editForm"><label>Subject<input name="subject" value="'+e(m.subject)+'" required></label><label>Body<textarea name="body" rows="8" required>'+e(m.body)+'</textarea></label><div class="grid2"><label>Department<select name="department_id"><option value="">None</option>'+deps+'</select></label><label>Category<select name="category_id"><option value="">None</option>'+cats+'</select></label><label>Priority<select name="priority"><option '+(m.priority==="Normal"?"selected":"")+'>Normal</option><option '+(m.priority==="High"?"selected":"")+'>High</option><option '+(m.priority==="Urgent"?"selected":"")+'>Urgent</option></select></label></div><div class="top-actions"><button class="btn">Save changes</button><button type="button" class="link" id="cancelEdit">Cancel</button></div><div id="editMsg"></div></form></div>';
 document.body.append(d);document.querySelector("#cancelEdit").onclick=()=>d.remove();
 document.querySelector("#editForm").onsubmit=async x=>{x.preventDefault();try{await api("/api/v2/memos/"+id,{method:"PATCH",body:JSON.stringify(Object.fromEntries(new FormData(x.target)))});d.remove();await detail(id)}catch(z){document.querySelector("#editMsg").innerHTML=msg(z.message,true)}};
}
