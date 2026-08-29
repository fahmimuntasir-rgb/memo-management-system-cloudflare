const detailWithDraftActions=detail;
detail=async function(id){
 await detailWithDraftActions(id);
 const d=await api("/api/v2/memos/"+id),m=d.memo,editable=m.author_id===me.id&&["Draft","Changes Requested"].includes(m.status);
 const files=d.attachments||[],section=document.createElement("section");section.className="panel attachment-panel";
 section.innerHTML='<div class="panel-head"><h2>Attachments</h2></div><div class="padded"><div class="attachment-list">'+(files.length?files.map(f=>'<div class="attachment-row"><div><strong>'+e(f.file_name)+'</strong><small>'+formatBytes(f.size)+' · '+date(f.created_at)+'</small></div><div class="top-actions"><a class="btn secondary" href="/api/v2/memos/'+encodeURIComponent(id)+'/attachments/'+encodeURIComponent(f.id)+'">Download</a>'+(editable?'<button class="link danger remove-attachment" data-file="'+e(f.id)+'">Remove</button>':"")+'</div></div>').join(""):'<p class="empty compact">No attachments.</p>')+'</div>'+(editable?'<form id="attachmentUpload" class="form inline attachment-upload"><input name="file" type="file" accept=".pdf,.png,.jpg,.jpeg,.txt,.doc,.docx" required><button class="btn">Upload file</button></form><small>PDF, PNG, JPG, TXT, DOC or DOCX. Maximum 750 KB per file.</small><div id="attachmentMessage"></div>':"")+'</div>';
 const comments=[...document.querySelectorAll(".panel")].find(x=>x.querySelector("h2")?.textContent==="Comments");
 comments?.before(section);
 document.querySelector("#attachmentUpload")?.addEventListener("submit",async x=>{x.preventDefault();const out=document.querySelector("#attachmentMessage"),button=x.target.querySelector("button");button.disabled=true;out.innerHTML=msg("Uploading…");try{const r=await fetch("/api/v2/memos/"+id+"/attachments",{method:"POST",body:new FormData(x.target)}),z=await r.json().catch(()=>({}));if(!r.ok)throw Error(z.error||"Upload failed");await detail(id)}catch(z){out.innerHTML=msg(z.message,true);button.disabled=false}});
 document.querySelectorAll(".remove-attachment").forEach(x=>x.onclick=async()=>{if(!confirm("Remove this attachment?"))return;try{await api("/api/v2/memos/"+id+"/attachments/"+x.dataset.file,{method:"DELETE"});await detail(id)}catch(z){alert(z.message)}});
};
function formatBytes(n){return n<1024?n+" bytes":n<1048576?(n/1024).toFixed(1)+" KB":(n/1048576).toFixed(1)+" MB"}
