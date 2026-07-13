const STORE = "nahadai-reminders-v1";
const pad = n => String(n).padStart(2,"0");
const dateKey = (d=new Date()) => `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}`;
const addDays = n => { const d=new Date(); d.setDate(d.getDate()+n); return dateKey(d) };
const today = dateKey();
const priorities = {high:{label:"Важливе",color:"#e76f51"},medium:{label:"Звичайне",color:"#d7a22a"},low:{label:"Можна згодом",color:"#77a88d"}};
const starters = [
  {id:1,title:"Зателефонувати мамі",note:"Запитати, як минув тиждень",date:today,time:"18:30",priority:"high",done:false},
  {id:2,title:"Забрати посилку",note:"Відділення працює до 20:00",date:today,time:"19:15",priority:"medium",done:false},
  {id:3,title:"Підготувати презентацію",note:"Додати фінальні цифри й висновки",date:addDays(1),time:"10:00",priority:"high",done:false},
  {id:4,title:"Полити рослини",note:"",date:addDays(2),time:"09:00",priority:"low",done:false},
  {id:5,title:"Купити квитки до Львова",note:"Перевірити ранкові потяги",date:addDays(4),time:"12:00",priority:"medium",done:false}
];
let reminders;
try { reminders=JSON.parse(localStorage.getItem(STORE)) || starters } catch { reminders=starters }
let filter="upcoming", query="", editingId=null, selectedPriority="medium", monthOffset=0;
let telegramConfig=JSON.parse(localStorage.getItem("nahadai-telegram")||"null");

const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const saveStore = () => localStorage.setItem(STORE,JSON.stringify(reminders));
const esc = s => String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const prettyDay = d => d===today ? "Сьогодні" : d===addDays(1) ? "Завтра" : new Intl.DateTimeFormat("uk-UA",{day:"numeric",month:"long"}).format(new Date(d+"T12:00"));
const weekday = d => new Intl.DateTimeFormat("uk-UA",{weekday:"short"}).format(new Date(d+"T12:00"));
$("#today-label").textContent = new Intl.DateTimeFormat("uk-UA",{weekday:"long",day:"numeric",month:"long"}).format(new Date())+". Гарного вам дня!";

function telegramHeaders(){return {"content-type":"application/json","authorization":"Bearer "+telegramConfig.key}}
async function syncTelegram(item){
  if(!telegramConfig||item.done)return;
  try{
    const response=await fetch(telegramConfig.url+"/api/reminders",{method:"POST",headers:telegramHeaders(),body:JSON.stringify({id:item.id,title:item.title,note:item.note,dueAt:new Date(item.date+"T"+item.time).toISOString()})});
    if(!response.ok)throw new Error("sync");
  }catch{console.warn("Telegram sync failed")}
}
async function removeTelegram(id){
  if(!telegramConfig)return;
  try{await fetch(telegramConfig.url+"/api/reminders/"+encodeURIComponent(id),{method:"DELETE",headers:telegramHeaders()})}catch{}
}
function renderTelegramStatus(){
  const status=$("#telegram-status");if(!status)return;
  status.textContent=telegramConfig?"Підключено":"Не підключено";
  status.classList.toggle("connected",!!telegramConfig);
}

function render(){
  const visible=reminders.filter(r=>{
    const found=(r.title+" "+r.note).toLowerCase().includes(query.toLowerCase());
    if(!found)return false;
    if(filter==="today")return r.date===today&&!r.done;
    if(filter==="done")return r.done;
    return !r.done;
  }).sort((a,b)=>(a.date+a.time).localeCompare(b.date+b.time));
  const groups=Object.groupBy ? Object.groupBy(visible,r=>r.date) : visible.reduce((a,r)=>((a[r.date]??=[]).push(r),a),{});
  $("#today-count").textContent=reminders.filter(r=>r.date===today&&!r.done).length;
  $("#done-count").textContent=reminders.filter(r=>r.done).length;
  $("#shown-count").textContent=visible.length;
  const labels={upcoming:["НАЙБЛИЖЧІ СПРАВИ","Попереду"],today:["НА СЬОГОДНІ","Ваш день"],done:["АРХІВ","Виконані"]};
  [$("#section-kicker").textContent,$("#section-name").textContent]=labels[filter];
  $("#reminders").innerHTML=visible.length ? Object.entries(groups).map(([date,items])=>`
    <div class="day-group"><div class="day-heading"><strong>${prettyDay(date)}</strong><span>${weekday(date)}</span></div>
    ${items.map(r=>`<article class="reminder-card ${r.done?"done":""}" data-id="${r.id}">
      <button class="check-btn" data-action="toggle" aria-label="${r.done?"Повернути":"Виконано"}">${r.done?"✓":""}</button>
      <div class="card-content"><div class="card-title-row"><h3>${esc(r.title)}</h3><i class="priority-dot" style="background:${priorities[r.priority].color}" title="${priorities[r.priority].label}"></i></div>
      ${r.note?`<p>${esc(r.note)}</p>`:""}<span class="time">◷ &nbsp;${r.time}</span></div>
      <div class="menu-wrap"><button class="more-btn" data-action="menu">•••</button>
      <div class="card-menu hidden"><button data-action="edit">✎ &nbsp;Редагувати</button><button class="danger" data-action="delete">⌫ &nbsp;Видалити</button></div></div>
    </article>`).join("")}</div>`).join("") : `<div class="empty"><span class="empty-icon">♢</span><h3>Тут поки тихо</h3><p>${query?"Нічого не знайдено. Спробуйте інший запит.":"Додайте нагадування — і ми допоможемо нічого не забути."}</p></div>`;
  const done=reminders.filter(r=>r.done).length;
  $("#progress-label").textContent=`${done} виконано`;
  $("#progress-bar").style.width=`${Math.min(100,done/Math.max(1,reminders.length)*100)}%`;
  renderCalendar();
  renderTelegramStatus();
}
function renderCalendar(){
  const d=new Date(); d.setDate(1); d.setMonth(d.getMonth()+monthOffset);
  $("#month-title").textContent=new Intl.DateTimeFormat("uk-UA",{month:"long",year:"numeric"}).format(d);
  const first=new Date(d.getFullYear(),d.getMonth(),1).getDay();
  const offset=first===0?6:first-1;
  const count=new Date(d.getFullYear(),d.getMonth()+1,0).getDate();
  $("#calendar").innerHTML='<span></span>'.repeat(offset)+Array.from({length:count},(_,i)=>{
    const day=i+1,key=`${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(day)}`;
    return `<span class="${key===today?"current":""} ${reminders.some(r=>r.date===key&&!r.done)?"has":""}">${day}</span>`
  }).join("");
}
async function openModal(item=null){
  editingId=item?.id||null;
  $("#modal-title").textContent=item?"Змінити нагадування":"Нове нагадування";
  $("#save-label").textContent=item?"Зберегти":"Нагадати мені";
  $("#title").value=item?.title||"";
  $("#note").value=item?.note||"";
  $("#date").value=item?.date||today;
  $("#date").min=today;
  $("#time").value=item?.time||"09:00";
  selectedPriority=item?.priority||"medium";
  $$(".priority-options button").forEach(b=>b.classList.toggle("selected",b.dataset.priority===selectedPriority));
  $("#modal").classList.remove("hidden");
  setTimeout(()=>$("#title").focus(),50);
}
function closeModal(){ $("#modal").classList.add("hidden"); editingId=null }
function toast(){ $("#toast").classList.remove("hidden"); setTimeout(()=>$("#toast").classList.add("hidden"),2600) }

$("#new-btn").onclick=$("#quick-add").onclick=async()=>{
  if("Notification" in window && Notification.permission==="default") await Notification.requestPermission();
  openModal();
};
$("#close-modal").onclick=$("#cancel").onclick=closeModal;
$("#modal").addEventListener("mousedown",e=>{if(e.target===e.currentTarget)closeModal()});
$$(".priority-options button").forEach(b=>b.onclick=()=>{
  selectedPriority=b.dataset.priority;
  $$(".priority-options button").forEach(x=>x.classList.toggle("selected",x===b));
});
$("#reminder-form").onsubmit=e=>{
  e.preventDefault();
  const data={title:$("#title").value.trim(),note:$("#note").value.trim(),date:$("#date").value,time:$("#time").value,priority:selectedPriority};
  if(!data.title)return;
  let saved;
  if(editingId){reminders=reminders.map(r=>r.id===editingId?{...r,...data,notified:false}:r);saved=reminders.find(r=>r.id===editingId)}
  else{saved={id:Date.now(),...data,done:false,notified:false};reminders.push(saved)}
  saveStore(); syncTelegram(saved); closeModal(); render(); toast();
};
$(".sidebar nav").onclick=e=>{
  const b=e.target.closest("[data-filter]"); if(!b)return;
  filter=b.dataset.filter;
  $$(".sidebar nav button").forEach(x=>x.classList.toggle("active",x===b)); render();
};
$("#search").oninput=e=>{query=e.target.value;render()};
$("#reminders").onclick=e=>{
  const action=e.target.closest("[data-action]"); if(!action)return;
  const card=action.closest(".reminder-card"),id=Number(card.dataset.id),item=reminders.find(r=>r.id===id);
  if(action.dataset.action==="toggle"){item.done=!item.done;item.done?removeTelegram(id):syncTelegram(item);saveStore();render()}
  if(action.dataset.action==="menu"){card.querySelector(".card-menu").classList.toggle("hidden")}
  if(action.dataset.action==="edit")openModal(item);
  if(action.dataset.action==="delete"){reminders=reminders.filter(r=>r.id!==id);removeTelegram(id);saveStore();render()}
};
$("#telegram-settings").onclick=()=>{
  $("#worker-url").value=telegramConfig?.url||"";
  $("#worker-key").value=telegramConfig?.key||"";
  $("#connection-result").textContent="";
  $("#telegram-modal").classList.remove("hidden");
};
$("#close-telegram").onclick=()=>$("#telegram-modal").classList.add("hidden");
$("#disconnect-telegram").onclick=()=>{
  telegramConfig=null;localStorage.removeItem("nahadai-telegram");
  $("#telegram-modal").classList.add("hidden");renderTelegramStatus();
};
$("#telegram-form").onsubmit=async e=>{
  e.preventDefault();
  const url=$("#worker-url").value.trim().replace(/\/$/,""),key=$("#worker-key").value.trim();
  const result=$("#connection-result");result.textContent="Перевіряємо…";result.className="connection-result";
  try{
    const response=await fetch(url+"/api/check",{headers:{authorization:"Bearer "+key}});
    if(!response.ok)throw new Error();
    const chat=await fetch(url+"/api/connect-chat",{method:"POST",headers:{authorization:"Bearer "+key}});
    if(!chat.ok)throw new Error();
    telegramConfig={url,key};localStorage.setItem("nahadai-telegram",JSON.stringify(telegramConfig));
    result.textContent="Підключено успішно";result.classList.add("success");renderTelegramStatus();
    reminders.filter(r=>!r.done).forEach(syncTelegram);
    setTimeout(()=>$("#telegram-modal").classList.add("hidden"),700);
  }catch{result.textContent="Не вдалося підключитися. Перевірте URL і ключ.";result.classList.add("error")}
};

$("#prev-month").onclick=()=>{monthOffset--;renderCalendar()};
$("#next-month").onclick=()=>{monthOffset++;renderCalendar()};
document.addEventListener("keydown",e=>{if(e.key==="Escape")closeModal()});
setInterval(()=>{
  const now=new Date();
  reminders.forEach(r=>{
    if(!r.done&&!r.notified&&new Date(r.date+"T"+r.time)<=now){
      if("Notification" in window&&Notification.permission==="granted")new Notification(r.title,{body:r.note||"Час виконати заплановане"});
      r.notified=true;saveStore();
    }
  });
},30000);
render();







