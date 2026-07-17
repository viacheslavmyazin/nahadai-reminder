const WORKER_URL="https://nahadai-telegram.slavamyazin.workers.dev";
const LEGACY_STORE="nahadai-reminders-v1",SESSION_STORE="nahadai-session-v2",USER_STORE="nahadai-user-v2";
const pad=n=>String(n).padStart(2,"0"),dateKey=(d=new Date())=>`${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}`;
const addDays=n=>{const d=new Date();d.setDate(d.getDate()+n);return dateKey(d)},today=dateKey();
const priorities={high:{label:"Висока критичність",color:"#e76f51"},medium:{label:"Середня критичність",color:"#d7a22a"},low:{label:"Низька критичність",color:"#77a88d"}};
let reminders=[],filter="reminders",query="",editingId=null,selectedPriority="medium",selectedItemType="reminder",monthOffset=0;
let sessionToken=localStorage.getItem(SESSION_STORE)||"",currentUser;
let botActivationTimer=null,botActivationAttempts=0,botActivationBusy=false;
try{currentUser=JSON.parse(localStorage.getItem(USER_STORE)||"null")}catch{currentUser=null}
const q=s=>document.querySelector(s),qa=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const prettyDay=d=>d===today?"Сьогодні":d===addDays(1)?"Завтра":new Intl.DateTimeFormat("uk-UA",{day:"numeric",month:"long"}).format(new Date(d+"T12:00"));
const weekday=d=>new Intl.DateTimeFormat("uk-UA",{weekday:"short"}).format(new Date(d+"T12:00"));
q("#today-label").textContent=new Intl.DateTimeFormat("uk-UA",{weekday:"long",day:"numeric",month:"long"}).format(new Date())+". Гарного вам дня!";
const cacheKey=()=>currentUser?`nahadai-cache-v2:${currentUser.id}`:"";
const saveCache=()=>{if(currentUser)localStorage.setItem(cacheKey(),JSON.stringify(reminders))};
const loadCache=()=>{try{return currentUser?JSON.parse(localStorage.getItem(cacheKey())||"[]"):[]}catch{return[]}};
function clearSession(){sessionToken="";currentUser=null;localStorage.removeItem(SESSION_STORE);localStorage.removeItem(USER_STORE)}
async function api(path,options={},auth=true){
 const headers=new Headers(options.headers||{});if(options.body&&!headers.has("content-type"))headers.set("content-type","application/json");
 if(auth&&sessionToken)headers.set("authorization",`Bearer ${sessionToken}`);
 const response=await fetch(WORKER_URL+path,{...options,headers});let data={};try{data=await response.json()}catch{}
 if(response.status===401&&auth){clearSession();showAuth("Сесія завершилась. Увійдіть ще раз.")}
 if(!response.ok){const error=new Error(data.error||`HTTP ${response.status}`);error.status=response.status;throw error}return data;
}
function fillAvatar(el,user){el.textContent="";if(user?.picture){const img=document.createElement("img");img.src=user.picture;img.alt="";img.referrerPolicy="no-referrer";el.append(img)}else el.textContent=(user?.name||"М").trim()[0].toUpperCase()}
function updateAccountUI(){if(!currentUser)return;const caption=currentUser.username?"@"+currentUser.username:"Telegram підключено";
 q("#profile-name").textContent=q("#account-name").textContent=currentUser.name;q("#profile-caption").textContent=q("#account-username").textContent=caption;
 [q("#profile-avatar"),q("#header-account"),q("#account-avatar")].forEach(el=>fillAvatar(el,currentUser));q("#telegram-status").textContent="Підключено";q("#telegram-status").classList.add("connected")}
function showAuth(message=""){document.body.classList.add("auth-required");q("#auth-gate").classList.remove("hidden");q("#auth-message").textContent=message||"Без паролів. Без спільних ключів."}
function hideAuth(){document.body.classList.remove("auth-required");q("#auth-gate").classList.add("hidden")}
function showBotOnboarding(){q("#bot-check-result").textContent="";q("#bot-check-result").className="connection-result";q("#bot-onboarding").classList.remove("hidden")}
function hideBotOnboarding(){q("#bot-onboarding").classList.add("hidden")}
function setBotStatus(connected){const status=q("#telegram-status");status.textContent=connected?"Нагадування активні":"Потрібна активація";status.classList.toggle("connected",connected)}
async function refreshBotConnection(showWhenMissing=false){
 try{const data=await api("/api/bot/status");setBotStatus(Boolean(data.connected));if(data.connected)hideBotOnboarding();else if(showWhenMissing)showBotOnboarding();return Boolean(data.connected)}
 catch(error){console.warn("Bot status unavailable",error);return false}
}
function stopBotActivation(){if(botActivationTimer)clearInterval(botActivationTimer);botActivationTimer=null;botActivationBusy=false}
async function attemptBotActivation(manual=false){
 if(botActivationBusy)return false;botActivationBusy=true;
 const button=q("#bot-check"),result=q("#bot-check-result");if(manual){button.disabled=true;result.className="connection-result";result.textContent="Перевіряємо підключення…"}
 try{await api("/api/bot/connect",{method:"POST"});stopBotActivation();result.className="connection-result success";result.textContent="Готово! Бот підключено — нагадування активні.";setBotStatus(true);notify("Telegram підключено","Нагадування активні");setTimeout(hideBotOnboarding,900);return true}
 catch(error){botActivationAttempts++;if(manual){result.className="connection-result error";result.textContent=error.message||"У Telegram спочатку натисніть Start, потім повторіть перевірку."}if(botActivationAttempts>=30){stopBotActivation();result.className="connection-result error";result.textContent="Не вдалося підтвердити Start. Натисніть Start у боті та перевірте підключення ще раз."}return false}
 finally{botActivationBusy=false;if(manual)button.disabled=false}
}
function beginBotActivation(){stopBotActivation();botActivationAttempts=0;const result=q("#bot-check-result");result.className="connection-result";result.textContent="Очікуємо Start у Telegram… Після повернення перевіримо автоматично.";botActivationTimer=setInterval(()=>attemptBotActivation(false),3000)}
async function verifyBotConnection(){return attemptBotActivation(true)}
function cleanAuthParameters(){const url=new URL(location.href);url.searchParams.delete("login_code");url.searchParams.delete("auth_error");history.replaceState({},"",url.pathname+url.search+url.hash)}
async function exchangeLoginCode(code){const data=await api("/api/auth/exchange",{method:"POST",body:JSON.stringify({code})},false);sessionToken=data.token;currentUser=data.user;localStorage.setItem(SESSION_STORE,sessionToken);localStorage.setItem(USER_STORE,JSON.stringify(currentUser))}
function fromRemote(row){const due=new Date(Number(row.due_at)),done=Boolean(row.done);return{id:String(row.id),title:row.title,note:row.note||"",date:dateKey(due),time:`${pad(due.getHours())}:${pad(due.getMinutes())}`,priority:priorities[row.priority]?row.priority:"medium",done,notified:Boolean(row.sent),itemType:row.item_type==="task"?"task":"reminder",status:row.status||(done?"done":"planned"),recurrenceType:row.recurrence_type||"none",recurrenceInterval:Number(row.recurrence_interval)||1,timezone:row.timezone||Intl.DateTimeFormat().resolvedOptions().timeZone||"Europe/Kyiv"}}
const toRemote=item=>({id:String(item.id),title:item.title,note:item.note||"",dueAt:new Date(item.date+"T"+item.time).toISOString(),priority:item.priority,done:Boolean(item.done),itemType:item.itemType||"reminder",status:item.status||(item.done?"done":"planned"),recurrenceType:item.itemType==="reminder"?(item.recurrenceType||"none"):"none",recurrenceInterval:Number(item.recurrenceInterval)||1,timezone:item.timezone||Intl.DateTimeFormat().resolvedOptions().timeZone||"Europe/Kyiv"});
async function loadReminders(){try{const data=await api("/api/reminders");reminders=(data.reminders||[]).map(fromRemote);saveCache()}catch(error){if(error.status===401)return;reminders=loadCache();notify("Офлайн-режим","Показано останню копію",false)}}
async function migrateLegacy(){
 if(!currentUser)return;const marker=`nahadai-migrated-v2:${currentUser.id}`;if(localStorage.getItem(marker))return;let legacy=[];
 try{legacy=JSON.parse(localStorage.getItem(LEGACY_STORE)||"[]")}catch{}
 if(!Array.isArray(legacy)||!legacy.length){localStorage.setItem(marker,"1");return}
 const ids=new Set(reminders.map(item=>String(item.id)));
 for(const item of legacy){if(!item?.title||!item?.date||!item?.time)continue;const old=String(item.id||"");const id=ids.has(old)?old:crypto.randomUUID();
  try{await api("/api/reminders",{method:"POST",body:JSON.stringify(toRemote({...item,id,priority:item.priority||"medium"}))})}catch(error){console.warn("Migration failed",error)}}
 localStorage.setItem(marker,"1");localStorage.removeItem(LEGACY_STORE);await loadReminders();
}
async function loginFromTelegramMiniApp(){
 const webApp=window.Telegram?.WebApp;
 const initData=webApp?.initData;

 if(!initData){
  return false;
 }

 webApp.ready();
 webApp.expand();

 const data=await api(
  "/api/auth/webapp",
  {
   method:"POST",
   body:JSON.stringify({initData})
  },
  false
 );

 sessionToken=data.token;
 currentUser=data.user;

 localStorage.setItem(SESSION_STORE,sessionToken);
 localStorage.setItem(USER_STORE,JSON.stringify(currentUser));

 return true;
}
async function initializeAuth(){
 const params=new URLSearchParams(location.search),code=params.get("login_code"),authError=params.get("auth_error");
 if(code){try{q("#auth-message").textContent="Завершуємо вхід…";await exchangeLoginCode(code)}catch{clearSession();showAuth("Не вдалося завершити вхід. Спробуйте ще раз.")}finally{cleanAuthParameters()}}
 else if(authError){clearSession();showAuth("Telegram не підтвердив вхід. Спробуйте ще раз.");cleanAuthParameters()}
 if(sessionToken){try{const data=await api("/api/me");currentUser=data.user;localStorage.setItem(USER_STORE,JSON.stringify(currentUser))}catch(error){if(error.status!==401&&currentUser)console.warn("Account check unavailable",error)}}
 if(!sessionToken||!currentUser){reminders=[];render();showAuth();return}
 hideAuth();updateAccountUI();await loadReminders();await migrateLegacy();render();await refreshBotConnection(true);
}
async function syncReminder(item){await api("/api/reminders",{method:"POST",body:JSON.stringify(toRemote(item))});saveCache()}
async function deleteRemote(id){await api("/api/reminders/"+encodeURIComponent(id),{method:"DELETE"});saveCache()}
function repeatLabel(item){const n=Number(item.recurrenceInterval)||1,labels={daily:n===1?"Щодня":`Кожні ${n} дні`,weekdays:"Робочі дні",weekly:n===1?"Щотижня":`Кожні ${n} тижні`,monthly:n===1?"Щомісяця":`Кожні ${n} місяці`};return labels[item.recurrenceType]||""}
function statusLabel(status){return status==="in_progress"?"У роботі":status==="done"?"Виконано":"Заплановано"}
function isOverdue(item,now=Date.now()){
 if(item.done)return false;

 const dueDateTime=new Date(`${item.date}T${item.time}`).getTime();

 return Number.isFinite(dueDateTime)&&dueDateTime<now;
}

function updateSummarySelection(){
 qa(".summary-grid [data-summary-filter]").forEach(card=>{
  card.classList.toggle(
   "active-summary",
   card.dataset.summaryFilter===filter
  );
 });
}

function activateFilter(nextFilter){
 filter=nextFilter;
 query="";
 q("#search").value="";

 qa(".sidebar nav button").forEach(button=>{
  button.classList.toggle(
   "active",
   button.dataset.filter===nextFilter
  );
 });

 updateSummarySelection();
 render();
}
function getNextReminder(){
 const now=Date.now();

 return reminders
  .filter(item=>!item.done)
  .map(item=>({
    ...item,
    due:new Date(`${item.date}T${item.time}`).getTime()
  }))
  .filter(item=>Number.isFinite(item.due)&&item.due>=now)
  .sort((a,b)=>a.due-b.due)[0]||null;
}

function formatRemaining(ms){
 const totalMinutes=Math.floor(ms/60000);

 const days=Math.floor(totalMinutes/1440);
 const hours=Math.floor((totalMinutes%1440)/60);
 const minutes=totalMinutes%60;

 if(days>0){
  return `через ${days} дн. ${hours} год.`;
 }

 if(hours>0){
  return `через ${hours} год. ${minutes} хв.`;
 }

 return `через ${Math.max(1,minutes)} хв.`;
}
function updateSummaryDashboard(){
 const now=new Date();
 const currentDateTime=now.getTime();

 const activeItems=reminders.filter(item=>!item.done);
 const todayItems=activeItems.filter(item=>item.date===today);
 const overdueItems=activeItems.filter(item=>
  isOverdue(item,currentDateTime)
 );
 const doneItems=reminders.filter(item=>item.done);

 q("#active-count").textContent=activeItems.length;
 q("#today-summary-count").textContent=todayItems.length;
 q("#overdue-count").textContent=overdueItems.length;
 q("#done-summary-count").textContent=doneItems.length;

 const todayAllItems=reminders.filter(item=>item.date===today);
 const todayDoneItems=todayAllItems.filter(item=>item.done);
 const todayProgress=todayAllItems.length
  ? Math.round(todayDoneItems.length/todayAllItems.length*100)
  : 0;

 let progress=q("#day-progress");

 if(!progress){
  progress=document.createElement("div");
  progress.id="day-progress";
  progress.className="day-progress";
  progress.innerHTML=`
   <div class="day-progress-head">
    <span id="day-progress-label"></span>
    <strong id="day-progress-percent"></strong>
   </div>
   <div class="day-progress-track">
    <span id="day-progress-bar"></span>
   </div>
  `;
  q("#summary-subtitle").insertAdjacentElement("afterend",progress);
 }

 q("#day-progress-label").textContent=todayAllItems.length
  ? `Виконано ${todayDoneItems.length} із ${todayAllItems.length} справ на сьогодні`
  : "На сьогодні справ немає";

 q("#day-progress-percent").textContent=`${todayProgress}%`;
 q("#day-progress-bar").style.width=`${todayProgress}%`;

 const hour=now.getHours();
 let greeting="Добрий вечір";

 if(hour>=5&&hour<12){
  greeting="Доброго ранку";
 }else if(hour>=12&&hour<18){
  greeting="Добрий день";
 }

 const userName=currentUser?.name?.trim().split(/\s+/)[0]||"";

 q("#greeting").textContent=userName
  ? `${greeting}, ${userName} 👋`
  : `${greeting} 👋`;

 const next=getNextReminder();

 if(overdueItems.length>0){
  q("#summary-title").textContent=
   `У вас ${overdueItems.length} прострочених справ`;

  q("#summary-subtitle").textContent=
   "Рекомендуємо почати з них, а потім перейти до запланованих справ.";

 }else if(next){
  q("#summary-title").textContent=next.title;

  q("#summary-subtitle").textContent=
   `${prettyDay(next.date)}, ${next.time} • ${formatRemaining(next.due-currentDateTime)}`;

 }else{
  q("#summary-title").textContent=
   "Усі справи виконані";

  q("#summary-subtitle").textContent=
   "Чудова робота. Можна додати нову задачу або нагадування.";
 }
}
function render(){
 updateSummaryDashboard();
 updateSummarySelection();
 
 const visible=reminders.filter(item=>{
 const found=(item.title+" "+item.note)
  .toLowerCase()
  .includes(query.toLowerCase());

 if(!found)return false;

 if(filter==="active"){
  return !item.done;
 }

 if(filter==="today"){
  return item.date===today&&!item.done;
 }

 if(filter==="overdue"){
  return isOverdue(item);
 }

 if(filter==="done"){
  return item.done;
 }

 if(filter==="tasks"){
  return item.itemType==="task"&&!item.done;
 }

 return item.itemType!=="task"&&!item.done;
}).sort((a,b)=>
 (a.date+a.time).localeCompare(b.date+b.time)
);
 const groups=Object.groupBy
 ? Object.groupBy(visible,item=>item.date)
 : visible.reduce((all,item)=>{
    (all[item.date]??=[]).push(item);
    return all;
   },{});
 q("#today-count").textContent=reminders.filter(r=>r.date===today&&!r.done).length;q("#reminder-count").textContent=reminders.filter(r=>r.itemType!=="task"&&!r.done).length;q("#task-count").textContent=reminders.filter(r=>r.itemType==="task"&&!r.done).length;q("#done-count").textContent=reminders.filter(r=>r.done).length;q("#shown-count").textContent=visible.length;
 const labels={  reminders:["ВАШІ НАГАДУВАННЯ","Нагадування"],  tasks:["ПЛАНУВАННЯ РОБОТИ","Задачі"],  active:["УСІ ВІДКРИТІ СПРАВИ","Активні"],  today:["НА СЬОГОДНІ","Ваш день"],  overdue:["ПОТРЕБУЮТЬ УВАГИ","Прострочені"],  done:["АРХІВ","Виконані"] };[q("#section-kicker").textContent,q("#section-name").textContent]=labels[filter]||labels.reminders;
 q("#reminders").innerHTML=visible.length?Object.entries(groups).map(([date,items])=>`
  <div class="day-group"><div class="day-heading"><strong>${prettyDay(date)}</strong><span>${weekday(date)}</span></div>
  ${items.map(r=>{const repeat=repeatLabel(r),isTask=r.itemType==="task";return `<article class="reminder-card ${r.done?"done":""} ${isTask?"task-card":""}" data-id="${esc(r.id)}">
   <button class="check-btn" data-action="toggle" aria-label="${r.done?"Повернути":"Виконано"}">${r.done?"✓":""}</button>
   <div class="card-content"><div class="card-meta"><span class="item-badge ${isTask?"task":"reminder"}">${isTask?"Задача":"Нагадування"}</span>${isTask?`<span class="status-badge ${esc(r.status)}">${statusLabel(r.status)}</span>`:""}${repeat?`<span class="repeat-badge">↻ ${esc(repeat)}</span>`:""}</div><div class="card-title-row"><h3>${esc(r.title)}</h3><i class="priority-dot" style="background:${priorities[r.priority].color}" title="${priorities[r.priority].label}"></i></div>
   ${r.note?`<p>${esc(r.note)}</p>`:""}<span class="time">◷ &nbsp;${r.time}</span></div>
   <div class="menu-wrap"><button class="more-btn" data-action="menu">•••</button><div class="card-menu hidden">${isTask&&r.status==="planned"?'<button data-action="start">▶ &nbsp;У роботу</button>':""}<button data-action="edit">✎ &nbsp;Редагувати</button><button class="danger" data-action="delete">⌫ &nbsp;Видалити</button></div></div>
  </article>`}).join("")}</div>`).join(""):`<div class="empty"><span class="empty-icon">♢</span><h3>Тут поки тихо</h3><p>${query?"Нічого не знайдено. Спробуйте інший запит.":filter==="tasks"?"Додайте першу задачу, визначте строк і статус.":"Додайте нагадування — одноразове або регулярне."}</p></div>`;
 const done=reminders.filter(r=>r.done).length;q("#progress-label").textContent=done+" виконано";q("#progress-bar").style.width=Math.min(100,done/Math.max(1,reminders.length)*100)+"%";renderCalendar();
}
function renderCalendar(){
 const d=new Date();d.setDate(1);d.setMonth(d.getMonth()+monthOffset);q("#month-title").textContent=new Intl.DateTimeFormat("uk-UA",{month:"long",year:"numeric"}).format(d);
 const first=new Date(d.getFullYear(),d.getMonth(),1).getDay(),offset=first===0?6:first-1,count=new Date(d.getFullYear(),d.getMonth()+1,0).getDate();
 q("#calendar").innerHTML="<span></span>".repeat(offset)+Array.from({length:count},(_,i)=>{const day=i+1,key=`${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(day)}`;return `<span class="${key===today?"current":""} ${reminders.some(r=>r.date===key&&!r.done)?"has":""}">${day}</span>`}).join("");
}
function updateRecurrenceUi(){const type=q("#recurrence-type").value,wrap=q("#recurrence-interval-wrap"),value=Math.max(1,Number(q("#recurrence-interval").value)||1);wrap.classList.toggle("hidden",type==="none"||type==="weekdays");const units={daily:value===1?"день":"дні",weekly:value===1?"тиждень":"тижні",monthly:value===1?"місяць":"місяці"};q("#recurrence-hint").textContent=`Кожні ${value} ${units[type]||""}`.trim()}
function updateFormMode(){const isTask=selectedItemType==="task";q("#task-options").classList.toggle("hidden",!isTask);q("#reminder-options").classList.toggle("hidden",isTask);qa(".item-type-options button").forEach(b=>b.classList.toggle("selected",b.dataset.itemType===selectedItemType));q("#save-label").textContent=editingId?"Зберегти":isTask?"Додати задачу":"Створити нагадування";q("#modal-title").textContent=editingId?(isTask?"Змінити задачу":"Змінити нагадування"):(isTask?"Нова задача":"Нове нагадування")}
function openModal(item=null,preferredType=null){editingId=item?.id||null;selectedItemType=item?.itemType||preferredType||(filter==="tasks"?"task":"reminder");q("#title").value=item?.title||"";q("#note").value=item?.note||"";q("#date").value=item?.date||today;if(item)q("#date").removeAttribute("min");else q("#date").min=today;q("#time").value=item?.time||"09:00";selectedPriority=item?.priority||"medium";
 q("#task-status").value=item?.status||"planned";q("#recurrence-type").value=item?.recurrenceType||"none";q("#recurrence-interval").value=item?.recurrenceInterval||1;qa(".priority-options button").forEach(b=>b.classList.toggle("selected",b.dataset.priority===selectedPriority));updateFormMode();updateRecurrenceUi();q("#modal").classList.remove("hidden");setTimeout(()=>q("#title").focus(),50)}
function closeModal(){q("#modal").classList.add("hidden");editingId=null}
function notify(title,message,success=true){q("#toast-title").textContent=title;q("#toast-message").textContent=message;q("#toast").classList.toggle("toast-error",!success);q("#toast").classList.remove("hidden");setTimeout(()=>q("#toast").classList.add("hidden"),2800)}
function openAccount(){if(!currentUser)return;updateAccountUI();q("#account-modal").classList.remove("hidden")}
q("#telegram-login").onclick=()=>{q("#auth-message").textContent="Відкриваємо Telegram…";location.href=WORKER_URL+"/api/auth/login"};
async function openCreate(preferredType){if("Notification" in window&&Notification.permission==="default")await Notification.requestPermission();openModal(null,preferredType)}
q("#new-btn").onclick=()=>openCreate(filter==="tasks"?"task":"reminder");q("#quick-add").onclick=()=>openCreate("reminder");
q("#close-modal").onclick=q("#cancel").onclick=closeModal;q("#modal").addEventListener("mousedown",e=>{if(e.target===e.currentTarget)closeModal()});
qa(".priority-options button").forEach(b=>b.onclick=()=>{selectedPriority=b.dataset.priority;qa(".priority-options button").forEach(x=>x.classList.toggle("selected",x===b))});
qa(".item-type-options button").forEach(b=>b.onclick=()=>{selectedItemType=b.dataset.itemType;updateFormMode()});
q("#recurrence-type").onchange=updateRecurrenceUi;q("#recurrence-interval").oninput=updateRecurrenceUi;
q("#reminder-form").onsubmit=async e=>{
 e.preventDefault();const status=selectedItemType==="task"?q("#task-status").value:"planned";const data={title:q("#title").value.trim(),note:q("#note").value.trim(),date:q("#date").value,time:q("#time").value,priority:selectedPriority,itemType:selectedItemType,status,done:status==="done",recurrenceType:selectedItemType==="reminder"?q("#recurrence-type").value:"none",recurrenceInterval:Math.max(1,Number(q("#recurrence-interval").value)||1),timezone:Intl.DateTimeFormat().resolvedOptions().timeZone||"Europe/Kyiv"};if(!data.title)return;let saved;
 if(editingId){reminders=reminders.map(r=>r.id===editingId?{...r,...data,notified:false}:r);saved=reminders.find(r=>r.id===editingId)}else{saved={id:crypto.randomUUID(),...data,notified:false};reminders.push(saved)}
 saveCache();closeModal();render();try{await syncReminder(saved);notify("Готово!",saved.itemType==="task"?"Задачу збережено":"Нагадування збережено")}catch{notify("Не синхронізовано","Перевірте інтернет і повторіть редагування",false)}
};
q(".sidebar nav").onclick=e=>{  const button=e.target.closest("[data-filter]");   if(!button)return;   activateFilter(button.dataset.filter); };
q(".summary-grid").onclick=e=>{
 const card=e.target.closest("[data-summary-filter]");

 if(!card)return;

 activateFilter(card.dataset.summaryFilter);
};

q(".summary-grid").onkeydown=e=>{
 const card=e.target.closest("[data-summary-filter]");

 if(!card)return;

 if(e.key==="Enter"||e.key===" "){
  e.preventDefault();
  activateFilter(card.dataset.summaryFilter);
 }
};
q("#search").oninput=e=>{query=e.target.value;render()};
q("#reminders").onclick=async e=>{
 const action=e.target.closest("[data-action]");if(!action)return;const card=action.closest(".reminder-card"),id=card.dataset.id,item=reminders.find(r=>String(r.id)===id);if(!item)return;
 if(action.dataset.action==="toggle"){item.done=!item.done;item.status=item.done?"done":"planned";item.notified=false;saveCache();render();try{await syncReminder(item)}catch{notify("Не синхронізовано","Спробуйте ще раз",false)}}
 if(action.dataset.action==="start"){item.status="in_progress";item.done=false;item.notified=false;saveCache();render();try{await syncReminder(item);notify("Задача в роботі",item.title)}catch{notify("Не синхронізовано","Спробуйте ще раз",false)}}
 if(action.dataset.action==="menu")card.querySelector(".card-menu").classList.toggle("hidden");if(action.dataset.action==="edit")openModal(item);
 if(action.dataset.action==="delete"){reminders=reminders.filter(r=>String(r.id)!==id);saveCache();render();try{await deleteRemote(id)}catch{notify("Не синхронізовано","Видалення не збережено на сервері",false)}}
};
q("#telegram-settings").onclick=q("#profile-button").onclick=q("#header-account").onclick=openAccount;
q("#close-account").onclick=q("#close-account-primary").onclick=()=>q("#account-modal").classList.add("hidden");
q("#bot-check").onclick=verifyBotConnection;q("#bot-later").onclick=()=>{stopBotActivation();hideBotOnboarding()};q("#open-bot").onclick=beginBotActivation;
document.addEventListener("visibilitychange",()=>{if(document.visibilityState==="visible"&&botActivationTimer)attemptBotActivation(false)});
window.addEventListener("focus",()=>{if(botActivationTimer)attemptBotActivation(false)});
q("#account-modal").addEventListener("mousedown",e=>{if(e.target===e.currentTarget)q("#account-modal").classList.add("hidden")});
q("#logout").onclick=async()=>{try{await api("/api/logout",{method:"POST"})}catch{}clearSession();reminders=[];q("#account-modal").classList.add("hidden");render();showAuth("Ви вийшли з облікового запису.")};
q("#prev-month").onclick=()=>{monthOffset--;renderCalendar()};q("#next-month").onclick=()=>{monthOffset++;renderCalendar()};
document.addEventListener("keydown",e=>{if(e.key==="Escape"){closeModal();q("#account-modal").classList.add("hidden")}});
async function checkBrowserReminders(){
 if(!sessionToken||!currentUser||!("Notification" in window)||Notification.permission!=="granted")return;
 const run=async()=>{
  let fresh;try{const data=await api("/api/reminders");fresh=(data.reminders||[]).map(fromRemote)}catch{return}
  reminders=fresh;saveCache();if(document.visibilityState==="visible"&&q("#modal").classList.contains("hidden"))render();
  const now=Date.now();
  for(const reminder of fresh){
   if(reminder.done||reminder.notified||new Date(reminder.date+"T"+reminder.time).getTime()>now)continue;
   const key=`nahadai-browser-notified:${currentUser.id}:${reminder.id}:${reminder.date}:${reminder.time}`;
   if(localStorage.getItem(key))continue;
   localStorage.setItem(key,String(now));
   new Notification(reminder.title,{body:reminder.note||"Час виконати заплановане",tag:key});
  }
 };
 if(navigator.locks){await navigator.locks.request("nahadai-browser-reminder-check",{ifAvailable:true},lock=>lock?run():undefined)}else await run();
}
setInterval(checkBrowserReminders,60000);
render();initializeAuth();


