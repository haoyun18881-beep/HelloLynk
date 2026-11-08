import crypto from "node:crypto";

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
// Use the desktop conversation SDK. WorkBuddy 5.8.2 no longer registers the
// former wb:conversations:local:list IPC channel, although __wbInvoke still exists.
// Authentication and normal model permissions stay in the running desktop.
export function createWorkBuddyNativeTaskClient({ debugEndpoint = "http://127.0.0.1:9337", targetId, ownedSessionIds = [], timeoutMs = 30_000, transport } = {}) {
  const endpoint = new URL(debugEndpoint);
  if (endpoint.protocol !== "http:" || endpoint.hostname !== "127.0.0.1" || !endpoint.port || endpoint.username || endpoint.password || endpoint.pathname !== "/" || endpoint.search || endpoint.hash) throw failure("workbuddy_native_debug_endpoint_invalid");
  const owned = new Set(ownedSessionIds.map(validId));
  const sent = new Map();
  async function evaluate(expression, customTimeout = timeoutMs) {
    if (transport) return transport(expression);
    const response = await fetch(new URL("/json/list", endpoint), { signal: AbortSignal.timeout(5_000) });
    if (!response.ok) throw failure("workbuddy_native_debug_unavailable");
    const targets = await response.json();
    if (!Array.isArray(targets)) throw failure("workbuddy_native_debug_response_invalid");
    const pages = targets.filter((item) => item.type === "page" && (targetId ? item.id === targetId : item.title === "WorkBuddy"));
    if (pages.length !== 1) throw failure("workbuddy_native_target_ambiguous");
    // Never return or log the target page URL; it can contain accountSnapshot.
    const address = new URL(pages[0].webSocketDebuggerUrl);
    if (address.protocol !== "ws:" || address.hostname !== endpoint.hostname || address.port !== endpoint.port || address.username || address.password || address.search || address.hash || !/^\/devtools\/page\/[A-Za-z0-9-]+$/.test(address.pathname)) throw failure("workbuddy_native_socket_invalid");
    return evaluateOnSocket(address.href, expression, customTimeout);
  }
  function requireOwned(id) { validId(id); if (!owned.has(id)) throw failure("workbuddy_native_task_not_owned"); return id; }
  return Object.freeze({
    async probe() {
      return evaluate("({available:typeof window.wb?.conversations?.create==='function'&&typeof window.wb?.conversations?.get==='function'&&typeof window.wb?.conversations?.local?.list==='function'})");
    },
    async mcpRegistrationStatus({ connect = false } = {}) {
      return evaluate(mcpExpression(`let item=(await daemon.mcpList()).find(x=>x.id==='custom-mcp:hellolynk');if(${connect === true}&&item?.trusted===true&&item.enabled===true&&item.state!=='ready'){await daemon.mcpConnect({id:item.id,interactive:false});item=(await daemon.mcpList()).find(x=>x.id==='custom-mcp:hellolynk');}return project(item);`));
    },
    async approveHelloLynkMcp({ command, args, storeRoot }) {
      if (typeof command !== "string" || !Array.isArray(args) || args.some(x=>typeof x!=="string") || typeof storeRoot !== "string") throw failure("workbuddy_native_mcp_expected_config_invalid");
      const expected = { command, args, storeRoot };
      // Refusals come back as values: a thrown renderer error would reach
      // here only as workbuddy_native_call_failed.
      const value = await evaluate(mcpExpression(`
        const expected=${JSON.stringify(expected)};
        const find=async()=>(await daemon.mcpList()).find(x=>x.id==='custom-mcp:hellolynk');
        await daemon.mcpRefresh();
        let item=await find();
        const form=item?.form;
        if(!form||item.transport!=='stdio'||form.name!=='hellolynk'||form.command!==expected.command||JSON.stringify(form.args)!==JSON.stringify(expected.args)||!Array.isArray(form.env)||form.env.length!==1||form.env[0].key!=='HELLOLYNK_NEUTRAL_STORE_ROOT'||form.env[0].value!==expected.storeRoot)return {refused:'workbuddy_native_mcp_config_mismatch'};
        if(item.enabled!==true)return {refused:'workbuddy_native_mcp_disabled'};
        if(item.trusted!==true){const approved=await daemon.mcpApprove({id:item.id,configHash:item.configHash});if(approved?.ok===false)return {refused:'workbuddy_native_mcp_approval_failed'};}
        const connected=item.trusted===true&&item.state==='ready'?null:await daemon.mcpConnect({id:item.id,interactive:false});
        item=await find();
        if(connected?.ok===false)return {...project(item),status:'connection_failed',errorCode:connected.code??'workbuddy_native_mcp_connection_failed'};
        // A just-approved server is still starting; wait briefly for it.
        for(let waited=0;item?.trusted===true&&item.enabled===true&&item.state!=='ready'&&waited<10000;waited+=250){await new Promise(r=>setTimeout(r,250));item=await find();}
        return project(item);
      `), 60_000);
      if (value?.refused) throw failure(/^workbuddy_native_mcp_[a-z_]{1,60}$/.test(value.refused) ? value.refused : "workbuddy_native_mcp_approval_failed");
      return value;
    },
    async create({ nativeSessionId = crypto.randomUUID(), title = "HelloLynk" } = {}) {
      validId(nativeSessionId);
      if (owned.has(nativeSessionId)) throw failure("workbuddy_native_task_already_owned");
      if (typeof title !== "string" || title.length < 1 || title.length > 160 || /[\u0000-\u001f]/.test(title)) throw failure("workbuddy_native_task_title_invalid");
      const params = { conversationId: nativeSessionId, title, transport: "local", isPlayground: true, conversationOrigin: "local" };
      const result = await evaluate(conversationExpression(`const r=await api.create(${JSON.stringify(params)});return {nativeSessionId:r?.info?.id??null,errorCode:r?.errorCode??null,transport:r?.info?.transport??null};`));
      if (result?.errorCode || result?.nativeSessionId !== nativeSessionId || result.transport !== "local") throw failure("workbuddy_native_create_unconfirmed");
      owned.add(nativeSessionId);
      return { nativeSessionId, status: "created", nativeRoute: `workbuddy://chat/${encodeURIComponent(nativeSessionId)}` };
    },
    async send({ nativeSessionId, clientRequestId, text }) {
      requireOwned(nativeSessionId); validId(clientRequestId);
      if (typeof text !== "string" || !text.trim() || Buffer.byteLength(text) > 64 * 1024) throw failure("workbuddy_native_prompt_invalid");
      const key = `${nativeSessionId}:${clientRequestId}`;
      if (sent.has(key)) return { ...sent.get(key), duplicate: true };
      const unknown = { nativeSessionId, clientRequestId, status: "dispatch_unknown" };
      // The owning worker must also persist this marker before calling send;
      // this map stops accidental in-process repetition of an ambiguous call.
      sent.set(key, unknown);
      const args = [[{ type: "text", text }], { clientRequestId, _expectQueueReceipt: true }];
      let value;
      try {
        value = await evaluate(conversationExpression(`const task=await api.get(${JSON.stringify(nativeSessionId)});if(task?.info?.id!==${JSON.stringify(nativeSessionId)}||task.info.transport!=='local'||typeof task.sendPrompt!=='function')throw Error('workbuddy_native_task_unavailable');const r=await task.sendPrompt(...${JSON.stringify(args)});return {errorCode:r?.errorCode??null,queued:r?.disposition==='queued'};`));
      } catch { return unknown; }
      if (value?.errorCode) return unknown;
      const result = { nativeSessionId, clientRequestId, status: value?.queued ? "queued_unconfirmed" : "submitted_unconfirmed" };
      sent.set(key, result);
      return result;
    },
    async status(nativeSessionId) {
      requireOwned(nativeSessionId);
      // get() may return a pooled live object. Read fresh lifecycle metadata
      // from the active/completed view and the separate archived view.
      // Nothing outside this exact owned ID leaves the renderer.
      return evaluate(conversationExpression(`${ORIGIN_ITEM}const id=${JSON.stringify(nativeSessionId)};const item=await originItem(id);return item?{nativeSessionId:id,state:item.state??null,missing:false,archived:item.lifecycle==='archived'}:{nativeSessionId:null,missing:true,archived:false};`));
    },
    // Original conversation of a reply: any ID the hook recorded, not only
    // HelloLynk tasks. Returns lifecycle and busy flags only; never opens it.
    async listConversations() {
      return evaluate(conversationExpression(`const conversations=new Map();for(const view of ['all','archived']){for(let page=1;;page++){const r=await api.local.list({view,page,size:100});if(r?.errorCode||r?.errors?.length||!Array.isArray(r?.items)||!Number.isSafeInteger(r.total)||r.total<0)throw Error('workbuddy_native_catalog_unknown');for(const item of r.items){if(typeof item.id!=='string'||!/^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$/.test(item.id))continue;conversations.set(item.id,{targetConversationId:item.id,title:item.title||item.name||item.id,project:(item.space?.cwd||item.cwd||item.workspacePath||'').split(/[\\\\/]/).filter(Boolean).at(-1)||'',state:item.lifecycle==='archived'?'archived':['planning','working','pending'].includes(item.state)?'active':'idle'});}if(page*100>=r.total)break;if(!r.items.length)throw Error('workbuddy_native_catalog_incomplete');}}return {conversations:[...conversations.values()],coverage:'complete',exactTargetSupported:true};`));
    },
    async inspectOrigin(nativeSessionId) {
      validId(nativeSessionId);
      return evaluate(conversationExpression(`${ORIGIN_BUSY}${ORIGIN_ITEM}const id=${JSON.stringify(nativeSessionId)};const item=await originItem(id);if(!item)return {present:false,archived:false,busy:false};if(item.lifecycle==='archived')return {present:true,archived:true,busy:false};if(await busy(null,item))return {present:true,archived:false,busy:true};const task=await api.get(id);if(task?.info?.id!==id)throw Error('workbuddy_native_lifecycle_unknown');return {present:true,archived:false,busy:await busy(task,item)};`));
    },
    // Re-checks lifecycle and idle in the same renderer call as sendPrompt, so
    // a reply is not sent to a conversation archived or deleted since the
    // inspection, nor queued behind a running turn or an open question.
    async sendToIdle({ nativeSessionId, clientRequestId, text }) {
      validId(nativeSessionId); validId(clientRequestId);
      if (typeof text !== "string" || !text.trim() || Buffer.byteLength(text) > 64 * 1024) throw failure("workbuddy_native_prompt_invalid");
      const key = `${nativeSessionId}:${clientRequestId}`;
      if (sent.has(key)) return { ...sent.get(key), duplicate: true };
      const unknown = { nativeSessionId, clientRequestId, status: "dispatch_unknown" };
      sent.set(key, unknown);
      const args = [[{ type: "text", text }], { clientRequestId, _expectQueueReceipt: true }];
      let value;
      try {
        value = await evaluate(conversationExpression(`${ORIGIN_BUSY}${ORIGIN_ITEM}const id=${JSON.stringify(nativeSessionId)};let item;try{item=await originItem(id);}catch{return {held:'lifecycle_unknown'};}if(!item)return {held:'missing'};if(item.lifecycle==='archived')return {held:'archived'};let task;try{task=await api.get(id);if(task?.info?.id!==id||typeof task.sendPrompt!=='function')return {held:'missing'};if(await busy(task,item))return {held:'busy'};}catch{return {held:'lifecycle_unknown'};}const r=await task.sendPrompt(...${JSON.stringify(args)});return {errorCode:r?.errorCode??null,queued:r?.disposition==='queued'};`));
      } catch { return unknown; }
      if (["busy", "missing", "archived", "lifecycle_unknown"].includes(value?.held)) {
        // Nothing was submitted; a later tick may try again.
        sent.delete(key);
        return { nativeSessionId, clientRequestId, status: value.held };
      }
      if (value?.errorCode) return unknown;
      const result = { nativeSessionId, clientRequestId, status: value?.queued ? "queued_unconfirmed" : "submitted_unconfirmed" };
      sent.set(key, result);
      return result;
    },
    async open(nativeSessionId) {
      requireOwned(nativeSessionId);
      const nativeRoute = `workbuddy://chat/${encodeURIComponent(nativeSessionId)}`;
      // The installed renderer's dispatchInternalDeeplink uses this exact
      // cancelable event; its normal chat handler consumes only known routes.
      const value = await evaluate(`(()=>{const event=new CustomEvent('workbuddy:internal-deeplink',{cancelable:true,detail:{url:${JSON.stringify(nativeRoute)}}});window.dispatchEvent(event);return {opened:event.defaultPrevented};})()`);
      if (!value?.opened) throw failure("workbuddy_native_route_unavailable");
      return { nativeSessionId, status: "open_requested", nativeRoute };
    },
  });
}

// WorkBuddy 5.8.2 renderer: isBusyState is planning|working, "pending" waits
// for the person, and hasActiveInteraction() covers these three getters.
const ORIGIN_BUSY = "const busy=async(task,item)=>{for(const state of [task?.info?.state,item?.state])if(['planning','working','pending'].includes(state))return true;for(const name of ['getPendingInfo','getCloudServiceConfirmation','getPluginRecommendation'])if(typeof task?.[name]==='function'&&(await task[name]())!=null)return true;return false;};";
// "all" excludes archives in WorkBuddy's SDK. Fall through to its archived
// view before consulting get(), whose pooled object can retain old lifecycle.
const ORIGIN_ITEM = "const originItem=async(id)=>{let item=null;for(const view of ['all','archived']){for(let page=1;page<=100;page++){const r=await api.local.list({view,page,size:100});if(r?.errorCode||r?.errors?.length||!Array.isArray(r?.items)||!Number.isSafeInteger(r.total)||r.total<0)throw Error('workbuddy_native_lifecycle_unknown');item=r.items.find(x=>x.id===id)??null;if(item||page*100>=r.total||!r.items.length)break;}if(item)break;}if(!item){if(await api.get(id)==null)return null;throw Error('workbuddy_native_lifecycle_unknown');}if(!['active','archived','completed'].includes(item.lifecycle))throw Error('workbuddy_native_lifecycle_unknown');return item;};";

// Use the desktop SDK namespace, not a hashed renderer chunk or minified
// export name. Approval still uses the app's exact configuration hash.
function conversationExpression(body) {
  return `(async()=>{const api=window.wb?.conversations;if(!api)throw Error('workbuddy_native_conversation_sdk_unavailable');${body}})()`;
}

function mcpExpression(body) {
  return `(async()=>{const api=window.wb?.mcp;if(!api)throw Error('workbuddy_native_mcp_sdk_unavailable');const daemon={mcpList:async()=>{const r=await api.list();if(!Array.isArray(r?.items))throw Error('workbuddy_native_mcp_response_invalid');return r.items;},mcpConnect:params=>api.connect(params),mcpApprove:params=>api.approve(params),mcpRefresh:()=>api.refresh()};const project=(item)=>({id:item?.id??null,status:item?.state??'missing',enabled:item?.enabled===true,trusted:item?.trusted===true,blockedReason:item?.blockedReason??null,configHash:item?.configHash??null,tools:(item?.tools??[]).map(t=>({name:t.name,enabled:t.enabled!==false}))});${body}})()`;
}

async function evaluateOnSocket(address, expression, timeoutMs) {
  if (typeof globalThis.WebSocket !== "function") throw failure("workbuddy_native_websocket_runtime_required");
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(address);
    let settled = false;
    const finish = (error, value) => { if (settled) return; settled = true; clearTimeout(timer); socket.close(); error ? reject(failure(error)) : resolve(value); };
    const timer = setTimeout(() => finish("workbuddy_native_call_unknown"), timeoutMs);
    socket.onopen = () => socket.send(JSON.stringify({ id: 1, method: "Runtime.evaluate", params: { expression, returnByValue: true, awaitPromise: true } }));
    socket.onerror = () => finish("workbuddy_native_socket_failed");
    socket.onclose = () => { if (!settled) finish("workbuddy_native_call_unknown"); };
    socket.onmessage = (event) => {
      let message; try { message = JSON.parse(event.data); } catch { finish("workbuddy_native_response_invalid"); return; }
      if (message.id !== 1) return;
      if (message.error || message.result?.exceptionDetails) { finish("workbuddy_native_call_failed"); return; }
      finish(null, message.result?.result?.value);
    };
  });
}
function validId(value) { if (typeof value !== "string" || !ID.test(value)) throw failure("workbuddy_native_id_invalid"); return value; }
function failure(code) { return Object.assign(new Error(code), { code }); }
