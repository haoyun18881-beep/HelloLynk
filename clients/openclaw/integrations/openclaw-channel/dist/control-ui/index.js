// Hand-authored browser entry; OpenClaw requires this dedicated dist directory.
// This dependency-free native page runs only after
// the operator enables OpenClaw's official Custom plugin UI setting.
const plugin = {
  id: "hellolynk",
  activate(host) {
    return host.ui.registerPage({ id: "hellolynk-inbox", label: "HelloLynk 通讯", mount });
  },
};

function mount(container, context) {
  const document = container.ownerDocument;
  const root = document.createElement("div");
  root.style.cssText = "display:flex;flex-direction:column;height:100%;min-height:360px;width:100%";
  const status = document.createElement("p");
  status.setAttribute("role", "status");
  const retry = document.createElement("button");
  retry.type = "button";
  retry.textContent = "重新打开 / Reopen";
  root.append(status, retry);
  container.append(root);
  let disposed = false;
  let opening = false;
  let frame;
  async function open() {
    if (disposed || opening || context.signal.aborted) return;
    opening = true;
    retry.hidden = true;
    status.textContent = "正在打开 HelloLynk… / Opening HelloLynk…";
    try {
      const result = await context.host.request("hellolynk.workbench.open", {});
      if (disposed || context.signal.aborted) return;
      const parent = new URL(document.defaultView.location.href);
      const target = new URL(result.url);
      if (parent.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(parent.hostname)
        || target.protocol !== "http:" || target.hostname !== parent.hostname || target.origin === parent.origin
        || !target.port || target.pathname !== "/workbench" || target.search || target.hash
        || target.username || target.password) throw new Error("Invalid local page");
      frame?.remove();
      frame = document.createElement("iframe");
      frame.title = "HelloLynk 通讯";
      // This frame has its own loopback origin; it cannot read the Gateway DOM
      // or its credentials. Same-origin here refers to the workbench itself.
      frame.setAttribute("sandbox", "allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox");
      frame.referrerPolicy = "origin";
      frame.style.cssText = "width:100%;flex:1;min-height:360px;border:0";
      frame.src = target.href;
      status.hidden = true;
      root.append(frame);
    } catch {
      if (!disposed && !context.signal.aborted) {
        status.hidden = false;
        status.textContent = "HelloLynk 暂时无法打开，请确认本机 Gateway 已连接后重试。 / HelloLynk could not open. Check the local Gateway connection and retry.";
        retry.hidden = false;
      }
    } finally { opening = false; }
  }
  retry.addEventListener("click", open);
  void open();
  return { dispose() { disposed = true; retry.removeEventListener("click", open); root.remove(); } };
}

export default plugin;
