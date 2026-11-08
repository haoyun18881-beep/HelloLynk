import { mountWorkbench, publicError } from "/assets/app.mjs";
import { createWorkbenchHttpTransport } from "/assets/http-transport.mjs";

const PORTAL_URLS = Object.freeze({
  keys: "https://hellolynk.com/account#keys",
  devices: "https://hellolynk.com/account#devices",
});
const transport = createWorkbenchHttpTransport();
const nativeAccountLinks = document.body.dataset.nativeAccountLinks === "true";

function openPortal(target) {
  const url = PORTAL_URLS[target];
  if (!url) throw new Error("workbench_portal_target_invalid");
  if (nativeAccountLinks) return transport.openAccount(url);
  window.open(url, "_blank", "noopener,noreferrer");
}

try {
  mountWorkbench({ transport, openPortal,
    ...(nativeAccountLinks ? { openConnectionLink: (url) => transport.openAccount(url) } : {}),
  });
} catch (error) {
  document.getElementById("state-title").textContent = "HelloLynk 暂时打不开 / HelloLynk couldn’t open";
  document.getElementById("state-message").textContent = `页面没能启动。请回到客户端，重新打开 HelloLynk 通讯；一直不行，请把下面的错误码告诉你的 AI。 / The page didn’t start. Go back to your client and reopen HelloLynk Messaging; if it keeps failing, tell your AI the error code below.\n${publicError(error)}`;
  document.querySelector(".spinner")?.setAttribute("hidden", "");
}
