import crypto from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const UI_ROOT = path.join(MODULE_DIR, "ui");

const MODULES = Object.freeze([
  ["bridge", path.join(UI_ROOT, "mcp-app-client.mjs")],
  ["contract", path.join(MODULE_DIR, "contract.mjs")],
  ["state", path.join(MODULE_DIR, "state.mjs")],
  ["i18n", path.join(MODULE_DIR, "i18n.mjs")],
  ["connection", path.join(UI_ROOT, "connection-form.mjs")],
  ["app", path.join(UI_ROOT, "app.mjs")],
]);
const ASSETS = Object.freeze([
  ["brand", "/assets/hellolynk-mark.png", path.join(UI_ROOT, "hellolynk-mark.png"), "image/png"],
  ["arrowLeft", "/assets/icons/arrow-left.svg", path.join(UI_ROOT, "icons", "arrow-left.svg"), "image/svg+xml"],
  ["close", "/assets/icons/close.svg", path.join(UI_ROOT, "icons", "close.svg"), "image/svg+xml"],
  ["contacts", "/assets/icons/contacts.svg", path.join(UI_ROOT, "icons", "contacts.svg"), "image/svg+xml"],
  ["inbox", "/assets/icons/inbox.svg", path.join(UI_ROOT, "icons", "inbox.svg"), "image/svg+xml"],
  ["refresh", "/assets/icons/refresh.svg", path.join(UI_ROOT, "icons", "refresh.svg"), "image/svg+xml"],
  ["search", "/assets/icons/search.svg", path.join(UI_ROOT, "icons", "search.svg"), "image/svg+xml"],
  ["security", "/assets/icons/security.svg", path.join(UI_ROOT, "icons", "security.svg"), "image/svg+xml"],
  ["settings", "/assets/icons/settings.svg", path.join(UI_ROOT, "icons", "settings.svg"), "image/svg+xml"],
]);

// MCP Apps receive one self-contained HTML resource. This composer wraps the
// exact shared modules instead of maintaining a second Workbench implementation.
export async function composeWorkbenchMcpAppHtml(options = {}) {
  const title = options.title ?? "HelloLynk · Codex";
  if (!["HelloLynk · Codex", "HelloLynk · Claude"].includes(title)) throw new Error("workbench_mcp_title_invalid");
  const [html, css, entry, moduleSources, assetSources] = await Promise.all([
    readFile(path.join(UI_ROOT, "index.html"), "utf8"),
    readFile(path.join(UI_ROOT, "styles.css"), "utf8"),
    readFile(path.join(UI_ROOT, "mcp-app-entry.mjs"), "utf8"),
    Promise.all(MODULES.map(([, file]) => readFile(file, "utf8"))),
    Promise.all(ASSETS.map(([, , file]) => readFile(file))),
  ]);
  const expectedEntry = '<script type="module" src="/assets/loopback-entry.mjs"></script>';
  const expectedStyle = '<link rel="stylesheet" href="/assets/styles.css">';
  if (!html.includes(expectedEntry) || !html.includes(expectedStyle)) throw new Error("workbench_mcp_template_invalid");

  const wrapped = [];
  const exportedByModule = {};
  for (let index = 0; index < MODULES.length; index += 1) {
    const [label] = MODULES[index];
    const source = moduleSources[index].replace(/\r\n?/g, "\n");
    const exports = exportedNames(source);
    exportedByModule[label] = exports;
    const body = stripModuleSyntax(source);
    wrapped.push(`const __hellolynk_${label} = (() => {\n${body}\nreturn Object.freeze({ ${exports.join(", ")} });\n})();`);
    wrapped.push(`const { ${exports.join(", ")} } = __hellolynk_${label};`);
  }
  const entryBody = stripModuleSyntax(entry.replace(/\r\n?/g, "\n"));
  const script = `${wrapped.join("\n")}\n${entryBody}`.replaceAll("</script", "<\\/script");
  let output = html
    .replace(expectedStyle, `<style>${css}</style>`)
    .replace(expectedEntry, `<script>${script}</script>`)
    .replace("<title>HelloLynk</title>", `<title>${title}</title>`);
  for (let index = 0; index < ASSETS.length; index += 1) {
    const [, sourceUrl, , mime] = ASSETS[index];
    output = output.replaceAll(sourceUrl, `data:${mime};base64,${assetSources[index].toString("base64")}`);
  }

  const manifest = Object.freeze({
    contract: "hellolynk-workbench-mcp-app-bundle-v1",
    sourceContract: "hellolynk-workbench-snapshot-v12",
    sourceHashes: Object.freeze({
      html: sha256(html),
      css: sha256(css),
      entry: sha256(entry),
      ...Object.fromEntries(MODULES.map(([label], index) => [label, sha256(moduleSources[index])])),
      ...Object.fromEntries(ASSETS.map(([label], index) => [label, sha256(assetSources[index])])),
    }),
    outputSha256: sha256(output),
  });
  if (options.withManifest === true) return Object.freeze({ html: output, manifest });
  return output;
}

function exportedNames(source) {
  const names = [...source.matchAll(/^export\s+(?:const|class|function)\s+([A-Za-z_$][\w$]*)/gm)].map((match) => match[1]);
  if (!names.length || names.length !== new Set(names).size) throw new Error("workbench_mcp_exports_invalid");
  return names;
}

function stripModuleSyntax(source) {
  return source
    .replace(/^import\s+[\s\S]*?\s+from\s+["'][^"']+["'];\s*$/gm, "")
    .replace(/^export\s+(?=(?:const|class|function)\s+)/gm, "");
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}
