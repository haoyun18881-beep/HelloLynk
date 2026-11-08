import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";
import { normalizeWorkbenchLocale, SUPPORTED_WORKBENCH_LOCALES, translateWorkbench } from "../workbench/i18n.mjs";

const exec = promisify(execFile);
const commandOptions = { encoding: "utf8", windowsHide: true, timeout: 2000, maxBuffer: 8192 };
const localeTag = value => typeof value === "string" && /^[A-Za-z]{2,8}(?:[-_][A-Za-z0-9]{2,8})*(?:\.[A-Za-z0-9_-]+)?(?:@[A-Za-z0-9_-]+)?$/.test(value.trim())
  ? value.trim().split(/[.@]/, 1)[0] : null;

// Lazy and single-flight: no subprocess on idle receiver ticks, and at most
// one display-language lookup per process. No saved setting or polling loop.
export function createNativeNoticeLocaleReader({ platform = process.platform, env = process.env, run = exec } = {}) {
  let pending;
  async function read() {
    let languages;
    try {
      if (platform === "win32") {
        const executable = path.win32.join(env.SystemRoot || "C:\\Windows", "System32", "reg.exe");
        // Read display-language tags directly: a console's UI culture can be
        // filtered by its code page, and Intl reports the formatting region.
        const deadline = Date.now() + commandOptions.timeout;
        for (const [key, name] of [["HKCU\\Control Panel\\Desktop", "PreferredUILanguages"],
          ["HKCU\\Control Panel\\Desktop\\MuiCached", "MachinePreferredUILanguages"]]) {
          const timeout = deadline - Date.now();
          if (timeout <= 0) break;
          const result = await run(executable, ["query", key, "/v", name], { ...commandOptions, timeout }).catch(() => ({ stdout: "" }));
          languages = /REG_MULTI_SZ[ \t]+([^\r\n]*)/.exec(result.stdout)?.[1].split("\\0").map(localeTag);
          if (languages?.some(Boolean)) break;
        }
      } else if (platform === "darwin") {
        const result = await run("/usr/bin/defaults", ["read", "-g", "AppleLanguages"], commandOptions);
        // defaults prints an array of language tags, in preferred order.
        languages = result.stdout.trim().replace(/^\(\s*|\s*\)$/g, "").split(",")
          .map(value => localeTag(value.trim().replace(/^"|"$/g, "")));
      } else {
        const messages = env.LC_ALL || env.LC_MESSAGES || env.LANG;
        if (!messages || /^(?:C|POSIX)(?:\.|$)/i.test(messages)) return "en";
        languages = (env.LANGUAGE || messages || "").split(":").map(localeTag);
      }
    } catch { /* A locale lookup must never prevent receipt of a message. */ }
    if (languages?.some(Boolean)) return normalizeWorkbenchLocale(languages);
    return "en";
  }
  return () => pending ||= read();
}

export const readNativeNoticeLocale = createNativeNoticeLocaleReader();
export const nativeNoticeText = (locale, key, vars) => translateWorkbench(locale, `nativeNotice.${key}`, vars);
export const NATIVE_NOTICE_PREFIXES = Object.freeze(SUPPORTED_WORKBENCH_LOCALES.map(locale => nativeNoticeText(locale, "source")));
