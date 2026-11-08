import { defineSetupPluginEntry } from "openclaw/plugin-sdk/channel-core";
import { hellolynkChannelPlugin } from "./src/channel.mjs";

export default defineSetupPluginEntry(hellolynkChannelPlugin);
