const BINDING_REFERENCE = Object.freeze({
  type: "string",
  const: "protected-store:openclaw",
});

const NEUTRAL_PROPERTIES = Object.freeze({
  enabled: { type: "boolean" },
  hostMode: { type: "string", const: "neutral" },
  bindingRef: BINDING_REFERENCE,
  nativeModel: {
    type: "object",
    description: "Requests a model and thinking level for HelloLynk turns. OpenClaw may select another model; nativeModelSelection.hostObservation is session-level and is not correlated to this turn.",
    additionalProperties: false,
    required: ["provider", "model"],
    properties: {
      provider: { type: "string", pattern: "^[a-z0-9][a-z0-9._-]{0,79}$" },
      model: { type: "string", minLength: 1, maxLength: 240, pattern: "^[^\\s\\x00-\\x1f\\x7f]+$" },
      thinkingLevel: { type: "string", pattern: "^[a-z][a-z0-9_-]{0,31}$" },
    },
  },
});

export const HELLOLYNK_CHANNEL_CONFIG_SCHEMA = Object.freeze({
  $schema: "http://json-schema.org/draft-07/schema#",
  type: "object",
  additionalProperties: false,
  required: ["enabled", "hostMode", "bindingRef"],
  properties: NEUTRAL_PROPERTIES,
});

export const HELLOLYNK_CHANNEL_CONFIG_SCHEMA_DESCRIPTOR = Object.freeze({
  schema: HELLOLYNK_CHANNEL_CONFIG_SCHEMA,
});
