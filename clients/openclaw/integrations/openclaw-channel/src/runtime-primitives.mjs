import { createHash } from "node:crypto";

export class HelloLynkContractError extends Error {
  constructor(message) {
    super(message);
    this.name = "HelloLynkContractError";
  }
}

export function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}
