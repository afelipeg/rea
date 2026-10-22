import { createRequire } from "node:module";
import { isIP } from "node:net";
import { Ajv } from "ajv";
import { z } from "zod";
import { CaptureFormatError } from "./CaptureFormatError.js";
import { captureObject } from "./CaptureRedaction.js";

/** Validate using the unchanged, pinned upstream HAR 1.2 draft-06 schemas. */
export const createHarValidator = (): ((
  value: unknown,
) => HarValidationAdaptations) => {
  const require = createRequire(import.meta.url);
  const schemas = z
    .record(z.string(), z.record(z.string(), z.unknown()))
    .parse(require("har-schema"));
  const ajv = new Ajv({ strict: false, allErrors: false, ownProperties: true });
  ajv.addMetaSchema(require("ajv/dist/refs/json-schema-draft-06.json"));
  const plugin: unknown = require("ajv-formats");
  if (typeof plugin !== "function")
    throw new Error("Pinned AJV formats plugin is unavailable");
  plugin(ajv);
  for (const schema of Object.values(schemas)) ajv.addSchema(schema);
  const validate = ajv.getSchema("har.json#");
  if (validate === undefined)
    throw new Error("Pinned HAR root schema is unavailable");
  return (value) => {
    const adaptations = allowObservedProducerRepresentations(value);
    if (!validate(value)) {
      const error = validate.errors?.[0];
      // AJV messages name the violated constraint, such as the missing
      // property, without restating any captured value.
      throw new CaptureFormatError(
        "format",
        error === undefined
          ? "HAR schema validation failed: unknown constraint."
          : `HAR schema validation failed: ${error.keyword} (${error.message ?? "no detail"}).`,
        error?.instancePath ?? "",
      );
    }
    return adaptations;
  };
};

/** Per-entry limitations naming each validation-copy adaptation, keyed by entry ordinal. */
export type HarValidationAdaptations = ReadonlyMap<number, readonly string[]>;

const BRACKETED_IPV6 = {
  playwright:
    "This capture declares Playwright 1.58.2 and reports bracketed IPv6 serverIPAddress. Original spellings are retained; brackets were removed only from valid IPv6 values in the validation copy. Producer declarations are not authenticated.",
  webInspector:
    "This capture declares Chrome DevTools WebInspector 537.36 and reports bracketed IPv6 serverIPAddress. Original spellings are retained; brackets were removed only from valid IPv6 values in the validation copy. Producer declarations are not authenticated.",
} as const;
const WEB_INSPECTOR_EMPTY_ADDRESS =
  "This capture declares Chrome DevTools WebInspector 537.36 and reports an empty serverIPAddress, meaning the producer recorded no remote address. The empty string is retained; the optional field was omitted only from the validation copy. Producer declarations are not authenticated.";

/** Adapt only observed producer representations in the disposable validation copy. */
const allowObservedProducerRepresentations = (
  value: unknown,
): HarValidationAdaptations => {
  const adaptations = new Map<number, string[]>();
  if (!captureObject(value) || !captureObject(value.log)) return adaptations;
  const log = value.log;
  if (!captureObject(log.creator) || !Array.isArray(log.entries))
    return adaptations;
  const mitmproxy =
    log.creator.name === "mitmproxy" && log.creator.version === "12.2.3";
  const playwright =
    log.creator.name === "Playwright" && log.creator.version === "1.58.2";
  // Chrome freezes this WebKit version string, so it names the exporter, not a Chrome release.
  const webInspector =
    log.creator.name === "WebInspector" && log.creator.version === "537.36";
  if (!mitmproxy && !playwright && !webInspector) return adaptations;
  const adapt = (ordinal: number, limitation: string) =>
    adaptations.set(ordinal, [...(adaptations.get(ordinal) ?? []), limitation]);
  for (const [ordinal, entry] of log.entries.entries()) {
    const candidate: unknown = entry;
    if (!captureObject(candidate)) continue;
    const address = candidate.serverIPAddress;
    if (
      (playwright || webInspector) &&
      typeof address === "string" &&
      address.startsWith("[") &&
      address.endsWith("]") &&
      isIP(address.slice(1, -1)) === 6
    ) {
      candidate.serverIPAddress = address.slice(1, -1);
      adapt(
        ordinal,
        playwright ? BRACKETED_IPV6.playwright : BRACKETED_IPV6.webInspector,
      );
    }
    if (webInspector && address === "") {
      delete candidate.serverIPAddress;
      adapt(ordinal, WEB_INSPECTOR_EMPTY_ADDRESS);
    }
    if (!mitmproxy) continue;
    const request = candidate.request;
    if (!captureObject(request)) continue;
    const body = request.postData;
    if (captureObject(body) && body.text === null) delete body.text;
  }
  return adaptations;
};
