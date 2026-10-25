import { BUILD, CORE, RUNNER, SCRIPTS } from "../data/generated.mjs";

export { BUILD, CORE, RUNNER, SCRIPTS };

export function findScript(id) {
  if (typeof id !== "string") return null;
  return SCRIPTS.find((script) => script.id === id) || null;
}

/** Metadata safe to expose publicly (never the payload). */
export function publicScripts() {
  return SCRIPTS.map((script) => ({
    id: script.id,
    name: script.name,
    description: script.description,
    author: script.author,
    version: script.version,
    tags: script.tags,
    size: script.size,
  }));
}
