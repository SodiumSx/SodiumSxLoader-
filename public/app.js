const scriptsEl = document.getElementById("scripts");
const emptyEl = document.getElementById("empty");
const toastEl = document.getElementById("toast");
const buildEl = document.getElementById("build");
const footerBuildEl = document.getElementById("footer-build");

let toastTimer;

function toast(message) {
  toastEl.textContent = message;
  toastEl.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toastEl.classList.remove("show"), 1800);
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Đã copy raw link");
  } catch {
    const input = document.createElement("textarea");
    input.value = text;
    document.body.append(input);
    input.select();
    document.execCommand("copy");
    input.remove();
    toast("Đã copy raw link");
  }
}

function card(script) {
  const el = document.createElement("article");
  el.className = "card";

  const head = document.createElement("div");
  head.className = "card-head";

  const title = document.createElement("h4");
  title.textContent = script.name;

  const version = document.createElement("span");
  version.className = "version";
  version.textContent = "v" + script.version;

  head.append(title, version);

  const description = document.createElement("p");
  description.textContent = script.description;

  const tags = document.createElement("div");
  tags.className = "tags";
  for (const tag of script.tags || []) {
    const chip = document.createElement("span");
    chip.className = "tag";
    chip.textContent = tag;
    tags.append(chip);
  }

  const url = document.createElement("div");
  url.className = "raw-url mono";
  url.textContent = script.raw;
  url.title = script.raw;

  const actions = document.createElement("div");
  actions.className = "actions";

  const copyButton = document.createElement("button");
  copyButton.className = "primary";
  copyButton.type = "button";
  copyButton.textContent = "Copy raw link";
  copyButton.addEventListener("click", () => copy(script.raw));

  const openButton = document.createElement("button");
  openButton.type = "button";
  openButton.textContent = "Xem raw";
  openButton.addEventListener("click", () => window.open(script.raw, "_blank", "noopener"));

  actions.append(copyButton, openButton);
  el.append(head, description, tags, url, actions);
  return el;
}

async function main() {
  try {
    const response = await fetch("/api/hub", { headers: { accept: "application/json" } });
    if (!response.ok) throw new Error("hub " + response.status);
    const data = await response.json();

    if (data.build) {
      buildEl.textContent = "build " + data.build.version;
      footerBuildEl.textContent = data.build.version;
    }

    if (!data.scripts || data.scripts.length === 0) {
      emptyEl.hidden = false;
      return;
    }

    const fragment = document.createDocumentFragment();
    for (const script of data.scripts) fragment.append(card(script));
    scriptsEl.append(fragment);

    const usage = document.getElementById("usage");
    usage.textContent = `loadstring(game:HttpGet("${data.scripts[0].raw}"))()`;
    document.getElementById("copy-usage").addEventListener("click", () => copy(usage.textContent));
  } catch (error) {
    emptyEl.hidden = false;
    emptyEl.textContent = "Không tải được danh sách script: " + error.message;
  }
}

main();
