// Starts the console. Trunk's own loader is an inline script, which the
// page's Content-Security-Policy refuses, so Trunk.toml has it write an
// element naming the bundle instead (`pattern_script`), and this loads it.
const { js, wasm } = document.getElementById("bundle").dataset;
const { default: init } = await import(js);
await init({ module_or_path: wasm });
