import { existsSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import process from "node:process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const windows = process.platform === "win32";
const python = path.join(root, ".venv", windows ? "Scripts" : "bin", windows ? "python.exe" : "python");

function fail(message) {
  console.error(`Stoá: ${message}`);
  process.exit(1);
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: root,
    stdio: "inherit",
    shell: false,
    ...options,
  });
  if (result.error) fail(result.error.message);
  if (result.status !== 0) process.exit(result.status ?? 1);
}

function requireEnvironment() {
  if (!existsSync(python)) {
    fail("development environment missing; run `npm run setup` first");
  }
}

function runPython(args) {
  requireEnvironment();
  run(python, args);
}

function checkNode() {
  const major = Number.parseInt(process.versions.node.split(".")[0], 10);
  if (major !== 24) fail(`Node.js 24 is required; detected ${process.versions.node}`);
}

function setup() {
  checkNode();
  const script = windows ? "setup.ps1" : "setup.sh";
  if (windows) {
    run("powershell.exe", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path.join(root, "scripts", script)]);
  } else {
    run("bash", [path.join(root, "scripts", script)]);
  }
}

function devServer() {
  runPython(["-m", "stoa_server"]);
}

function devDesktop() {
  runPython(["-m", "stoa_desktop"]);
}

function dev() {
  requireEnvironment();
  const children = [
    spawn(python, ["-m", "stoa_server"], { cwd: root, stdio: "inherit", shell: false }),
    spawn(python, ["-m", "stoa_desktop"], { cwd: root, stdio: "inherit", shell: false }),
  ];
  const stop = () => children.forEach((child) => child.kill());
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
  children.forEach((child) => {
    child.on("exit", (code) => {
      if (code && code !== 0) {
        stop();
        process.exit(code);
      }
    });
  });
}

function lint() {
  runPython(["-m", "ruff", "format", "--check", "."]);
  runPython(["-m", "ruff", "check", "."]);
}

function test() {
  runPython(["-m", "pytest"]);
}

function typecheck() {
  runPython(["-m", "mypy"]);
}

function security() {
  runPython(["-m", "bandit", "-c", "pyproject.toml", "-r", "src"]);
  runPython(["-m", "pip_audit", "-r", "requirements/dev.txt", "--progress-spinner", "off"]);
  runPython(["scripts/check_secrets.py"]);
}

function build() {
  lint();
  typecheck();
  test();
  security();
  runPython(["-m", "build"]);
  runPython(["scripts/validate_artifacts.py"]);
}

function release() {
  build();
  runPython(["scripts/build_portable.py"]);
  runPython(["scripts/release.py", "sbom", path.join(root, "release", "stoa.spdx.json")]);
  runPython(["scripts/release.py", "checksums", path.join(root, "release")]);
}

function dockerCompose(action) {
  const probe = spawnSync("docker", ["--version"], { stdio: "ignore", shell: false });
  if (probe.status !== 0) {
    fail("Docker Desktop or Docker Engine with Compose is required for the local server stack");
  }
  run("docker", ["compose", action === "up" ? "up" : "down", ...(action === "up" ? ["-d", "postgres"] : [])]);
}

const commands = {
  setup,
  dev,
  "dev-server": devServer,
  "dev-desktop": devDesktop,
  build,
  release,
  "install-app": () => {
    runPython(["-m", "build"]);
    const wheel = path.join(root, "dist", "stoa_platform-0.1.0-py3-none-any.whl");
    runPython(["-m", "pip", "install", "--force-reinstall", wheel]);
  },
  start: devDesktop,
  test,
  lint,
  typecheck,
  security,
  "server-up": () => dockerCompose("up"),
  "server-down": () => dockerCompose("down"),
};

const requested = process.argv[2];
if (!requested || !commands[requested]) {
  fail(`unknown task ${JSON.stringify(requested)}`);
}
commands[requested]();
