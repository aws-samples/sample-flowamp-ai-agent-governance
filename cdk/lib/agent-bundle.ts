import * as fs from "fs";
import * as path from "path";
import { execFileSync } from "child_process";
import * as crypto from "crypto";

/**
 * Assemble a self-contained AgentCore direct-code-deploy bundle at synth time.
 *
 * AgentCore's direct-code (zip) deployment uses a Lambda-style shared
 * responsibility model: AWS provides the Python language runtime, and YOU must
 * package your dependencies into the zip. `AgentRuntimeArtifact.fromCodeAsset`
 * only uploads the directory as-is — it does NOT run pip — so a bundle with a
 * bare `requirements.txt` crashes at runtime with ModuleNotFoundError.
 *
 * This helper produces a runtime-ready bundle by:
 *   1. copying the agent's own source (main.py, tools.py, requirements.txt),
 *   2. copying any requested shared packages (flowamp_tools,
 *      flowamp_compliance_checks) to the bundle root, and
 *   3. vendoring the pip dependencies for the runtime's platform
 *      (linux/arm64, cp312) INTO the bundle via `uv pip install --target`,
 *      exactly per the AWS direct-code-deploy Python guide:
 *      https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-get-started-code-deploy-python.html
 *
 * No Docker is required (uv resolves arm64 wheels cross-platform). The staged
 * path is returned for use as the fromCodeAsset `path`.
 */
export function assembleAgentBundle(opts: {
  /** Absolute path to the agent's own source directory (contains main.py). */
  agentDir: string;
  /** Absolute path to the `_shared` directory holding the Python packages. */
  sharedDir: string;
  /** Package directory names under `sharedDir` to vendor into the bundle. */
  sharedPackages: string[];
  /** Absolute path to the staging root (e.g. cdk.out/agent-bundles). */
  stagingRoot: string;
  /** Stable name for this bundle (used as the staging subdirectory). */
  bundleName: string;
}): string {
  const { agentDir, sharedDir, sharedPackages, stagingRoot, bundleName } = opts;

  const requirementsPath = path.join(agentDir, "requirements.txt");
  const dest = path.join(stagingRoot, bundleName);

  // Cache guard: re-vendoring pip deps is the slow part (~10-30s/bundle). Skip it
  // when the inputs (requirements + shared package set) are unchanged since the
  // last synth. A hash marker file records what the current bundle was built from.
  const inputHash = hashInputs(requirementsPath, sharedDir, sharedPackages);
  const marker = path.join(dest, ".bundle-hash");
  if (fs.existsSync(marker) && fs.readFileSync(marker, "utf-8") === inputHash) {
    // Still refresh the (fast) source copy so code edits are always picked up,
    // but keep the already-vendored site-packages.
    copySources(agentDir, sharedDir, sharedPackages, dest);
    return dest;
  }

  // Rebuild from scratch.
  fs.rmSync(dest, { recursive: true, force: true });
  fs.mkdirSync(dest, { recursive: true });

  copySources(agentDir, sharedDir, sharedPackages, dest);

  // Vendor arm64/cp312 dependencies into the bundle root (only if the agent
  // declares any). --only-binary=:all: keeps it to prebuilt wheels (no local
  // compilation / no Docker); --python-platform targets the AgentCore runtime.
  if (fs.existsSync(requirementsPath) && fs.readFileSync(requirementsPath, "utf-8").trim()) {
    execFileSync(
      "uv",
      [
        "pip", "install",
        "--python-platform", "aarch64-manylinux2014",
        "--python-version", "3.12",
        "--target", dest,
        "--only-binary=:all:",
        "-r", requirementsPath,
      ],
      { stdio: "inherit" }
    );
  }

  fs.writeFileSync(marker, inputHash);
  return dest;
}

/** Copy the agent source + shared packages into the bundle (fast; no pip). */
function copySources(agentDir: string, sharedDir: string, sharedPackages: string[], dest: string): void {
  copyDir(agentDir, dest);
  for (const pkg of sharedPackages) {
    const src = path.join(sharedDir, pkg);
    if (!fs.existsSync(src)) {
      throw new Error(`assembleAgentBundle: shared package not found: ${src}`);
    }
    copyDir(src, path.join(dest, pkg));
  }
}

/** Hash the requirements file + shared-package contents to detect changes. */
function hashInputs(requirementsPath: string, sharedDir: string, sharedPackages: string[]): string {
  const h = crypto.createHash("sha256");
  h.update(fs.existsSync(requirementsPath) ? fs.readFileSync(requirementsPath) : Buffer.from(""));
  for (const pkg of sharedPackages) {
    h.update(pkg);
    hashDir(path.join(sharedDir, pkg), h);
  }
  return h.digest("hex");
}

function hashDir(dir: string, h: crypto.Hash): void {
  if (!fs.existsSync(dir)) return;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    if (entry.name === "__pycache__" || entry.name.endsWith(".pyc")) continue;
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) hashDir(p, h);
    else h.update(fs.readFileSync(p));
  }
}

/** Recursively copy a directory, skipping Python build artifacts. */
function copyDir(src: string, dest: string): void {
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    // Skip caches / compiled artifacts / test dirs / the marker so the bundle
    // stays lean. Dockerfiles are unused in direct-code deploy — skip them too.
    if (
      entry.name === "__pycache__" || entry.name.endsWith(".pyc") ||
      entry.name === "tests" || entry.name === "Dockerfile" || entry.name === ".bundle-hash"
    ) {
      continue;
    }
    const s = path.join(src, entry.name);
    const d = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyDir(s, d);
    } else {
      fs.copyFileSync(s, d);
    }
  }
}
