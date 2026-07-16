import path from "node:path";
import { fileURLToPath } from "node:url";

import { createPiRuntimeBinding } from "./bootstrap.mjs";

function main() {
	if (
		process.platform !== "linux"
		|| process.execArgv.length !== 0
		|| process.argv.length !== 3
		|| process.env.NODE_OPTIONS
		|| process.env.NODE_PATH
		|| process.env.LD_AUDIT
		|| process.env.LD_LIBRARY_PATH
		|| process.env.LD_PRELOAD
	) {
		throw new Error("Pi runtime binding installer invocation is invalid");
	}
	const scriptPath = fileURLToPath(import.meta.url);
	const releaseRoot = path.dirname(path.dirname(scriptPath));
	if (
		scriptPath
		!== path.join(releaseRoot, "pi_bridge", "create-runtime-binding.mjs")
	) {
		throw new Error("Pi runtime binding installer path is invalid");
	}
	const runtimeRoot = path.resolve(process.argv[2]);
	const result = createPiRuntimeBinding({ releaseRoot, runtimeRoot });
	process.stdout.write(`${JSON.stringify({ ok: true, ...result })}\n`);
}

try {
	main();
} catch {
	process.stderr.write("Pi runtime binding creation failed\n");
	process.exitCode = 1;
}
