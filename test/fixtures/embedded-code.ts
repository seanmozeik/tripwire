// Inert policy inputs. Never pass these strings to a shell or language runtime.
interface CodeFixture {
  readonly name: string;
  readonly command: string;
  readonly allowed: boolean;
}
const quote = (source: string): string => `'${source.replaceAll("'", String.raw`'\''`)}'`;
const protectedPath = '/tripwire-policy-fixture/protected';

const pythonDestructive = [
  `import shutil; shutil.rmtree("${protectedPath}")`,
  `import os; os.unlink("${protectedPath}")`,
  `from pathlib import Path; Path("${protectedPath}").unlink()`,
  `from os import remove as discard; discard("${protectedPath}")`,
  `import shutil as s; target = "${protectedPath}"; s.rmtree(target)`,
  `import shutil; f = shutil.rmtree; f("${protectedPath}")`,
  `import os; os.remove("/tripwire-policy-fixture/" + "protected")`,
  `import os; os.truncate("${protectedPath}", 0)`,
  'open(".env", "w")',
  'open(".env", "w").write("secret")',
  'from pathlib import Path; Path(".env").write_text("secret")',
  `import os; os.rename("/tmp/source", "${protectedPath}")`,
  `import subprocess; subprocess.run(["rm", "-rf", "${protectedPath}"])`,
  'import subprocess; subprocess.run(["git", "reset", "--hard"])',
  `import subprocess; subprocess.run("rm -rf ${protectedPath}", shell=True)`,
  `import os; getattr(os, "un" + "link")("${protectedPath}")`,
  `__import__("os").remove("${protectedPath}")`,
  `exec("import os; os.remove('${protectedPath}')")`,
  'import ctypes; ctypes.CDLL(None).unlink(b"/protected")',
  `import os\nif True:\n os.unlink("${protectedPath}")`,
  `import os\nfor p in ["${protectedPath}"]:\n os.unlink(p)`,
  `import os\ndef cleanup():\n os.unlink("${protectedPath}")\ncleanup()`,
  `import os; [os.remove(p) for p in ["${protectedPath}"]]`,
  'import os; os.unlink("/tmp/../protected")',
  String.raw`import os; os.unlink("/tmp/\x2e\x2e/protected")`,
  'import os; os.unlink(input())',
  'import os; os.unlink(',
];

const javascriptDestructive = [
  `require("fs").rmSync("${protectedPath}", {recursive:true, force:true})`,
  `const fs = require("node:fs"); fs.unlinkSync("${protectedPath}")`,
  `const fs = require("fs"); const del = fs.rmSync; del("${protectedPath}")`,
  `const {unlinkSync: del} = require("fs"); del("${protectedPath}")`,
  `import {rm as discard} from "node:fs/promises"; await discard("${protectedPath}")`,
  `require("fs")["un" + "linkSync"]("${protectedPath}")`,
  `require("fs").truncateSync("${protectedPath}", 0)`,
  'require("fs").writeFileSync(".env", "secret")',
  'require("fs").writeFileSync(".env", "")',
  `require("fs").renameSync("/tmp/source", "${protectedPath}")`,
  `require("child_process").execFileSync("rm", ["-rf", "${protectedPath}"])`,
  'require("child_process").spawnSync("git", ["reset", "--hard"])',
  `require("child_process").execSync("rm -rf ${protectedPath}")`,
  `eval("require('fs').unlinkSync('${protectedPath}')")`,
  `Function("require('fs').unlinkSync('${protectedPath}')")()`,
  `if (true) require("fs").unlinkSync("${protectedPath}")`,
  `function cleanup() { require("fs").unlinkSync("${protectedPath}"); } cleanup()`,
  `setTimeout(() => require("fs").unlinkSync("${protectedPath}"), 0)`,
  `const options = {get force() { require("fs").unlinkSync("${protectedPath}"); return true; }};`,
  `const p: string = "${protectedPath}"; require("fs").rmSync(p)`,
  `await Deno.remove("${protectedPath}", {recursive:true})`,
  'require("fs").unlinkSync("/tmp/../protected")',
  'require("fs").unlinkSync(process.env.TARGET)',
  'await import("./uninspected.js")',
  'require("fs").unlinkSync(',
];

const codeFixtures: readonly CodeFixture[] = [
  ...pythonDestructive.flatMap((source, index) => [
    { name: `Python inline ${index}`, command: `python3 -c ${quote(source)}`, allowed: false },
    { name: `Python heredoc ${index}`, command: `python3 - <<'PY'\n${source}\nPY`, allowed: false },
  ]),
  ...javascriptDestructive.flatMap((source, index) => [
    { name: `Node inline ${index}`, command: `node -e ${quote(source)}`, allowed: false },
    { name: `Bun heredoc ${index}`, command: `bun - <<'JS'\n${source}\nJS`, allowed: false },
  ]),
  ...[
    'python3 cleanup.py',
    'python3 -m cleanup',
    'node cleanup.js',
    'bun run cleanup.ts',
    'deno run cleanup.ts',
    'tsx cleanup.ts',
    'ts-node cleanup.ts',
    'python3 -',
    'node',
    'node -r ./cleanup.js -e "1"',
    'node --import ./cleanup.js -e "1"',
    'python3 -ic "print(1)"',
    'printf code | python3',
    'python3 < cleanup.py',
    'python3 -c "$CODE"',
    'python3 - <<PY\n$CODE\nPY',
    'env python3 -c "import os; os.remove(\'/protected\')"',
    'sh -c \'node -e "require(\\\"fs\\\").unlinkSync(\\\"/protected\\\")"\'',
    "node -e \"require('fs').rmSync('/protected')\" # tripwire-allow: fixture",
  ].map((command, index) => ({ name: `Opaque carrier ${index}`, command, allowed: false })),
  ...[
    'python3 -c "print(1 + 1)"',
    'node -e "console.log(1 + 1)"',
    'deno eval "console.log(2)"',
    'python3 --version',
    'node --help',
    'bun --version',
    'python3 - <<\'PY\'\nprint("os.remove is text")\nPY',
    'node - <<\'JS\'\nconsole.log("rm -rf /")\nJS',
    'cat <<\'PY\'\nimport os; os.unlink("/protected")\nPY',
    'printf \'%s\' \'require("fs").unlinkSync("/protected")\'',
    'python3 -c \'import os; os.unlink("dist/fixture")\'',
    'node -e \'require("fs").rmSync("dist/fixture")\'',
    'python3 -c \'from pathlib import Path; Path("README.md").write_text("updated")\'',
    'node -e \'require("fs").writeFileSync("README.md", "updated")\'',
    'python3 -c \'import subprocess; subprocess.run(["git", "status"])\'',
    'node -e \'require("child_process").execFileSync("git", ["status"])\'',
  ].map((command, index) => ({ name: `Safe control ${index}`, command, allowed: true })),
];

export { codeFixtures };
