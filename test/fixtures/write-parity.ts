// Policy data only. Each write is paired with the same operation on a protected
// destination. No payload is executed, including deletion/truncation controls.
const quote = (source: string): string => `'${source.replaceAll("'", String.raw`'\''`)}'`;
const python = (source: string): string => `python3 -c ${quote(source)}`;
const node = (source: string): string => `node -e ${quote(source)}`;

const writes = [
  {
    name: 'Python empty write',
    command: (p: string) => python(`from pathlib import Path; Path("${p}").write_text("")`),
  },
  {
    name: 'Python JSON serialization',
    command: (p: string) =>
      python(
        `from pathlib import Path; import json; Path("${p}").write_text(json.dumps({"ok":1}, indent=2), encoding="utf-8")`,
      ),
  },
  {
    name: 'Python file writer',
    command: (p: string) =>
      python(`with open("${p}", "w", encoding="utf-8") as f:\n f.write("output")`),
  },
  {
    name: 'Python JSON file output',
    command: (p: string) =>
      python(`import json\nwith open("${p}", "w") as f:\n json.dump({"ok":1}, f, indent=2)`),
  },
  {
    name: 'Python append',
    command: (p: string) => python(`f=open("${p}", "a"); f.write("line"); f.close()`),
  },
  {
    name: 'Python exclusive create',
    command: (p: string) => python(`open("${p}", "x").write("new")`),
  },
  {
    name: 'Python strip and copy',
    command: (p: string) =>
      python(
        `from pathlib import Path; Path("${p}").write_text(Path("input.txt").read_text().strip())`,
      ),
  },
  {
    name: 'Python empty slice',
    command: (p: string) =>
      python(
        `from pathlib import Path; Path("${p}").write_text(Path("input.txt").read_text()[0:0])`,
      ),
  },
  {
    name: 'Python replacement removes text',
    command: (p: string) =>
      python(
        `from pathlib import Path; Path("${p}").write_text(Path("input.txt").read_text().replace("old", "", 1))`,
      ),
  },
  {
    name: 'Python computed replacement text',
    command: (p: string) =>
      python(
        `from pathlib import Path; s=Path("input.txt").read_text(); Path("${p}").write_text(s.replace(s, ""))`,
      ),
  },
  {
    name: 'Python regex empty replacement',
    command: (p: string) =>
      python(
        `from pathlib import Path; import re; Path("${p}").write_text(re.sub(".*", "", Path("input.txt").read_text()))`,
      ),
  },
  {
    name: 'Python regex backreference',
    command: (p: string) =>
      python(
        String.raw`from pathlib import Path; import re; Path("${p}").write_text(re.sub("()", r"\1", Path("input.txt").read_text()))`,
      ),
  },
  {
    name: 'Node empty write',
    command: (p: string) => node(`require("fs").writeFileSync("${p}", "")`),
  },
  {
    name: 'Node generated JSON',
    command: (p: string) =>
      node(
        `require("fs").writeFileSync("${p}", JSON.stringify({ok:1}), {encoding:"utf8",flag:"w"})`,
      ),
  },
  {
    name: 'Node promise writer',
    command: (p: string) =>
      node(
        `const fs=require("node:fs/promises"); await fs.writeFile("${p}", JSON.stringify({ok:1}), "utf8")`,
      ),
  },
  {
    name: 'Node append',
    command: (p: string) =>
      node(`require("fs").appendFileSync("${p}", "", {encoding:"utf8",flag:"a"})`),
  },
  {
    name: 'Node hex encoding',
    command: (p: string) => node(`require("fs").writeFileSync("${p}", "x", "hex")`),
  },
  {
    name: 'Node base64 encoding',
    command: (p: string) => node(`require("fs").writeFileSync("${p}", "x", {encoding:"base64"})`),
  },
  {
    name: 'Node decoded input',
    command: (p: string) =>
      node(
        `const fs=require("fs"); fs.writeFileSync("${p}", fs.readFileSync("input.txt", "utf16le").replace("old", "new"))`,
      ),
  },
  {
    name: 'Node replacement tokens',
    command: (p: string) =>
      node(
        `const fs=require("fs"); fs.writeFileSync("${p}", fs.readFileSync("input.txt", "utf8").replace("old", "$&"))`,
      ),
  },
  {
    name: 'Deno generated JSON',
    command: (p: string) =>
      `deno eval ${quote(`Deno.writeTextFileSync("${p}", JSON.stringify({ok:1}), {append:false,create:true})`)}`,
  },
];

const writeParityFixtures = [
  ...writes.flatMap(({ name, command }) => [
    { name: `${name}: ordinary destination`, command: command('output.json'), allowed: true },
    { name: `${name}: protected destination`, command: command('.env'), allowed: false },
  ]),
  ...[
    python('import os; os.unlink("output.json")'),
    python('import os; os.truncate("output.json", 0)'),
    node('require("fs").rmSync("output.json")'),
    node('require("fs").truncateSync("output.json", 0)'),
    python(
      'import json; from pathlib import Path; p=json.load(open("input.json"))["path"]; Path(p).write_text("output")',
    ),
    node(
      'const fs=require("fs"); const p=JSON.parse(fs.readFileSync("input.json","utf8")).path; fs.writeFileSync(p,"output")',
    ),
    python('open("output.json", "w", opener=print)'),
    python('open("output.json", "w", encoding="custom-codec")'),
    python(
      'from pathlib import Path; Path("output.json").write_text("x", encoding="custom-codec")',
    ),
    python('import json; json.dumps({}, default=eval)'),
    node('require("fs").writeFileSync("output.json", "x", {get encoding(){return "utf8"}})'),
    node('require("fs").writeFileSync("output.json", "x", {encoding:"custom-codec"})'),
  ].map((command, index) => ({
    name: `Write boundary negative ${index}`,
    command,
    allowed: false,
  })),
];

export { writeParityFixtures };
