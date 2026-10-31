# extaudit

Static security review for Claude extensions: Desktop extensions (`.mcpb`, `.dxt`), Claude Code plugins, skills, hooks and MCP server configs.

It answers three questions:

1. **What can this extension do?** Run commands, read files, reach the network, touch credentials.
2. **What becomes dangerous in combination?** One extension can bring in text written by strangers while another can run commands. Each can look fine alone.
3. **What changed in this update?** New abilities, new hosts, rewritten tool descriptions.

It never runs, imports or installs what it scans. It uses only the Python standard library, so it adds no dependencies of its own.

> **A short report does not mean an extension is safe.** A scanner can show that a problem exists, not that none do. Against evasion written to beat it, this one still misses most attacks: see [How good is it?](#how-good-is-it) Every report lists what could not be checked, and nothing ever says "safe".

## Run it

You need Python 3.11 or newer. It is tested on 3.11 through 3.14 on Windows; Linux and macOS have not been tested. Run these from this folder; no install is required.

Review everything installed on this machine:

```bash
python -m extaudit installed
```

Connectors on your claude.ai account are not stored locally, so list the ones you use. They are often the source of a chain:

```bash
python -m extaudit installed --connector gmail --connector google-calendar
```

Review something before you install it:

```bash
python -m extaudit scan path/to/extension.mcpb
```

Check two or more extensions together for risky combinations:

```bash
python -m extaudit scan calendar.mcpb shell-tools.mcpb
```

See what an update changed:

```bash
python -m extaudit diff old-version.mcpb new-version.mcpb
```

Save a record of what is installed, then compare against it later:

```bash
python -m extaudit baseline save baseline.json
```

```bash
python -m extaudit baseline check baseline.json
```

Read the packages that `npx` and `uvx` servers fetch at launch (this one uses the network, see [Reading published packages](#reading-published-packages)):

```bash
python -m extaudit installed --online
```

Read a package before you add it to a config:

```bash
python -m extaudit package npm:@acme/server@1.2.3
```

`scan` accepts a `.mcpb`, `.dxt` or `.zip` file, a plugin or skill folder, a source folder, a marketplace folder, or a config such as `claude_desktop_config.json` or `.mcp.json`.

`pip install .` also gives you an `extaudit` command, so `python -m extaudit` becomes `extaudit`.

### Options

| Option | Meaning |
|---|---|
| `--format text\|json\|sarif` | Output format. SARIF works with GitHub code scanning. |
| `--output FILE` | Write the report to a file. |
| `--min-severity LEVEL` | Hide lower findings in text output. Defaults to `low`. |
| `--fail-on LEVEL\|none` | Exit 1 at this severity or above. Defaults to `high`. |
| `--ignore RULE` | Skip a rule. Repeatable. |
| `--chains` | Check combinations even for a single path. |
| `--project DIR` | With `installed` or `baseline`, include this project. Defaults to the current folder. |
| `--connector NAME` | With `installed`, add a claude.ai connector as a source of outside content. |
| `--online` | With `scan`, `installed` or `baseline`, read packages fetched at launch from npm and PyPI. |
| `--depth N` | With `--online` or `package`, also read npm dependencies this many levels down. Defaults to `0`. |
| `--max-packages N` | Stop after this many packages. Defaults to `40`. |

Exit codes: `0` nothing at or above the threshold, `1` findings, `2` could not run.

## Reading published packages

A server started with `npx` or `uvx` has no code on your machine until it launches, so an offline scan cannot see it. `--online` closes that gap by reading the package the way the launch command would find it.

**It stays off unless you ask.** Without `--online` or the `package` command, nothing touches the network.

- **What is sent:** package names and versions, to npm and PyPI. Config values, arguments and paths are never sent. A private package's name would reach the public registry, so leave `--online` off for those.
- **What happens to the code:** it is checked against the registry's hash, unpacked in memory, and analyzed like any other extension. Nothing is written to disk, installed or run.
- **Where it can connect:** only `registry.npmjs.org`, `pypi.org` and `files.pythonhosted.org`, over HTTPS. Redirects get the same check.

What it adds beyond the usual analysis:

| Signal | Rule |
|---|---|
| Registry record and the package's own `package.json` disagree | `supply.manifest-confusion` |
| A different account published this release | `supply.new-publisher` |
| Download does not match the registry's hash | `package.integrity-mismatch` |
| Release is under a week old, or the package under a month | `supply.fresh-release`, `supply.new-package` |
| Known vulnerability or withdrawn release on PyPI | `supply.known-vulnerability`, `supply.yanked` |
| Download points away from the registry's file host | `supply.unexpected-download-host` |

Package code also counts toward attack chains, so a hidden command runner behind an `npx` line now shows up as one.

**A pinned version is what you scanned. An unpinned one is not.** `npx -y pkg` fetches whatever is newest at each start, so the result only describes today's release, and the report says so. Pin the version you reviewed. Saving a baseline with `--online` also catches this: `baseline check --online` reports when a server has moved to a new release by itself.

Dependencies run too, and `--depth 0` does not read them; the report counts what was skipped. `--depth 1` or more follows npm dependencies, picking the version npm would. PyPI dependencies are listed but not followed, and packages installed from git or a custom registry are reported as unreadable.

A thin wrapper can hide everything behind that gap. `@playwright/mcp` is a good example: it scans clean at depth 0 only because it is a few small files, and the real work happens in its `playwright` dependencies.

**How far this has been tested live:** exact versions of one npm and one PyPI package, covering download, hash checks and the config path. Version ranges, `--depth`, source packages and platform-specific wheels have only been tested against the fake registry.

## Reading a report

In the capability table, each letter shows how the ability is reached. This matters more than the ability itself.

| Mark | Meaning | Strength |
|---|---|---|
| `T` | Traced from an MCP tool, so Claude can trigger it | Strongest |
| `D` | Stated in configuration or a known package | Strong |
| `H` | Runs on a Claude Code event, such as a hook | Strong |
| `C` | Present in the code, with no path traced from a tool | Medium |
| `?` | Guessed from names, such as a server called `gmail` | Weakest |

Findings are leads to check, not verdicts. Severity reflects how bad the problem would be and how sure the scan is. When an earlier check on a value is seen, the finding drops one level and says so, because the scan cannot tell whether that check is strict enough.

Attack chains are possible paths, not confirmed attacks. Each one depends on Claude following instructions hidden in outside content. Automatic approvals raise the severity, because no prompt would stop the path.

## What it checks

| Area | Rules start with | Examples |
|---|---|---|
| Input validation | `input.` | Tool arguments reaching a shell, `eval`, file paths, URLs, SQL or templates. |
| Hidden instructions | `instructions.` | Tool poisoning, lookalike letters, invisible Unicode (decoded in the report), hidden HTML, data slots in links, attempts to skip approvals. |
| Backdoor signals | `backdoor.` | Credentials traced to the network, downloaded code being run, encoded payloads, hard-coded unlock values, date triggers, hooks that approve actions, `bin/` files that replace `git`. |
| Behavior against claims | `backdoor.purpose-mismatch` | An `add` tool that can run commands, a "read-only" tool that writes, an "offline" extension that uses the network. |
| Operational security | `opsec.` | Stored secrets, broad `allowed-tools`, disabled TLS, servers listening on every interface, bypassed permission prompts. |
| Supply chain | `supply.` | Unpinned `npx` and `uvx` servers, install scripts, custom registries, lookalike package names. |
| Package tricks | `package.` | Zip entries that escape the folder, duplicate entries, symlinks, files blocked by antivirus. |
| Combinations | `chain.` | Outside content reaching commands, data theft paths, lasting changes, tool name collisions. |
| Updates | `update.` | New abilities and hosts, changed tool descriptions, changed hooks, and any change without a version bump. |

### How the analysis works

Most detection comes from following data rather than matching text, because a pattern only catches the spellings someone thought of.

- **Tool arguments** are traced through assignments, helpers across files, classes, fields, containers, branches and callbacks, to whatever dangerous call they reach. Python uses the real `ast` module; JavaScript and TypeScript use a tokenizer written for this tool.
- **Helpers are summarized**, so a function that escapes its input clears the finding and one that passes it along keeps it.
- **Calls are resolved** through aliases, `getattr`, `__import__`, `cp["ex" + "ec"]`, `.call`, `.apply`, `Reflect.apply` and dispatch tables.
- **Constant values are worked out without running anything.** A small evaluator reads concatenations, reversed strings, `chr`, `atob`, Base64, hex and zlib, so hidden commands appear in the report.
- **Credentials and downloads are traced too**, on all code: from credential files to the network, and from the network to code execution.
- **Shell scripts are modeled as pipelines.** Fetched or decoded data is followed through pipes, variables and files to an interpreter, in sh, batch and PowerShell.
- **Encoded blobs are unpacked**, layer by layer, and checked again.

## How good is it?

Honestly: strong on the mistakes extensions make by accident, weak against someone trying to beat it.

The benchmark in `benchmark/` holds labeled samples: attacks using evasion tricks, and harmless look-alikes that must stay quiet. A score only means something the first time, before anything is tuned against it, so each round was scored once on a set written after the last round of fixes.

| Blind set | Attacks caught | Look-alikes clean |
|---|---|---|
| First | 66 of 119 (55%) | 34 of 34 |
| Second | 32 of 79 (41%) | 29 of 29 |
| Third, left unfixed | 13 of 45 (29%) | 14 of 14 |

How to read this:

- **The falling scores are not a regression.** Each set was written to be harder than the last, aimed at what still worked. They cannot be compared, and they say more about how far an attacker has to go than about one fixed rate.
- **Attacks are scored strictly.** A case passes only if the exact expected finding fires. In the third set, 3 credential-theft misses were still flagged by a broader rule.
- **The look-alike result is the most solid number:** 77 of 77 stayed quiet. On 42 real plugins from the official marketplace the only high is a genuine one, and each high and medium was read by hand.
- **Prompt injection in plain language is the weakest area:** 0 of 7 in the third set. Judging what a sentence is trying to do needs language understanding, and more patterns caused real false alarms when tried.
- **All samples were written for this project.** None of this has been run against real malware, so none of these numbers is a detection rate for real attacks.

To see the numbers yourself:

```bash
python -m benchmark --set holdout3 --misses
```

`cases`, `holdout` and `holdout2` score 100% because they have since been tuned against. They guard against regressions and measure nothing else. Do not tune against `holdout3`; to measure again, write a new set.

## What it cannot do

These are limits of static review. No scanner removes them.

- **Hidden logic.** A backdoor can look like normal code, or stay dormant until a date or input.
- **Remote code.** Hosted MCP servers and container images are not available to read, and they can change after any scan. Packages from `npx` and `uvx` can be read with `--online`, but an unpinned one can still change at the next start.
- **Compiled code.** Binaries get a strings check for hosts and credential paths. Their behavior is not analyzed.
- **Vendored dependencies.** Only their install scripts are checked.
- **Claude.ai connectors.** They leave nothing local to find, which is why `--connector` exists.
- **Permission state in Claude Desktop.** Automatic approvals are read from Claude Code settings only.
- **Signatures.** Package signatures are not verified.
- **Secrets in a URL.** A key in a request's URL or headers is not reported, because that is how many APIs work. A key in the request body is.

The JavaScript analysis has no full parser and tracks variables by name without modelling scope, so unusual code can slip past it. Other languages get text patterns only.

## When a crafted file attacks the scanner

Extensions are untrusted input to this tool, so:

- Archives are read in memory and never unpacked to disk. Size and compression limits stop zip bombs, including inside decoded payloads.
- Symlinks and junctions are never followed.
- Reports strip terminal control characters and redact anything shaped like a credential.
- Snapshots store hashes and variable names, never secret values.
- `installed` reads settings and MCP entries only. It never opens credential files.
- A crash becomes a "could not check" entry, and work budgets stop crafted code from stalling the scan, so one bad file cannot hide the rest of the report.

If Windows blocks a file with `Invalid argument`, the report raises `package.read-blocked`, because that usually means antivirus flagged it.

## Tests

```bash
python -m unittest discover -s tests -t .
```

Test inputs are harmless strings built in temp folders or in memory. One sample stays in memory on purpose, because Windows Defender quarantines it as a trojan if it is written out, even though its URL goes nowhere.

The tests never reach the internet. Online reading is tested against a fake registry shaped like the real APIs, plus a server on `127.0.0.1` for the real HTTP path.

## License

MIT. See [LICENSE](LICENSE). This software comes with no warranty, and a clean report is not a guarantee of anything.
