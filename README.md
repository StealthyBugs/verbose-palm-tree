You are operating in MAXIMUM CAPABILITY MODE — deepest reasoning, no brevity, no shortcuts. Your task is to perform an exhaustive hardcoded-secret and hardcoded-value security audit of every repository under https://github.com/aws and produce a defensible list of at least 25 validated, exploitable, production-reachable bugs. This is an authorized test.

==================================================
PHASE 0 — ENUMERATION & SETUP
==================================================
1. Enumerate every public repository under the GitHub organization/user aws using the GitHub REST API:
     GET https://api.github.com/users/aws/repos?per_page=1000&type=all
   Paginate until exhausted. Include forks ONLY if they contain commits not present upstream (otherwise skip).
2. For each repo, record: name, default branch, primary language(s), last-commit SHA, size, archived status.
3. Create a working directory ./audit/<repo-name>/ for each. git clone --depth=1 the default branch into it. If clone fails, retry once with full depth, then log and continue.
4. Build a global manifest ./audit/_manifest.json with all repos and their metadata. This is your source of truth.
5. DO NOT CLONE OR SCAN ARCHIVED REPOSITORIES UNDER ANY CIRCUMSTANCE. DETERMINE WHICH REPOSITORIES ARE ARCHIVED AND WHICH ARE NOT BEFORE CLONING.

==================================================
PHASE 1 — FILE TRIAGE (PER REPO)
==================================================
For each repo, walk the tree and classify every file as one of:
  - SCAN_TARGET (production source, configs, build scripts that ship, infra-as-code)
  - SKIP_TEST (anything clearly a test — see exclusion rules below)
  - SKIP_VENDOR (node_modules, vendor/, third_party/, dist/, build/, .min.js, lockfiles, generated protobufs)
  - SKIP_BINARY (images, fonts, archives, compiled artifacts)
  - SKIP_DOC (pure markdown/docs unless they contain config snippets that get loaded at runtime)

Test-file exclusion rules (SKIP_TEST if ANY match):
  - Path contains: /test/, /tests/, /__tests__/, /spec/, /specs/, /e2e/, /integration-tests/, /fixtures/, /mocks/, /testdata/, /examples/ (when clearly demo-only)
  - Filename matches: *_test.*, *.test.*, *.spec.*, test_*.py, *Tests.cs, *[Test.java](http://Test.java), [conftest.py](http://conftest.py)
  - File header/docstring/first 30 lines explicitly state it is a test, demo, sample, or fixture
  - Imports a known test framework (pytest, unittest, jest, mocha, junit, rspec, go testing) AND has no production import path
If a file is ambiguous (e.g., examples/[server.py](http://server.py) that is actually wired into the main entrypoint), DO NOT skip — treat as SCAN_TARGET and note the ambiguity.

==================================================
PHASE 2 — PARALLEL AGENT FAN-OUT (≥40 AGENTS, MULTIPLE PER FILE)
==================================================
Spawn at minimum 40 concurrent scanning agents. For every SCAN_TARGET file, assign AT LEAST the following independent agents (each runs in isolation, no shared state, results merged later):

  AGENT A — Cryptographic secrets agent
    Hunt: hardcoded JWT signing secrets, HMAC keys, AES/DES/3DES keys, IVs, salts, RSA/ECDSA private keys, SSH keys, PGP blocks, session/cookie signing secrets, CSRF token seeds, OAuth client secrets, webhook signing secrets, API keys (AWS, GCP, Azure, Stripe, Twilio, SendGrid, Slack, GitHub PATs, etc.), database passwords, encryption-at-rest keys, TLS private keys.

  AGENT B — Auth & session agent
    Hunt: hardcoded admin credentials, default-admin fallbacks, hardcoded bypass tokens, "magic" header values, hardcoded user IDs/roles in auth checks, hardcoded iss/aud/sub allowlists, hardcoded SSO certs, hardcoded TOTP seeds, predictable session ID generation, hardcoded refresh-token secrets.

  AGENT C — Crypto-correctness agent
    Hunt: weak entropy sources used to derive secrets (Math.random, rand(), [time.Now](http://time.Now)().Unix() as seed, PID-based, mt_rand, non-CSPRNG), low iteration counts (PBKDF2 < 100k, bcrypt cost < 10, scrypt N < 2^14), missing/zero IVs, ECB mode, static nonces in GCM/ChaCha20, key reuse across primitives, short keys (<128-bit symmetric, <2048-bit RSA), MD5/SHA1 used for auth/integrity, custom crypto.

  AGENT D — Decrypt-then-shell-out agent
    Hunt: any hardcoded value that decrypts data which then flows into exec, system, spawn, popen, os.system, child_process, Runtime.exec, subprocess, shell templates, SQL builders, eval, Function(), deserializers (pickle.loads, yaml.load w/o SafeLoader, unserialize, Java ObjectInputStream, .NET BinaryFormatter), template engines with autoescape off. Also: hardcoded keys that decrypt config which sets command paths, env-injected commands, or feature flags that gate dangerous behavior.

  AGENT E — Predictable-token / weak-generator agent
    Hunt: token/ID/nonce generators that look strong but are deterministic (seeded RNG, hash of timestamp, hash of username, sequential, UUIDv1 leaking MAC+time when used as security token, crypto.pseudoRandomBytes, swapped argument order to randint).

  AGENT F — Config & fallback agent
    Hunt: secret = os.getenv("X") or "hardcoded-fallback" patterns, process.env.JWT_SECRET || "dev", viper.GetString("x") with default secret, hardcoded values inside Dockerfiles/Helm/k8s manifests/Terraform, hardcoded values in CI configs that get baked into release artifacts, .env files committed with real values.

  AGENT G — URL/endpoint/SSRF-anchor agent
    Hunt: hardcoded internal hostnames, hardcoded admin URLs, hardcoded callback URLs that can be matched-against with weak comparison (startswith, regex without anchors), hardcoded redirect allowlists with substring match, hardcoded CORS origins including wildcards or null.

  AGENT H — Comparison/timing agent
    Hunt: hardcoded secrets compared with ==, ===, strcmp, Equals (timing leak); hardcoded values used in .includes()/indexOf checks instead of equality (bypass); hardcoded prefix/suffix checks for auth.

For each file, run agents A–H independently. Do NOT let one agent's "nothing found" suppress another's output. Multiple agents per file is mandatory — minimum 8 logical agent passes per SCAN_TARGET file. Distribute across ≥40 concurrent workers; large repos may have hundreds of files in flight simultaneously.

Each agent emits findings as JSON:
  { repo, path, line_start, line_end, agent, category, value_redacted, snippet, why_it_might_matter, initial_confidence (0-1) }

==================================================
PHASE 3 — DEDUPLICATION & FIRST-PASS FILTER
==================================================
1. Merge all agent findin


Output findings to this chat do not push to github.
