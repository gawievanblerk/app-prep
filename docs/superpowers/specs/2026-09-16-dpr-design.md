# dpr: deterministic data protection review

Date: 2026-09-16
Status: draft for review
Source behaviour: the data-protection-review skill in `Active Projects/data-protection-review/`

## 1. Goal

A Python package, `dpr`, that runs the same seven reviews as the data-protection-review skill against a code repository, with no LLM. It must be usable two ways: imported as a module (`import dpr`) and run as a CLI (`dpr scan`). It is for private use on repositories the owner controls.

Success means: on the fixture apps, every planted defect is reported with the correct rule id and evidence tag, the clean fixtures report none of them, and no secret value ever appears in any output.

## 2. Scope

### In scope for v1

- Languages: JavaScript, TypeScript (including JSX/TSX, and the `<script>` blocks of `.vue` and `.svelte` files), Python.
- Frameworks recognised: Next.js (app and pages router), Express, Fastify, Django, Django REST Framework, FastAPI, Flask.
- Data layers recognised: Supabase, Postgres SQL migrations, Prisma, Drizzle, Django ORM, SQLAlchemy.
- All seven reviews: inventory, rls, auth, baseline, owasp, leaks, abuse.
- Outputs: Markdown report, JSON, SARIF 2.1.0.
- Optional adapters: Semgrep, `npm audit`, `pip-audit`, live header read.

### Out of scope for v1

- Ruby, Go, PHP, Java. The rule interface must allow adding them later without redesign.
- Firebase security rules (`firestore.rules`, `storage.rules`). Listed under "What this review did not cover" when found.
- Any small language model. Findings keep snippet and location so a later model can re-grade INFERRED findings.
- Generating executable auth tests.
- Publishing to PyPI. Install is from the local path with `uv`.
- HTML report.
- Any exploitation, credential testing, fuzzing or path enumeration. Never in scope.

## 3. Decisions

| Decision | Choice | Reason |
|---|---|---|
| Matching depth | Regex for simple patterns, real parsers for structure | Without an LLM, accuracy is the product. Parsers let findings reach CONFIRMED. |
| JS/TS parser | `tree-sitter` + `tree-sitter-javascript` + `tree-sitter-typescript` | Prebuilt wheels with the grammars inside, no compiler, no runtime download. `tree-sitter-language-pack` 1.x was rejected: it downloads grammars into a user cache at first use, which breaks the no-network rule. |
| Python parser | stdlib `ast` | No dependency, exact. |
| SQL and Prisma | Small own parsers | Only a narrow set of statements matters (section 7). |
| OWASP breadth | Optional Semgrep adapter | Free rule packs give injection, XSS, crypto and config coverage. Rules license allows internal use, which fits private use. |
| First consumer | CLI and CI | Core returns plain objects, so later import by another app needs no change. |
| Unanswerable facts | Answers file, optional prompts | CI never blocks. Missing answers become UNKNOWN. |
| OWASP numbering | OWASP Top 10 2021 | Same numbering as the skill and Semgrep rule metadata. |
| Python | 3.12, managed by `uv` | System Python is 3.9. |
| Name | `dpr` | Short. Can be renamed before the first release tag. |

### Deliberate deviations from the skill text

1. **"Policy on select only leaves insert, update and delete wide open."** In Postgres, once RLS is enabled, a command with no matching policy is denied for roles without `BYPASSRLS`. So `dpr` does not report this as open. It reports `RLS-SELECT-ONLY` as a low informational finding: client writes are denied, so if the app writes to that table it is probably using a service key, which is then checked by the leaks review.
2. **"USING without WITH CHECK on insert/update lets the caller write rows owned by someone else."** Tested on PostgreSQL 14.17: an UPDATE policy with only `USING` reuses it as the check and blocks moving a row to another owner, and an INSERT policy with no `WITH CHECK` blocks the insert. The real defect is a `WITH CHECK` that is present but does not check ownership, such as `WITH CHECK (true)`. For UPDATE that is only exploitable when the table's select policies do not restrict ownership either, because Postgres also checks the new row against select policies when the update has a filter. `dpr` reports this as `RLS-WEAK-WITH-CHECK` (section 10.2).
3. **Report title** uses a colon instead of a dash: `# Data Protection Review: <project>`.
4. **SARIF.** GitHub shows SARIF inline only for public repositories or with paid GitHub Code Security. The CI example therefore uploads the Markdown report as a workflow artifact. SARIF output is still produced.
5. **Tag case.** Evidence tags are uppercase strings (CONFIRMED, INFERRED, UNVERIFIED, UNKNOWN) in JSON and SARIF output, matching section 6.2; section 11.2's lowercase rule applies to severity and exploitability only.

### Milestone 2 refinements to this spec

Found while planning and reviewing reviews 4, 5 and 7. The tables in section 10 already include them.

6. **Calibration.** CONFIRMED only when a parser reads the fact at the cited location. A finding that rests on the absence of evidence is INFERRED whenever the app has a global mechanism the classifier cannot read.
7. **Header checks per surface.** "Not set in any header config" would let a static site that sets `X-Frame-Options` hide an API that sets nothing. Each surface (static host config, Next.js, Express, FastAPI, Django) is judged on its own, and one finding per header lists every surface that lacks it. Vercel and Netlify configs count HSTS as set, because both platforms send it by default.
8. **OWASP categories on baseline and abuse rules** (A01, A02, A04, A05, A07), so SARIF properties and a later Semgrep dedupe can use them. Review 5's "Categories reviewed" part counts only its own rules and cross-references the others.
9. **Route access.** Auth words in dependency, decorator, wrapper and middleware names match whole snake or camel case words (`get_author` is not auth). Database session dependencies (`get_db`, `get_session`, parameters typed `Session` or `AsyncSession`) are not auth. FastAPI reads `APIRouter(dependencies=...)` and `include_router(..., dependencies=...)` up the include chain. Express counts `.use` middleware only when its mount path covers the route, ignores known non-auth middleware (`session()`, `passport.initialize()`, `express.json()`, routers) and reads middleware placed in front of a router where another file mounts it. Mounts, `include_router` calls and `.use` middleware in test files never count. A router is authenticated through its mounts only when every mount is guarded; when mounts disagree the route is public with a "mixed" basis and the guard as evidence. A Next.js matcher is read as a path pattern, so a negative lookahead excludes its listed prefixes. Django `LoginRequiredMiddleware` in any settings module makes plain Django views authenticated unless marked `login_not_required`; DRF views (`APIView`, `@api_view`, viewsets) are exempt from it, as DRF itself exempts them. DRF permissions are read from the syntax tree of any module holding `INSTALLED_APPS` or `REST_FRAMEWORK` (comments never count; test, local and development settings modules are used only when no other settings module exists, and production modules that disagree give a "mixed" basis): `IsAuthenticated` requires sign-in, `IsAdminUser` requires an admin, and `IsAuthenticatedOrReadOnly` leaves `GET`, `HEAD` and `OPTIONS` public, so a view that serves both reads and writes gets a "mixed" basis. Each public answer records whether it rests on an explicit marker, on absence, or on a mixed answer.
10. **Paid routes** follow helpers through the calling file's own definitions and imports, up to two calls deep, not only within one file. SDK names are read per file, including a client imported from another repository file (`from app.clients import client`, `import { openai } from "@/lib/openai"`). A method call is followed only when its receiver is an imported module, or an instance built from a class the file defines or imports, where the instance is assigned at module level (`ai_service = AIService()`, also when imported from its module) or in the calling function's own body before the call; assignments inside other functions and parameters (including `Depends(...)` defaults) are never used, and method calls on other objects are never followed. A helper matched by name alone (an import that cannot be read to its definition) makes `ABUSE-PAID-UNAUTH` INFERRED.
11. **`ABUSE-INMEMORY-LIMITER` also applies to multi-process deploys**, not only serverless hosting: two gunicorn workers keep two counters just as two functions do. The worker count or the serverless host's config file (for example `vercel.json`) is cited as a second location.
12. **`OWASP-A01-UNSCOPED-QUERY`**: a later comparison or non-logging call that uses both the caller and the loaded record counts as an ownership check and clears the finding; a later call that receives only the caller makes it INFERRED. Only models that belong to someone are reported (user-like models, owner or tenant columns, or a parent key to an owned model), so reference data is skipped, and so is a read lookup (`findUnique`, `findFirst`, `findMany`, `findOne`, `select`, `filter`, `get`) whose own filter has a top-level visibility key (`published`, `is_public`, `isPublic`, `visible`, `visibility`) set to a literal that means public (`True`, `true`, `1`, `"public"`, `"published"`), when the handler does not write to the loaded record afterwards. A value from the request, any other literal (`"team"`, `"members"`), a key inside `include`, `select` or a joined model, writes (`update`, `delete`, `upsert`) and a later write to the record (attribute assignment, `save`, `update`, `commit` or `delete` involving it) do not skip the lookup. On a public route the finding is INFERRED: the record type may be meant to be public. FastAPI form and body fields are not record identifiers. `OWASP-A01-GUESSABLE-ID` is folded into this rule (refinement 36).
13. **`ABUSE-FORM-NO-CHALLENGE`** needs the route to be public and not a `GET`; `is_public_form` alone also marks signed-in upload routes. One finding per file lists every route.
14. **`ABUSE-ERROR-LEAK`** covers catch-all exceptions (`Exception`, `BaseException`, bare `except`); messages of narrow exceptions such as `ValueError` are usually written for users.
15. **`OWASP-A02-SECRET-IN-URL`** does not report `token=` in one-time links (reset, verify, confirm, invite, magic, activate, unsubscribe): that is the standard delivery for single-use tokens.
16. **`OWASP-A03-RAW-SQL`** skips Python files under Alembic and `migrations/` folders (JS and TS migration files are still read), and is CONFIRMED only when a request value, or a name assigned from one, is inside the SQL string's interpolations. A request value passed as a bound parameter does not count.
17. **`BASE-WEAK-HASH`** does not report a fast hash of a token, reset link, one-time code, nonce or API key, or of a value from `randomBytes` or `secrets.token_*`: storing a SHA-256 of a high-entropy random value is the recommended pattern. A password argument is still reported.
18. **`BASE-CSP-WEAK`** does not report `'unsafe-inline'` next to a nonce or hash source and `'strict-dynamic'`, because browsers that support nonces ignore it there.
19. **Route paths include router prefixes** for FastAPI and Flask, so tables read `/auth/register`. Review modules may define a `finish(ctx, section, findings)` hook to summarise their own findings.
20. **Snippets mask credential shapes** as well as key patterns: URL passwords with or without a user name, password flags on command lines, secret query parameter values (also a quoted value or a value concatenated as a separate literal) and literals assigned to password, secret, token or API key names, including adjacent, concatenated, escaped and triple-quoted literals, each masked on the whole line before the line is cut. The patterns use bounded repetition, so redaction stays linear on long minified lines. Credential rules mask their own Python literal by its source range, so it is hidden however it is spelled. Since v0.2 the line masks also cover a literal default of a secret-named environment read (the second argument, `default=`, or an `or` fallback), the password of an `auth=("user", "...")` pair, a literal `Basic`, `Bearer` or `Token` authorization value, and literals assigned to `salt` names (refinement 40).
21. **tree-sitter 0.26 `Point.row`** corrupts memory past line 256. Helpers index points (`start_point[0]`) rather than read `.row` or `.column`.
22. **Rules added beyond the original tables**, from gaps found against a private comparison run: `BASE-LITERAL-PASSWORD-HASH`, `BASE-SEED-ON-START`, `BASE-SHORT-PASSWORD-MIN`, `BASE-SAMESITE-NONE-NO-CSRF`, `BASE-DB-NETWORK-OPEN`, `BASE-DB-ADMIN-LOGIN`, `BASE-HTTPS-NOT-ENFORCED`, `OWASP-A01-EMAIL-OWNERSHIP`, `OWASP-A01-PATH-TRAVERSAL`, `OWASP-A03-HTML-EMAIL`, `OWASP-A05-XML-PARSER`, `OWASP-A08-UNPINNED-DEPS`, `OWASP-A08-UNPINNED-INSTALL`, `ABUSE-LIMITER-NOT-APPLIED`, `ABUSE-LIMITER-PROXY-IP`, `ABUSE-UPLOAD-UNBOUNDED`, `LEAK-PUBLIC-GATE-KEY` and `LEAK-DEFAULT-CREDENTIAL`. Their rows are in sections 10.1 and 10.4 to 10.6.

### v0.2 refinements to this spec

Found by comparing v0.1.0 with a manual audit of a large Django repository, where about 95% of the findings were noise. The tables in section 10 already include them.

23. **Scan scope follows git.** In a git repository the index holds tracked files only (`git ls-files`). `--include-untracked` (`dpr.review(include_untracked=True)`) adds untracked files that git does not ignore (`git ls-files --others --exclude-standard`); ignored files are never read. A repository that tracks no file under the scanned folder yet is scanned as if the flag were set. When untracked files were left out, `not_covered` gives their count and three examples. Outside a git repository, or when git is unavailable, every file under the folder is walked as before and `not_covered` says so. Skipped directories and size limits are unchanged. Build output folders (section 7.1) are read whatever git says, because they are generated and usually ignored.
24. **"Committed" means tracked.** `INV-PII-FILE-IN-REPO` says a file is committed only when git tracks it (high). An untracked file scanned on request is "in the working folder, not committed" (medium, with a fix that moves the data out of the folder instead of rewriting history), and outside git the finding says whether it is committed is not known. `LEAK-COMMITTED-DATA-FILE` counts tracked files only, including the email check in tests and documentation. Any finding whose every location is an untracked file scanned on request ends its detail with "not tracked by git: it is in this working folder only". `LEAK-ENV-TRACKED` and `LEAK-ENV-IN-HISTORY` already read git directly and are unchanged.
25. **Vendored code.** A JS or CSS file is a copied library when its name matches `vendored_libs.yaml` (jQuery, Bootstrap, Select2, DataTables, PDF.js, Moment.js, Lodash and about 40 more; the version and `.min` are removed first), it is minified (`.min.js`, `.min.css`, or at least 4 KB with lines over 300 characters on average), or its header is a library banner (`/*!` at the start, `@license`, `@preserve`, a webpack bootstrap). A whole folder is vendored when it is named after a known library and holds no `.py`, `.ts`, `.tsx`, `.jsx`, `.vue` or `.svelte` file, is a child of a third-party folder (`third-party`, `third_party`, `vendors`, `bower_components` and similar), or holds its own `LICENSE` or `COPYING` file with no project manifest (`package.json`, `pyproject.toml`, `setup.py`, `requirements.txt`, `manage.py` and similar) anywhere below it, such as a Django app copied from another project. Collected static output (`staticfiles`, or a `static` folder that holds Django admin's collected `admin/js/core.js`) is vendored too, but only the libraries inside it are named. Sink rules skip vendored files: `OWASP-A03-XSS-SINK`, `OWASP-A03-COMMAND`, `OWASP-A03-RAW-SQL`, `OWASP-A02-SECRET-IN-URL`, `OWASP-A02-WEAK-RANDOM-TOKEN`, `OWASP-A08-UNSAFE-DESERIALISE`, `OWASP-A08-NO-SRI`, `LEAK-LOGGED-PII`, and `LEAK-SOURCEMAP` for maps under a vendored folder. Key patterns (`LEAK-HARDCODED-KEY`, `LEAK-KEY-IN-BUILD`) and route, settings and access rules still read them. Each library is reported once as `OWASP-A06-VENDORED-LIB` (section 10.5), one finding per library name listing every copy (refinement 69); the register groups them into one issue per app root.

26. **Path traversal sinks.** `OWASP-A01-PATH-TRAVERSAL` fires only when a request value reaches a file system path: `open()` (reads and writes), `Path.write_*`, `read_*`, `unlink` and `open("w")`, `os.rename`, `os.replace`, `os.remove` and `shutil` copy, move and delete calls, a Django storage's `save`, `open` or `delete` (`default_storage`, a `*_storage` name, or a `FileSystemStorage(...)` instance), an uploaded file's own `save(path)` (Flask `request.files`, or a receiver named `file`, `upload` or `attachment`), and `send_file` / `FileResponse(path)` when imported from Flask, FastAPI or Starlette. Django `form.save()`, model `.save()` and FileField assignment are never sinks: the storage cleans the file name. `request.user`, `request.session` and `request.method` are not request values, a database lookup (`.objects.`, `get_object_or_404`) returns a stored record rather than the value that selected it, and Django's `safe_join`, `get_valid_filename` and `slugify` count as sanitisers. Helpers are followed only to the definition the calling file itself defines or imports (or a method of the calling class through `self`), as in refinement 10, never to a same-named function elsewhere. The finding is CONFIRMED only when every step from the request to the sink was read (assignments, `os.path` and `pathlib` builders, string methods, f-strings); a step through any other call makes it INFERRED. The title says whether the path is written, deleted or read.
27. **Settings that production never loads.** `BASE-DEBUG-ON` (the Django `DEBUG = True` literal) and `BASE-WEAK-HASH` (the `PASSWORD_HASHERS` setting) skip a settings module inside a vendored package (a copied app's own settings, used by its tests), and a test, CI, local or development module (`tests_settings.py`, `ci_settings.py`, `settings_test.py`, `testing.py`, `settings/local.py`, any settings file under a tests folder) while another settings module holding `INSTALLED_APPS` exists. This is the same production-first choice as refinement 9, which now also treats `ci` as a local word. `BASE-DEBUG-ON` also reports a `DEBUG` that reads the environment and is on when the variable is unset (refinement 42).
28. **`OWASP-A02-WEAK-RANDOM-TOKEN` needs a secret.** The name must say the value is a secret (`token`, `secret`, `otp`, `reset`, `nonce`, `password`, `passcode`, `salt`, an API, private, signing or access key, a verification, confirmation, auth, login, activation or one-time code, or a `pin`); a bare `code` is an identifier, not a secret. A Python value with a neutral name is still reported, CONFIRMED, when the same function passes it to `set_password`, `make_password` or a cookie, puts it in a link with `?token=`, `?code=`, `?key=` or `?otp=` or a reset or verification path, or sends it as an `Authorization` header. A random value returned by a helper and set as a password elsewhere is not followed.
29. **`LEAK-BROAD-RESPONSE` needs a response and personal data.** A Python `model_to_dict`, `vars()` or `__dict__` dump is reported only when it reaches the handler's HTTP response: returned, passed to a response call (`JsonResponse`, `Response`, `HttpResponse`, `jsonify` and similar), or assigned to a name that is. A dump kept for a diff, a log or a template context is not, and neither is a filtered comprehension that picks some keys. A DRF serializer with `fields = "__all__"` is skipped when its model is read and the personal data classifier finds no personal field on it (a lookup table); an unknown model is still reported.
30. **`ABUSE-ERROR-LEAK` needs an HTTP response.** Exception text counts when it is put in a response call, returned by a route handler, or returned by a helper whose result a handler in the same file sends in its response. Celery tasks (`@shared_task`, `@app.task` and similar) and other internal return values are not responses.
31. **Logout that ends the server session.** `AUTH-LOGOUT-NO-REVOKE` treats a class view built on Django's `LogoutView` (which calls `auth.logout()` and flushes the session), and a call that expires a token (`expire_token`), as revocation, like `logout()`, `flush()` and token `delete()` before.
32. **`INV-SDK-RECEIVES-PII` keys.** A keyword argument is identifying only when the classifier marks it personal without the bare `name` term, so SDK settings such as `region_name` or `bucket_name` do not count. The `Body` of a storage upload (`put_object`, blobs) is a file of unknown contents, not free text, so content keys do not count for storage SDKs.
33. **`OWASP-A03-RAW-SQL` built from constants.** SQL formatted only from literals, UPPER_CASE names and attributes (module and class constants), local names only ever assigned such values, and `tuple()`, `list()`, `str()` or `", ".join()` of them is not reported: it cannot carry caller input. The same applies to JavaScript template strings and concatenation whose parts are literals, UPPER_CASE names or local names declared with a literal.
34. **Django views follow the urls module's imports.** A URL pattern's view (`views.retrieve_file`, an imported name, `views.Page.as_view()`) is resolved through the imports of the `urls.py` that names it, following one re-export, and only then by name under the `urls.py` folder. A Celery task (`@shared_task`, `@app.task`, `@periodic_task`) is never a view, so a task that shares a view's name is not used. A pattern that mounts `something.urls` (a Django Ninja API, the admin site) is not a route. Django Ninja operations (`@api.get(...)`, `@router.post(...)` in a file importing `ninja`) are routes: `auth=` on the operation, else on the `NinjaAPI(...)` or `Router(...)` it is declared on, makes them authenticated, and `auth=None` makes one public.
35. **Custom Django auth decorators, one level.** A decorator the repository defines (in the view's file, or imported into it) counts as a guard when its body calls `login_required`, `user_passes_test`, `permission_required` or `staff_member_required` (such as `def is_complaints_user(f): return login_required(user_passes_test(test)(f))`), or when it reads `request.user` and sends a failing caller to login or a 403 (`redirect_to_login`, a login URL, `PermissionDenied`, `HttpResponseForbidden`). Such routes are authenticated, and admin when the wrapped decorator is `staff_member_required`. Access records a role check beyond sign-in (`role`): `user_passes_test`, `permission_required`, a custom decorator that uses one of them or tests `has_perm`, `is_superuser`, `is_staff`, groups or a `user.is_<role>` flag, a `PermissionRequiredMixin`, or a DRF permission class other than `IsAuthenticated`, `AllowAny`, `IsAuthenticatedOrReadOnly` and `IsAdminUser`. Decorators are read together, so `@login_required` above `@user_passes_test` is role-gated.
36. **`OWASP-A01-UNSCOPED-QUERY` request values and role gates.** Besides path parameters, identifiers come from `request.GET`, `request.POST`, `request.data`, `request.query_params`, a JSON body (`json.loads(request.body)`), a DRF serializer's `validated_data` and a Django Ninja body schema, directly or through names assigned from them in line order (splits, subscripts and decoders such as `hashids.decode(...)` keep the value; a record loaded with it, and `request.user`, do not). A request value counts when its request key or name is an identifier (`id`, `pk`, `*_id`, `*_number`, `*_no`, `ref`, `uuid`, `slug`, `hash`) or a personal identifier (ID number, policy number, email, phone); a search term does not. The first parameter of a Django view is the request whatever its name (`req`). DRF `@api_view` functions and the HTTP method handlers of class views (`get`, `post`, `retrieve`, `update`, `@action` methods and so on) are read. A queryset method named for the caller (`filter_by_user`, `for_user`, `visible_to`, `owned_by`, `accessible_by`) scopes the lookup. A serializer, form or response built with the caller in its `context` is not an ownership check. A Django `ForeignKey` or `OneToOneField` is read as its column (`user` as `user_id`), so owner and parent keys count as they do in SQL schemas. Code after a function's first top-level `return` or `raise` is not read. On an authenticated route with a role gate (refinement 35, or a `request.user.has_perm`, `is_superuser`, `is_staff` or groups test in the handler), the finding is low, low exploitability and INFERRED ("role-gated back-office access, confirm by design"). `OWASP-A01-GUESSABLE-ID` is no longer reported on its own: when the lookup is by primary key on an owned model with an auto-increment key, the finding's detail says so and cites the key field, and on a public route the severity becomes critical. A public route reported as CONFIRMED by `OWASP-A01-PUBLIC-SENSITIVE` carries its lookup there instead.
37. **`OWASP-A01-PUBLIC-SENSITIVE`.** Once per public route (file and path): the handler sets a password (`set_password` on a user record loaded from the database, or `SetPasswordForm(...).save()`) or saves a loaded user record, with no token check (`check_token`, `signing.loads`, `unsign`); passes a request value to a read (`get`, `filter`, `Q`, `get_object_or_404`, or a call named lookup, search, find, fetch, retrieve or query) through a keyword naming a personal identifier (`id_number`, `policy_number`, `email`, `phone`, `cell`, `msisdn`, `passport`, `account_number`, also inside `a__id_number__contains`); returns a file (`FileResponse`, `send_file`, `StreamingHttpResponse`, a `content_type` of PDF, zip, octet-stream, Office or CSV, or a `Content-Disposition` header); or starts a background job (`.delay`, `.apply_async`, `.submit`, `run_in_background`, a thread or process) in the handler or in a helper it calls through its own imports. A handler that reads no input at all (no parameter, query string, form, body, files or headers) and creates, updates or deletes records, itself or in such a helper, is reported as a back-office write. The title names the first of these in that order; the detail lists all. CONFIRMED and critical for a password, or for personal data or a file reached through a lookup keyed by a request value that is not a random link key (`uuid`, `token`, `secret`, `signature`, `nonce`), when no unread global guard applies; otherwise INFERRED and high. Background jobs and writes are not reported on routes that `OWASP-A01-UNSIGNED-CALLBACK` reports.
38. **`OWASP-A01-UNSIGNED-CALLBACK`.** A public route whose path or handler name reads as a callback (`webhook`, `callback`, `hook`, `push`, `ipn`, `notify`, `notification`, `dlr`, `result`, `response`, `confirmation`) and whose handler, up to its first top-level return, changes data (`save`, `create`, `update`, `delete`, `accept`, `decline`, `approve`, `confirm`, `cancel`, `create_*`, `update_*`, `process_*`, `.delay`) while neither it nor its decorators mention a signature, HMAC, `compare_digest`, a secret, token or API key, an authorization header, or the caller's address (`REMOTE_ADDR`, `X-Forwarded-For`, an allowlist). INFERRED (the proxy may restrict the path), high. The register groups them into one issue per app root.
39. **`OWASP-A05-DEBUG-ENDPOINT`.** A public route named like a health, test or debug endpoint (`readyz`, `healthz`, `livez`, `health`, `ping`, `debug`, `test`, `version`, `diagnostics`, `env`, `info`, `serialization_error`) whose handler uses exception text (`str(e)`), a traceback, settings, environment values or versions, and returns something other than a literal response such as `HttpResponse("OK")`. Low.

40. **`LEAK-SECRET-ENV-DEFAULT`.** In code production may load (not a test, not vendored, not a test, CI or local settings module), a secret-named environment read with a non-empty literal fallback: `os.environ.get(NAME, "...")`, `os.getenv`, `os.environ.setdefault`, django-environ `env(NAME, default=...)` and `env.str/bool/int`, python-decouple `config(NAME, default=...)`, and `os.environ.get(NAME) or "..."`; also a secret-named `NAME = "..."` literal at module level in a settings module (a file holding `INSTALLED_APPS`, or named or foldered `*settings*`), and a literal `Hashids(salt=...)` anywhere. A name is secret when a whole token is `SECRET`, `PASSWORD`, `PASSWD`, `PWD`, `PASS`, `TOKEN`, `SALT`, `CREDENTIAL(S)`, `KEY(S)`, `APIKEY` or `MEMKEY`, unless a later token says the value is about the secret (`URL`, `ENDPOINT`, `ID`, `TIMEOUT`, `PATH` and similar: `PASSWORD_RESET_TIMEOUT`, `AWS_ACCESS_KEY_ID`) or a key is named for what it looks up (`SITE_KEY`, `HOST_KEY`, `CACHE_KEY`, `S3_KEY`); the variable's name is used, or the assigned name when only that is secret. Empty, `None` and URL values are not fallbacks. One finding per file lists every name and cites each line, never the value: critical when a signing key (`SECRET_KEY`, `*_SECRET_KEY`, `SIGNING_KEY`, `JWT_SECRET*`, `SESSION_SECRET`) falls back, high otherwise, and low when every value is a placeholder (`changeme`, `pass`, `password`, `secret`, `xxx`, `<...>`, short `test`/`dummy`/`your-` words). `LEAK-LITERAL-HTTP-AUTH` reports, once per file, a literal password in `auth=("user", "...")`, `HTTPBasicAuth`/`HTTPDigestAuth`/`BasicAuth` calls and a literal `Authorization: Basic|Bearer|Token ...` header value, following one module-level constant. Both are CONFIRMED and print no snippet.
41. **`BASE-PICKLE-SESSIONS`** reports `SESSION_SERIALIZER = "...PickleSerializer"` in a production settings module. When a signing key has a committed fallback (refinement 40), its location is cited second and the register joins the two into one issue: "..., and sessions use Pickle, so a signed session can run code on the server". A `linked` register chain may give the text it adds when its rules join (`joined`).
42. **Settings evaluated with the environment unset.** A setting that reads the environment is evaluated as if every variable were unset: each read becomes its default (`None` with none), and constants, comparisons (`==`, `!=`, `in`, `not in`, `is`), `x if c else y`, `and`, `or`, `not`, `.lower()`-style string methods, `bool()` and `str()` are followed; anything else leaves the value unknown and nothing is reported. `BASE-DEBUG-ON` fires when `DEBUG` in a production settings module is then true or a true word (`DEBUG = False if os.environ.get("DEBUG") == "False" else True`, `os.environ.get("DEBUG", "True")`, `env.bool("DEBUG", default=True)`), unless every deploy config sets it false. `BASE-ENV-DEFAULTS-PROD` (medium) fires when a module-level flag in production code is then production: `IS_PROD`, `PROD`, `PRODUCTION`, `IS_LIVE` and similar names that come out true (`IS_PROD = os.environ.get("DOMAIN", "<prod host>") in [...]`), or `ENV`, `ENVIRONMENT`, `STAGE` (optionally `APP_`, `DJANGO_`, `DEPLOY_` prefixed) that come out as `prod`, `production`, `live` or `prd`.
43. **`BASE-FEATURE-DEFAULT-ON`** (low): `WAFFLE_SWITCH_DEFAULT`, `WAFFLE_FLAG_DEFAULT` or `WAFFLE_SAMPLE_DEFAULT` set to `True` in a production settings module, one finding per file.
44. **django-axes.** `"axes"` in any production settings module (installed app, `AxesMiddleware`, `AxesBackend` or `AxesStandaloneBackend`) is a sign-in lockout for its app root even when no manifest declares the package: `AUTH-NO-LOCKOUT` records case 1 as passing, and `ABUSE-FORM-NO-CHALLENGE` counts the root's sign-in routes as limited. `AXES_*` settings are read from every production settings module in the root. `AUTH-LOCKOUT-WEAK` (CONFIRMED) reports no `AXES_COOLOFF_TIME` (a lockout lasts until an administrator clears it), an `AXES_FAILURE_LIMIT` above 10, and lockout keyed by user name only (`AXES_LOCKOUT_PARAMETERS = ["username"]` or `AXES_ONLY_USER_FAILURES`) or by IP address only (the default); medium when there is no cool-off or the key is the user name alone, else low. django-ratelimit's `@ratelimit(...)` decorator already counts as a limiter.
45. **`OWASP-A01-OPEN-REDIRECT`.** A Python redirect (`HttpResponseRedirect`, `HttpResponsePermanentRedirect`, `redirect`, `RedirectResponse`) or an Express/Next `.redirect(...)` whose target starts with a request value (refinement 36's sources, followed through local assignments, `or`, `x if c else y`, f-strings, `+` and `%` whose first part it is) or with the Referer header (`HTTP_REFERER`, `headers.get("Referer")`, `request.referrer`, `req.get("Referer")`), in a function that never mentions `url_has_allowed_host_and_scheme`, `is_safe_url`, `allowed_hosts`, an allowlist or `.netloc`. A literal first part (a path on this site or a full URL), `reverse`/`url_for`, and a record loaded with a request value do not count. A request value is CONFIRMED and medium, one finding per call; Referer redirects are INFERRED and low, one finding per file.
46. **`OWASP-A01-CSRF-EXEMPT`.** Top-level Django views marked `@csrf_exempt` (or `method_decorator(csrf_exempt)`) that the route classifier marks authenticated or admin (or, when no route resolves, carry a sign-in decorator) and never mention a token, signature, HMAC, API key or Authorization header. One finding per file: medium when a view changes data (`save`, `create`, `update`, `delete`, `.delay`, `set_password`, or a call named `create_*`, `update_*`, `add_*`, `send_*`, `process_*`, `perform_*` and similar), high with high exploitability when a production settings module also sets `SESSION_COOKIE_SAMESITE` or `CSRF_COOKIE_SAMESITE` to `"None"` (cited last), low when no view visibly changes data. Views that move money or payroll records are named in the detail.
47. **`OWASP-A04-GET-SIDE-EFFECT`.** A signed-in Django function view (or class view `get` method), or a Flask GET route, with no method check (`request.method`, `require_POST`, `require_http_methods`, `is_valid()`, or reading the request's `POST`, `FILES` or body; `require_GET`/`require_safe` mean GET only) that itself starts a job or thread (`.delay`, `.apply_async`, `.submit`, `Thread`, `Process`, `run_in_background`), sends messages in a loop, deletes records, or writes in bulk (`bulk_create`/`bulk_update`, queryset `update`/`delete`, writes in a loop). Public routes are left to `OWASP-A01-PUBLIC-SENSITIVE`. Medium and one finding per route; routes whose only effect is a single delete are low and grouped per file.
48. **Upload rules.** `OWASP-A04-UPLOAD-LIMIT` (medium): `DATA_UPLOAD_MAX_MEMORY_SIZE` or `FILE_UPLOAD_MAX_MEMORY_SIZE` of 100,000,000 bytes or more (constant arithmetic is evaluated), or `DATA_UPLOAD_MAX_MEMORY_SIZE = None`, in a production settings module; one finding per file. `OWASP-A04-UNCHECKED-UPLOAD` (low, INFERRED): model, form and serializer `FileField`s with no `validators=` and no `clean*` method of their class that names them, outside migrations and tests, one finding per app folder (the file's folder, or its parent for `forms/`, `models/`, `views/`, `serializers/` and `api/` packages). `ImageField` is not reported: Django checks its content with Pillow, which rejects HTML, SVG and PDF.
49. **`OWASP-A01-PRIVILEGE-FIELDS`.** A `ModelForm`, `ModelSerializer`, `UserChangeForm` or `UserCreationForm` subclass (not in `admin.py`) that accepts `is_superuser`, `is_staff` or `user_permissions` (listed in `Meta.fields` or declared, not read-only, disabled, excluded or popped from `self.fields`), or `groups`/`permissions` on a user model or on a model that declares a superuser or staff flag (a role template); `fields = "__all__"` on such a model accepts the ones it has. Reported (CONFIRMED, high; critical when a public route binds it) when a route fills it from the request (`Form(request.POST)`, `data=`, or a writable class view whose `form_class`/`serializer_class` it is) and that route is not superuser-only (its decorators or first guard mention `is_superuser` with no `or`).
50. **Weak generated passwords.** `OWASP-A02-WEAK-RANDOM-TOKEN` also follows a helper's return value: a function whose returned value comes from `random.*` (through names, `+=`, `.append()` and nested helpers, not `secrets` or `SystemRandom`) is a weak generator, and a call resolves to one by name when every repository function of that name is one. A weak generator's output reaching `set_password`, `make_password` or `create_user(password=...)` is CONFIRMED at that call, citing the random call second. The detail notes when the same function, or a caller of a function that returns the password, passes it to an email or SMS call.
51. **Outbound calls.** `OWASP-A02-PLAIN-HTTP-CALL`: a `requests`, `httpx` or `urlopen` call (or JS `fetch`/`axios`) whose URL resolves (locals, class attributes, module constants, `settings.X` from production settings modules, environment defaults) to `http://` on a host outside the local network (not localhost, private or link-local addresses, single-label names, `.local`, `.internal`, `.svc`, `.test`, example domains), and URL-named settings (`*_URL`, `*_ENDPOINT`, `*_HOST`, `*_API`...) holding such an address; one finding per file, CONFIRMED, high when the call's `params`, `data`, `json`, `auth` or `headers` carry a secret-named or personal key, else medium. `OWASP-A02-SECRET-IN-URL` also reports a secret-named key (`password`, `pass`, `pwd`, a secret, token or key name) in a dict given to `params=` of such a call or to `urlencode()`, and `pass` counts as a secret query parameter (and is masked). `OWASP-A05-NO-TIMEOUT` (low): `requests.*` and `urlopen` calls with no `timeout` and no `**kwargs`, one finding per file.
52. **`OWASP-A05-HARDCODED-VENDOR-URL`** (low, INFERRED). A module- or class-level URL constant holding a literal public `http(s)` address (directly or through another constant), not read from the environment anywhere, read by a function that makes an HTTP call, and marked as live: its name or its source's name says `LIVE`/`PROD`, the same scope holds a test, staging, sandbox or UAT alternative, or it is in a settings module whose other settings read the environment. An alias that selects a live constant (`CURRENT_ENDPOINT = API_LIVE_ENDPOINT`) is reported instead of the constant. One finding per file.
53. **`OWASP-A06-EOL-COMPONENT`.** Versions declared in `requirements*.txt` and `pyproject.toml`/`Pipfile` (exact `==`, `~=`, `===` pins of Django), `Pipfile` `python_version`, `package.json` (`next`, `express` and `engines.node` with a caret, tilde or plain major), Dockerfile `FROM` images (`python`, `node`, `ubuntu`, `debian`, and the Debian release in `-buster`-style tags) and `pythonX.Y` in `RUN` steps, `.python-version`, `runtime.txt` and `.nvmrc`, are compared with the scan date (`Options.today`, the report date) using `data/eol.yaml`, an offline table of end-of-support dates with its own `as_of` date; a cycle older than the oldest listed one is out of support "no later than" that date. One CONFIRMED finding per component and cycle, citing the first site in each file: high for frameworks (Django, Next.js, Express), medium for runtimes and base images. Test folders are skipped. No network is used; `pip-audit` stays behind `--with-audit`. Known advisories come from a separate bundled table (refinement 76).
54. **Container and permission rules (review 4, A05).** `BASE-DOCKER-ROOT` (medium): a Dockerfile whose final stage has no `USER`, or switches back to `root`/`0`, unless its image is a `nonroot` variant. `BASE-WORLD-WRITABLE` (high): `chmod` with an octal mode that gives others write (`777`, `666`, `0777`; not sticky `1777`) or a symbolic mode that adds write for others or all (`a+w`, `a+rw`, `o+w`, `ugo+rwx`), in Dockerfiles, shell scripts and Python (also `os.chmod(..., 0o777)` and `stat.S_IWOTH`, and Python 2 scripts, which are read as text); one finding per file. `BASE-DOCKERIGNORE-THIN` (high): a Dockerfile that copies its whole context (`COPY . <dest>`) while the `.dockerignore` beside it (or at the repository root) is missing or does not exclude `.git`, `.env*`, `*.sql` dumps, an existing `media`/`uploads` folder, `node_modules` when there is a `package.json`, and secret files the context's `.gitignore` names (`local_settings.py`, `*.pem`, `*.key`, `secrets*`).
55. **Personal data by value.** A South African ID number counts only when it has 13 digits, a real YYMMDD date (1900s or 2000s), a citizenship digit of 0, 1 or 2 and a valid Luhn checksum; an IBAN only when mod-97 passes; a bank account (7 to 12 digits) only in a table that also has a branch code column (a `branch` header, or mostly known universal branch codes such as 250655, 632005, 470010, 198765, 051001 and 678910); a mobile number is `+27`/`0027`/`0` then 6, 7 or 8 and eight digits (under a phone-like header such as `cell`, `contact` or `preferred`, also without the leading 0). `INV-PII-FILE-IN-REPO` also reads `.tsv`, `.psv`, `.txt`, `.dat` (delimiter sniffed from the first lines), `.json`, `.jsonl`, `.ndjson`, `.sql`, `.xml` and `.yaml` files (not vendored files, nor licence, authors, notice, readme or changelog files, which list their authors' addresses). In a table, a column counts for a kind with at least 3 distinct valid values that are at least 20% of its non-empty cells; the first row is data, not a header, when one of its cells is itself a valid value, so a file with no header row is judged by its values and its first row is never printed as column names. In free text, 3 distinct ID numbers or IBANs, or 10 distinct mobile numbers or email addresses. At most 256 KB and 2,000 rows are read per file. The finding states the counts and the basis ("67 South African ID numbers that pass the checksum and date check and 67 bank account numbers next to a branch code column (no header row)"), never a value; it is CONFIRMED when ID numbers, IBANs or accounts pass, and INFERRED for mobile numbers or email addresses alone. A file under a test path found by value only is low: fixtures there are usually made up. New rule `LEAK-PII-LITERAL-IN-CODE` (review 6): one finding per tracked, non-vendored `.py`, `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs` or `.cjs` file (migrations and settings included) with 3 or more distinct valid ID numbers written as literals, quoted or bare (CONFIRMED, high), or 5 or more distinct quoted mobile numbers (INFERRED, medium); low in test files; the location spans the first to last hit and there is no snippet. Email addresses in code are not counted: settings and templates hold too many role addresses. Every snippet also masks valid ID numbers (`<redacted:id-number>`), valid IBANs (`<redacted:iban>`) and mobile numbers (`<redacted:phone>`).
56. **Record lists.** A handler sends a record list when a queryset that starts at `Model.objects`, or at a related manager of a local record (`batch.premiums.all()`, resolved through the `related_name` of a Django relation field when only one model uses that name), is built only with `all`, `order_by`, `values`, `values_list`, `select_related`, `only`, `distinct`, slices and similar steps, or with `filter`/`exclude` whose arguments use no parameter or local name, and reaches the response: returned, passed to `render`, `smart_respond`, `render_to_string`, `TemplateResponse`, `JsonResponse`, `Response`, `HttpResponse`, `jsonify` or a `*Serializer`, directly or through names, dict items and `x.update(...)` (a list reduced by `count`, `exists`, `aggregate`, `first`, `get` and similar is not). A class view based on `ListView`, `ListAPIView`, `ListCreateAPIView`, `ModelViewSet` or `ListModelMixin` with a `queryset` or `model` and no `get_queryset`, `list`, `get` or `filter_queryset` method sends its list. `OWASP-A01-PUBLIC-SENSITIVE` adds the action "lists stored {model} records" for a public route whose list is of a user model, a model with personal fields or a `FileField` (CONFIRMED), or of a model with an owner column (INFERRED: a public catalogue of users' posts may be intended).
57. **`OWASP-A01-UNSCOPED-LIST`** (high). A route the classifier marks authenticated, with no role gate (refinement 36), that sends a list of a whole table (not a related manager) of a user model (CONFIRMED) or of a model with personal fields (INFERRED, asking who may see every record). One finding per route, at the queryset.
58. **Debug routes that raise.** `OWASP-A05-DEBUG-ENDPOINT` also reports a public debug-named route (refinement 39) whose handler fails on every call: a top-level `raise`, `assert False`, or a division by the literal `0` before any return. Its title says the route "raises an error for anyone", and the detail says each call writes an error log entry and an error tracker event carrying request data.
59. **`LEAK-REQUEST-LOG`** (review 6, place 3). A function in application code that passes whole request headers (`request.headers`, `request.META`), a whole request body (`request.body`, `request.data`, `request.POST`, `request.GET`) or a whole response body (`response.content`, `response.data`) to a `Model.objects.create`-style write, or whole headers to a log call (bodies in log lines are left to `LEAK-LOGGED-PII`), directly or through local names, dict items and `update`/`append` calls, when the function mentions no redaction (`redact`, `mask`, `scrub`, `sanitize`, `obfuscate`). A value narrowed by a subscript or `.get(...)` is not whole. One finding per function, CONFIRMED: medium when headers are stored, low for bodies only.
60. **`AUTH-TOKEN-COMPARE`** (review 3, low). A request value (headers, `META`, cookies, query string, form, data or body, directly or through local names) compared by `==`, `!=`, `in` or `not in` with a secret: a `settings.X` or environment read whose name says token, secret, key, password, passcode, signature or HMAC, or a `digest()`/`hexdigest()` result. Comparisons with a literal are not reported. One finding per file, CONFIRMED.
61. **Role template choices.** `OWASP-A01-PRIVILEGE-FIELDS` also counts a declared `ModelChoiceField`, `ModelMultipleChoiceField` or `PrimaryKeyRelatedField` whose `queryset` reads a model that declares `is_superuser` or `is_staff` (a role template such as a designation) and does not mention that flag, as "{field} (a {Model}, which sets is_superuser)": saving such a choice usually copies the flag to the user.
62. **`OWASP-A04-GET-SIDE-EFFECT` and `update`.** An `update(...)` call counts as a bulk write only on a queryset (a `filter`/`all`/`exclude` chain, `.objects.`, or a name assigned from one); inside a loop it is usually a dict being filled.
63. **Folded register chains.** A `register.yaml` chain may give `severity`, so only findings of that severity join it and the rest stay in their rule's issue, and `fold`, so the Markdown section prints its findings as one entry per app (the chain's `detail`, then one line per file listing each finding's subject and line) instead of one block each. Role-gated `OWASP-A01-UNSCOPED-QUERY` findings (low) use both: one register issue and one report entry per app. The JSON report keeps every finding.
64. **`OWASP-A01-UNSCOPED-QUERY` checks after the load and quiet responses.** A later check scopes the lookup only when it is a guard: a comparison or call in the test of an `if` whose branch returns or raises (a redirect, a 404 or a 403 on mismatch), an `assert`, or a call named like a check (a name word `has`, `can`, `check`, `verify`, `assert`, `ensure`, `require`, `validate`, `allowed`, `authorize`, `permitted` or `owns`, such as `has_commission_access(request.user, user.advisor_id)`), that uses both the caller (or a name derived from it, such as `advisor = request.user.advisor`) and the loaded record; the caller's own name is removed before the record is looked for, so `request.user` never matches a record named `user`. Any other call that receives the caller and the record makes the finding INFERRED ("a later call receives the caller"). In Django and DRF views `request.user` (and `<first parameter>.user`) is the caller on every route, so a public route, or one behind a mixin the classifier cannot read, that guards on it is scoped too. A lookup is skipped when it only checks existence or counts (`.exists()`, `.count()`, `.aggregate()`), and a handler is skipped when it calls nothing whose name starts with a write verb (`save`, `delete`, `create`, `update`, `set`, `send`, `process`, `approve`, `generate`, `run` and similar, or ends in `_or_create`) and every response it returns is a redirect to a literal, `reverse(...)` or an id, an error status, or a body (`HttpResponse`, `JsonResponse`, `Response`, `jsonify`) built only from literals, comparisons, counts and field reads that the personal data classifier does not mark (judged by the field read, so `division_display_name` holding `get_division_display()` is not personal), with no queryset, serializer, form, template or record dump. Consistent with the classifier, a premium or other financial value is personal, so a premium calculator stays reported. A date in the URL (`from_date`, `year`, `month` and similar) is not an identifier.
65. **Role-gated tenant lookups.** A request id is a tenant id when every word before its key suffix (`id`, `pk`, `uuid`, `code`, `slug`) names a tenant kind: brokerage, company, branch, organisation, organization, org, account, agency, tenant, workspace, firm, franchise, practice or team (`brokerage_id`, `brokerage_branch_id`; not `pasa_blocked_account_id`). A tenant record looked up by a tenant id is reported even when its model has no owner column, because it is the tenant itself. On a role-gated route (refinement 36) such a lookup is cited first and the finding is medium, medium exploitability, INFERRED ("the role check does not tie brokerage_id to the caller's own brokerage"): a role says what a caller may do, not which tenant they belong to. The register groups these into one folded issue per app, "Role-gated routes reach any brokerage, company or branch by its id".
66. **One finding per route for A01.** A public route that `OWASP-A01-PUBLIC-SENSITIVE` reports (CONFIRMED or INFERRED) or that `OWASP-A01-UNSIGNED-CALLBACK` reports gives no `OWASP-A01-UNSCOPED-QUERY` finding: the other finding carries the lookup's location (and the model's sequential key). `OWASP-A01-PUBLIC-SENSITIVE` adds the action "looks up a {model} record by {key}" after lists and before jobs when it has no personal data lookup of its own, and `OWASP-A01-UNSIGNED-CALLBACK` adds to its detail that it picks the record to change by that key. Either becomes critical when the lookup is by the sequential primary key of an owned model, so the stronger severity is kept.
67. **Django signing salts.** A salt-named setting whose every read in the repository is the `salt=` of a Django signing call (`Signer`, `TimestampSigner`, `signing.dumps`/`loads`, signed cookies) only separates one kind of signature from another: the signing secret is `SECRET_KEY`, which `LEAK-SECRET-ENV-DEFAULT` already covers. Such a fallback is not reported. A salt that is read anywhere else (hashed with a value, `Hashids(salt=...)`) is still a secret.
68. **Vendored markup and operator input.** `BASE-MIXED-CONTENT` skips vendored files, like the sink rules of refinement 25, so a copied library's own HTML pages are not reported. `LEAK-LOGGED-PII` does not count a bare name that its scope (the function, or the module for top-level code) only ever sets to a literal or to what the person running the script typed or passed (`input()`, `getpass()`, `sys.argv[...]`, and string methods of those): printing it discloses nothing about anyone else. A function parameter is never such a name.
69. **`OWASP-A06-VENDORED-LIB` per library.** Copies of one library (by name, case ignored) form one finding: the title lists every version read in version order ("jQuery 1.4.1, 1.7.2, 1.12.4, 3.4.1 and 3.6.0"), the detail counts the copies and the files and says how many copies have no readable version, and the locations give the first file of each copy first (up to 20). A known library's version is also read from a version constant within its first 64 KB, named for the library or bare (`var pdfjsVersion = '2.2.222'`, `version = "1.12.4"`), and a library folder's version from its build output (`pdfjs/build/pdf.worker.js`). Files in a documentation folder (`docs`, `doc`, `documentation`), such as a saved web page and its assets, stay vendored so sink rules skip them, but are not reported as libraries.
70. **Two smaller cuts.** A route whose path carries a one-time token parameter (`<uidb64>/<token>`, `{token}`, `:token`) or ends in `done`, `complete`, `completed`, `success` or `sent` is not a public form (Django's `PasswordResetConfirmView` needs a signed token and the done page is static), so `ABUSE-FORM-NO-CHALLENGE` and the other public-form checks skip it. `BASE-HEADER-MISSING-*` does not cite a settings module production never loads (refinement 27: vendored, test, CI or local settings while a production settings module exists).
71. **Secret path segments.** A route whose only protection is a random literal path segment (a capability URL) must not print that segment. `Route` masks, when it is built, every literal segment of 16 or more characters that is a UUID, single-case hex with a digit and some entropy, or base64url that mixes case in short runs (camelCase words and slugs break into long runs), as `<redacted:path-token>`; parameters, words, versions, numeric ids and slugs stay. Every finding, section, table, register entry, SARIF result and CLI line takes the path from `Route`, and snippets mask the same segments next to a slash. Express mounts, Next.js matchers and frontend references are masked the same way before they are compared with a route path. `OWASP-A01-UNSIGNED-CALLBACK` says a masked callback is protected only by a secret path segment.
72. **Back-office admin gates and tenant lookups.** Refinement 65 applies only when some role check on the route is one an ordinary member or agent may pass. The checks are read from the route's decorators (with the source of decorators the repository defines), a class view's `permission_required` and base names, and role tests in the handler. A check is back-office administration when it is a superuser or staff test, a permission or group whose name has the word `admin`, `administrator`, `administer`, `superuser`, `staff` or `manage` (`brokerage.brokerage_admin`), or a permission to add, change or delete the tenant model itself (`change_brokerage` for `brokerage_id`). When every check is administration, the tenant lookup is by design and joins the low role-gated group; a member-level permission (`view_commission`), a custom role test (`u.is_advisor`) or a mix (`is_superuser or has_perm('x.view_commission')`) keeps it medium.
73. **Caller filters.** Names derived from the caller are followed in line order and through each other, including assignments inside a branch: after `user = request.user` and `rows = rows.filter(agent=user)`, `rows` is the caller's, so a later lookup on it (`rows.filter(status=status)`) is scoped. A related manager of the caller (`request.user.agent.policies.get(pk=pk)`) and a helper given the caller (`policies = own_policies(request.user)`) were already scoped by the same rule.
74. **Prices and reference records are not personal in responses.** Refinement 64's quiet-response test now treats a financial name as a price when it has a price word (`premium`, `price`, `fee`, `cost`, `rate`, `tariff`, and an insurance plan's `cover` and `benefit`): the price words and any `total`, `amount` or `sum` beside them are dropped before the name is classified again, so `total_premium`, `premium_payable__sum` and `cover_amount` are not personal while `basic_salary`, `commission_amount` and an invoice `total` still are (the classifier itself is unchanged). A response is also quiet when it is built from records of a reference model (not a user or person model, no field the classifier marks personal, no file field, no owner or tenant column; a rate table, a plan or product catalogue), from a helper whose name is a price (`get_grocery_education_premium(age, option)`) or that is given only values of reference records, or from the caller's own input (`request.POST['cover_amount']`). This replaces the last sentence of refinement 64: premium and cover calculators are no longer reported.
75. **Status and delivery callbacks; one role-gated finding per app.** `OWASP-A01-UNSIGNED-CALLBACK` also reads a route as a callback when its path or handler name has the word `delivery`, `delivered` or `receipt(s)`, or has `status` or `report` together with a message or payment channel word (`sms`, `message`, `mail`, `email`, `whatsapp`, `ussd`, `payment`, `transaction`), and it counts `run_in_background(...)` as a change, so a provider's delivery hook and `/report_sms_status` are callbacks rather than `OWASP-A01-UNSCOPED-QUERY` or `OWASP-A01-PUBLIC-SENSITIVE` findings. Role-gated `OWASP-A01-UNSCOPED-QUERY` lookups (low) are now one finding per app root: its title counts the routes, its locations are every route's lookup in file and line order, and its detail lists every route by file with its line, model, key and role check, so the JSON report keeps the list. This replaces the "one JSON finding each" of refinement 63; the low register chain no longer folds, while the tenant chain (refinement 65) still does.
76. **`OWASP-A06-KNOWN-ADVISORY`.** Exact dependency pins (`name==1.2.3` or `===` in `requirements*.txt`, `pyproject.toml` dependencies and Pipfile packages, an exact Poetry version, a bare or `=` version in `package.json`; ranges are not resolved) and versions read from copied libraries (refinement 69, mapped to a package by the table's `names`) are compared with `data/advisories.yaml`, a small, hand-checked, dated table (`as_of`) of published advisories: package, ecosystem, advisory id, dpr severity, a one-line summary and affected ranges as `[introduced, fixed)` pairs (`"0"` for every earlier version, a null fixed for no fix). Versions compare by their numeric parts, a pre-release sorting before its release and a post release as the release. One CONFIRMED finding per package and version, citing every manifest line or copy (test folders skipped), severity the worst of its advisories; the detail lists each id with its severity, fixed version and summary and names the table date, and the fix names the lowest version that fixes them all. The table lists only advisories whose id, range and fixed version are certain, so absence proves nothing: the "What this review did not cover" list says so with the table date. No network is used; `pip-audit` and `npm audit` stay behind `--with-audit`.
77. **`OWASP-A03-RAW-SQL` with bound arguments and SQL helpers.** A JS or TS SQL string is not reported when every part resolves to literal text: a literal or number, an UPPER_CASE constant, a ternary between such values, arithmetic or a comparison (a number or a boolean), a local or module name whose every assignment is such a value (`+=` appends included, and a name destructured from a helper call reads that key of the object the helper returns), `.join()` of a fixed array or of a `.map()` whose callback returns fixed text (the index parameter is a number), the parameter of an unexported local helper whose every caller in its scope passes fixed text (a helper also used as a value keeps its finding), and a call to a same-file or relatively imported helper whose returned text is fixed once its parameters take the call's arguments or their defaults. What is left is medium INFERRED when it carries no request value, passes values as extra bound arguments and its text holds `$1` or `?` placeholders. A finding in a file under a `scripts/` folder that no file outside such folders imports (a command-line tool no route reaches) is low.
78. **`OWASP-A03-XSS-SINK` for `Markup()` and `mark_safe()`.** A Python argument is safe, and not reported, when it is built only from constants, `escape()` or `Markup.escape()` output, f-string fields with a numeric format spec (`{n:,.0f}`, `{n:05d}`), concatenation, lists, comprehensions and `.join()` of such values, and local names whose every assignment is such a value; a comprehension variable is escaped when it iterates an escaped list. A field with no spec or a text spec (`{name}`, `{label:>10}`) is still reported. `OWASP-A03-HTML-EMAIL` shares the same test.
79. **`LEAK-HARDCODED-KEY` in tests and example comments.** Test files (the shared test-path check: `tests/`, `__tests__/`, `spec/`, `fixtures/`, `e2e/`, `test_*.py`, `*_test.py`, `*.test.ts`, `*.spec.ts` and similar) and scripts named `test-*`, `test_*`, `*_test.*` or `*.test.*` in any folder are not read: they feed key-shaped values to the code under test. A key on a comment line (`#`, `//`, `/*`, `*`, `--`, `<!--`, `;`, `rem`) that also holds a placeholder word (`example`, `sample`, `placeholder`, `dummy`, `fake`) is skipped, such as a comment naming a provider's documented example key. The same value outside a comment, or in a comment with no placeholder word, is still reported.
80. **`LEAK-ENV-IN-HISTORY` for test env files.** A historic `.env.test`, `.env.testing` or `.env.test.local` is low, with a detail that says its name marks it as a test environment file and a fix that asks to rotate only values that worked against a real service. Its values are still never read. `.env.example`, `.env.sample` and `.env.template` stay skipped, as in `LEAK-ENV-TRACKED`; `.env`, `.env.production`, `.env.staging` and other names stay high.
81. **Container rules read the build context and the shipped stages.** `BASE-DOCKERIGNORE-THIN` reads the `.dockerignore` of each build context: the `build` folder or `build.context` of every compose service (`docker-compose*.yml`, `compose*.yml`) whose Dockerfile it is, else the Dockerfile's own folder. A repository-root `.dockerignore` no longer covers a subfolder context (this replaces "or at the repository root" in refinement 54). The git history is required only when the context folder holds `.git`. Only a `COPY . <dest>` that ends in the image counts: one in the final stage, in a stage the final stage is built `FROM`, or in a stage whose whole root or `WORKDIR` it copies with `COPY --from`. A multi-stage build whose final stage copies only named build output (`/app/dist`, package files, `prisma`, `assets`) ships nothing from the context and is not reported. The finding cites the `COPY` line itself. `BASE-DOCKER-ROOT` is low, with a note, for a Dockerfile named for development (`Dockerfile.dev`, `*.development`, `dev.Dockerfile`) or built only by development compose files: a compose file whose name has `dev`, `development`, `local` or `override`, or that has no `prod`/`production` word while a compose file beside it does. A Dockerfile that a production compose file also builds, or that no compose file builds, stays medium. A final stage on the stock `nginx` image with no `USER` is skipped: its master process needs root to bind port 80 and its workers drop to the `nginx` user.
82. **FastAPI dependency gates.** A `dependencies=` list on a route decorator, on `APIRouter(...)` or `FastAPI(...)`, or on `include_router(...)` is also read through a module-level name it refers to (`_internal = [Depends(verify_internal_token)]`, then `dependencies=_internal`). A dependency guards the route when its name is an auth word (as before) or when its body turns callers away: it raises with 401 or 403 (`HTTP_401_UNAUTHORIZED`, `Forbidden`, `PermissionDenied`), or it takes a `Header(...)`, `APIKeyHeader(...)` or `Security(...)` parameter and compares it with a secret (`compare_digest`, or a comparison with a `settings.X`, `os.environ`, `getenv` or `config.X` read). A dependency whose every definition does nothing (only a docstring, `pass`, `...` or a constant or bare `return`) guards nothing whatever its name. An internal-token gate is such a header compared with a configured secret, with no user lookup (`get_current_user`, `decode(`, `jwt.`): `ABUSE-PAID-UNLIMITED` skips the routes behind it, since the limit belongs to the backend routes that call the service. When that gate returns early while the secret is unset (`if not expected: return`, `is None`, `== ""`, before any `raise`), `ABUSE-GATE-FAIL-OPEN` (review 7, low, CONFIRMED) reports it once per app root, citing the gate function and counting the routes and paid routes behind it.

## 4. Non-negotiable rules, enforced in code

| Skill rule | Enforcement |
|---|---|
| Inventory, not legal advice | Report renderer test fails if output matches `compliant with`, `complies with`, `satisfies Article`, `satisfies Section`, `lawful basis is`. Templates contain the fixed disclaimer. |
| Evidence tag on every finding | `Finding.tag` is required. `Finding.__post_init__` raises `ValueError` if tag is CONFIRMED and `locations` is empty. |
| Never upgrade a tag | Tags are set once at creation. `Finding` is a frozen dataclass. Dedupe chooses between existing findings and never changes a tag. |
| Static analysis by default | The only network calls are: live header read (needs `--url` and `--i-own-this-host`), Semgrep's own download of registry rules when Semgrep is installed and no local rules folder is given (`--semgrep DIR` avoids it), and audits (needs `--with-audit`). A test patches `socket.socket.connect` and asserts the `dpr` process opens no connection in a run with `semgrep="off"`, no `url`, and no audits. |
| Never print a secret value | Matchers replace the matched secret span with `<redacted:KIND>` before building any object. `Finding` has no raw-match field. Every snippet also masks credential shapes on the whole line before cutting it (refinement 20 in section 3). Route paths mask secret-looking literal segments (capability URLs) as `<redacted:path-token>` when the route is built (refinement 71). Personal values are masked the same way: email addresses, South African mobile numbers, and ID numbers and IBANs that pass their checks (refinement 55); rules that find personal data by value report counts only. Tests assemble fake keys, a corpus of credential shapes and checksum-valid fake ID numbers, IBANs, accounts and mobile numbers and a hex path token at runtime, run all formats and CLI output, and assert none of the values appear. Semgrep results from secret rules have `extra.lines` dropped. |
| Report is sensitive | `dpr.review()` writes nothing. Only the CLI writes, to `<PATH>/data-protection-review/` by default. The CLI prints a gitignore hint if that folder is not ignored. It never edits `.gitignore` and never runs `git add` or `git commit`. |
| Rank by risk removed per minute | Section 6.3. |

## 5. Architecture

### 5.1 Public API

```python
import dpr

report = dpr.review(
    path="/path/to/repo",
    reviews=("all",),              # or ("leaks", "rls") or (2, 5)
    answers="dpr-answers.yaml",    # path, dict, or None
    url=None,                      # live header read
    owns_host=False,               # must be True when url is set
    login_path=None,               # default: detected from routes, else /login
    with_audit=False,
    semgrep="auto",                # "auto" | "off" | path to local rules dir
    db_dump=None,                  # path to pasted pg_tables / pg_policies output
    include_untracked=False,       # in git, also scan untracked files git does not ignore
)

report.findings        # list[Finding], ranked
report.detection       # Detection
report.sections        # dict[str, ReviewSection], keyed by review slug
report.questions       # list[QuestionResult], answered and open
report.not_covered     # list[str]
report.meta            # project name, scope, git sha or "uncommitted working tree", date, reviews run, method

dpr.render_markdown(report) -> str
dpr.render_json(report) -> str
dpr.render_sarif(report) -> str
```

`dpr.review()` has no side effects on disk.

### 5.2 Run pipeline

1. **Walk.** Build a `RepoIndex` of files once (section 7.1).
2. **Discover.** Produce `Detection` (section 8).
3. **Select reviews.** Resolve numbers and slugs. Drop reviews that do not apply and record why in `not_covered`. `rls` applies only when SQL table definitions, a Supabase client, or a `--db-dump` exist.
4. **Questions.** Merge the question ids of the selected reviews, drop those answered by detection, fill from the answers source, mark the rest UNKNOWN (section 9).
5. **Run reviews.** Each review is `run(index, detection, answers) -> ReviewResult(findings, section)`. Reviews read other reviews' results only through `Detection` and a shared read-only `Facts` store filled in a fixed order: leaks, rls, baseline, auth, owasp, abuse, inventory. Inventory runs last because it consumes logged-PII and SDK facts.
6. **Adapters.** Semgrep and audits run inside the owasp review. Live headers run inside the baseline review.
7. **Dedupe and rank** (section 6.3, 6.4).
8. **Return** `Report`.

### 5.3 Package layout

```
app-prep/
  pyproject.toml
  uv.lock
  src/dpr/
    __init__.py            review, render_markdown, render_json, render_sarif
    api.py                 review() pipeline
    cli.py                 argparse entry point: scan, questions
    model.py               Finding, Location, Tag, Severity, Exploitability, Report, ReviewSection
    rank.py                scoring and dedupe
    rules.py               rule decorator and registry
    walk.py                RepoIndex
    parsing/
      jsts.py              tree-sitter wrapper, query helpers
      pyast.py             ast helpers
      sql.py               statement splitter and schema state
      prisma.py            schema.prisma parser
      schemas.py           model extraction: Prisma, SQL, Django, SQLAlchemy, Drizzle
      routes.py            route extraction per framework
    discovery/
      detect.py            Detection builder
    reviews/
      inventory.py
      rls.py
      auth.py
      baseline.py
      owasp.py
      leaks.py
      abuse.py
    adapters/
      semgrep.py
      audits.py
      headers.py
    questions/
      catalogue.py
      prompt.py
    report/
      markdown.py
      templates/report.md.j2
      json_out.py
      sarif.py
    data/
      pii_terms.yaml       personal data terms by category
      secrets.yaml         key patterns and secret-name words
      sdks.yaml            SDK names, category, data recipient, paid
      costs.yaml           default limits per paid category
      weights.yaml         severity, exploitability weights, A01 boost
      questions.yaml       question catalogue
      rule_text.yaml       attack, blast, fix, verify templates per rule id
  tests/
  docs/superpowers/specs/
  tasks/
  .github/workflows/ci.yml
```

No module over about 400 lines. A review that grows past that splits into a package (`reviews/owasp/a01.py` and so on).

### 5.4 Dependencies

Runtime: `tree-sitter`, `tree-sitter-javascript`, `tree-sitter-typescript`, `pyyaml`, `jinja2`. Everything else is stdlib, including `urllib` for header reads and `argparse` for the CLI.

Dev: `pytest`, `pytest-cov`, `ruff`.

Optional, not declared as dependencies: `semgrep`, `npm`, `pip-audit`, `git`. Each is looked up with `shutil.which` and recorded as not run when missing.

## 6. Data model

### 6.1 Finding

```python
@dataclass(frozen=True)
class Location:
    file: str          # repo-relative, forward slashes
    line: int          # 1-based
    end_line: int | None = None

@dataclass(frozen=True)
class Finding:
    rule_id: str               # e.g. "LEAK-PUBLIC-SECRET"
    review: str                # slug
    title: str
    tag: Tag                   # CONFIRMED | INFERRED | UNVERIFIED | UNKNOWN
    severity: Severity         # critical | high | medium | low
    exploitability: Exploitability  # high | medium | low
    effort_minutes: int
    locations: tuple[Location, ...]
    snippet: str | None        # redacted source excerpt, max 5 lines
    detail: str                # what was found, one short paragraph
    proof_needed: str | None   # required when tag is INFERRED
    attack: str | None
    blast: str | None
    fix: str                   # exact change, diff, or SQL
    verify: str | None         # command the user runs
    owasp: str | None          # "A01" .. "A10"
    source: str = "dpr"        # "dpr" | "semgrep:<rule id>" | "npm-audit" | "pip-audit"
    refs: tuple[str, ...] = () # related rule ids for cross-references
```

Validation in `__post_init__`: CONFIRMED requires at least one location. INFERRED requires `proof_needed`.

### 6.2 Tags

| Tag | Set when |
|---|---|
| CONFIRMED | A parser or exact read proves it at a cited location. |
| INFERRED | A regex or heuristic matched, or a parser matched but a helper call or later check could change the answer. `proof_needed` says what would settle it. |
| UNVERIFIED | Needs a runtime or dashboard check. |
| UNKNOWN | A question with no answer. |

### 6.3 Ranking

`score = severity_weight * exploitability_weight * boost / max(effort_minutes, 1)`

Default `weights.yaml`:

```yaml
severity: {critical: 100, high: 40, medium: 10, low: 3}
exploitability: {high: 3, medium: 2, low: 1}
tag_factor: {CONFIRMED: 1.0, INFERRED: 0.6, UNVERIFIED: 0.4}
boost: {A01: 1.5}
leaks_order: [LEAK-PUBLIC-SECRET, LEAK-HARDCODED-KEY, LEAK-KEY-IN-BUILD, LEAK-ENV-TRACKED, LEAK-ENV-IN-HISTORY, LEAK-BROAD-RESPONSE, LEAK-SSR-PROPS, LEAK-LOGGED-PII]
```

`tag_factor` multiplies the score. UNKNOWN items are questions, not findings, and are not ranked. Within the leaks review section, findings are ordered by `leaks_order` first, then score. The report summary's "top three fixes" is the top three by score across all reviews.

### 6.4 Dedupe

Two passes:

1. Within `dpr` rules: key `(rule_id, first location file, first location line)`. Duplicates come from a rule matching the same line twice; keep the first.
2. Between Semgrep and `dpr`: a Semgrep finding is dropped when a `dpr` finding has the same `owasp` category and the same first location file and line. The `dpr` finding gains the Semgrep rule id in `refs`.

Dedupe chooses which existing finding survives. It never edits a tag.

### 6.5 Report sections

Each review returns a `ReviewSection` holding the tables and text blocks its part of the report template needs (for example the RLS table protection status rows, or the inventory data map rows). Section shapes are defined per review in section 10.

## 7. Walking and parsing

### 7.1 RepoIndex

- Skipped directories: `node_modules`, `.git`, `.next`, `dist`, `build`, `out`, `vendor`, `.venv`, `venv`, `__pycache__`, `.turbo`, `coverage`, `.pytest_cache`, `.mypy_cache`, `data-protection-review`, `site-packages`, and any directory that holds a `pyvenv.cfg` file (a virtualenv under any name, such as `.env/` or `env/`).
- Build output directories (`dist`, `build`, `out`, `.next/static`) are indexed separately as `build_files` and read only by the leaks review.
- In a git repository only tracked files are indexed, plus untracked files that git does not ignore with `--include-untracked`; outside git every file is walked (refinement 23 in section 3). Build output directories are read whatever git says.
- Symlinks are not followed.
- Binary files (null byte in the first 8 KB) are skipped.
- Source files over 1 MB are skipped and listed in `not_covered`. Build files up to 10 MB are scanned with key regexes only.
- Text read as UTF-8 with `errors="replace"`; a leading byte order mark is dropped (`utf-8-sig`).
- Parsed trees are cached per file for the run.

**Sanity check.** If a `package.json`, `pyproject.toml` or `requirements*.txt` is present and no supported source file was indexed at all (no JS/TS/Vue/Svelte file and no `.py` file), raise `ScanError`. A Python repository with a tooling-only `package.json`, or a JS repository with a docs `requirements.txt`, scans normally. This is the silent empty-scan failure the skill hit.

### 7.2 JS/TS

tree-sitter grammars `javascript`, `typescript`, `tsx`. `.vue` and `.svelte` files: extract each `<script>` block, parse it as `ts` when `lang="ts"` else `javascript`, and add the block's start line offset to every location.

Helpers: find call expressions by callee path (`prisma.*.findUnique`), read object literal keys and values, resolve a local `const` to its initialiser within the same function, list exported function names, find string literals matching a pattern.

### 7.3 Python

stdlib `ast`. Files that fail to parse are listed in `not_covered`. Helpers mirror 7.2: calls by dotted name, keyword arguments, class bases, decorators, assignments in module scope.

### 7.4 SQL

A statement splitter that respects single quotes (with backslash escapes inside `E'...'` strings), double-quoted identifiers, dollar quoting (`$$` and `$tag$`), `--` and `/* */` comments. Recognised statements:

- `CREATE TABLE` (columns and types, schema, primary key)
- `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` and `DISABLE`
- `CREATE POLICY`, `ALTER POLICY`, `DROP POLICY` (name, table, permissive, command, roles, `USING`, `WITH CHECK`)
- `CREATE VIEW` / `CREATE OR REPLACE VIEW` (options including `security_invoker`, source tables)
- `CREATE FUNCTION` / `CREATE OR REPLACE FUNCTION` (`SECURITY DEFINER`, `SET search_path`, tables referenced in body)
- `INSERT INTO storage.buckets` (id, `public`)
- `GRANT ... TO anon | authenticated | public`
- `DROP TABLE`

Migration files are applied in filename order to a `SchemaState`. Sources: `supabase/migrations/*.sql`, `migrations/**/*.sql`, `prisma/migrations/*/migration.sql`, `db/**/*.sql`, `schema.sql`.

Predicates (`USING`, `WITH CHECK`) are kept as normalised text (lowercased outside string literals, whitespace collapsed) and inspected with targeted patterns, not a full expression parser.

### 7.5 Prisma

Line parser for `model` blocks: field name, type, optional/list markers, attributes (`@id`, `@unique`, `@default(autoincrement())`, `@relation(... onDelete: Cascade)`, `@map`), and block attributes (`@@map`, `@@unique`).

### 7.6 Schema extraction

`schemas.py` returns a common `Model(name, table, source, fields[Field(name, type, unique, location)])` from Prisma, SQL `SchemaState`, Django (`models.Model` subclasses), SQLAlchemy (classes with `__tablename__`, `Column` or `mapped_column`), and Drizzle (`pgTable`, `mysqlTable`, `sqliteTable` calls).

### 7.7 Routes

`routes.py` returns `Route(method, path, file, line, framework, is_public_form, wrappers, handler_node)`:

All Next.js paths below are also matched under `src/`.

- Next.js app router: `app/**/route.{js,ts}` exported `GET`, `POST`, `PUT`, `PATCH`, `DELETE`. Path from folders, `[id]` kept as `:id`, route groups `(name)` removed.
- Next.js server actions: functions in files starting with `"use server"`. Method recorded as `ACTION`.
- Next.js pages router: `pages/api/**`. Method `ANY` unless the handler branches on `req.method`.
- Express and Fastify: `app.<method>(` and `router.<method>(` calls.
- Django: `path()` and `re_path()` in `urls.py`, resolved to the view function or class the `urls.py` imports, else by name in the same app, never to a Celery task (refinement 34). DRF `router.register`.
- Django Ninja: `@api.<method>` and `@router.<method>` decorators in files importing `ninja`.
- FastAPI: `@app.<method>` and `@router.<method>` decorators.
- Flask: `@app.route` and `@bp.route` with `methods=`.

Handlers passed through a wrapper call, such as `export const POST = withAuth(async () => ...)` or `router.get('/x', auth, asyncHandler(async (req, res) => ...))`, are unwrapped to the last function argument, and `export { handler as GET, handler as POST }` is followed to `handler`. A wrapper call with no function argument is kept as the handler. `wrappers` lists the wrapper callees, outermost first, and for Express and Fastify it starts with the middleware names between the path and the handler (Fastify `onRequest`, `preParsing`, `preValidation` and `preHandler` options included).

`is_public_form` is true when the path or handler name contains `signup`, `sign-up`, `register`, `login`, `signin`, `reset`, `forgot`, `contact`, `waitlist`, `newsletter`, `feedback`, `invite`, `upload`.

## 8. Discovery

`Detection` fields:

| Field | Source |
|---|---|
| `languages` | file counts per language |
| `frameworks` | dependency names in `package.json`, `pyproject.toml`, `requirements*.txt`, plus file signals (`next.config.*`, `manage.py`) |
| `databases`, `orms` | dependencies and schema files |
| `auth_providers` | dependencies and imports: Supabase auth, Clerk, Auth0, NextAuth / Auth.js, Firebase auth, Passport, Lucia, Better Auth, Django auth, FastAPI security utilities; hashing libraries |
| `env_vars` | names from every `.env*` file in the repo root and app folders, and code references (`process.env.X`, `import.meta.env.X`, `os.environ["X"]`, `os.getenv("X")`, `env("X")` from django-environ). Env files are read line by line and only the text before `=` is kept; the rest of the line is discarded before any object is built, and the safety test covers this. Each name has `public: bool` from prefixes `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `PUBLIC_`, `NUXT_PUBLIC_`, `EXPO_PUBLIC_`, `GATSBY_`, and the files and lines it appears in. |
| `public_supabase_key` | true when a public-prefixed env name contains `SUPABASE` |
| `sdks` | `sdks.yaml` matched against dependencies and imports, with call-site locations |
| `routes` | section 7.7 |
| `models` | section 7.6 |
| `hosting` | `vercel.json`, `netlify.toml`, `fly.toml`, `render.yaml`, `railway.json`, `app.yaml`, `Procfile`, `Dockerfile`, `docker-compose.yml`, `serverless.yml`, `*.tf` |
| `ci` | `.github/workflows/*` |
| `logging` | logger libraries and Sentry init locations |
| `header_config` | files that set security headers |
| `rate_limiters` | limiter libraries and call sites |
| `test_frameworks` | jest, vitest, playwright, pytest, django test runner |
| `git` | is repo, HEAD sha or `uncommitted working tree`, via `git` subprocess when present |
| `serverless` | true when hosting is Vercel, Netlify, or `serverless.yml` / Lambda handlers exist |

The detection table in the report shows: language and framework, database and ORM, auth provider, hosting, API route count, third-party SDK count, RLS or policy files present, rate limiting present, security headers configured. It then lists which reviews apply and which do not, with the reason.

## 9. Questions and answers

`questions.yaml` entries:

```yaml
- id: db_region
  reviews: [inventory]
  text: Which region are the database, object storage and backups provisioned in?
  type: choice            # choice | multi | text
  options_from: hosting   # detection field used to build options
  static_options: []
  honest_out: ["Not sure"]
  answered_by: null       # detection key that answers it, if any
  lawyer: true            # also listed for the data protection lawyer
```

v1 catalogue (merged and deduped from the skill's "Cannot be determined from code" lists):

| id | Reviews |
|---|---|
| `user_countries` | inventory |
| `company_country` | inventory |
| `db_region` | inventory |
| `retention_policy` | inventory |
| `prod_access` | inventory |
| `dpas_in_place` | inventory |
| `data_outside_repo` | inventory |
| `frontend_key_type` | rls |
| `rls_via_dashboard` | rls |
| `tables_not_in_migrations` | rls |
| `buckets_public` | rls |
| `provider_email_templates` | auth |
| `provider_session_lifetimes` | auth |
| `edge_protection` (CDN or WAF headers, rate limits, blocking) | auth, baseline, owasp, abuse |
| `provider_hash_params` | baseline |
| `tls_termination` | baseline |
| `prod_config_matches_repo` | owasp |
| `hosting_env_not_in_repo` | leaks |
| `log_tool_access_retention` | leaks |
| `traffic_peak` | abuse |
| `spend_caps` | abuse |
| `alert_channel` | abuse |

Answers source, in order: the `answers` dict or YAML file (keys are question ids, unknown keys produce a warning), then `--interactive` prompts on a TTY for up to 8 remaining questions in catalogue order, then UNKNOWN. A value of `"Not sure"` or `"No formal policy"` is recorded as UNKNOWN with that wording kept.

`dpr questions PATH` runs discovery only and writes `dpr-answers.yaml` with the open questions for that repo as commented entries, options included.

Lawyer questions: the 11 from the skill's inventory reference, each mapped to the question ids or detection fields that answer it. Rendered in the three groups of the report template: answered by this review, still open (with why the repo cannot answer and who can), and for the data protection lawyer.

## 10. Reviews

Each subsection lists rule ids with default tag, severity and exploitability. Effort minutes and fix text come from `rule_text.yaml`.

### 10.1 Leaks (`leaks`, review 6)

| Rule | Detects | Tag | Sev | Expl |
|---|---|---|---|---|
| `LEAK-PUBLIC-SECRET` | Public-prefixed env name containing a secret word from `secrets.yaml` (`SERVICE_ROLE`, `SECRET`, `PRIVATE`, `ADMIN`, `WEBHOOK_SECRET`, `DATABASE_URL`, `DB_URL`, `SMTP`, `PASSWORD`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `AWS_SECRET`, `ACCESS_KEY`) at a code reference or example env file line | CONFIRMED | critical | high |
| `LEAK-HARDCODED-KEY` | Key pattern in indexed source: `sk_live_`, `rk_live_`, `sk_test_`, `sb_secret_`, `xox[baprs]-`, `AKIA[0-9A-Z]{16}`, `ghp_`, `gho_`, `github_pat_`, `AIza[0-9A-Za-z_-]{35}`, JWTs whose decoded payload has `role: service_role`; test files and example comments skipped (refinement 79) | CONFIRMED | critical (test keys: high) | high |
| `LEAK-KEY-IN-BUILD` | Same patterns in `build_files` | CONFIRMED | critical | high |
| `LEAK-ENV-TRACKED` | `git ls-files` lists `.env*` other than `.example`, `.sample`, `.template`. The file's variable names are read (never values) | CONFIRMED | critical when a name is not public-prefixed or looks secret, or the file cannot be read (for example tracked but deleted from the working tree); low when every name is public-prefixed and not secret-like, with the note that frameworks such as Next.js commit these on purpose | high |
| `LEAK-ENV-IN-HISTORY` | `git log --all --diff-filter=A --name-only` shows such a file was ever added | CONFIRMED | high; low for `.env.test` or `.env.testing` (refinement 80) | medium |
| `LEAK-SOURCEMAP` | `*.map` in build output (not under a vendored library folder), `productionBrowserSourceMaps: true`, Vite `build.sourcemap: true` | CONFIRMED | medium | medium |
| `LEAK-BROAD-RESPONSE` | Route returns a whole record: `NextResponse.json(x)` / `res.json(x)` where `x` comes from an ORM call without `select`; DRF serializer `fields = "__all__"` on a model with a personal field or an unknown model; a `model_to_dict`, `vars()` or `__dict__` dump that reaches the handler's response; `select *` or Supabase `.select('*')` in a route | INFERRED | high if the model has a sensitive column (`password`, `hash`, `token`, `secret`, `stripe_customer_id`, `role`), else medium | medium |
| `LEAK-SSR-PROPS` | `getServerSideProps` / loader returning an ORM result without `select` | INFERRED | medium | medium |
| `LEAK-LOGGED-PII` | `console.log/error`, `logger.*`, `print`, `logging.*` with an argument named or rooted in `req`, `request`, `body`, `user`, `token`, `payload`, `headers`, `err` / `e` of a DB call; `traceback.print_exc()`. A name its scope only sets to the operator's own input or a literal is not counted (refinement 68) | INFERRED | medium | low |
| `LEAK-SENTRY-PII` | `sendDefaultPii: true`, `send_default_pii=True`, or Sentry init without `beforeSend` / `before_send` | CONFIRMED | medium | low |
| `LEAK-REQUEST-LOG` | A request or response logger that stores whole headers or bodies in a log or table with no redaction (refinement 59); one finding per function | CONFIRMED | medium; low for bodies only | low |
| `LEAK-PUBLIC-GATE-KEY` | Public-prefixed env name that reads as an access gate (`BYPASS`, `UNLOCK`, `OVERRIDE`, `MASTER_KEY`, `ACCESS_CODE`, `INVITE_CODE`, `MAINTENANCE_KEY` and similar), citing any committed value's location | CONFIRMED | low | medium |
| `LEAK-DEFAULT-CREDENTIAL` | Committed default credentials in compose files, scripts and docs: literal secret-named compose values, shell defaults such as `${DB_PASSWORD:-value}`, connection URLs with an inline password, password flags on command lines. Reports locations only, never the value | CONFIRMED | low | low |
| `LEAK-SECRET-ENV-DEFAULT` | A secret-named environment read with a non-empty literal fallback, a secret-named literal in a settings module, or a literal Hashids salt, in code production may load (refinement 40); a salt read only by Django signing is not a secret (refinement 67). One finding per file naming each setting, never the value | CONFIRMED | critical for a signing key; high; low when every value is a placeholder | medium |
| `LEAK-LITERAL-HTTP-AUTH` | A literal password in `auth=("user", "...")`, `HTTPBasicAuth` and similar, or a literal `Authorization` header value (refinement 40) | CONFIRMED | high | high |
| `LEAK-PII-LITERAL-IN-CODE` | Three or more distinct South African ID numbers that pass the date and checksum checks written as literals in a code file, or five or more quoted mobile numbers; one finding per file with counts, never the values (refinement 55) | CONFIRMED; INFERRED for mobile numbers alone | high; medium for mobile numbers; low in tests | medium |

Every key finding's fix text starts with "Rotate the key now. It already reached a browser or history; removing it from the next build does not undo that." The key value is never included; the finding names the variable or key kind and the location.

Section shape: leak blocks in the skill's output format.

### 10.2 RLS (`rls`, review 2)

Input: `SchemaState` from migrations and, when given, `--db-dump`.

| Rule | Detects | Tag | Sev | Expl |
|---|---|---|---|---|
| `RLS-TABLE-OFF` | Table in `public` schema never enabled, or disabled last | CONFIRMED | critical when `public_supabase_key` is true, else high with a reduced-relevance note | high |
| `RLS-NO-POLICIES` | Enabled, zero policies | CONFIRMED | low | low |
| `RLS-SELECT-ONLY` | Select policies only (deviation 1 in section 3) | CONFIRMED | low | low |
| `RLS-POLICY-TRUE` | `USING (true)` on a table with an owner or tenant column | CONFIRMED | high | high |
| `RLS-AUTHENTICATED-NOT-OWNER` | Predicate only checks `auth.role() = 'authenticated'`, or `TO authenticated` with a predicate that never references `auth.uid()` or `auth.jwt()`. Like `RLS-POLICY-TRUE`, only on tables with an owner or tenant column, or with unknown columns (dump only) | CONFIRMED, or INFERRED when the predicate calls a helper function | high | high |
| `RLS-WEAK-WITH-CHECK` | `INSERT`, `UPDATE` or `ALL` policy on a table with an owner column whose `WITH CHECK` is present and references neither the owner column, `auth.uid()` nor `auth.jwt()` (deviation 2 in section 3) | CONFIRMED, or INFERRED when the `WITH CHECK` calls a helper function | high for `INSERT`; for `UPDATE` and `ALL`, low when the table has select policies and every select policy on the table references the owner column or `auth.uid()`, else high | high |
| `RLS-WRONG-ROLE` | Write policy granted `TO public` or `TO anon` on a table with an owner column | CONFIRMED, or INFERRED when the predicate calls a helper function | high | high |
| `RLS-CLIENT-OWNER` | Predicate reads `user_metadata` from `auth.jwt()`, or `current_setting('request.headers'` | CONFIRMED | high | high |
| `RLS-TENANT-UNBOUND` | Predicate has a subquery over a membership-like table (`member`, `membership`, `org_users`, `team_users`) filtered by `auth.uid()` but never references the policy table's tenant column (`org_id`, `organization_id`, `tenant_id`, `workspace_id`, `team_id`) | INFERRED (the membership match is a heuristic); when the predicate calls a helper function, `proof_needed` asks to read that function | high | high |
| `RLS-VIEW-BYPASS` | View in `public` over an RLS table without `security_invoker = true` | CONFIRMED | high | high |
| `RLS-DEFINER-FUNCTION` | `SECURITY DEFINER` function in `public`; severity high if its body reads an RLS table, plus a note when `search_path` is not set | CONFIRMED | medium or high | medium |
| `RLS-PUBLIC-BUCKET` | `storage.buckets` row with `public = true`, or `createBucket(..., { public: true })` | CONFIRMED | medium | medium |

Policy checks that look for a policy granting too much (`RLS-POLICY-TRUE`, `RLS-AUTHENTICATED-NOT-OWNER`, `RLS-WEAK-WITH-CHECK`, `RLS-WRONG-ROLE`, `RLS-TENANT-UNBOUND`) ignore restrictive policies, which cannot grant access, and policies granted only to `service_role`, `postgres` or `supabase_admin`, which clients do not use. The select policies counted for `RLS-WEAK-WITH-CHECK` severity are the permissive `SELECT` and `ALL` policies left after the same filter. A helper function is any function call in the predicate other than `auth.uid()`, `auth.jwt()` and `auth.role()`; its `proof_needed` is "Read the called function to confirm it checks the row owner or tenant." `ALTER TABLE ... RENAME TO` moves the table, its policies and its RLS flag to the new name.

Owner column detection: `user_id`, `owner_id`, `created_by`, `author_id`, `profile_id` (first match wins). Tenant column: list above.

Generated SQL per gap: `alter table ... enable row level security;` plus select, insert, update, delete policies using `auth.uid() = <owner column>`, or `<tenant column> in (select <tenant column> from <membership table> where user_id = auth.uid())` when a tenant column and membership table exist. When no owner or tenant column exists, the fix says so and gives the enable statement only, with a comment to choose the predicate.

Breakage note: routes from detection that query the table through the Supabase client are listed as "queries that may start returning nothing after this change".

Section shape: table `table | RLS enabled | policy count | reachable by anon key | verdict | evidence`, policy defects, missing policies (SQL), the two `pg_tables` / `pg_policies` queries when migrations are absent or incomplete, and outside confirmation commands (`curl` against `/rest/v1/<table>` with `$ANON_KEY`, pass and fail described). `dpr` never runs these commands.

When the data layer is Prisma or another server-only ORM and no public client key is detected, the section states reduced relevance and emits no RLS findings.

`--db-dump` accepts psql aligned output or CSV of the two queries. Findings from it use `Location(file="<dump file>", line=<row line>)`.

### 10.3 Auth failure path test plan (`auth`, review 3)

The ten cases from the skill are fixed templates with Expected text. Each case has detector functions that set "This app".

| Case | Detectors | Possible result |
|---|---|---|
| 1 Wrong password five times | limiter on the login route; lockout fields (`failed_attempts`, `locked_until`); `django-axes` declared or in settings, with `AUTH-LOCKOUT-WEAK` for weak `AXES_*` settings (refinement 44) | INFERRED; CONFIRMED for axes settings |
| 2 Reset for unregistered email | string literal matching `no (account\|user) (found\|exists\|with)`, `not registered`, `does(n't\| not) exist` in reset handlers or UI | CONFIRMED fail when found, else UNVERIFIED |
| 3 Verification link twice | token model has `used_at` / `consumed` / `verified_at`, or token deleted in the verify handler | INFERRED |
| 4 Signup with existing email | string literal matching `already (registered\|exists\|in use\|taken)` | CONFIRMED fail when found, else UNVERIFIED |
| 5 Session left open | cookie `maxAge` / `expires`; JWT `expiresIn`; NextAuth `session.maxAge`; Django `SESSION_COOKIE_AGE`; cookie flags | CONFIRMED values |
| 6 Expired reset link | server-side expiry comparison in the reset handler | INFERRED |
| 7 Reset token for someone else | reset handler reads both `email` and `token` from the body and updates by `email` | INFERRED fail |
| 8 Concurrent signup | unique constraint on the email field | CONFIRMED pass or fail |
| 9 Email change | handler writes `email` directly with no verification token step | INFERRED fail |
| 10 Logout and back button | logout only clears client storage; `Cache-Control: no-store` on authenticated responses | INFERRED |

When a managed provider handles a case, "This app" says so and the result is UNVERIFIED with the provider named.

Failed cases also become findings `AUTH-CASE-<n>` so they rank with everything else. Outside the cases, `AUTH-TOKEN-COMPARE` (low, CONFIRMED) reports request tokens compared with a secret by `==` rather than a constant-time compare (refinement 60). Case 2 and 4 findings carry `refs` to the baseline enumeration note instead of duplicating it.

Section shape: one block per case (`CASE n`, Expected, This app, Risk, Test), failing cases first by exploitability.

### 10.4 Baseline (`baseline`, review 4)

| Rule | Detects | Tag | Sev | Expl |
|---|---|---|---|---|
| `BASE-COOKIE-HTTPONLY` / `-SECURE` / `-SAMESITE` | Parsed cookie set calls: Next `cookies().set`, `res.cookie`, `Set-Cookie` literals, `response.set_cookie`, Django `SESSION_COOKIE_*` / `CSRF_COOKIE_*` | CONFIRMED | high for session-like names (`sid`, `session`, `token`, `auth`, `jwt`), else low | medium |
| `BASE-HEADER-MISSING-<NAME>` | HSTS, CSP, X-Content-Type-Options, frame protection, Referrer-Policy, Permissions-Policy not set on a header surface; each static host config and app is judged on its own (refinement 7 in section 3); settings modules production never loads are not cited (refinement 70) | UNVERIFIED, CONFIRMED with `--url` | HSTS high, CSP medium, others low | low |
| `BASE-CSP-WEAK` | `unsafe-inline` in `script-src` (not when a nonce or hash source and `'strict-dynamic'` are present), or `default-src *` | CONFIRMED | medium | medium |
| `BASE-VERSION-DISCLOSURE` | Next `poweredByHeader` not false; Express without `app.disable('x-powered-by')` or helmet; live `Server` / `X-Powered-By` with a version | INFERRED, CONFIRMED with `--url` | low | low |
| `BASE-WEAK-HASH` | `md5`, `sha1`, `sha256` via `hashlib` or `crypto.createHash` inside a function or on a variable whose name contains `password`, except a hash of a token, reset link, one-time code, nonce, API key or `randomBytes` / `secrets.token_*` value when no password is hashed; Django `PASSWORD_HASHERS` first entry MD5 or SHA1, except in a test, CI, local or vendored settings module (refinement 27) | INFERRED, CONFIRMED for Django setting | critical | medium |
| `BASE-NO-HTTPS-REDIRECT` | `--url` http root does not redirect to https | CONFIRMED | high | medium |
| `BASE-DEBUG-ON` | Django `DEBUG = True` as a literal in a settings module that production loads (refinement 27), or a `DEBUG` read from the environment that is on when the variable is unset (refinement 42); `FastAPI(debug=True)`, `Flask(debug=True)` or `run(debug=True)`; a settings class whose `debug` defaults to `True` | INFERRED | high | medium |
| `BASE-MIXED-CONTENT` | `http://` asset URLs in `src`/`href` (excluding localhost, XML namespaces), not in vendored files (refinement 68) | INFERRED | low | low |
| `BASE-CACHE-AUTH` | login page response without `Cache-Control: no-store` (live only) | CONFIRMED | low | low |
| `BASE-LITERAL-PASSWORD-HASH` | Password hashing calls (`get_password_hash`, `hash_password`, `make_password`, `bcrypt.hash`, a password context's `hash`) whose argument resolves to text written in the repository; copies of the same text elsewhere are found by SHA-256 digest and cited, never printed | CONFIRMED; INFERRED when the text is only an environment variable fallback | critical; high for a fallback | high |
| `BASE-SEED-ON-START` | A start command (shell start script, Procfile, Dockerfile `CMD`, platform start command, `package.json` start scripts) runs a seed step | INFERRED | critical when the seed file hashes committed passwords, else high | high |
| `BASE-SHORT-PASSWORD-MIN` | A password length check or schema minimum below 8 characters | CONFIRMED | low | low |
| `BASE-SAMESITE-NONE-NO-CSRF` | `SameSite=None` in configuration or code with no CSRF package, Django, or `csrf` reference anywhere in the code | INFERRED | low | medium |
| `BASE-DB-NETWORK-OPEN` | Terraform exposing a database: Azure firewall rules `0.0.0.0` to `0.0.0.0` (medium) or to `255.255.255.255` (high); security group ingress, `aws_security_group_rule` or `aws_vpc_security_group_ingress_rule` opening a database port to `0.0.0.0/0` or `::/0` (high); `publicly_accessible = true` (medium); Cloud SQL authorized network `0.0.0.0/0` (high). Commented-out values never count | CONFIRMED | medium or high | medium |
| `BASE-DB-ADMIN-LOGIN` | A Terraform connection string built from an admin or master login variable | INFERRED | medium | medium |
| `BASE-HTTPS-NOT-ENFORCED` | Azure web or function app without `https_only = true`, CloudFront `allow-all` viewers, HTTP load balancer listener without a redirect | CONFIRMED | low | low |
| `BASE-PICKLE-SESSIONS` | `SESSION_SERIALIZER` is `PickleSerializer` in a production settings module; cites a committed signing key fallback second (refinement 41) | CONFIRMED | high | medium |
| `BASE-ENV-DEFAULTS-PROD` | An environment flag that means production when the variable is unset (refinement 42) | CONFIRMED | medium | low |
| `BASE-FEATURE-DEFAULT-ON` | `WAFFLE_SWITCH_DEFAULT`, `WAFFLE_FLAG_DEFAULT` or `WAFFLE_SAMPLE_DEFAULT` set to `True` (refinement 43) | CONFIRMED | low | low |
| `BASE-DOCKER-ROOT` | A Dockerfile's final stage has no non-root `USER`; a stock `nginx` final stage is skipped (refinements 54 and 81) | CONFIRMED | medium; low when only for development (refinement 81) | low |
| `BASE-WORLD-WRITABLE` | `chmod` to a world-writable mode in a Dockerfile, shell or Python script, one finding per file (refinement 54) | CONFIRMED | high | medium |
| `BASE-DOCKERIGNORE-THIN` | `COPY . <dest>` that ends in the image, with the build context's `.dockerignore` missing or thin (refinements 54 and 81) | CONFIRMED | high | medium |

Password storage delegated to a managed provider is a section note, not a finding. Account enumeration is a section note referencing `AUTH-CASE-2` and `AUTH-CASE-4`.

Live header read (`adapters/headers.py`): only when `url` is set and `owns_host` is true, else `ScanError`. Exactly three `HEAD` requests: `https` root following redirects, `https` login path following redirects, `http` root without following redirects. 10 second timeout each. Failures become UNVERIFIED with the reason.

Section shape: fix blocks in the skill's format (`FIX n`, Where, Now, Change, Verify), ordered by score.

### 10.5 OWASP (`owasp`, review 5)

Own rules:

| Rule | Detects | Tag | Sev | Expl |
|---|---|---|---|---|
| `OWASP-A01-UNSCOPED-QUERY` | In a route handler, an identifier from the request (`params.id`, `req.params.*`, `searchParams.get`, FastAPI path parameter, Django view kwarg, `request.GET` / `POST` / `data` / `query_params`, a JSON body, `validated_data`, a Django Ninja body schema; refinement 36) reaches an ORM lookup (Prisma `findUnique/findFirst/update/delete`, Django `get/filter/get_object_or_404`, SQLAlchemy `session.get` / `filter`, Supabase `.eq`) whose filter has no session subject (`session.user.id`, `auth()`, `getServerSession`, `request.user`, `current_user`, `auth.uid`) and no caller-scoped queryset method (`filter_by_user`, `for_user`), with no later guard on the caller and the record, whose handler sends personal data or writes, and that is not an existence check or count (refinement 64). A route that `OWASP-A01-PUBLIC-SENSITIVE` or `OWASP-A01-UNSIGNED-CALLBACK` reports carries its lookup there (refinement 66). The detail notes a sequential primary key | CONFIRMED when the filter literal is fully visible and the function has no later comparison against the session subject; INFERRED when a later call receives the caller without a guard, the model is unknown, the route is public, or the route is role-gated (refinements 12, 36 and 64 in section 3) | high; critical on a public route with a sequential key; low when role-gated, one finding per app listing every route (refinement 75); medium when role-gated by a member-level check and keyed by a tenant id (refinements 65 and 72) | high; low when role-gated; medium for a tenant id |
| `OWASP-A01-UNSCOPED-LIST` | A signed-in route with no role gate that sends every record of a user model or of a model with personal fields (refinements 56 and 57) | CONFIRMED for user models, else INFERRED | high | high |
| `OWASP-A01-UNGUARDED-METHOD` | Same route file: one exported method calls an auth check, another write method does not | CONFIRMED; INFERRED when the unguarded method is public only by absence and the app has a global auth mechanism the classifier cannot read | high | high |
| `OWASP-A01-MASS-ASSIGNMENT` | Request body passed whole into ORM create or update (`data: body`, `...body`, `**request.data`, `**payload.dict()`) | CONFIRMED when the model has `role`, `is_admin`, `org_id`, `plan`, `is_staff`; else INFERRED | high | high |
| `OWASP-A01-CLIENT-ONLY-GUARD` | UI conditional on `isAdmin` / `role === 'admin'` while the matching admin API route has no role check | INFERRED | medium | medium |
| `OWASP-A02-WEAK-RANDOM-TOKEN` | `Math.random()` or `random.random/choice/randint/...` assigned to a secret name (`token`, `secret`, `otp`, `reset`, `nonce`, `password`, a key, a verification or one-time code; not a bare `code`), or in Python to any name that the same function passes to `set_password` or a cookie, puts in a token link or sends as an `Authorization` header (refinement 28); the output of a repository helper built on `random` reaching `set_password`, `make_password` or `create_user` (refinement 50) | INFERRED for a name; CONFIRMED for a use | high | medium |
| `OWASP-A02-SECRET-IN-URL` | URL string built with `token=`, `password=`, `pass=`, `apikey=` query parameters; a secret-named key in a dict passed to `params=` or `urlencode()` (refinement 51) | INFERRED | medium | low |
| `OWASP-A03-RAW-SQL` | `$queryRawUnsafe`, `$executeRawUnsafe`, string concatenation or f-string into `execute`, `.raw()`, `text()`, unless every interpolated part is a literal, a constant or fixed helper text (refinements 33 and 77); Python files under `alembic/` or `migrations/` are skipped | CONFIRMED when a request value, or a name assigned from one in the same function, is inside the string's interpolations; else INFERRED | high; medium with bound arguments and placeholders, low in a script no route reaches (refinement 77) | high |
| `OWASP-A03-XSS-SINK` | `dangerouslySetInnerHTML` with a non-literal, `v-html`, `innerHTML =`, `{@html}`, Python `Markup()` or `mark_safe()` over a value that is not constant, escaped or numeric (refinement 78) | INFERRED | high | medium |
| `OWASP-A03-COMMAND` | `child_process.exec` / `execSync` with a non-literal; `subprocess` with `shell=True` and a non-literal; `eval`, `new Function` | INFERRED | high | high |
| `OWASP-A04-CLIENT-PRICE` | Request body fields `price`, `amount`, `total`, `plan`, `isPaid`, `discount` passed to Stripe or an ORM write | INFERRED | high | high |
| `OWASP-A08-NO-SRI` | `<script src="https://...">` without `integrity` in HTML or JSX | CONFIRMED | low | low |
| `OWASP-A08-UNSAFE-DESERIALISE` | `pickle.loads`, `yaml.load` without a safe loader, `node-serialize` | INFERRED | high | medium |
| `OWASP-A08-CI-UNTRUSTED` | GitHub workflow on `pull_request_target` that checks out the PR head ref | CONFIRMED | high | medium |
| `OWASP-A09-NO-AUTH-FAIL-LOG` | Login handler failure branch has no logger call | INFERRED | low | low |
| `OWASP-A10-SSRF` | `fetch`, `axios`, `requests`, `httpx`, `urllib` called with a URL from the request in the same function with no host allowlist comparison | INFERRED | high | high |
| `OWASP-A01-EMAIL-OWNERSHIP` | A non-user model matched to the caller by comparing its email with the signed-in user's email | INFERRED | high | medium |
| `OWASP-A01-PUBLIC-SENSITIVE` | A public route that sets a password or changes a user account, looks up personal data by a request value, returns a file, lists stored records of a personal, file or owned model (refinement 56), starts a background job, or runs a back-office write that takes no input (refinement 37); one finding per route, carrying the route's unscoped lookup (refinement 66) | CONFIRMED for a password, or personal data or a file behind a lookup keyed by a non-random request value; else INFERRED | critical; high when INFERRED; critical when the carried lookup uses a sequential key | high |
| `OWASP-A01-UNSIGNED-CALLBACK` | A public callback-named route (also a delivery, receipt, or channel status or report route; refinement 75) that changes data or starts a background job with no signature, shared secret or source address check (refinement 38), carrying the route's unscoped lookup (refinement 66) | INFERRED | high; critical when the carried lookup uses a sequential key | medium |
| `OWASP-A05-DEBUG-ENDPOINT` | A public health, test or debug route that returns exception text, settings, environment values or versions, or raises an error on every call (refinements 39 and 58) | CONFIRMED; INFERRED when an unread global guard may apply | low | low |
| `OWASP-A01-PATH-TRAVERSAL` | A request value (FastAPI parameter, Flask or Django path parameter, `request.files` / `request.form`, Express `req.body` / `req.params`, `originalname`) reaches a file system path (refinement 26: `open()`, `pathlib` and `os` / `shutil` file calls, Django storage `save` / `open` / `delete`, an upload's own `save(path)`, `send_file` / path `FileResponse`; never Django `form.save()` or model `.save()`), directly or through a helper the calling file defines or imports, without `secure_filename`, `basename`, `safe_join`, `get_valid_filename` or a resolved-path check. Parameters typed `int`, `float`, `bool`, `UUID`, `Decimal`, `date`, `datetime`, an `Enum` or a `Literal`, and `<int:>` / `<uuid:>` path converters, are not sources | CONFIRMED when every step from the request to the sink is read; INFERRED when the value passes through another call or a helper matched by name only | high | medium |
| `OWASP-A03-HTML-EMAIL` | HTML f-strings in email code that insert values without `html.escape` | INFERRED | low | low |
| `OWASP-A05-XML-PARSER` | XML or spreadsheet parsing when the project does not declare `defusedxml` | INFERRED | low | low |
| `OWASP-A08-UNPINNED-DEPS` | `requirements*.txt` with at least half its entries unpinned and no lock file or hashes beside it; `package.json` with dependencies and no lock file in its folder or above | CONFIRMED | low | low |
| `OWASP-A08-UNPINNED-INSTALL` | `pip install` of unpinned packages in start scripts or CI, unpinned `npx` of scoped packages, `npm install` (not `npm ci`) in CI | CONFIRMED | low | low |
| `OWASP-A06-VENDORED-LIB` | A third-party library copied into the repository (refinement 25 in section 3), once per library name with every copy (refinement 69): name, each copy's version when a file name, banner, version constant, `package.json`, `bower.json` or `__version__` shows it, and up to 20 file locations, the first file of each copy first. Copies in a documentation folder are not listed. Fix: manage it as a dependency and keep it updated | CONFIRMED when the name comes from the library list or a banner; INFERRED when only the file's shape, a third-party folder or a licence file marks it | low | low |
| `OWASP-A01-OPEN-REDIRECT` | A redirect whose target starts with a request value or the Referer header, with no allowed-host check (refinement 45) | CONFIRMED for a request value; INFERRED for Referer | medium; low for Referer, one per file | medium; low for Referer |
| `OWASP-A01-CSRF-EXEMPT` | Session-authenticated Django views marked `@csrf_exempt`, one finding per file (refinement 46) | CONFIRMED | medium; high with `SameSite=None`; low when no view changes data | medium; high with `SameSite=None` |
| `OWASP-A04-GET-SIDE-EFFECT` | A signed-in route with no method check whose GET starts a job, sends in a loop, deletes or writes in bulk (refinements 47 and 62) | CONFIRMED | medium; low for single deletes, grouped per file | medium |
| `OWASP-A04-UPLOAD-LIMIT` | Upload size settings of 100 MB or more, or none (refinement 48) | CONFIRMED | medium | medium |
| `OWASP-A04-UNCHECKED-UPLOAD` | `FileField`s with no validators, one finding per app (refinement 48) | INFERRED | low | low |
| `OWASP-A01-PRIVILEGE-FIELDS` | A form or serializer that accepts superuser, staff, group or permission fields, or a choice of a role template that carries the superuser or staff flag, bound by a route that is not superuser-only (refinements 49 and 61) | CONFIRMED | high; critical on a public route | medium |
| `OWASP-A02-PLAIN-HTTP-CALL` | Outbound calls and URL settings using `http://` to a host outside the local network, one finding per file (refinement 51) | CONFIRMED | medium; high with credentials or personal data | low; medium with credentials |
| `OWASP-A05-NO-TIMEOUT` | `requests` and `urlopen` calls with no timeout, one finding per file (refinement 51) | CONFIRMED | low | low |
| `OWASP-A05-HARDCODED-VENDOR-URL` | A live vendor address fixed in code with no environment override (refinement 52) | INFERRED | low | low |
| `OWASP-A06-EOL-COMPONENT` | A declared framework, runtime or base image version past its end of support on the scan date, from the bundled `data/eol.yaml` (refinement 53) | CONFIRMED | high for frameworks; medium for runtimes and images | medium |
| `OWASP-A06-KNOWN-ADVISORY` | An exactly pinned dependency or a copied library version inside an affected range of the bundled, dated `data/advisories.yaml`, one finding per package and version listing every advisory id (refinement 76) | CONFIRMED | the worst advisory's severity from the table | medium |

Sink rules (`OWASP-A03-XSS-SINK`, `OWASP-A03-COMMAND`, `OWASP-A03-RAW-SQL`, `OWASP-A02-SECRET-IN-URL`, `OWASP-A02-WEAK-RANDOM-TOKEN`, `OWASP-A08-UNSAFE-DESERIALISE`, `OWASP-A08-NO-SRI`) skip vendored files.

Shared findings: A05 debug and error exposure use `BASE-DEBUG-ON` and `ABUSE-ERROR-LEAK`; CORS uses the abuse rules; A07 references the auth review. These are cross-references, not duplicates.

Route classification table: every route marked public, authenticated, authenticated and ownership-checked, or admin, from the presence of auth calls, ownership predicates and role checks (refinement 9 in section 3). Used by A01 rules and printed in the section.

**Semgrep adapter.** When `semgrep` is `"auto"` and the binary exists, or a local rules path is given: `semgrep scan --json --metrics=off --timeout 30 --config p/owasp-top-ten --config p/javascript --config p/typescript --config p/python` (or `--config <local dir>`), scoped to the repo with the same skipped directories, overall timeout 300 seconds. Each result becomes a `Finding` with `source="semgrep:<check_id>"`, tag INFERRED, `owasp` parsed from `extra.metadata.owasp`, severity from `extra.severity` (`ERROR` high, `WARNING` medium, `INFO` low). Results without an OWASP mapping are kept under `A05`. The `lines` field is dropped for rules whose id or metadata mentions secrets. Semgrep's rules are downloaded from the Semgrep registry unless a local path is given; code is scanned locally.

**End of life and advisories.** `OWASP-A06-EOL-COMPONENT` and `OWASP-A06-KNOWN-ADVISORY` need no network: the tables in `data/eol.yaml` and `data/advisories.yaml` are bundled and dated, each finding names its table's date, and the advisory table's date is also in "What this review did not cover".

**Audits.** With `with_audit`: `npm audit --omit=dev --json` when `package-lock.json` exists, `pip-audit -f json` against requirements or the project. Advisories become `OWASP-A06-VULN-DEP` findings, tag INFERRED, `proof_needed` "call path from the app to the vulnerable function was not traced". Without the flag, A06 lists only `OWASP-A06-VENDORED-LIB`, `OWASP-A06-EOL-COMPONENT` and `OWASP-A06-KNOWN-ADVISORY` findings and notes that the audit adapters did not run.

Section shape: finding blocks in the skill's format (`FINDING n`, Where, Attack, Blast, Fix) ordered by score, the route classification table, then categories reviewed with no finding.

### 10.6 Abuse and bill guard (`abuse`, review 7)

`costs.yaml` maps SDK categories (llm, email, sms, storage, image, browser, maps, payments) to a cost note and starting limits (`per_user`, `per_ip`, `window`) taken from the skill's example table.

| Rule | Detects | Tag | Sev | Expl |
|---|---|---|---|---|
| `ABUSE-PAID-UNAUTH` | Route whose handler, or a helper it reaches through its file's definitions or imports (up to two calls deep), calls a paid SDK, with no auth guard found for the route (refinements 9, 10 and 82 in section 3) | CONFIRMED; INFERRED when the helper was matched by name only, or the route is public only by absence and the app has a global auth mechanism the classifier cannot read | critical | high |
| `ABUSE-PAID-UNLIMITED` | Paid route with no limiter reference in the handler file or matching middleware; routes behind an internal-token FastAPI gate are skipped (refinement 82) | INFERRED | high | high |
| `ABUSE-GATE-FAIL-OPEN` | A FastAPI internal-token dependency that returns without checking when its secret is unset; one finding per app root (refinement 82) | CONFIRMED | low | low |
| `ABUSE-INMEMORY-LIMITER` | When more than one process or instance serves requests (a worker count above one, or serverless hosting): `express-rate-limit` or `express-slow-down` imported and called without `store`; a slowapi or Flask-Limiter `Limiter` whose storage is `memory://`, falls back to memory, or is not passed; a module-level `Map` counter. The worker count or the host's config file is the second location | CONFIRMED for `express-rate-limit` or `express-slow-down` without `store` and a literal `memory://`; INFERRED for a memory fallback, a counter `Map`, or storage that app config or the environment can set (`RATELIMIT_STORAGE_URI`), including settings that disagree; settings in test files never count | medium | medium |
| `ABUSE-FORM-NO-CHALLENGE` | `is_public_form` route (not a token link or a done page, refinement 70) with no Turnstile, hCaptcha or reCAPTCHA verification and no honeypot field | INFERRED | medium | medium |
| `ABUSE-CORS-WILDCARD` | `origin: '*'`, `Access-Control-Allow-Origin: *` on routes with auth, `CORS_ALLOW_ALL_ORIGINS = True`, FastAPI `allow_origins=["*"]` | CONFIRMED | high | medium |
| `ABUSE-CORS-REFLECT` | `origin: true`, `callback(null, true)` without an allowlist check, or `Access-Control-Allow-Origin` set from the request `Origin`; critical when credentials are allowed | CONFIRMED | high or critical | high |
| `ABUSE-CORS-LOOSE-REGEX` | Origin regex without `^` and `$` anchors | CONFIRMED | medium | medium |
| `ABUSE-ERROR-LEAK` | Response body built from `err.message`, `err.stack`, `str(e)`, `repr(e)`, `traceback.format_exc()`: in a response call, returned by a route handler, or returned by a helper whose result the handler sends; never a Celery task or other internal return value (refinement 30) | CONFIRMED | medium | medium |
| `ABUSE-NO-KILL-SWITCH` | Paid SDK call sites with no env flag check nearby (`*_ENABLED`, `DISABLE_*`, feature flag call) | INFERRED | low | low |
| `ABUSE-LIMITER-NOT-APPLIED` | slowapi `Limiter(default_limits=...)` while `SlowAPIMiddleware` is never added | CONFIRMED | medium | medium |
| `ABUSE-LIMITER-PROXY-IP` | Limiter keyed on `get_remote_address`, or `express-rate-limit` without `keyGenerator`, on a hosted app with no forwarded-address trust configured anywhere | INFERRED | medium | medium |
| `ABUSE-UPLOAD-UNBOUNDED` | A route reads a whole `UploadFile` or `request.files` upload into memory with no size limit, or checks the size only after reading | CONFIRMED | low | medium |

Section shape: cost surface table (route, calls, cost note, auth, limited), limits table with numbers from `costs.yaml` marked "starting default, not measured traffic", an implementation snippet chosen by stack (Upstash rate limit for Next.js on Vercel, `express-rate-limit` with a Redis store for Express, `slowapi` for FastAPI, `django-ratelimit` for Django), CORS and error message rewrites, and alerts and kill switch text: rate-of-spend alert (hourly paid calls over 3 times the 7-day hourly average), provider-side hard caps, signup rate anomaly, error spike on paid routes, and a named env flag per paid route.

### 10.7 Inventory (`inventory`, review 1)

Field sources: models (7.6), validation schemas in signup, register and onboarding files (zod `z.object`, yup, Joi, pydantic `BaseModel`, DRF serializers, Django forms), and runtime-captured data (`x-forwarded-for`, `req.ip`, `request.client.host`, `REMOTE_ADDR`, `user-agent`, geolocation headers).

Matching: names split on camelCase and underscores into tokens, matched against `pii_terms.yaml` categories: identifiers, account, financial, technical, behavioural, content, inferred, special category, children, and South African identifiers (`id_number`, `sa_id`, `identity_number`, `passport_number`, `tax_number`).

| Rule | Detects | Tag | Sev | Expl |
|---|---|---|---|---|
| `INV-SPECIAL-CATEGORY` | Field in the special category list | CONFIRMED | high | low |
| `INV-CHILDREN-SIGNAL` | `age`, `date_of_birth` with minimum under 18, `parent`, `guardian`, `school`, `grade` fields | INFERRED | high | low |
| `INV-CATCHALL-JSON` | `json`/`jsonb` column or Prisma `Json` named `metadata`, `properties`, `custom_fields`, `extra`, `payload`, `raw`, `attributes`, `data` | CONFIRMED | medium | low |
| `INV-UNUSED-FIELD` | Personal data field whose name appears only in schema, migrations and at most one write | INFERRED | low | low |
| `INV-NO-DELETION-PATH` | Table with personal data and no delete path: no cascade, no scheduled job deleting it (`vercel.json` crons, Celery beat, GitHub `schedule`, `cron` libraries), no TTL | INFERRED | medium | low |
| `INV-SDK-RECEIVES-PII` | Call to a data-recipient SDK whose argument object has personal data keys (CONFIRMED) or is a whole user object or free text (INFERRED); SDK settings such as `region_name` and a storage upload's `Body` do not count (refinement 32) | CONFIRMED or INFERRED | medium | low |
| `INV-PII-FILE-IN-REPO` | `.csv` / `.json` whose header row or top-level keys match personal data terms, or a data file (`.csv`, `.tsv`, `.txt`, `.json`, `.sql` and similar) whose values include several valid South African ID numbers or IBANs, bank accounts next to a branch code, or bulk mobile numbers or email addresses, with or without a header row (refinement 55). Called committed only when git tracks it (refinement 24 in section 3) | CONFIRMED; INFERRED for mobile numbers or email addresses alone | high; medium for an untracked file scanned with `--include-untracked` | medium |

Section shape: the data map table (`Field | What it is | Where collected | Where it lives | Third parties with a copy | Retention | Who internally can read it | Evidence`), one flow line per collection point (`signup form (file) -> users table -> Stripe customers.create -> Sentry on error`, tagged INFERRED because flows are joined by shared model and file references, not traced), "collected with no clear reason", "not covered by this repo", and the lawyer questions (section 9). Retention is "retained indefinitely, no deletion path found" or UNKNOWN; a period is never invented. Who can read: admin routes and roles found, remainder UNKNOWN.

## 11. Output

### 11.1 Markdown

Jinja2 template mirroring the skill's `report-template.md` section for section, with only the sections for reviews that ran, in review number order (1 to 7) regardless of run order. Header: project name, date, scope and git sha, reviews run, method (static analysis, plus header checks against the named URL with the owner's confirmation, plus Semgrep and audits when they ran). Fixed disclaimer paragraph. Summary counts by severity plus open question count. Top three fixes. Evidence tag legend. Detection table. Per-review sections. Open questions in three groups. What this review did not cover: systems outside the repo, production config differences, runtime behaviour, skipped files, rules that errored, adapters not run, Firebase rules if present.

### 11.2 JSON

`{"schema_version": 1, "meta": ..., "detection": ..., "findings": [...], "sections": ..., "questions": ..., "not_covered": [...]}`. Enums as lowercase strings (evidence tags stay uppercase, deviation 5 in section 3), locations as objects.

### 11.3 SARIF 2.1.0

One run, tool name `dpr`, one rule per `rule_id` (Semgrep rule ids kept). Level: critical and high `error`, medium `warning`, low `note`. Properties: `tag`, `severity`, `exploitability`, `owasp`, `review`. Questions are not included.

### 11.4 Files written by the CLI

`<out>/REPORT-YYYY-MM-DD.md`, `<out>/report-YYYY-MM-DD.json`, `<out>/report-YYYY-MM-DD.sarif`, for the requested formats. Default `out` is `<PATH>/data-protection-review/`. A same-day rerun overwrites. After writing, the CLI prints at most 15 lines: counts by severity, top three fixes, open UNKNOWN count, file paths, and the gitignore hint when applicable.

## 12. CLI

```
dpr scan [PATH]
    --reviews all | 1..7 | inventory rls auth baseline owasp leaks abuse   (default all)
    --answers FILE
    --interactive
    --url URL --i-own-this-host [--login-path PATH]
    --with-audit
    --semgrep auto|off|DIR        (default auto)
    --db-dump FILE
    --format md,json,sarif        (default md,json)
    --out DIR
    --fail-on critical|high|medium|none   (default none)
    --include-untracked           in git, also scan untracked files git does not ignore

dpr questions [PATH] [--out FILE]  (default FILE: <PATH>/dpr-answers.yaml)
```

Exit codes: `0` completed and nothing at or above `--fail-on`; `1` a finding at or above `--fail-on`; `2` `ScanError`, invalid arguments, or any other unexpected error (one line `dpr: error: <Type>: <message>` on stderr; with `DPR_STRICT=1` the exception is re-raised).

## 13. Error handling

| Situation | Behaviour |
|---|---|
| Path missing, sanity check fails, `--url` without `--i-own-this-host`, invalid answers YAML | `ScanError`, exit 2, one-line message |
| Unknown key in answers | Warning printed, key ignored |
| File fails to parse | Listed in `not_covered`, run continues |
| File cannot be read, or is not a regular file | Unreadable files are listed in `not_covered`; pipes, sockets and devices are skipped; run continues |
| Rule raises | Caught per rule, `rule <id> failed: <ExceptionType>` in `not_covered`, run continues. With env `DPR_STRICT=1` the exception is re-raised (set in tests). |
| A review module's `run()` raises | Caught per review, `review <slug> failed: <ExceptionType>` in `not_covered`, that review's section and rules are skipped, run continues. With env `DPR_STRICT=1` the exception is re-raised. |
| Optional tool missing | Listed as not run with the reason |
| Adapter timeout | Semgrep 300 s, audits 120 s, header request 10 s; listed as incomplete |
| Not a git repo | Git-based rules skipped and listed; meta shows `uncommitted working tree` |

## 14. Testing

- **Unit tests** per parser: SQL splitter (dollar quoting, comments, nested quotes), policy extraction, Prisma, schema extraction per ORM, route extraction per framework, Vue/Svelte script offsets.
- **Rule tests**: each rule has at least one positive and one negative snippet test.
- **Fixture apps** in `tests/fixtures/`:
  - `next-supabase-bad`: public-prefixed service role key reference; hardcoded live Stripe-shaped key; migrations with a table without RLS, a `using (true)` policy, an update policy with `with check (true)`, a view without `security_invoker`; invoice route with an unscoped `findUnique`; generate route calling OpenAI with no auth and no limiter; signup route logging the body, returning "already registered", and setting a cookie without `httpOnly`; `productionBrowserSourceMaps: true`; Sentry `sendDefaultPii: true`; reflected CORS with credentials; `dangerouslySetInnerHTML` with user content; tracked `.env`; `metadata jsonb` column; `medical_conditions` column.
  - `next-supabase-good`: the same app with each defect fixed and security headers configured.
  - `django-bad`: `DEBUG = True`, MD5 first in `PASSWORD_HASHERS`, `get_object_or_404(Invoice, pk=pk)` without a user filter, `CORS_ALLOW_ALL_ORIGINS = True`, `SESSION_COOKIE_SECURE = False`, `requests.get(request.GET["url"])`, f-string SQL with a request value, `traceback.format_exc()` in a response, serializer `fields = "__all__"`, `send_default_pii=True`.
  - `fastapi-good`: response models, `get_current_user` scoping, `slowapi` limiter, CORS allowlist, bcrypt hashing.
  - Each fixture has `expected.yaml`: bad fixtures list `{rule_id, file, line, tag}` that must be reported; good fixtures list `must_not_report` rule ids.
- **Secrets never committed.** Key-shaped strings are assembled at test runtime and written into a temporary copy of the fixture, and git-based fixtures (`.env` tracked, history) are created with `git init` in `tmp_path`. No key-shaped string is committed, so push protection is never triggered.
- **Safety tests**: planted key strings absent from Markdown, JSON and SARIF; no legal verdict phrases; CONFIRMED always has a location; no network connection in a default run.
- **Snapshot test** of the full Markdown report for `next-supabase-bad`, with date and sha normalised.
- **Semgrep tests**: adapter mapping tested with saved Semgrep JSON. One integration test marked `semgrep` runs the real binary and is skipped when it is missing.
- **Smoke runs** (manual, recorded in `tasks/todo.md`): `dpr scan` on `Active Projects/RocoVit` and `Active Projects/DataPulse` with `--out` pointing to a scratch folder. Nothing is written into those repositories. Results reviewed for false alarms, which become new negative rule tests.
- **Test report**: `pytest` summary and `pytest-cov` coverage printed and shared before any push.

## 15. CI

`.github/workflows/ci.yml`, triggered on push to `feature/**`, `bugfix/**`, `develop`, `main`, and on pull requests:

- Job `test`: `uv sync`, `ruff check`, `ruff format --check`, `pytest -m "not semgrep"` with coverage on Python 3.12.
- Job `semgrep`: install `semgrep`, run `pytest -m semgrep`.

`docs/ci-example.yml`: a workflow for other repos that installs `dpr` from its git URL, runs `dpr scan --format md,sarif --fail-on critical`, and uploads the report folder as an artifact with `retention-days: 7`.

## 16. Milestones

Each milestone ends with all tests green locally and in CI.

1. **Core, leaks, RLS.** Project scaffold, `model`, `rank`, `rules`, `walk` with sanity check, JS/TS and Python parsers, SQL and Prisma parsers, schema and route extraction, discovery, questions catalogue and answers loading, Markdown and JSON output, CLI `scan` and `questions`, leaks review, RLS review, safety tests, `next-supabase-bad` and `next-supabase-good` fixtures for those rules.
2. **Baseline, abuse, own OWASP rules.** Live header adapter, baseline review, abuse review, OWASP own rules and route classification, SARIF output, `django-bad` and `fastapi-good` fixtures.
3. **Semgrep, audits, inventory, auth.** Semgrep adapter, audit adapters, inventory review, auth test plan review, full snapshot test, CI workflow including the Semgrep job, CI example, smoke runs, project contributor notes.

## 17. Repository and workflow

- Gitflow: `main`, `develop`, work on `feature/dpr-scanner` branched from `develop`. Merges go through pull requests. No direct commits to `develop` or `main`.
- No remote is added and nothing is pushed until the owner asks.
- Commit messages contain no AI attribution.
- Plan and progress tracked in `tasks/todo.md`.
