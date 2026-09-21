from dpr.reviews.leaks_logs import personal_name, words
from tests.reviews.helpers import findings_for, write


def found(root):
    return {str(f.locations[0]): f for f in findings_for(root, "leaks", "LEAK-LOGGED-PII")}


def lines(root):
    found_all = findings_for(root, "leaks", "LEAK-LOGGED-PII")
    return sorted(str(loc) for f in found_all for loc in f.locations)


def test_words_and_personal_names():
    assert words("toEmail") == ["to", "email"]
    assert words("client_ip") == ["client", "ip"]
    assert personal_name("to_email") and personal_name("firstName") and personal_name("client_ip")
    assert personal_name("name", "client") and not personal_name("name", "file")
    assert not personal_name("email_template") and not personal_name("user_id")
    assert not personal_name("email_from_address", "self._settings")


def test_python_identifiers_and_counts_are_not_personal_data(tmp_path):
    write(
        tmp_path,
        "app/services/portal.py",
        "import logging\nlogger = logging.getLogger(__name__)\n\n"
        "def pick(user, clients, payload, current_user):\n"
        "    logger.warning('%d records for user %s', len(clients), user.id)\n"
        "    logger.info('truncated %s of %s for %s', len(payload['rows']), payload['total'], current_user.id)\n"
        "    logger.info('request %s created for insured %s', request.id, insured.id)\n"
        "    logger.info('sender %s', settings.email_from_address)\n"
        "    logger.info('app %s', settings.app_name)\n",
    )
    assert found(tmp_path) == {}


def test_python_personal_values_and_objects_are_reported(tmp_path):
    write(
        tmp_path,
        "app/services/mail.py",
        "import logging\nlogger = logging.getLogger(__name__)\n\n"
        "def send(to_email, client, user, request):\n"
        "    logger.info('Email sent: to=%s', to_email)\n"
        "    logger.info('notified %s', client.name)\n"
        "    logger.warning('FAIL %s', user.email)\n"
        "    logger.warning('failed login', extra={'client_ip': request.client.host if request.client else 'x'})\n"
        "    logger.debug(f'body {request.json}')\n",
    )
    [finding] = found(tmp_path).values()
    assert [str(loc) for loc in finding.locations] == [
        "app/services/mail.py:5",
        "app/services/mail.py:6",
        "app/services/mail.py:7",
        "app/services/mail.py:8",
        "app/services/mail.py:9",
    ]
    assert finding.detail.startswith("5 log calls in this file. A personal value")
    assert "A request, user, token" in finding.detail
    assert finding.severity.value == "medium"


def test_health_check_query_errors_are_not_reported(tmp_path):
    write(
        tmp_path,
        "app/main.py",
        "async def health():\n    try:\n        await session.execute(text('SELECT 1'))\n"
        "    except Exception as e:\n        logger.error(f'Health check DB error: {e}')\n",
    )
    assert found(tmp_path) == {}


def test_database_errors_and_global_handlers_with_tracebacks_are_reported(tmp_path):
    write(
        tmp_path,
        "app/main.py",
        "@app.exception_handler(Exception)\n"
        "async def handler(request, exc):\n"
        "    logger.error('Unhandled on %s: %s', request.url.path, exc, exc_info=True)\n\n"
        "async def save(db, row):\n    try:\n        db.add(row)\n        await db.commit()\n"
        "    except Exception as e:\n        logger.error(f'save failed: {str(e)}')\n\n"
        "def parse(raw):\n    try:\n        return int(raw)\n"
        "    except ValueError as e:\n        logger.error('bad %s', e, exc_info=True)\n",
    )
    assert lines(tmp_path) == ["app/main.py:10", "app/main.py:3"]


def test_print_in_operator_scripts_is_low_with_a_console_note(tmp_path):
    write(
        tmp_path,
        "api/scripts/send_resets.py",
        "def main(users):\n    for user in users:\n        print(user.email)\n"
        "        logger.info('sent %s', user.email)\n",
    )
    console, logged = sorted(
        findings_for(tmp_path, "leaks", "LEAK-LOGGED-PII"), key=lambda f: f.severity.value
    )
    assert [str(loc) for loc in console.locations] == ["api/scripts/send_resets.py:3"]
    assert console.severity.value == "low"
    assert console.detail.endswith("It goes to the console of whoever runs this script.")
    assert [str(loc) for loc in logged.locations] == ["api/scripts/send_resets.py:4"]
    assert logged.severity.value == "medium"


def test_destination_is_named_when_the_app_exports_logs(tmp_path):
    write(tmp_path, "api/requirements.txt", "fastapi\nazure-monitor-opentelemetry\n")
    write(
        tmp_path,
        "api/app/main.py",
        "from azure.monitor.opentelemetry import configure_azure_monitor\nconfigure_azure_monitor()\n",
    )
    write(tmp_path, "api/app/mail.py", "def send(to_email):\n    logger.info('to %s', to_email)\n")
    write(tmp_path, "worker/requirements.txt", "celery\n")
    write(tmp_path, "worker/job.py", "def run(to_email):\n    logger.info('to %s', to_email)\n")
    result = found(tmp_path)
    assert result["api/app/mail.py:2"].detail.endswith(
        "Log records from this app are exported to azure-monitor."
    )
    assert "exported" not in result["worker/job.py:2"].detail


def test_javascript_selected_fields_are_not_reported(tmp_path):
    write(
        tmp_path,
        "src/middleware/requestLogger.ts",
        "export const requestLogger = (req, res, next) => {\n"
        "  logger.info({ method: req.method, path: req.path, statusCode: res.statusCode,\n"
        "    userAgent: req.get('user-agent'), userId: req.user?.id })\n"
        "  next()\n}\n",
    )
    assert found(tmp_path) == {}


def test_javascript_error_middleware_and_personal_values_are_reported(tmp_path):
    write(
        tmp_path,
        "src/middleware/errorHandler.ts",
        "export const errorHandler = (err, req, res, _next) => {\n"
        "  logger.error({ err, path: req.path })\n}\n"
        "export function notify(user) {\n  console.log(`mailing ${user.email}`)\n"
        "  console.log('recipient', { email: user.email })\n}\n",
    )
    assert lines(tmp_path) == [
        "src/middleware/errorHandler.ts:2",
        "src/middleware/errorHandler.ts:5",
        "src/middleware/errorHandler.ts:6",
    ]


def test_test_files_are_skipped(tmp_path):
    write(tmp_path, "tests/test_mail.py", "def test_x(user):\n    print(user.email)\n")
    assert found(tmp_path) == {}


def test_logged_pii_walks_each_module_a_fixed_number_of_times(tmp_path, monkeypatch):
    import ast

    from dpr import reviews, rules
    from dpr.discovery.detect import detect
    from dpr.reviews import leaks_logs
    from dpr.walk import RepoIndex

    write(
        tmp_path,
        "svc/views.py",
        "".join(
            f"def f{i}():\n    try:\n        Invoice.objects.get(id={i})\n"
            '    except Exception as e:\n        logger.error("bad %s", e)\n'
            for i in range(50)
        ),
    )
    reviews.available()
    index = RepoIndex(tmp_path)
    ctx = rules.Context(index=index, detection=detect(index))
    walks = []
    original = ast.walk
    monkeypatch.setattr(
        ast, "walk", lambda node: walks.append(isinstance(node, ast.Module)) or original(node)
    )
    findings = list(leaks_logs.logged_pii(ctx))
    assert len(findings) == 1
    assert len(findings[0].locations) == 10
    assert sum(walks) <= 5


def test_logged_pii_walks_each_module_a_fixed_number_of_times_without_db_touches(
    tmp_path, monkeypatch
):
    import ast

    from dpr import reviews, rules
    from dpr.discovery.detect import detect
    from dpr.reviews import leaks_logs
    from dpr.walk import RepoIndex

    write(
        tmp_path,
        "svc/views.py",
        "".join(
            f"def f{i}():\n    try:\n        step({i})\n"
            '    except Exception as e:\n        logger.error("bad %s", e)\n'
            for i in range(50)
        ),
    )
    reviews.available()
    index = RepoIndex(tmp_path)
    ctx = rules.Context(index=index, detection=detect(index))
    walks = []
    original = ast.walk
    monkeypatch.setattr(
        ast, "walk", lambda node: walks.append(isinstance(node, ast.Module)) or original(node)
    )
    findings = list(leaks_logs.logged_pii(ctx))
    assert findings == []
    assert sum(walks) <= 5
