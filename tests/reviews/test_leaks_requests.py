from tests.reviews.helpers import findings_for, write

MIDDLEWARE = (
    "import json\nimport logging\nlogger = logging.getLogger(__name__)\n"
    "class LoggingMiddleware:\n"
    "    def __call__(self, request):\n"
    "        data = {'request_headers': json.dumps(dict(request.headers)), 'path': request.path}\n"
    "        body = json.loads(request.body.decode('utf-8') if request.body else '{}')\n"
    "        data['request_body'] = json.dumps(body)\n"
    "        response = self.get_response(request)\n"
    "        data.update({'response_body': response.content.decode('utf-8')})\n"
    "        ApiLog.objects.create(**data)\n"
    "        return response\n"
)


def test_request_logger_that_stores_headers_and_bodies(tmp_path):
    write(tmp_path, "lib/middleware/log_requests.py", MIDDLEWARE)
    [finding] = findings_for(tmp_path, "leaks", "LEAK-REQUEST-LOG")
    assert finding.title == (
        "LoggingMiddleware.__call__ stores whole request headers and request and response bodies"
    )
    assert (finding.tag.value, finding.severity.value) == ("CONFIRMED", "medium")
    assert [str(loc) for loc in finding.locations] == [
        "lib/middleware/log_requests.py:11",
        "lib/middleware/log_requests.py:6",
    ]


def test_request_log_skips_redacted_and_picked_values(tmp_path):
    write(
        tmp_path,
        "lib/audit.py",
        "import logging\nlogger = logging.getLogger(__name__)\n"
        "def log_call(request):\n"
        "    headers = redact(dict(request.headers))\n    logger.info(headers)\n"
        "def log_path(request):\n"
        "    logger.info('%s %s', request.path, request.headers.get('User-Agent'))\n"
        "    ApiLog.objects.create(path=request.path, method=request.method)\n"
        "def log_body(request):\n    logger.info(request.body)\n"
        "def save_form(request):\n    form = MemberForm(request.POST or None)\n"
        "    Amendment.objects.create(data=form)\n"
        "def hook(request):\n    call = Call.create_from(request.GET.dict())\n"
        "    Contact.objects.update_or_create(call=call)\n"
        "def save_body(request):\n    ApiLog.objects.create(body=request.body)\n",
    )
    write(tmp_path, "tests/test_mw.py", "def test_x(request):\n    logger.info(request.body)\n")
    [finding] = findings_for(tmp_path, "leaks", "LEAK-REQUEST-LOG")
    assert finding.title == "save_body stores whole request bodies"
    assert finding.severity.value == "low"
