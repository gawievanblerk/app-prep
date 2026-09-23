from tests.reviews.helpers import findings_for, write

MODELS = (
    "from django.db import models\n"
    "class PoliciesUser(models.Model):\n    email = models.EmailField()\n"
    "class Policy(models.Model):\n    owner_id = models.IntegerField()\n"
    "    policy_number = models.CharField(max_length=20)\n"
    "class PolicyDocument(models.Model):\n    uuid = models.UUIDField()\n"
    "    policy = models.ForeignKey(Policy, on_delete=models.CASCADE)\n"
)
ROUTES = {
    "forgot": "forgot",
    "reset_by_token": "reset_by_token",
    "signup": "signup",
    "search": "search",
    "doc/<str:uuid>/<str:policy_number>": "document",
    "claim/<str:hashed_pk>": "claim_letter",
    "brochure": "brochure",
    "zip": "make_zip",
    "fsca": "reprocess",
    "contact": "contact",
    "report": "report",
    "staff_reset": "staff_reset",
    "letter/<str:uuid>": "encrypted_letter",
}
VIEWS = (
    "from django.contrib.auth.decorators import login_required\n"
    "from django.http import FileResponse, HttpResponse, JsonResponse\n"
    "from desk import models\nfrom desk.jobs import build_zip\nfrom desk.tasks import send_report\n"
    "def forgot(req):\n"
    "    users = models.PoliciesUser.objects.filter(username=req.POST['username'])\n"
    "    user = users[0]\n    user.set_password(nicepass())\n    user.save()\n"
    "def reset_by_token(request, uid, token):\n"
    "    user = models.PoliciesUser.objects.get(pk=uid)\n"
    "    if default_token_generator.check_token(user, token):\n"
    "        user.set_password(request.POST['password'])\n"
    "def signup(request):\n"
    "    user = models.PoliciesUser(email=request.POST['email'])\n"
    "    user.set_password(request.POST['password'])\n    user.save()\n"
    "def search(request):\n"
    "    term = request.GET.get('term', '')\n"
    "    found = models.Policy.objects.filter(Q(policy_number__contains=term))\n"
    "    return JsonResponse(list(found.values('id')), safe=False)\n"
    "def document(request, uuid, policy_number):\n"
    "    doc = get_object_or_404(models.PolicyDocument, uuid=uuid, policy__policy_number=policy_number)\n"
    "    return FileResponse(doc.file, content_type='application/pdf')\n"
    "def claim_letter(request, hashed_pk):\n"
    "    claim_pk = hashids.decode(hashed_pk)[0]\n"
    "    policy = get_object_or_404(models.Policy, pk=claim_pk)\n"
    "    response = HttpResponse(policy.letter, content_type='application/pdf')\n"
    "    response['Content-Disposition'] = 'attachment; filename=x.pdf'\n    return response\n"
    "def brochure(request):\n    return FileResponse(open('static/brochure.pdf', 'rb'))\n"
    "def make_zip(request):\n    build_zip()\n    return HttpResponse('ok')\n"
    "def reprocess(request):\n"
    "    for policy in models.Policy.objects.all():\n"
    "        models.Policy.objects.filter(pk=policy.pk).delete()\n"
    "    return HttpResponse('ok')\n"
    "def contact(request):\n"
    "    models.Policy.objects.create(policy_number=request.POST['number'])\n"
    "    return HttpResponse('ok')\n"
    "def report(request):\n    send_report.delay()\n    return HttpResponse('ok')\n"
    "def encrypted_letter(request, uuid):\n"
    "    doc = get_object_or_404(models.PolicyDocument, uuid=uuid)\n"
    "    pdf = PDF(doc.file)\n    pdf.set_password(doc.policy.id_number)\n    return pdf.as_bytes()\n"
    "@login_required\ndef staff_reset(request):\n"
    "    user = models.PoliciesUser.objects.get(pk=request.POST['user_id'])\n"
    "    user.set_password('x')\n"
)


def app(root):
    write(root, "desk/models.py", MODELS)
    patterns = "".join(f"    path('{p}/', views.{v}),\n" for p, v in ROUTES.items())
    write(
        root,
        "desk/urls.py",
        f"from django.urls import path\nfrom desk import views\nurlpatterns = [\n{patterns}]\n",
    )
    write(root, "desk/views.py", VIEWS)
    write(
        root,
        "desk/jobs.py",
        "from desk.models import UploadFile\n"
        "def build_zip():\n    UploadFile.objects.create(kind='zip')\n",
    )
    write(root, "desk/tasks.py", "@shared_task\ndef send_report():\n    pass\n")
    return root


def test_public_sensitive_actions(tmp_path):
    found = findings_for(app(tmp_path), "owasp", "OWASP-A01-PUBLIC-SENSITIVE")
    got = {f.title: (f.tag.value, f.severity.value, str(f.locations[0])) for f in found}
    assert got == {
        "ANY /forgot sets a user's password without sign-in": (
            "CONFIRMED",
            "critical",
            "desk/views.py:9",
        ),
        "ANY /search looks up personal data by policy_number without sign-in": (
            "INFERRED",
            "high",
            "desk/views.py:21",
        ),
        "ANY /doc/<str:uuid>/<str:policy_number> looks up personal data by policy_number "
        "without sign-in": ("INFERRED", "high", "desk/views.py:24"),
        "ANY /claim/<str:hashed_pk> returns a file without sign-in": (
            "CONFIRMED",
            "critical",
            "desk/views.py:29",
        ),
        "ANY /brochure returns a file without sign-in": ("INFERRED", "high", "desk/views.py:33"),
        "ANY /zip runs a back-office write that takes no input without sign-in": (
            "INFERRED",
            "high",
            "desk/jobs.py:3",
        ),
        "ANY /fsca runs a back-office write that takes no input without sign-in": (
            "INFERRED",
            "high",
            "desk/views.py:39",
        ),
        "ANY /report starts a background job without sign-in": (
            "INFERRED",
            "high",
            "desk/views.py:45",
        ),
    }
    doc = next(f for f in found if "/doc/" in f.title)
    assert "returns a file" in doc.detail


def test_public_sensitive_route_replaces_the_unscoped_finding(tmp_path):
    root = app(tmp_path)
    unscoped = findings_for(root, "owasp", "OWASP-A01-UNSCOPED-QUERY")
    assert not any("/claim/" in f.title or "/doc/" in f.title for f in unscoped)
    doc = next(
        f for f in findings_for(root, "owasp", "OWASP-A01-PUBLIC-SENSITIVE") if "/doc/" in f.title
    )
    assert doc.tag.value == "INFERRED"


def test_unsigned_callbacks(tmp_path):
    write(
        tmp_path,
        "hooks/urls.py",
        "from django.urls import path\nfrom hooks import views\nurlpatterns = [\n"
        "    path('reg26a_confirmation_result_hook/', views.result_hook),\n"
        "    path('push/', views.push), path('signed/webhook/', views.signed),\n"
        "    path('status/callback/', views.read_only), path('orders/', views.orders),\n"
        "    path('hooks/start_call_hook/', views.start_call), path('care_hook/', views.care),\n"
        "    path('sms/response/', views.sms_response),\n]\n",
    )
    write(
        tmp_path,
        "hooks/views.py",
        "import hmac\n"
        "def result_hook(request):\n"
        "    Call.create_from_request(request.GET.dict())\n    return HttpResponse('ok')\n"
        "def push(request):\n"
        "    consent = Consent.objects.filter(server_id=request.GET['id']).first()\n"
        "    consent.accept()\n"
        "def signed(request):\n"
        "    if not hmac.compare_digest(sign(request.body), request.headers['X-Signature']):\n"
        "        return HttpResponse(status=403)\n    Event.objects.create(body=request.body)\n"
        "def read_only(request):\n    return JsonResponse({'ok': True})\n"
        "def orders(request):\n    Order.objects.create(ref=request.POST['ref'])\n"
        "def start_call(request):\n    process.delay(request.GET.dict())\n    return HttpResponse('ok')\n"
        "def care(request):\n    return HttpResponse('ok')\n    Call.objects.create(ref=1)\n"
        "def sms_response(request):\n"
        "    params = request.GET.dict() if hasattr(request, 'GET') else {}\n"
        "    Reply.objects.create(phone=params.get('fn'))\n",
    )
    found = findings_for(tmp_path, "owasp", "OWASP-A01-UNSIGNED-CALLBACK")
    assert findings_for(tmp_path, "owasp", "OWASP-A01-PUBLIC-SENSITIVE") == []
    assert sorted((f.title, str(f.locations[1]), f.tag.value) for f in found) == [
        (
            "Callback ANY /hooks/start_call_hook changes data without checking the caller",
            "hooks/views.py:17",
            "INFERRED",
        ),
        (
            "Callback ANY /push changes data without checking the caller",
            "hooks/views.py:7",
            "INFERRED",
        ),
        (
            "Callback ANY /reg26a_confirmation_result_hook changes data without checking the "
            "caller",
            "hooks/views.py:3",
            "INFERRED",
        ),
        (
            "Callback ANY /sms/response changes data without checking the caller",
            "hooks/views.py:24",
            "INFERRED",
        ),
    ]


def test_debug_endpoints_that_disclose_detail(tmp_path):
    write(
        tmp_path,
        "ops/urls.py",
        "from django.urls import path\nfrom ops import views\nurlpatterns = [\n"
        "    path('readyz/', views.readyz), path('healthz/', views.healthz),\n"
        "    path('debug/settings/', views.show), path('about/', views.about),\n]\n",
    )
    write(
        tmp_path,
        "ops/views.py",
        "def readyz(request):\n    checks = {}\n    try:\n        db_check()\n"
        "    except Exception as e:\n        checks['db'] = {'ok': False, 'error': str(e)}\n"
        "    return JsonResponse({'checks': checks})\n"
        "def healthz(request):\n    try:\n        db_check()\n    except Exception as e:\n"
        "        log(str(e))\n    return HttpResponse('OK', content_type='text/plain')\n"
        "def show(request):\n    return JsonResponse({'debug': settings.DEBUG})\n"
        "def about(request):\n    return JsonResponse({'version': sys.version})\n",
    )
    found = findings_for(tmp_path, "owasp", "OWASP-A05-DEBUG-ENDPOINT")
    assert sorted((f.title, str(f.locations[0])) for f in found) == [
        ("Public ANY /debug/settings returns internal detail", "ops/views.py:15"),
        ("Public ANY /readyz returns internal detail", "ops/views.py:6"),
    ]
    assert {f.severity.value for f in found} == {"low"}


def test_debug_routes_that_raise_on_demand(tmp_path):
    write(
        tmp_path,
        "ops/urls.py",
        "from django.urls import path\nfrom ops import views\nurlpatterns = [\n"
        "    path('test/error/', views.test_error),\n"
        "    path('test/serialization_error/', views.test_serialization_error),\n"
        "    path('test/checked/', views.test_checked), path('boom/', views.boom),\n"
        "    path('debug/staff/', views.staff_error),\n]\n",
    )
    write(
        tmp_path,
        "ops/views.py",
        "def test_error(request):\n    100 / 0\n"
        "def test_serialization_error(request):\n"
        "    raise ValidationError('This is a test error')\n"
        "def test_checked(request):\n    if request.GET.get('x'):\n        raise Http404\n"
        "    return HttpResponse('OK')\n"
        "def boom(request):\n    raise ValueError('boom')\n"
        "@login_required\ndef staff_error(request):\n    raise ValueError('boom')\n",
    )
    found = findings_for(tmp_path, "owasp", "OWASP-A05-DEBUG-ENDPOINT")
    assert sorted((f.title, str(f.locations[0])) for f in found) == [
        ("Public ANY /test/error raises an error for anyone", "ops/views.py:2"),
        ("Public ANY /test/serialization_error raises an error for anyone", "ops/views.py:4"),
    ]
    assert "error tracker" in found[0].detail


LIST_MODELS = (
    "from django.db import models\n"
    "class UploadFile(models.Model):\n    file_name = models.FileField()\n"
    "class Batch(models.Model):\n    date = models.DateField()\n"
    "class Premium(models.Model):\n    policy_number = models.CharField(max_length=20)\n"
    "    member_id = models.IntegerField()\n"
    "    batch = models.ForeignKey('Batch', related_name='premiums', on_delete=models.CASCADE)\n"
    "class Article(models.Model):\n    title = models.CharField(max_length=20)\n"
)
LIST_VIEWS = (
    "def uploaded(request):\n    context = {}\n"
    "    context['files'] = UploadFile.objects.order_by('-id')\n"
    "    return smart_respond(request, 'files.html', context)\n"
    "def batch(request, batch_id):\n    found = get_object_or_404(Batch, pk=batch_id)\n"
    "    premiums = found.premiums.all()\n    premiums = narrow(premiums)\n"
    "    return render(request, 'batch.html', {'premiums': premiums})\n"
    "def articles(request):\n"
    "    return render(request, 'a.html', {'items': Article.objects.all()})\n"
    "def counts(request):\n"
    "    return JsonResponse({'n': UploadFile.objects.all().count()})\n"
    "def mine(request):\n"
    "    files = UploadFile.objects.filter(owner=request.user)\n"
    "    return render(request, 'f.html', {'files': files})\n"
)


def test_public_routes_that_list_stored_records(tmp_path):
    write(tmp_path, "desk/models.py", LIST_MODELS)
    names = ("uploaded", "batch/<int:batch_id>", "articles", "counts", "mine")
    patterns = "".join(f"    path('{p}/', views.{p.split('/')[0]}),\n" for p in names)
    write(
        tmp_path,
        "desk/urls.py",
        f"from django.urls import path\nfrom desk import views\nurlpatterns = [\n{patterns}]\n",
    )
    write(tmp_path, "desk/views.py", LIST_VIEWS)
    found = findings_for(tmp_path, "owasp", "OWASP-A01-PUBLIC-SENSITIVE")
    got = sorted((f.title, f.tag.value, str(f.locations[0])) for f in found)
    assert got == [
        (
            "ANY /batch/<int:batch_id> lists stored Premium records without sign-in",
            "INFERRED",
            "desk/views.py:7",
        ),
        (
            "ANY /uploaded lists stored UploadFile records without sign-in",
            "CONFIRMED",
            "desk/views.py:3",
        ),
    ]
