from dpr.api import review
from tests.reviews.helpers import findings_for, write

MODELS = (
    "from django.db import models\n"
    "class Brokerage(models.Model):\n    label = models.CharField(max_length=20)\n"
    "class Advisor(models.Model):\n"
    "    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)\n"
    "    brokerage = models.ForeignKey(Brokerage, on_delete=models.CASCADE)\n"
    "    id_number = models.CharField(max_length=13)\n"
    "    division = models.CharField(max_length=5)\n"
    "class Policy(models.Model):\n"
    "    owner = models.ForeignKey('auth.User', on_delete=models.CASCADE)\n"
    "    policy_number = models.CharField(max_length=20)\n"
    "    premium = models.IntegerField()\n    risk_band = models.IntegerField()\n"
    "class UploadFile(models.Model):\n"
    "    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)\n"
    "    name = models.CharField(max_length=20)\n"
)
ROUTES = {
    "owner-after/<int:pk>": "owner_after",
    "portal/<int:pk>": "PortalView.as_view()",
    "scoped/<int:pk>": "scoped",
    "division/<int:pk>": "division",
    "id-number/<int:pk>": "id_number",
    "premium": "premium",
    "taken": "taken",
    "remove/<int:pk>": "remove",
    "page/<int:pk>": "page",
    "statement/<int:brokerage_id>/<str:from_date>": "statement",
    "staff/<int:pk>": "staff",
    "sms/response": "sms_response",
    "download/<int:file_id>": "download",
    "file/<int:file_id>": "file_link",
    "mail/<int:pk>": "mail",
    "portal-user/<int:pk>": "portal_user",
    "log-view/<int:pk>": "log_view",
    "ensured/<int:pk>": "ensured",
}
VIEWS = (
    "import json\n"
    "from django.contrib.auth.decorators import login_required, user_passes_test\n"
    "from django.http import HttpResponse, JsonResponse\n"
    "from django.shortcuts import get_object_or_404, redirect, render\n"
    "from desk import tasks\nfrom desk.models import Advisor, Brokerage, Policy, UploadFile\n"
    "def has_access(user, brokerage_id):\n    return user.advisor.brokerage_id == brokerage_id\n"
    "class TokenMixin:\n    pass\n"
    "@login_required\ndef owner_after(request, pk):\n"
    "    policy = Policy.objects.get(pk=pk)\n"
    "    if policy.owner_id != request.user.id:\n        raise PermissionDenied\n"
    "    return render(request, 'p.html', {'policy': policy})\n"
    "class PortalView(TokenMixin, View):\n"
    "    def get(self, request, pk):\n"
    "        user = Advisor.objects.get(pk=pk)\n"
    "        if not has_access(request.user, user.brokerage_id):\n"
    "            return redirect('login')\n"
    "        return render(request, 'a.html', {'user': user})\n"
    "@login_required\ndef scoped(request, pk):\n"
    "    policy = get_object_or_404(Policy, pk=pk, owner=request.user)\n"
    "    return render(request, 'p.html', {'policy': policy})\n"
    "@login_required\ndef division(request, pk):\n"
    "    advisor = get_object_or_404(Advisor, pk=pk)\n"
    "    data = {'division_display_name': advisor.get_division_display()}\n"
    "    return JsonResponse(data)\n"
    "@login_required\ndef id_number(request, pk):\n"
    "    advisor = get_object_or_404(Advisor, pk=pk)\n"
    "    return HttpResponse(json.dumps({'id_number': advisor.id_number}))\n"
    "@login_required\ndef premium(req):\n"
    "    policy_id = req.POST['policy_id']\n"
    "    policy = Policy.objects.filter(pk=policy_id)[0]\n"
    "    band = policy.risk_band * 2\n"
    "    result = str(band) + ';0'\n"
    "    return HttpResponse(result)\n"
    "@login_required\ndef taken(request):\n"
    "    number = request.GET['policy_number']\n"
    "    exists = Policy.objects.filter(policy_number=number).exists()\n"
    "    return render(request, 't.html', {'taken': exists})\n"
    "@login_required\ndef remove(request, pk):\n"
    "    Policy.objects.filter(pk=pk).delete()\n"
    "    return JsonResponse({'success': True})\n"
    "@login_required\ndef page(request, pk):\n"
    "    policy = Policy.objects.get(pk=pk)\n"
    "    return render(request, 'p.html', {'policy': policy})\n"
    "@login_required\n@user_passes_test(lambda u: u.has_perm('desk.view_commission'))\n"
    "def statement(req, brokerage_id, from_date):\n"
    "    brokerage = get_object_or_404(Brokerage, pk=brokerage_id)\n"
    "    rows = Policy.objects.filter(created_at__gt=from_date)\n"
    "    return render(req, 's.html', {'brokerage': brokerage, 'rows': rows})\n"
    "@login_required\n@user_passes_test(lambda u: u.has_perm('desk.view_policy'))\n"
    "def staff(request, pk):\n"
    "    policy = Policy.objects.get(pk=pk)\n"
    "    return render(request, 'p.html', {'policy': policy})\n"
    "def sms_response(request):\n"
    "    policy = Policy.objects.get(pk=request.GET['policy_id'])\n"
    "    policy.premium = 0\n    policy.save()\n"
    "    return HttpResponse('ok')\n"
    "def download(request, file_id):\n"
    "    upload = UploadFile.objects.get(pk=file_id)\n"
    "    tasks.download.delay(upload.pk)\n"
    "    return HttpResponse('ok')\n"
    "@login_required\ndef file_link(request, file_id):\n"
    "    saved = UploadFile.objects.get(pk=file_id)\n"
    "    return redirect(saved.file_name.url)\n"
    "@login_required\ndef mail(request, pk):\n"
    "    advisor = get_object_or_404(Advisor, pk=pk)\n"
    "    return HttpResponse(cleaner.clean_html(advisor.id_number))\n"
    "@login_required\ndef portal_user(request, pk):\n"
    "    advisor = get_object_or_404(Advisor, pk=pk)\n"
    "    advisor.create_portal_user()\n"
    "    return redirect(reverse('advisor', kwargs={'pk': advisor.pk}))\n"
    "@login_required\ndef log_view(req, pk):\n"
    "    policy = Policy.objects.get(pk=pk)\n"
    "    record_view(req.user, policy)\n"
    "    return render(req, 'p.html', {'policy': policy})\n"
    "@login_required\ndef ensured(request, pk):\n"
    "    policy = Policy.objects.get(pk=pk)\n"
    "    ensure_can_view(request.user, policy)\n"
    "    return render(request, 'p.html', {'policy': policy})\n"
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
    write(root, "config/settings.py", "INSTALLED_APPS = ['desk']\n")
    return root


def by_path(found):
    return {f.title.split(" ")[1]: f for f in found}


def test_checks_after_the_load_and_quiet_responses(tmp_path):
    found = by_path(findings_for(app(tmp_path), "owasp", "OWASP-A01-UNSCOPED-QUERY"))
    # An ownership check after the load scopes it, on a signed-in and on a public route.
    assert "/owner-after/<int:pk>" not in found
    assert "/portal/<int:pk>" not in found
    assert "/scoped/<int:pk>" not in found
    assert "/ensured/<int:pk>" not in found
    # Responses with no personal data, and existence checks, send nothing about the record.
    assert "/division/<int:pk>" not in found
    assert "/premium" not in found
    assert "/taken" not in found
    # Personal fields in the response, a write, or a rendered record stay reported.
    assert found["/id-number/<int:pk>"].severity.value == "high"
    assert found["/remove/<int:pk>"].severity.value == "high"
    assert found["/page/<int:pk>"].severity.value == "high"
    # A redirect to the record's file, a personal field passed to a method, a write through a
    # method of the record: none of these is quiet.
    for path in ("/file/<int:file_id>", "/mail/<int:pk>", "/portal-user/<int:pk>"):
        assert found[path].severity.value == "high"
    # A call that receives the caller and the record is not a guard: it only asks for proof.
    item = found["/log-view/<int:pk>"]
    assert (item.tag.value, item.severity.value) == ("INFERRED", "high")
    assert "A later call receives the caller" in item.proof_needed


def test_role_gated_tenant_lookup_stays_medium(tmp_path):
    found = by_path(findings_for(app(tmp_path), "owasp", "OWASP-A01-UNSCOPED-QUERY"))
    item = found["/statement/<int:brokerage_id>/<str:from_date>"]
    assert (item.severity.value, item.tag.value) == ("medium", "INFERRED")
    assert "Brokerage by brokerage_id" in item.title
    assert "does not tie" in item.proof_needed
    # A date from the path is not an identifier, so the later query is not a second lookup.
    assert [str(loc) for loc in item.locations] == ["desk/views.py:59"]
    assert found["/staff/<int:pk>"].severity.value == "low"
    issues = {i.title: i for i in review(tmp_path, reviews=["owasp"]).register}
    tenant = issues["Role-gated routes reach any brokerage, company or branch by its id"]
    assert (tenant.count, tenant.severity.value) == (1, "medium")


def test_callback_and_public_sensitive_routes_carry_the_lookup(tmp_path):
    root = app(tmp_path)
    found = by_path(findings_for(root, "owasp", "OWASP-A01-UNSCOPED-QUERY"))
    assert "/sms/response" not in found
    assert "/download/<int:file_id>" not in found
    [hook] = findings_for(root, "owasp", "OWASP-A01-UNSIGNED-CALLBACK")
    assert "desk/views.py:68" in [str(loc) for loc in hook.locations]
    [public] = findings_for(root, "owasp", "OWASP-A01-PUBLIC-SENSITIVE")
    assert public.title == (
        "ANY /download/<int:file_id> looks up a UploadFile record by file_id without sign-in"
    )
    assert public.severity.value == "critical"
    assert [str(loc) for loc in public.locations][:2] == ["desk/views.py:73", "desk/views.py:74"]
    assert "desk/models.py:14" in [str(loc) for loc in public.locations]
