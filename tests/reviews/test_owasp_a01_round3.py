from dpr.api import review
from tests.reviews.helpers import findings_for, write

MODELS = (
    "from django.db import models\n"
    "class Brokerage(models.Model):\n    label = models.CharField(max_length=20)\n"
    "class Advisor(models.Model):\n"
    "    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)\n"
    "    brokerage = models.ForeignKey(Brokerage, on_delete=models.CASCADE)\n"
    "    id_number = models.CharField(max_length=13)\n"
    "    basic_salary = models.IntegerField()\n"
    "class Policy(models.Model):\n"
    "    owner = models.ForeignKey('auth.User', on_delete=models.CASCADE)\n"
    "    policy_number = models.CharField(max_length=20)\n"
    "    premium = models.IntegerField()\n    plan_code = models.CharField(max_length=5)\n"
    "class Interaction(models.Model):\n"
    "    agent = models.ForeignKey('auth.User', on_delete=models.CASCADE)\n"
    "    member_id = models.IntegerField()\n"
    "    status = models.CharField(max_length=5)\n    notes = models.TextField()\n"
    "class PlanRate(models.Model):\n"
    "    plan_code = models.CharField(max_length=5)\n"
    "    premium = models.IntegerField()\n    cover_amount = models.IntegerField()\n"
    "class SmsMessage(models.Model):\n"
    "    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)\n"
    "    reference = models.CharField(max_length=20)\n"
    "    delivered = models.BooleanField()\n"
)
ROUTES = {
    "admin/<int:brokerage_id>": "brokerage_admin",
    "super/<int:brokerage_id>": "brokerage_super",
    "manage/<int:brokerage_id>": "brokerage_change",
    "statement/<int:brokerage_id>": "statement",
    "either/<int:brokerage_id>": "either",
    "role/<int:brokerage_id>": "own_role",
    "interactions/<str:status>": "interactions",
    "all-interactions/<str:status>": "all_interactions",
    "mine/<int:pk>": "mine",
    "calc": "calc",
    "calc-helper": "calc_helper",
    "details": "details",
    "same-person": "same_person",
    "salary/<int:pk>": "salary",
    "products": "products",
    "invoice/<int:pk>": "invoice",
    "staff-a/<int:pk>": "staff_a",
    "staff-b/<int:pk>": "staff_b",
    "report_sms_status": "report_sms_status",
    "0f3a9c1d7e5b2a4c8d6e0f1a3b5c7d9e/delivery": "sms_delivery",
    "claim_status/<int:pk>": "claim_status",
}
VIEWS = (
    "from django.contrib.auth.decorators import login_required, permission_required\n"
    "from django.contrib.auth.decorators import user_passes_test\n"
    "from django.http import HttpResponse, JsonResponse\n"
    "from django.shortcuts import get_object_or_404, render\n"
    "from desk.models import Advisor, Brokerage, Interaction, PlanRate, Policy, SmsMessage\n"
    "from desk.jobs import run_in_background, parse_status\n"
    "def own_policies(user):\n    return Policy.objects.filter(owner=user)\n"
    "@login_required\n@permission_required('desk.brokerage_admin', raise_exception=True)\n"
    "def brokerage_admin(request, brokerage_id):\n"
    "    brokerage = get_object_or_404(Brokerage, id=brokerage_id)\n"
    "    return render(request, 'b.html', {'brokerage': brokerage})\n"
    "@login_required\n@user_passes_test(lambda u: u.is_superuser)\n"
    "def brokerage_super(request, brokerage_id):\n"
    "    brokerage = get_object_or_404(Brokerage, id=brokerage_id)\n"
    "    return render(request, 'b.html', {'brokerage': brokerage})\n"
    "@login_required\n@permission_required('desk.change_brokerage')\n"
    "def brokerage_change(request, brokerage_id):\n"
    "    brokerage = get_object_or_404(Brokerage, id=brokerage_id)\n"
    "    return render(request, 'b.html', {'brokerage': brokerage})\n"
    "@login_required\n@user_passes_test(lambda u: u.has_perm('desk.view_commission'))\n"
    "def statement(request, brokerage_id):\n"
    "    brokerage = get_object_or_404(Brokerage, pk=brokerage_id)\n"
    "    return render(request, 's.html', {'brokerage': brokerage})\n"
    "@login_required\n"
    "@user_passes_test(lambda u: u.is_superuser or u.has_perm('desk.view_commission'))\n"
    "def either(request, brokerage_id):\n"
    "    brokerage = get_object_or_404(Brokerage, pk=brokerage_id)\n"
    "    return render(request, 's.html', {'brokerage': brokerage})\n"
    "@login_required\n@user_passes_test(lambda u: u.is_advisor)\n"
    "def own_role(request, brokerage_id):\n"
    "    brokerage = get_object_or_404(Brokerage, pk=brokerage_id)\n"
    "    return render(request, 's.html', {'brokerage': brokerage})\n"
    "@login_required\ndef interactions(request, status=None):\n"
    "    rows = Interaction.objects.all()\n"
    "    user = request.user\n"
    "    if not user.is_executive:\n        rows = rows.filter(agent=user)\n"
    "    rows = rows.filter(status=status)\n"
    "    return render(request, 'i.html', {'rows': rows})\n"
    "@login_required\ndef all_interactions(request, status=None):\n"
    "    rows = Interaction.objects.all()\n"
    "    rows = rows.filter(status=status)\n"
    "    return render(request, 'i.html', {'rows': rows})\n"
    "@login_required\ndef mine(request, pk):\n"
    "    policies = own_policies(request.user)\n"
    "    policy = policies.get(pk=pk)\n"
    "    return render(request, 'p.html', {'policy': policy})\n"
    "@login_required\ndef calc(req):\n"
    "    policy_id = req.POST['policy_id']\n"
    "    policy = Policy.objects.get(pk=policy_id)\n"
    "    total_premium = policy.premium * 2\n"
    "    lc_premium = policy.premium\n"
    "    return HttpResponse(str(lc_premium) + ';' + str(total_premium))\n"
    "@login_required\ndef calc_helper(req):\n"
    "    policy = Policy.objects.get(pk=req.POST['policy_id'])\n"
    "    premium = get_funeral_premium(policy.plan_code, req.POST['plan_option'])\n"
    "    return HttpResponse(str(premium) + ';' + req.POST['cover_amount'])\n"
    "@login_required\ndef details(req):\n"
    "    policy = Policy.objects.get(pk=req.POST['policy_id'])\n"
    "    return JsonResponse(policy_details(policy))\n"
    "@login_required\ndef same_person(req):\n"
    "    rows = Policy.objects.filter(policy_number=req.POST['policy_number'])\n"
    "    data = []\n"
    "    for row in rows:\n"
    "        data.append({'name': row.fullname(), 'cover': row.get_cover_amount()})\n"
    "    return JsonResponse({'items': data})\n"
    "@login_required\ndef salary(req, pk):\n"
    "    advisor = Advisor.objects.get(pk=pk)\n"
    "    return JsonResponse({'salary': advisor.basic_salary})\n"
    "@login_required\ndef products(req):\n"
    "    policy = Policy.objects.get(pk=req.POST['policy_id'])\n"
    "    rates = PlanRate.objects.filter(plan_code=policy.plan_code)\n"
    "    data = []\n"
    "    for rate in rates:\n"
    "        data.append({'id': rate.id, 'premium': rate.premium, 'cover': rate.cover_amount})\n"
    "    return JsonResponse({'item_list': data})\n"
    "@login_required\ndef invoice(req, pk):\n"
    "    policy = Policy.objects.get(pk=pk)\n"
    "    return JsonResponse({'number': policy.policy_number, 'total': policy.total})\n"
    "@login_required\n@user_passes_test(lambda u: u.has_perm('desk.view_policy'))\n"
    "def staff_a(request, pk):\n"
    "    policy = Policy.objects.get(pk=pk)\n"
    "    return render(request, 'p.html', {'policy': policy})\n"
    "@login_required\n@user_passes_test(lambda u: u.has_perm('desk.view_policy'))\n"
    "def staff_b(request, pk):\n"
    "    policy = Policy.objects.get(pk=pk)\n"
    "    return render(request, 'p.html', {'policy': policy})\n"
    "def report_sms_status(request):\n"
    "    body = request.body\n"
    "    run_in_background(parse_status, body.decode('utf-8'))\n"
    "    return HttpResponse('ok')\n"
    "def sms_delivery(request):\n"
    "    message = SmsMessage.objects.get(reference=request.GET['rf'])\n"
    "    message.delivered = True\n    message.save()\n"
    "    return HttpResponse('ok')\n"
    "def claim_status(request, pk):\n"
    "    policy = Policy.objects.get(pk=pk)\n"
    "    policy.premium = 0\n    policy.save()\n"
    "    return HttpResponse('ok')\n"
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
    write(root, "desk/jobs.py", "def run_in_background(fn, *args):\n    fn(*args)\n")
    write(root, "config/settings.py", "INSTALLED_APPS = ['desk']\n")
    return root


def unscoped(root):
    found = findings_for(root, "owasp", "OWASP-A01-UNSCOPED-QUERY")
    single = {f.title.split(" ")[1]: f for f in found if f.severity.value != "low"}
    folded = [f for f in found if f.severity.value == "low"]
    return single, folded


def test_admin_gates_leave_the_tenant_group_and_member_gates_stay(tmp_path):
    single, [folded] = unscoped(app(tmp_path))
    # A back-office admin permission, a superuser test, or a permission to manage the tenant
    # model itself: looking up any brokerage is what the role is for.
    for path in ("/admin/<int:brokerage_id>", "/super/<int:brokerage_id>"):
        assert path not in single
        assert path in folded.detail
    assert "/manage/<int:brokerage_id>" in folded.detail
    # A permission any member or agent may hold keeps the tenant lookup medium (F-33), and so
    # does a gate that an ordinary role passes on its own.
    for path in (
        "/statement/<int:brokerage_id>",
        "/either/<int:brokerage_id>",
        "/role/<int:brokerage_id>",
    ):
        assert single[path].severity.value == "medium"
        assert path not in folded.detail


def test_caller_filters_scope_later_lookups(tmp_path):
    single, folded = unscoped(app(tmp_path))
    # Narrowed to the caller in a branch, through a name derived from request.user.
    assert "/interactions/<str:status>" not in single
    # A helper that returns the caller's own records.
    assert "/mine/<int:pk>" not in single
    # The same lookup with no caller filter stays reported.
    assert single["/all-interactions/<str:status>"].severity.value == "high"


def test_prices_and_reference_records_are_not_personal(tmp_path):
    single, _folded = unscoped(app(tmp_path))
    # A calculator that answers with premiums, and a product list read from a model with no
    # personal fields, send nothing personal.
    assert "/calc" not in single
    assert "/products" not in single
    # A helper named for a price, and the caller's own input echoed back.
    assert "/calc-helper" not in single
    # A helper that is not named for a price may return anything about the record.
    assert single["/details"].severity.value == "high"
    # A person's name beside a price is still personal.
    assert single["/same-person"].severity.value == "high"
    # A person's salary is still personal, and so is a total that is not a price.
    assert single["/salary/<int:pk>"].severity.value == "high"
    assert single["/invoice/<int:pk>"].severity.value == "high"


def test_provider_status_and_delivery_routes_are_callbacks(tmp_path):
    root = app(tmp_path)
    single, _folded = unscoped(root)
    hooks = {
        f.title.split(" ")[2]: f for f in findings_for(root, "owasp", "OWASP-A01-UNSIGNED-CALLBACK")
    }
    assert "/report_sms_status" in hooks
    delivery = next(path for path in hooks if path.endswith("/delivery"))
    assert "<redacted:path-token>" in delivery
    assert not [path for path in single if path.endswith("/delivery")]
    # A status route that names no message or payment channel is not a provider callback.
    assert "/claim_status/<int:pk>" not in hooks
    public = findings_for(root, "owasp", "OWASP-A01-PUBLIC-SENSITIVE")
    assert not [f for f in public if "/report_sms_status" in f.title]


def test_role_gated_lows_fold_into_one_finding_per_app(tmp_path):
    root = app(tmp_path)
    _single, [folded] = unscoped(root)
    assert folded.title == "5 role-gated back-office routes load records with no owner check"
    assert (folded.severity.value, folded.tag.value) == ("low", "INFERRED")
    # Every route is listed in the detail, and every lookup is a location.
    for path in ("/staff-a/<int:pk>", "/staff-b/<int:pk>", "/admin/<int:brokerage_id>"):
        assert path in folded.detail
    assert len(folded.locations) == 5
    assert "desk/views.py" in folded.detail
    issues = {i.title: i for i in review(root, reviews=["owasp"]).register}
    gated = issues["Role-gated back-office routes load records with no owner check"]
    assert (gated.count, gated.severity.value) == (1, "low")


def test_markdown_lists_twenty_places_then_a_count(tmp_path):
    from dataclasses import replace

    from dpr.model import Location
    from dpr.report.markdown import _block

    _single, [folded] = unscoped(app(tmp_path))
    many = replace(folded, locations=[Location("desk/views.py", n) for n in range(1, 26)])
    text = _block("FINDING", 1, many)
    assert "`desk/views.py:20` and 5 more (all in the JSON report)" in text
    assert "`desk/views.py:21`" not in text
