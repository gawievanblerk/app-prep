from tests.reviews.helpers import findings_for, write

URLS = """
from django.urls import path
from shop import views

urlpatterns = [
    path("qlink_action/", views.perform_qlink_action),
    path("comment/", views.add_note),
    path("status/", views.status),
    path("hook/", views.provider_hook),
    path("api/", views.token_api),
    path("send_unsent/", views.send_unsent),
    path("advisor_delete/<int:pk>/", views.advisor_delete),
    path("post_only/", views.post_only),
    path("form_view/", views.form_view),
    path("public_job/", views.public_job),
    path("report/", views.report),
    path("purge/", views.Purge.as_view()),
]
"""

VIEWS = """
import threading
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST


@login_required
@csrf_exempt
def perform_qlink_action(req):
    result = qlink_persal_transaction(req.POST.get("policy_id"))
    PolicyComment.add_comment(req.POST.get("policy_id"), result)
    return JsonResponse(result)


@csrf_exempt
@login_required
def add_note(request):
    Note.objects.create(text=request.POST["text"])
    return HttpResponse("ok")


@csrf_exempt
@login_required
def status(request):
    return JsonResponse({"ok": True})


@csrf_exempt
def provider_hook(request):
    Payment.objects.create(ref=request.POST["ref"])
    return HttpResponse("ok")


@csrf_exempt
@login_required
def token_api(request):
    if request.headers.get("Authorization") != settings.API_TOKEN:
        return HttpResponse(status=401)
    Order.objects.create(ref=request.POST["ref"])
    return HttpResponse("ok")


@login_required
def send_unsent(request):
    smses = SmsMessage.objects.filter(sent=False)
    t = threading.Thread(target=send_unsent_sms, args=(smses,))
    t.start()
    return HttpResponse("sent")


@login_required
def advisor_delete(request, pk):
    Advisor.objects.get(pk=pk).delete()
    return redirect("advisors")


@login_required
@require_POST
def post_only(request):
    Order.objects.filter(open=True).delete()
    return redirect("orders")


@login_required
def form_view(request):
    if request.method == "POST":
        Order.objects.filter(open=True).update(open=False)
    return render(request, "x.html")


def public_job(request):
    rebuild.delay()
    return HttpResponse("ok")


@login_required
def report(request):
    rows = Order.objects.filter(open=True)
    for row in rows:
        send_email(row.owner)
    Order.objects.get(pk=1).save()
    return render(request, "r.html", {"rows": rows})


class Purge(LoginRequiredMixin, View):
    def get(self, request):
        Order.objects.filter(stale=True).update(archived=True)
        return redirect("orders")
"""

SETTINGS = """
INSTALLED_APPS = ["shop"]
DEBUG = False
if not DEBUG:
    SESSION_COOKIE_SAMESITE = "None"
"""


def _app(tmp_path, samesite=True):
    write(tmp_path, "shop/urls.py", URLS)
    write(tmp_path, "shop/views.py", VIEWS)
    write(tmp_path, "shop/settings.py", SETTINGS if samesite else "INSTALLED_APPS = []\n")


def test_csrf_exempt_session_views_escalate_with_samesite_none(tmp_path):
    _app(tmp_path)
    [finding] = findings_for(tmp_path, "owasp", "OWASP-A01-CSRF-EXEMPT")
    assert finding.title == "3 signed-in view(s) turn off CSRF protection"
    assert (finding.severity.value, finding.tag.value) == ("high", "CONFIRMED")
    assert [str(loc) for loc in finding.locations] == [
        "shop/views.py:9",
        "shop/views.py:16",
        "shop/views.py:23",
        "shop/settings.py:5",
    ]
    assert "perform_qlink_action, add_note" in finding.detail
    assert "perform_qlink_action move money" in finding.detail
    assert "SameSite=None" in finding.detail


def test_csrf_exempt_without_samesite_none_is_medium(tmp_path):
    _app(tmp_path, samesite=False)
    [finding] = findings_for(tmp_path, "owasp", "OWASP-A01-CSRF-EXEMPT")
    assert finding.severity.value == "medium"
    assert "SameSite" not in finding.detail


def test_csrf_exempt_read_only_views_are_low(tmp_path):
    write(tmp_path, "shop/urls.py", URLS.replace("views.perform_qlink_action", "views.status"))
    write(
        tmp_path,
        "shop/views.py",
        "@csrf_exempt\n@login_required\ndef status(request):\n    return JsonResponse({})\n",
    )
    [finding] = findings_for(tmp_path, "owasp", "OWASP-A01-CSRF-EXEMPT")
    assert finding.severity.value == "low"
    assert "None of them visibly changes data" in finding.detail


def test_get_side_effects(tmp_path):
    _app(tmp_path)
    found = findings_for(tmp_path, "owasp", "OWASP-A04-GET-SIDE-EFFECT")
    titles = sorted(f.title for f in found)
    assert titles == [
        "GET /advisor_delete/<int:pk> deletes records",
        "GET /purge writes records in bulk",
        "GET /report sends messages in a loop",
        "GET /send_unsent starts a background job",
    ]
    [job] = [f for f in found if "send_unsent" in f.title]
    assert [str(loc) for loc in job.locations] == ["shop/views.py:47", "shop/views.py:45"]


def test_single_deletes_grouped_low_and_post_flows_skipped(tmp_path):
    write(
        tmp_path,
        "claims/urls.py",
        "from django.urls import path\nfrom claims import views\n\nurlpatterns = [\n"
        '    path("comment_delete/", views.comment_delete),\n'
        '    path("doc_delete/<int:pk>/", views.doc_delete),\n'
        '    path("note_delete/<int:pk>/", views.note_delete),\n]\n',
    )
    write(
        tmp_path,
        "claims/views.py",
        "@login_required\ndef comment_delete(req):\n    if req.POST:\n"
        "        Comment.objects.get(id=req.POST['id']).delete()\n    return JsonResponse({})\n\n\n"
        "@login_required\ndef doc_delete(request, pk):\n    Doc.objects.get(pk=pk).delete()\n"
        "    return redirect('docs')\n\n\n"
        "@login_required\ndef note_delete(request, pk):\n    Note.objects.get(pk=pk).delete()\n"
        "    return redirect('notes')\n",
    )
    [finding] = findings_for(tmp_path, "owasp", "OWASP-A04-GET-SIDE-EFFECT")
    assert finding.title == "GET /doc_delete/<int:pk> and 1 other route(s) delete records"
    assert (finding.severity.value, [loc.line for loc in finding.locations]) == ("low", [10, 16])


def test_dict_updates_in_a_loop_are_not_writes(tmp_path):
    write(
        tmp_path,
        "sync/urls.py",
        "from django.urls import path\nfrom sync import views\n\nurlpatterns = [\n"
        '    path("passwords/", views.passwords),\n'
        '    path("rename/", views.rename),\n]\n',
    )
    write(
        tmp_path,
        "sync/views.py",
        "@login_required\ndef passwords(request):\n    data = {}\n"
        "    for row in Secret.objects.all():\n        data.update({row.name: row.value})\n"
        "        extra = dict(name=row.name)\n        extra.update(**row.more)\n"
        "    return JsonResponse(data)\n\n\n"
        "@login_required\ndef rename(request):\n"
        "    for member in Member.objects.filter(active=True):\n"
        "        member.surname = 'x'\n        Member.objects.filter(pk=member.pk).update(x=1)\n"
        "    return redirect('home')\n",
    )
    [finding] = findings_for(tmp_path, "owasp", "OWASP-A04-GET-SIDE-EFFECT")
    assert finding.title == "GET /rename writes records in bulk"
