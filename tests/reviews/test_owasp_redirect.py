from tests.reviews.helpers import findings_for, write

VIEWS = """
from django.http import HttpResponseRedirect
from django.shortcuts import redirect
from django.utils.http import url_has_allowed_host_and_scheme


def login_user(request):
    form = LoginForm(request.POST)
    if form.is_valid():
        return HttpResponseRedirect(request.GET.get("next", "") or "/")


def go_back(request):
    return HttpResponseRedirect(request.META.get("HTTP_REFERER"))


def go_back_again(request):
    target = request.META.get("HTTP_REFERER", "/")
    return redirect(target)


def after_save(request):
    url = request.POST["return_url"]
    return redirect(url)


def checked(request):
    nxt = request.GET.get("next")
    if url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}):
        return redirect(nxt)
    return redirect("/")


def fixed(request, pk):
    return redirect(f"/orders/{request.GET['id']}/")


def named(request):
    return redirect(reverse(request.GET["view"]))


def same_page(request):
    params = request.GET.copy()
    query_string = params.urlencode()
    url = f"{request.path}?{query_string}" if query_string else request.path
    return redirect(url)


def to_record(request, pk):
    order = Order.objects.get(pk=request.GET["id"])
    return redirect(order)
"""


def test_open_redirect_from_request_values_and_referer(tmp_path):
    write(tmp_path, "shop/views.py", VIEWS)
    write(tmp_path, "shop/tests/test_views.py", VIEWS)
    found = findings_for(tmp_path, "owasp", "OWASP-A01-OPEN-REDIRECT")
    params = sorted((f.locations[0].line, f.title) for f in found if f.severity.value == "medium")
    assert params == [
        (10, "Redirect goes to the request value next"),
        (24, "Redirect goes to the request value return_url"),
    ]
    assert all(f.tag.value == "CONFIRMED" for f in found if f.severity.value == "medium")
    [referer] = [f for f in found if f.severity.value == "low"]
    assert [loc.line for loc in referer.locations] == [14, 19]
    assert referer.tag.value == "INFERRED"
    assert referer.title == "Redirect goes to the Referer header"


def test_express_redirect_to_query(tmp_path):
    write(
        tmp_path,
        "app/server.js",
        "app.get('/login', (req, res) => {\n  res.redirect(req.query.next);\n});\n"
        "app.get('/home', (req, res) => {\n  res.redirect('/dashboard');\n});\n",
    )
    [finding] = findings_for(tmp_path, "owasp", "OWASP-A01-OPEN-REDIRECT")
    assert str(finding.locations[0]) == "app/server.js:2"


def test_no_redirect_finding_for_safe_code(tmp_path):
    write(
        tmp_path,
        "shop/views.py",
        "from django.shortcuts import redirect\n\n\n"
        "def home(request):\n    return redirect('home')\n",
    )
    assert findings_for(tmp_path, "owasp", "OWASP-A01-OPEN-REDIRECT") == []
