from tests.reviews.helpers import findings_for, write

MODELS = (
    "from django.db import models\n"
    "class Policy(models.Model):\n    owner = models.ForeignKey('auth.User', on_delete=models.CASCADE)\n"
    "    policy_number = models.CharField(max_length=20)\n"
)
URLS = (
    "from django.urls import path\nfrom desk import views\nurlpatterns = [\n"
    "    path('by-get/', views.by_get), path('by-post/', views.by_post),\n"
    "    path('search/', views.search), path('body/', views.body),\n"
    "    path('serialized/', views.serialized), path('mine/', views.mine),\n"
    "    path('derived/', views.derived), path('claim/<str:hashed_pk>/', views.claim),\n"
    "    path('api/policy/<int:policy_id>/', views.policy_api),\n"
    "    path('api/policies/<int:pk>/', views.PolicyView.as_view()),\n"
    "    path('staff/<int:pk>/', views.staff), path('perm/<int:pk>/', views.perm),\n"
    "    path('admin-check/<int:pk>/', views.admin_check),\n"
    "    path('profile/<int:pk>/', views.profile),\n]\n"
)
VIEWS = (
    "import json\n"
    "from django.contrib.auth.decorators import login_required, user_passes_test\n"
    "from rest_framework.decorators import api_view\nfrom rest_framework.views import APIView\n"
    "from desk.models import Policy\n"
    "@login_required\ndef by_get(request):\n"
    "    return Policy.objects.get(pk=request.GET['policy_id'])\n"
    "@login_required\ndef by_post(req):\n"
    "    number = req.POST.get('policy_number')\n"
    "    return Policy.objects.filter(policy_number=number).first()\n"
    "@login_required\ndef search(request):\n"
    "    q = request.GET.get('q')\n    return Policy.objects.filter(name__icontains=q)\n"
    "@login_required\ndef body(request):\n"
    "    data = json.loads(request.body)\n"
    "    return Policy.objects.get(policy_number=data['policy_application_number'])\n"
    "@login_required\ndef serialized(request):\n"
    "    serializer = PolicySerializer(data=request.data)\n    serializer.is_valid()\n"
    "    return Policy.objects.get(pk=serializer.validated_data['policy_id'])\n"
    "@login_required\ndef mine(request):\n"
    "    pid = request.GET['pid']\n"
    "    return Policy.objects.filter_by_user(request.user).get(pk=pid)\n"
    "@login_required\ndef derived(request):\n"
    "    kind = request.GET.get('selected_value').split('_')\n    policy_pk = kind[0]\n"
    "    return Policy.objects.get(pk=policy_pk)\n"
    "@login_required\ndef claim(request, hashed_pk):\n"
    "    decoded = hashids.decode(hashed_pk)\n    claim_pk = decoded[0]\n"
    "    return Policy.objects.get(pk=claim_pk)\n"
    "@api_view(['GET', 'PUT'])\ndef policy_api(request, policy_id=None):\n"
    "    if request.method == 'GET':\n"
    "        policy = Policy.objects.get(pk=policy_id)\n        return Response(policy)\n"
    "    policy = Policy.objects.get(pk=policy_id)\n"
    "    serializer = PolicySerializer(instance=policy, context={'user': request.user})\n"
    "    return save_policy(request, serializer)\n"
    "class PolicyView(APIView):\n"
    "    def get(self, request, pk):\n        return Policy.objects.get(pk=pk)\n"
    "@login_required\n@user_passes_test(lambda u: u.has_perm('desk.view_policy'))\n"
    "def staff(request, pk):\n    return Policy.objects.get(pk=pk)\n"
    "@login_required\ndef perm(request, pk):\n"
    "    if not request.user.has_perm('desk.view_policy'):\n        raise PermissionDenied\n"
    "    return Policy.objects.get(pk=pk)\n"
    "@login_required\ndef admin_check(request, pk):\n    return Policy.objects.get(pk=pk)\n"
    "@login_required\ndef profile(request, pk):\n"
    "    user = Profile.objects.get(pk=pk)\n"
    "    if user.groups.filter(name='Capturer'):\n        user.set_password('x')\n"
)
SETTINGS = "INSTALLED_APPS = ['rest_framework']\nREST_FRAMEWORK = {'DEFAULT_PERMISSION_CLASSES': ['rest_framework.permissions.IsAuthenticated']}\n"


def app(root):
    write(root, "desk/models.py", MODELS)
    write(root, "desk/urls.py", URLS)
    write(root, "desk/views.py", VIEWS)
    write(root, "config/settings.py", SETTINGS)
    return root


def by_path(found):
    return {f.title.split(" ")[1]: f for f in found}


def test_request_values_reach_unscoped_lookups(tmp_path):
    found = by_path(findings_for(app(tmp_path), "owasp", "OWASP-A01-UNSCOPED-QUERY"))
    assert set(found) == {
        "/by-get",
        "/by-post",
        "/body",
        "/serialized",
        "/derived",
        "/claim/<str:hashed_pk>",
        "/api/policy/<int:policy_id>",
        "/api/policies/<int:pk>",
        "/staff/<int:pk>",
        "/perm/<int:pk>",
        "/admin-check/<int:pk>",
        "/profile/<int:pk>",
    }
    assert found["/by-get"].title == "ANY /by-get loads Policy by policy_id with no owner check"
    assert found["/by-post"].title.endswith("by number with no owner check")
    assert found["/body"].title.endswith("by policy_application_number with no owner check")
    assert str(found["/api/policy/<int:policy_id>"].locations[0]) == "desk/views.py:43"
    assert str(found["/api/policies/<int:pk>"].locations[0]) == "desk/views.py:50"


def test_role_gated_routes_are_lowered(tmp_path):
    found = by_path(findings_for(app(tmp_path), "owasp", "OWASP-A01-UNSCOPED-QUERY"))
    for path in ("/staff/<int:pk>", "/perm/<int:pk>"):
        item = found[path]
        assert (item.severity.value, item.exploitability.value, item.tag.value) == (
            "low",
            "low",
            "INFERRED",
        )
        assert "Role-gated back-office access" in item.proof_needed
    for path in ("/admin-check/<int:pk>", "/profile/<int:pk>"):
        assert found[path].severity.value == "high"
    assert found["/admin-check/<int:pk>"].tag.value == "CONFIRMED"


def test_public_sequential_lookup_is_critical(tmp_path):
    write(tmp_path, "desk/models.py", MODELS)
    write(
        tmp_path,
        "desk/urls.py",
        "from django.urls import path\nfrom desk import views\n"
        "urlpatterns = [path('p/<int:pk>/', views.page)]\n",
    )
    write(
        tmp_path,
        "desk/views.py",
        "from desk.models import Policy\n"
        "def page(request, pk):\n    return render(request, 'p.html', {'p': Policy.objects.get(pk=pk)})\n",
    )
    [item] = findings_for(tmp_path, "owasp", "OWASP-A01-UNSCOPED-QUERY")
    assert (item.severity.value, item.tag.value) == ("critical", "INFERRED")
    assert str(item.locations[-1]) == "desk/models.py:2"


def test_django_ninja_body_schema_ids(tmp_path):
    write(
        tmp_path,
        "mobile/models.py",
        "from django.db import models\n"
        "class Application(models.Model):\n    user_id = models.IntegerField()\n"
        "    application_number = models.CharField(max_length=20)\n",
    )
    write(
        tmp_path,
        "mobile/urls.py",
        "from django.urls import path\nfrom mobile.api import api\n"
        "urlpatterns = [path('agent_api/v2/', api.urls)]\n",
    )
    write(
        tmp_path,
        "mobile/api.py",
        "from ninja import NinjaAPI\nfrom mobile.models import Application\n"
        "api = NinjaAPI(auth=header_key)\n"
        "@api.post('/consent')\ndef consent(request, body: ConsentReq):\n"
        "    advisor = request.auth['advisor']\n"
        "    number = body.application_number\n"
        "    return Application.objects.get(application_number=number)\n"
        "@api.get('/application/{application_number}')\n"
        "def detail(request, application_number: str):\n"
        "    return Application.objects.get(application_number=application_number, advisor=request.auth['advisor'])\n"
        "@api.get('/ping', auth=None)\ndef ping(request):\n    return {'ok': True}\n",
    )
    from tests.reviews.test_access import classify

    levels = {path: (a.level, a.evidence) for (_m, path), a in classify(tmp_path).items()}
    assert levels == {
        "/consent": ("authenticated", "NinjaAPI(auth=header_key)"),
        "/application/{application_number}": ("authenticated", "NinjaAPI(auth=header_key)"),
        "/ping": ("public", "auth=None"),
    }
    [item] = findings_for(tmp_path, "owasp", "OWASP-A01-UNSCOPED-QUERY")
    assert item.title == "POST /consent loads Application by number with no owner check"


def test_annotation_without_value_in_a_class_view(tmp_path):
    write(tmp_path, "desk/models.py", MODELS)
    write(
        tmp_path,
        "desk/urls.py",
        "from django.urls import path\nfrom desk import views\n"
        "urlpatterns = [path('p/<int:pk>/', views.Page.as_view())]\n",
    )
    write(
        tmp_path,
        "desk/views.py",
        "class Page(LoginRequiredMixin, View):\n    def get(self, request, pk):\n"
        "        policy: Policy\n        policy = Policy.objects.get(pk=pk)\n",
    )
    [item] = findings_for(tmp_path, "owasp", "OWASP-A01-UNSCOPED-QUERY")
    assert str(item.locations[0]) == "desk/views.py:4"


def test_code_after_a_top_level_return_is_not_read(tmp_path):
    write(tmp_path, "desk/models.py", MODELS)
    write(
        tmp_path,
        "desk/urls.py",
        "from django.urls import path\nfrom desk import views\n"
        "urlpatterns = [path('hook/', views.hook)]\n",
    )
    write(
        tmp_path,
        "desk/views.py",
        "def hook(request):\n    return HttpResponse('ok')\n"
        "    policy = Policy.objects.get(pk=request.GET['policy_id'])\n",
    )
    assert findings_for(tmp_path, "owasp", "OWASP-A01-UNSCOPED-QUERY") == []


def test_signed_in_lists_of_every_user_or_personal_record(tmp_path):
    write(
        tmp_path,
        "api/models.py",
        "from django.db import models\n"
        "class PoliciesUser(models.Model):\n    email = models.EmailField()\n"
        "class Applicant(models.Model):\n    id_number = models.CharField(max_length=13)\n"
        "    email = models.EmailField()\n"
        "class Product(models.Model):\n    title = models.CharField(max_length=20)\n"
        "class Dependent(models.Model):\n    id_number = models.CharField(max_length=13)\n"
        "    applicant = models.ForeignKey(Applicant, related_name='dependents')\n",
    )
    write(
        tmp_path,
        "api/urls.py",
        "from django.urls import path\nfrom api import views\nurlpatterns = [\n"
        "    path('users/list/', views.user_list), path('members/', views.members),\n"
        "    path('products/', views.products), path('staff/users/', views.staff_users),\n"
        "    path('team/', views.team), path('member-api/', views.MemberList.as_view()),\n"
        "    path('deps/<int:pk>/', views.deps),\n]\n",
    )
    write(
        tmp_path,
        "api/views.py",
        "from django.contrib.auth.decorators import login_required, user_passes_test\n"
        "from rest_framework.decorators import api_view\n"
        "from rest_framework.generics import ListAPIView\n"
        "@api_view(['GET'])\ndef user_list(request):\n"
        "    users = PoliciesUser.objects.order_by('-username')\n"
        "    serializer = UserSerializer(users, many=True)\n"
        "    return JsonResponse(serializer.data, safe=False)\n"
        "@login_required\ndef members(request):\n"
        "    return render(request, 'm.html', {'members': Applicant.objects.all()[:100]})\n"
        "@login_required\ndef products(request):\n"
        "    return render(request, 'p.html', {'items': Product.objects.all()})\n"
        "@login_required\n@user_passes_test(lambda u: u.is_superuser)\ndef staff_users(request):\n"
        "    return render(request, 'u.html', {'users': PoliciesUser.objects.all()})\n"
        "@login_required\ndef team(request):\n"
        "    users = PoliciesUser.objects.filter(team=request.user.team)\n"
        "    return render(request, 't.html', {'users': users})\n"
        "class MemberList(ListAPIView):\n"
        "    queryset = PoliciesUser.objects.all()\n    serializer_class = UserSerializer\n"
        "@login_required\ndef deps(request, pk):\n    found = Applicant.objects.get(pk=pk)\n"
        "    return render(request, 'd.html', {'deps': found.dependents.all()})\n",
    )
    write(tmp_path, "config/settings.py", SETTINGS)
    found = findings_for(tmp_path, "owasp", "OWASP-A01-UNSCOPED-LIST")
    got = sorted((f.title, f.tag.value, str(f.locations[0])) for f in found)
    assert got == [
        (
            "ANY /member-api returns every PoliciesUser record to any signed-in user",
            "CONFIRMED",
            "api/views.py:24",
        ),
        (
            "ANY /members returns every Applicant record to any signed-in user",
            "INFERRED",
            "api/views.py:11",
        ),
        (
            "ANY /users/list returns every PoliciesUser record to any signed-in user",
            "CONFIRMED",
            "api/views.py:6",
        ),
    ]
