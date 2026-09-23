from tests.reviews.helpers import findings_for, write

URLS = (
    "from django.urls import path\nfrom shop import views\n\n"
    "urlpatterns = [path('login/', views.login_view), path('contact/', views.contact)]\n"
)
VIEWS = (
    "from django.contrib.auth import authenticate, login\n\n"
    "def login_view(request):\n"
    "    if request.method == 'POST':\n"
    "        user = authenticate(request, username=request.POST['username'],"
    " password=request.POST['password'])\n"
    "        if user is None:\n"
    "            return render(request, 'login.html', {'error': 'Invalid credentials'})\n"
    "        login(request, user)\n"
    "    return render(request, 'login.html')\n\n"
    "def contact(request):\n"
    "    if request.method == 'POST':\n"
    "        Message.objects.create(body=request.POST['body'])\n"
    "    return render(request, 'contact.html')\n"
)


def app(root, settings, extra=""):
    write(root, "requirements.txt", "django\n")
    write(root, "manage.py", "import django\n")
    write(root, "shop/urls.py", URLS)
    write(root, "shop/views.py", VIEWS)
    write(root, "shop/settings.py", 'ROOT_URLCONF = "shop.urls"\n' + settings)
    if extra:
        write(root, "shop/settings_site.py", extra)
    return root


def test_axes_in_settings_counts_as_a_sign_in_lockout(tmp_path):
    app(tmp_path, "INSTALLED_APPS = ['django.contrib.auth']\n")
    [finding] = findings_for(tmp_path, "auth", "AUTH-NO-LOCKOUT")
    assert finding.locations[0].file == "shop/views.py"
    app(tmp_path, "INSTALLED_APPS = ['django.contrib.auth', 'axes']\n")
    assert findings_for(tmp_path, "auth", "AUTH-NO-LOCKOUT") == []


def test_weak_axes_settings(tmp_path):
    app(
        tmp_path,
        "INSTALLED_APPS = ['django.contrib.auth', 'axes']\n",
        "AXES_FAILURE_LIMIT = 3\nAXES_LOCKOUT_PARAMETERS = ['username']\n",
    )
    [finding] = findings_for(tmp_path, "auth", "AUTH-LOCKOUT-WEAK")
    assert [str(loc) for loc in finding.locations] == [
        "shop/settings.py:2",
        "shop/settings_site.py:2",
    ]
    assert (finding.severity.value, finding.tag.value) == ("medium", "CONFIRMED")
    assert "AXES_COOLOFF_TIME is not set" in finding.detail
    assert "keyed by user name only" in finding.detail


def test_axes_by_ip_only_with_a_high_limit_is_low(tmp_path):
    app(
        tmp_path,
        "MIDDLEWARE = ['axes.middleware.AxesMiddleware']\nINSTALLED_APPS = []\n",
        "from datetime import timedelta\n"
        "AXES_FAILURE_LIMIT = 50\nAXES_COOLOFF_TIME = timedelta(minutes=15)\n",
    )
    [finding] = findings_for(tmp_path, "auth", "AUTH-LOCKOUT-WEAK")
    assert finding.severity.value == "low"
    assert "allows 50 failed attempts" in finding.detail
    assert "keyed by IP address only" in finding.detail


def test_well_set_axes_is_not_reported(tmp_path):
    app(
        tmp_path,
        "INSTALLED_APPS = ['axes']\n",
        "AXES_FAILURE_LIMIT = 5\nAXES_COOLOFF_TIME = 1\n"
        "AXES_LOCKOUT_PARAMETERS = [['username', 'ip_address'], 'ip_address']\n",
    )
    assert findings_for(tmp_path, "auth", "AUTH-LOCKOUT-WEAK") == []
    write(tmp_path, "shop/settings.py", "INSTALLED_APPS = ['django.contrib.auth']\n")
    assert findings_for(tmp_path, "auth", "AUTH-LOCKOUT-WEAK") == []


def test_django_ratelimit_decorator_counts_as_a_limit(tmp_path):
    app(tmp_path, "INSTALLED_APPS = ['django.contrib.auth']\n")
    write(
        tmp_path,
        "shop/views.py",
        "from django_ratelimit.decorators import ratelimit\n"
        + VIEWS.replace(
            "def login_view(request):",
            "@ratelimit(key='ip', rate='5/m', block=True)\ndef login_view(request):",
        ),
    )
    assert findings_for(tmp_path, "auth", "AUTH-NO-LOCKOUT") == []


def test_axes_counts_as_a_limit_on_public_login_forms(tmp_path):
    only_login = "from django.urls import path\nfrom shop import views\n\n" + (
        "urlpatterns = [path('login/', views.login_view)]\n"
    )
    app(tmp_path, "INSTALLED_APPS = ['django.contrib.auth']\n")
    write(tmp_path, "shop/urls.py", only_login)
    [finding] = findings_for(tmp_path, "abuse", "ABUSE-FORM-NO-CHALLENGE")
    assert "accept unlimited automated submissions" in finding.title + finding.detail
    write(tmp_path, "shop/settings.py", "INSTALLED_APPS = ['django.contrib.auth', 'axes']\n")
    [finding] = findings_for(tmp_path, "abuse", "ABUSE-FORM-NO-CHALLENGE")
    assert "have rate limits but no bot challenge" in finding.title + finding.detail
