from tests.reviews.helpers import findings_for, write

FORMS = """
from django import forms
from django.forms import ModelForm


class UserForm(ModelForm):
    class Meta:
        model = PoliciesUser
        fields = [
            "username",
            "groups",
        ]


class StaffFlagForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ["is_staff", "bio"]


class SafeUserForm(ModelForm):
    class Meta:
        model = PoliciesUser
        fields = ["username", "email"]


class AllUserForm(ModelForm):
    class Meta:
        model = User
        fields = "__all__"


class PoppedForm(ModelForm):
    class Meta:
        model = User
        fields = ["username", "is_superuser"]

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        if not user.is_superuser:
            self.fields.pop("is_superuser")


class ArticleForm(ModelForm):
    class Meta:
        model = Article
        fields = ["title", "groups"]
"""

URLS = """
from django.urls import path
from accounts import views

urlpatterns = [
    path("user/<int:user_id>/", views.user_page),
    path("staff/", views.staff_page),
    path("all/", views.all_page),
    path("popped/", views.popped_page),
    path("article/", views.article_page),
    path("safe/", views.safe_page),
]
"""

VIEWS = """
from django.contrib.auth.decorators import login_required, user_passes_test
from accounts import forms


@login_required
@user_passes_test(lambda u: u.is_superuser or u.is_system_support)
def user_page(request, user_id=None):
    form = forms.UserForm(request.POST or None)
    return render(request, "u.html", {"form": form})


@login_required
@user_passes_test(lambda u: u.is_superuser)
def staff_page(request):
    form = forms.StaffFlagForm(request.POST or None)
    return render(request, "s.html", {"form": form})


def all_page(request):
    form = forms.AllUserForm(request.POST or None)
    return render(request, "a.html", {"form": form})


@login_required
def popped_page(request):
    form = forms.PoppedForm(request.POST or None, user=request.user)
    return render(request, "p.html", {"form": form})


@login_required
def article_page(request):
    return render(request, "a.html", {"form": forms.ArticleForm()})


@login_required
def safe_page(request):
    return render(request, "a.html", {"form": forms.SafeUserForm()})
"""


def test_privilege_fields_on_forms_used_by_non_superuser_views(tmp_path):
    write(tmp_path, "accounts/forms.py", FORMS)
    write(tmp_path, "accounts/urls.py", URLS)
    write(tmp_path, "accounts/views.py", VIEWS)
    found = {f.title: f for f in findings_for(tmp_path, "owasp", "OWASP-A01-PRIVILEGE-FIELDS")}
    assert sorted(found) == [
        "AllUserForm lets its users set is_superuser, is_staff, user_permissions, groups, permissions",
        "UserForm lets its users set groups",
    ]
    user = found["UserForm lets its users set groups"]
    assert [str(loc) for loc in user.locations] == ["accounts/forms.py:9", "accounts/views.py:8"]
    assert (user.severity.value, user.tag.value) == ("high", "CONFIRMED")
    assert "/user/<int:user_id> (authenticated)" in user.detail
    everything = found[
        "AllUserForm lets its users set is_superuser, is_staff, user_permissions, groups, permissions"
    ]
    assert everything.severity.value == "critical"


def test_upload_limits_one_finding_per_settings_file(tmp_path):
    write(
        tmp_path,
        "proj/settings/django_settings.py",
        "INSTALLED_APPS = []\n"
        "DATA_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024 * 1000  # 1GB\n"
        "FILE_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024 * 1000\n",
    )
    write(
        tmp_path,
        "proj/settings/other.py",
        "INSTALLED_APPS = []\nDATA_UPLOAD_MAX_MEMORY_SIZE = None\n",
    )
    write(
        tmp_path,
        "proj/settings/ok.py",
        "INSTALLED_APPS = []\nDATA_UPLOAD_MAX_MEMORY_SIZE = 5242880\n",
    )
    write(
        tmp_path,
        "proj/settings/test.py",
        "INSTALLED_APPS = []\nDATA_UPLOAD_MAX_MEMORY_SIZE = None\n",
    )
    found = sorted(
        findings_for(tmp_path, "owasp", "OWASP-A04-UPLOAD-LIMIT"), key=lambda f: f.locations[0].file
    )
    assert [[str(loc) for loc in f.locations] for f in found] == [
        ["proj/settings/django_settings.py:2", "proj/settings/django_settings.py:3"],
        ["proj/settings/other.py:2"],
    ]
    assert "DATA_UPLOAD_MAX_MEMORY_SIZE is 1000 MB" in found[0].detail
    assert "is None (no limit)" in found[1].detail


def test_file_fields_without_validators_grouped_per_app(tmp_path):
    write(
        tmp_path,
        "claims/models.py",
        "from django.db import models\n\n\nclass Doc(models.Model):\n"
        "    scan = models.FileField(upload_to='docs')\n"
        "    checked = models.FileField(validators=[FileExtensionValidator(['pdf'])])\n"
        "    photo = models.ImageField(upload_to='p')\n",
    )
    write(
        tmp_path,
        "claims/forms/upload.py",
        "from django import forms\n\n\nclass UploadForm(forms.Form):\n"
        "    document = forms.FileField()\n    proof = forms.FileField()\n\n"
        "    def clean_proof(self):\n        return check(self.cleaned_data['proof'])\n",
    )
    write(tmp_path, "advisory/forms.py", "class F(forms.Form):\n    cv = forms.FileField()\n")
    write(tmp_path, "claims/migrations/0001_initial.py", "x = models.FileField()\n")
    found = findings_for(tmp_path, "owasp", "OWASP-A04-UNCHECKED-UPLOAD")
    by_app = {f.title: [str(loc) for loc in f.locations] for f in found}
    assert by_app == {
        "1 file upload field(s) in advisory accept any file type": ["advisory/forms.py:2"],
        "2 file upload field(s) in claims accept any file type": [
            "claims/forms/upload.py:5",
            "claims/models.py:5",
        ],
    }
    assert all(f.tag.value == "INFERRED" and f.severity.value == "low" for f in found)


def test_serializers_used_only_for_output_are_not_reported(tmp_path):
    write(
        tmp_path,
        "api/serializers.py",
        "class UserSerializer(serializers.ModelSerializer):\n    class Meta:\n"
        "        model = PoliciesUser\n        fields = ['username', 'is_superuser']\n\n\n"
        "class Designation(models.Model):\n    is_superuser = models.BooleanField()\n"
        "    groups = models.ManyToManyField(Group)\n\n\n"
        "class DesignationSerializer(serializers.ModelSerializer):\n    class Meta:\n"
        "        model = Designation\n        fields = '__all__'\n",
    )
    write(
        tmp_path,
        "api/urls.py",
        "from django.urls import path\nfrom api import views\n\nurlpatterns = [\n"
        '    path("users/", views.user_list),\n'
        '    path("designations/", views.DesignationViewSet.as_view()),\n]\n',
    )
    write(
        tmp_path,
        "api/views.py",
        "@api_view(['GET'])\ndef user_list(request):\n"
        "    return JsonResponse(UserSerializer(PoliciesUser.objects.all(), many=True).data)\n\n\n"
        "class DesignationViewSet(ModelViewSet):\n    serializer_class = DesignationSerializer\n",
    )
    [finding] = findings_for(tmp_path, "owasp", "OWASP-A01-PRIVILEGE-FIELDS")
    assert finding.title == "DesignationSerializer lets its users set is_superuser, groups"
