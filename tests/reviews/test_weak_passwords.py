from tests.reviews.helpers import findings_for, write

NICEPASS = """
import random
import string


def nicepass(alpha=6, numeric=2):
    vowels = ["a", "e", "i", "o", "u"]

    def a_part(slen):
        ret = ""
        for i in range(slen):
            randid = random.randint(0, 4)
            ret += vowels[randid]
        return ret

    start = a_part(alpha)
    end = a_part(alpha)
    return "%s%s" % (start, end)
"""

VIEWS = """
from .nicepass import nicepass


def forgotten_password(req):
    user = PoliciesUser.objects.get(username=req.POST["username"])
    new_password = nicepass()
    user.set_password(new_password)
    user.save()
    send_mail("Reset", "Your password is now " + new_password, "x@example.invalid", [user.email])


def safe_reset(req):
    user = PoliciesUser.objects.get(username=req.POST["username"])
    user.set_password(secrets.token_urlsafe(16))
"""

MODELS = """
import random


class PoliciesUser(AbstractUser):
    @staticmethod
    def generate_random_passphrase(num_words=2):
        password = []
        for x in range(4):
            password.append(random.choice(WORDS))
        return "".join(password)

    def set_random_password(self, num_words=2):
        password = self.generate_random_passphrase(num_words)
        self.set_password(password)
        return password


def reset_by_sms(user):
    new_password = user.set_random_password()
    send_sms(user.cell, "Your new password is %s" % new_password)
"""


def test_random_helper_output_reaching_set_password(tmp_path):
    write(tmp_path, "policies/nicepass.py", NICEPASS)
    write(tmp_path, "policies/views.py", VIEWS)
    write(tmp_path, "policies/models.py", MODELS)
    found = findings_for(tmp_path, "owasp", "OWASP-A02-WEAK-RANDOM-TOKEN")
    confirmed = sorted(
        ([str(loc) for loc in f.locations], f.detail) for f in found if f.tag.value == "CONFIRMED"
    )
    assert [locs for locs, _ in confirmed] == [
        ["policies/models.py:15", "policies/models.py:10"],
        ["policies/views.py:8", "policies/nicepass.py:12"],
    ]
    models, views = (detail for _, detail in confirmed)
    assert "generate_random_passphrase()" in models
    assert "sends the password in plain text by email or SMS (policies/models.py:21)" in models
    assert "nicepass()" in views and "(policies/views.py:10)" in views


def test_secrets_generated_passwords_are_not_reported(tmp_path):
    write(
        tmp_path,
        "policies/views.py",
        "import secrets\n\n\ndef make():\n    return secrets.token_urlsafe(12)\n\n\n"
        "def reset(user):\n    user.set_password(make())\n",
    )
    assert findings_for(tmp_path, "owasp", "OWASP-A02-WEAK-RANDOM-TOKEN") == []
