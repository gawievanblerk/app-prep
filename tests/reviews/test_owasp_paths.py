from tests.reviews.helpers import findings_for, write

DEPS = "from typing import Annotated\nfrom fastapi import Depends\nCurrentUser = Annotated[dict, Depends(get_current_user)]\n"


def test_fastapi_upload_writes(tmp_path):
    write(tmp_path, "api/app/deps.py", DEPS)
    write(
        tmp_path,
        "api/app/storage.py",
        "from pathlib import Path\n"
        "class Storage:\n"
        "    def save(self, upload, folder):\n"
        "        name = f'{uuid4().hex}_{upload.filename}'\n"
        "        return self._write(f'{folder}/{name}', b'')\n"
        "    def _write(self, blob_path, content):\n"
        "        dest = Path('data/uploads') / blob_path\n"
        "        dest.write_bytes(content)\n"
        "    def safe(self, upload):\n"
        "        dest = Path('data') / Path(upload.filename).name\n"
        "        dest.write_bytes(b'')\n",
    )
    write(
        tmp_path,
        "api/app/routes.py",
        "from fastapi import APIRouter, File, Form, UploadFile\nfrom app.deps import CurrentUser\n"
        "from app.storage import Storage\n"
        "router = APIRouter()\n"
        "@router.post('/docs')\n"
        "async def upload(current_user: CurrentUser, file: UploadFile = File(...)):\n"
        "    target = settings.upload_path / file.filename\n"
        "    target.write_bytes(await file.read())\n"
        "@router.post('/attachments')\n"
        "async def attach(current_user: CurrentUser, file: UploadFile = File(...), entity_id: str = Form(...),\n"
        "                 kind: str = Form(...)):\n"
        "    if kind not in KINDS:\n        raise HTTPException(400)\n"
        "    return Storage().save(file, f'{kind}/{entity_id}')\n"
        "@router.post('/safe')\n"
        "async def safe(current_user: CurrentUser, file: UploadFile = File(...)):\n"
        "    Storage().safe(file)\n"
        "    name = secure_filename(file.filename)\n"
        "    with open(f'data/{name}', 'wb') as out:\n        out.write(b'')\n"
        "@router.post('/checked')\n"
        "async def checked(current_user: CurrentUser, file: UploadFile = File(...)):\n"
        "    dest = (root / file.filename).resolve()\n"
        "    if not dest.is_relative_to(root):\n        raise ValueError()\n"
        "    dest.write_bytes(b'')\n"
        "@router.get('/cache')\n"
        "async def cache(current_user: CurrentUser):\n"
        "    with open(CACHE_FILE, 'w') as out:\n        out.write('x')\n",
    )
    found = findings_for(tmp_path, "owasp", "OWASP-A01-PATH-TRAVERSAL")
    assert sorted((f.title, [str(loc) for loc in f.locations], f.tag.value) for f in found) == [
        (
            "POST /attachments writes a file to a path built from the request values entity_id and file",
            ["api/app/routes.py:10", "api/app/storage.py:8"],
            "CONFIRMED",
        ),
        (
            "POST /docs writes a file to a path built from the request value file",
            ["api/app/routes.py:6", "api/app/routes.py:8"],
            "CONFIRMED",
        ),
    ]


def test_flask_and_express_writes(tmp_path):
    write(
        tmp_path,
        "web/app.py",
        "from flask import Flask, request\napp = Flask(__name__)\n"
        "@app.route('/upload', methods=['POST'])\ndef upload():\n"
        "    f = request.files['doc']\n    f.save('uploads/' + f.filename)\n"
        "@app.route('/avatar', methods=['POST'])\ndef avatar():\n"
        "    f = request.files['doc']\n    f.save(os.path.join('uploads', secure_filename(f.filename)))\n",
    )
    write(
        tmp_path,
        "server/files.js",
        "router.post('/files', requireAuth, async (req, res) => {\n"
        "  const target = path.join(UPLOADS, req.body.name)\n"
        "  await fs.promises.writeFile(target, req.body.content)\n"
        "  fs.writeFileSync(path.join(UPLOADS, path.basename(req.body.name)), '')\n"
        "})\n",
    )
    found = findings_for(tmp_path, "owasp", "OWASP-A01-PATH-TRAVERSAL")
    assert sorted(str(f.locations[-1]) for f in found) == ["server/files.js:3", "web/app.py:6"]


def test_typed_scalar_parameters_are_not_path_seeds(tmp_path):
    write(tmp_path, "api/app/deps.py", DEPS)
    write(
        tmp_path,
        "api/app/export.py",
        "import json\nfrom datetime import date, datetime\nfrom decimal import Decimal\n"
        "from enum import Enum\nfrom typing import Annotated, Literal, Optional\nfrom uuid import UUID\n"
        "from fastapi import APIRouter, Path\nfrom app.deps import CurrentUser\n"
        "router = APIRouter()\nEXPORT_DIR = '/data/exports'\n"
        "class Fmt(str, Enum):\n    csv = 'csv'\n    json = 'json'\n"
        "@router.post('/reports/{report_id}/export')\n"
        "def export(report_id: int, user: CurrentUser):\n"
        "    with open(f'{EXPORT_DIR}/{report_id}.json', 'w') as fh:\n        json.dump({}, fh)\n"
        "@router.post('/typed/{a}/{b}/{c}/{d}/{e}/{f}/{g}/{h}/{i}/{j}/{k}')\n"
        "def typed(a: UUID, b: Decimal, c: date, d: datetime, e: bool, f: float, g: Fmt,\n"
        "          h: Literal['csv', 'json'], i: Optional[int], j: int | None,\n"
        "          k: Annotated[int, Path()], user: CurrentUser):\n"
        "    open(f'{EXPORT_DIR}/{a}{b}{c}{d}{e}{f}{g}{h}{i}{j}{k}', 'w')\n"
        "@router.post('/named/{name}')\n"
        "def named(name: str, user: CurrentUser):\n"
        "    open(f'{EXPORT_DIR}/{name}.json', 'w')\n",
    )
    write(
        tmp_path,
        "web/app.py",
        "from flask import Flask\napp = Flask(__name__)\n"
        "@app.route('/r/<int:rid>', methods=['POST'])\ndef flask_report(rid):\n"
        "    open(f'exports/{rid}.json', 'w')\n",
    )
    found = findings_for(tmp_path, "owasp", "OWASP-A01-PATH-TRAVERSAL")
    assert [(f.title, str(f.locations[0])) for f in found] == [
        (
            "POST /named/{name} writes a file to a path built from the request value name",
            "api/app/export.py:24",
        )
    ]


def test_flask_upload_title_names_the_request_attribute(tmp_path):
    write(
        tmp_path,
        "app.py",
        "from flask import Flask, request\napp = Flask(__name__)\n"
        "@app.post('/upload')\ndef upload():\n    f = request.files['file']\n"
        "    f.save('/srv/uploads/' + f.filename)\n    return 'ok'\n",
    )
    [f] = findings_for(tmp_path, "owasp", "OWASP-A01-PATH-TRAVERSAL")
    assert (
        f.title == "POST /upload writes a file to a path built from the request value request.files"
    )


DJANGO_URLS = (
    "from django.urls import path\nfrom . import views\nurlpatterns = [\n"
    "    path('profile/', views.profile),\n    path('scan/', views.scan),\n"
    "    path('store/', views.store),\n    path('local/', views.local),\n"
    "    path('letter/<int:pk>/', views.letter),\n    path('export/', views.export),\n"
    "    path('cleaned/', views.cleaned),\n    path('download/', views.download),\n"
    "    path('record/', views.record),\n    path('report/', views.report),\n]\n"
)


def test_django_form_and_model_saves_are_not_file_paths(tmp_path):
    write(tmp_path, "shop/urls.py", DJANGO_URLS)
    write(
        tmp_path,
        "shop/views.py",
        "from django.core.files.storage import FileSystemStorage, default_storage\n"
        "from lib.pdf import write_pdf\n"
        "def profile(request):\n"
        "    form = ProfileForm(request.POST, request.FILES)\n"
        "    profile = form.save(request.user)\n"
        "    profile.avatar = request.FILES['avatar']\n"
        "    profile.save()\n"
        "def scan(request):\n"
        "    upload_file = request.FILES['scan']\n"
        "    document_form = DocumentForm(request.POST)\n"
        "    document_form.save(upload_file)\n"
        "def store(request):\n"
        "    upload = request.FILES['doc']\n"
        "    default_storage.save(request.POST['name'], upload)\n"
        "def local(request):\n"
        "    fs = FileSystemStorage(location='/srv/media')\n"
        "    fs.delete(request.GET['name'])\n"
        "def letter(request, pk):\n"
        "    return write_pdf('letter.html', {}, request.GET.get('name'))\n"
        "def export(request):\n"
        "    name = clean(request.POST['name'])\n"
        "    with open(os.path.join(EXPORTS, name), 'w') as out:\n        out.write('')\n"
        "def cleaned(request):\n"
        "    name = get_valid_filename(request.POST['name'])\n"
        "    open(os.path.join(EXPORTS, name), 'w')\n"
        "def download(request):\n"
        "    return FileResponse(open(os.path.join(EXPORTS, request.GET['name']), 'rb'))\n"
        "def record(request):\n"
        "    doc = Document.objects.get(pk=request.GET['id'])\n"
        "    return FileResponse(open(doc.file.path, 'rb'))\n"
        "def report(request):\n"
        "    data = ReportForm(request.POST, request.FILES).save()\n"
        "    return FileResponse(data, filename='report.csv')\n",
    )
    # The imported write_pdf ignores its third argument; a same-named helper elsewhere writes it.
    write(
        tmp_path,
        "lib/pdf.py",
        "def write_pdf(template, context, static_file=None):\n    return render(template, context)\n",
    )
    write(
        tmp_path,
        "shop/management/commands/symlinks.py",
        "def write_pdf(template, context, filename):\n"
        "    with open(filename, 'wb') as out:\n        out.write(b'')\n",
    )
    found = findings_for(tmp_path, "owasp", "OWASP-A01-PATH-TRAVERSAL")
    assert sorted((f.title, [str(loc) for loc in f.locations], f.tag.value) for f in found) == [
        (
            "ANY /download reads a file from a path built from the request value request.GET",
            ["shop/views.py:27", "shop/views.py:28"],
            "CONFIRMED",
        ),
        (
            "ANY /export writes a file to a path built from the request value request.POST",
            ["shop/views.py:20", "shop/views.py:22"],
            "INFERRED",
        ),
        (
            "ANY /local deletes a file at a path built from the request value request.GET",
            ["shop/views.py:15", "shop/views.py:17"],
            "CONFIRMED",
        ),
        (
            "ANY /store writes a file to a path built from the request value request.POST",
            ["shop/views.py:12", "shop/views.py:14"],
            "CONFIRMED",
        ),
    ]


def test_helper_resolves_through_the_callers_import(tmp_path):
    write(
        tmp_path,
        "web/app.py",
        "from flask import Flask, request, send_file\nfrom web.files import store\n"
        "app = Flask(__name__)\n"
        "@app.post('/upload')\ndef upload():\n    store(request.form['name'])\n"
        "@app.get('/file')\ndef fetch():\n    return send_file(os.path.join(ROOT, request.args['name']))\n",
    )
    write(
        tmp_path,
        "web/files.py",
        "def store(name):\n    with open(os.path.join(ROOT, name), 'wb') as out:\n        out.write(b'')\n",
    )
    write(tmp_path, "web/other.py", "def store(name):\n    return name\n")
    found = findings_for(tmp_path, "owasp", "OWASP-A01-PATH-TRAVERSAL")
    assert sorted((f.title, [str(loc) for loc in f.locations], f.tag.value) for f in found) == [
        (
            "GET /file reads a file from a path built from the request value request.args",
            ["web/app.py:8", "web/app.py:9"],
            "CONFIRMED",
        ),
        (
            "POST /upload writes a file to a path built from the request value request.form",
            ["web/app.py:5", "web/files.py:2"],
            "CONFIRMED",
        ),
    ]
