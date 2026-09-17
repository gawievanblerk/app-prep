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
            ["api/app/routes.py:9", "api/app/storage.py:8"],
            "CONFIRMED",
        ),
        (
            "POST /docs writes a file to a path built from the request value file",
            ["api/app/routes.py:5", "api/app/routes.py:7"],
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
