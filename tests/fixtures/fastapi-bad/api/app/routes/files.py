from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy import select

from app.config import settings
from app.core.deps import CurrentUser
from app.db.session import db
from app.models import Attachment

router = APIRouter(prefix="/files")
MAX_BYTES = 10 * 1024 * 1024


@router.post("")
async def upload(current_user: CurrentUser, file: UploadFile = File(...)):
    content = await file.read()
    if len(content) > MAX_BYTES:
        raise HTTPException(status_code=413, detail="Too large")
    target = Path(settings.upload_dir) / file.filename
    target.write_bytes(content)
    return {"stored": True}


@router.get("/{attachment_id}")
async def download(attachment_id: str, current_user: CurrentUser):
    result = await db.execute(select(Attachment).where(Attachment.id == attachment_id))
    return result.scalar_one_or_none()


@router.post("/import")
async def import_rows(current_user: CurrentUser, file: UploadFile = File(...)):
    import openpyxl

    workbook = openpyxl.load_workbook(file.file, read_only=True)
    return {"sheets": workbook.sheetnames}


@router.get("/export")
async def export_files(current_user: CurrentUser):
    return FileResponse(settings.export_file, media_type="text/csv", filename="files.csv")
