from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from sqlalchemy import select

from app.config import settings
from app.core.deps import CurrentUser
from app.db.session import db
from app.models import Attachment
from app.schemas import AttachmentOut

router = APIRouter(prefix="/files")
MAX_BYTES = 10 * 1024 * 1024


@router.post("")
async def upload(request: Request, current_user: CurrentUser, file: UploadFile = File(...)):
    if int(request.headers.get("content-length", "0")) > MAX_BYTES:
        raise HTTPException(status_code=413, detail="Too large")
    target = Path(settings.upload_dir) / f"{uuid4().hex}{Path(file.filename).suffix}"
    with target.open("wb") as out:
        while chunk := await file.read(64 * 1024):
            out.write(chunk)
    return {"stored": True}


@router.get("/{attachment_id}", response_model=AttachmentOut)
async def download(attachment_id: str, current_user: CurrentUser):
    result = await db.execute(
        select(Attachment).where(
            Attachment.id == attachment_id, Attachment.uploaded_by_id == current_user.id
        )
    )
    return result.scalar_one_or_none()


@router.post("/import")
async def import_rows(current_user: CurrentUser, file: UploadFile = File(...)):
    import openpyxl

    workbook = openpyxl.load_workbook(file.file, read_only=True)
    return {"sheets": workbook.sheetnames}
