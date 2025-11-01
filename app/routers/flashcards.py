from __future__ import annotations

import io
import os
import re
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Dict, List, Optional

import pdfplumber
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..db import get_db
from ..dependencies import require_session
from ..models import Flashcard, UserAccount
from ..services.sessions import Session

router = APIRouter()


class Question(BaseModel):
    number: int
    question: str
    choices: List[str]
    correct_answer: str


class ParseResponse(BaseModel):
    total_questions: int
    questions_with_answers: int
    questions_without_answers: int
    missing_numbers: List[int]
    questions: List[Question]


class SupabaseFlashcardStorage:
    """Supabase Storage client for flashcard PDFs (SUPABASE_BUCKET2)"""

    def __init__(self, url: str, bucket: str, service_role_key: str) -> None:
        self.url = url.rstrip('/')
        self.bucket = bucket
        self.key = service_role_key

    def object_url(self, path: str, public: bool = False) -> str:
        encoded_path = urllib.parse.quote(path)
        if public:
            return f"{self.url}/storage/v1/object/public/{self.bucket}/{encoded_path}"
        return f"{self.url}/storage/v1/object/{self.bucket}/{encoded_path}"

    def upload(self, path: str, content: bytes, content_type: str, upsert: bool = True) -> None:
        req = urllib.request.Request(
            self.object_url(path),
            data=content,
            method='POST',
            headers={
                'Authorization': f'Bearer {self.key}',
                'Content-Type': content_type or 'application/octet-stream',
                'x-upsert': 'true' if upsert else 'false',
            },
        )
        with urllib.request.urlopen(req) as resp:  # noqa: S310
            _ = resp.read()

    def public_url(self, path: str) -> str:
        return self.object_url(path, public=True)

    def download(self, path: str) -> bytes:
        """Download file content from storage"""
        req = urllib.request.Request(
            self.object_url(path),
            method='GET',
            headers={
                'Authorization': f'Bearer {self.key}',
            },
        )
        with urllib.request.urlopen(req) as resp:  # noqa: S310
            return resp.read()

    def delete(self, path: str) -> None:
        req = urllib.request.Request(
            self.object_url(path),
            method='DELETE',
            headers={
                'Authorization': f'Bearer {self.key}',
            },
        )
        with urllib.request.urlopen(req) as resp:  # noqa: S310
            _ = resp.read()


def get_flashcard_storage() -> Optional[SupabaseFlashcardStorage]:
    """Get Supabase storage client for flashcard bucket (SUPABASE_BUCKET2)"""
    url = os.getenv('SUPABASE_URL')
    bucket = os.getenv('SUPABASE_BUCKET2')
    key = os.getenv('SUPABASE_SERVICE_ROLE_KEY')
    if not url or not bucket or not key:
        return None
    return SupabaseFlashcardStorage(url=url, bucket=bucket, service_role_key=key)


def _sanitize_filename(name: str) -> str:
    """Sanitize filename for storage"""
    base = name.rsplit('/', 1)[-1].rsplit('\\', 1)[-1]
    base = base.strip() or 'file'
    filename_sanitize_re = re.compile(r'[^A-Za-z0-9._-]+')
    base = filename_sanitize_re.sub('-', base)
    if base.startswith('.'):
        base = base.lstrip('.') or 'file'
    return base[:200]


async def _get_user(session: Session, db: AsyncSession) -> UserAccount:
    """Get user from session"""
    user = await db.scalar(select(UserAccount).where(UserAccount.username == session.username))
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Account not found')
    return user


def clean_text(text: str) -> str:
    """Clean and normalize text"""
    text = re.sub(r'\s+', ' ', text)
    text = text.replace('–√', '√')
    return text.strip()


def extract_text_by_columns(pdf_bytes: bytes) -> str:
    """Extract text from PDF handling 2-column layout"""
    all_text = ""

    filter_patterns = [
        r'Part\s+\d+\s+General Education',
        r'\d+\s+QUESTIONS\s+With\s+ANSWERS',
        r'This file was submitted to www\.teachpinas\.com',
        r'Get more Free LET Reviewers @ www\.teachpinas\.com',
        r'www\.teachpinas\.com',
    ]

    pdf_file = io.BytesIO(pdf_bytes)
    with pdfplumber.open(pdf_file) as pdf:
        for page in pdf.pages:
            width = page.width
            height = page.height

            mid_point = width / 2

            left_bbox = (0, 0, mid_point, height)
            right_bbox = (mid_point, 0, width, height)

            left_crop = page.crop(left_bbox)
            left_text = left_crop.extract_text()

            right_crop = page.crop(right_bbox)
            right_text = right_crop.extract_text()

            if left_text:
                lines = left_text.split('\n')
                filtered_lines = [
                    line
                    for line in lines
                    if not any(re.search(pattern, line, re.IGNORECASE) for pattern in filter_patterns)
                ]
                all_text += '\n'.join(filtered_lines) + '\n'

            if right_text:
                lines = right_text.split('\n')
                filtered_lines = [
                    line
                    for line in lines
                    if not any(re.search(pattern, line, re.IGNORECASE) for pattern in filter_patterns)
                ]
                all_text += '\n'.join(filtered_lines) + '\n'

    return all_text


def extract_answers_improved(text: str) -> Dict[int, str]:
    """Improved answer extraction with multiple pattern matching"""
    answers = {}

    parts = re.split(r'(?i)(Answer\s*Keys?|ANSWER\s*KEYS?)', text)
    if len(parts) > 1:
        answers_section = ''.join(parts[1:])
    else:
        answers_section = text

    pattern1 = re.compile(r'(\d+)\.\s*([A-D])\b')
    for match in pattern1.finditer(answers_section):
        num = int(match.group(1))
        ans = match.group(2)
        answers[num] = ans

    pattern2 = re.compile(r'(\d+)\s*\.\s*([A-D])\b')
    for match in pattern2.finditer(answers_section):
        num = int(match.group(1))
        ans = match.group(2)
        if num not in answers:
            answers[num] = ans

    pattern3 = re.compile(r'(\d+)\.([A-D])\b')
    for match in pattern3.finditer(answers_section):
        num = int(match.group(1))
        ans = match.group(2)
        if num not in answers:
            answers[num] = ans

    return answers


def extract_single_question(text: str, qnum: int) -> Optional[tuple]:
    """Extract a single question by number with flexible choice matching"""
    pattern = re.compile(rf'{qnum}\.\s*(.+?)(?=\n{qnum+1}\.\s+|\nAnswer|\Z)', re.DOTALL)

    match = pattern.search(text)
    if not match:
        return None

    content = match.group(1)

    choices_dict = {}
    for choice_letter in ['A', 'B', 'C', 'D']:
        choice_pattern = re.compile(
            rf'{choice_letter}\.\s*(.+?)(?=\s+[A-D]\.\s+|\n\d+\.\s+|\Z)', re.DOTALL
        )
        choice_match = choice_pattern.search(content)
        if choice_match:
            choices_dict[choice_letter] = clean_text(choice_match.group(1))

    if 'A' in choices_dict:
        question_text = content.split('A.')[0]
    else:
        question_text = content

    return (str(qnum), clean_text(question_text), choices_dict)


def parse_pdf_questions(pdf_bytes: bytes) -> ParseResponse:
    """Parse PDF and extract questions with answers"""

    full_text = extract_text_by_columns(pdf_bytes)

    parts = re.split(r'(?i)(Answer\s*Keys?|ANSWER\s*KEYS?)', full_text, maxsplit=1)
    questions_text = parts[0]

    answers = extract_answers_improved(full_text)

    data = []
    max_qnum = max(answers.keys()) if answers else 150

    for qnum in range(1, max_qnum + 1):
        result = extract_single_question(questions_text, qnum)

        if result:
            qnum_str, question_text, choices_dict = result

            if len(question_text) < 3:
                continue

            choices = []
            for letter in ['A', 'B', 'C', 'D']:
                if letter in choices_dict:
                    choices.append(f"{letter}. {choices_dict[letter]}")
                else:
                    choices.append(f"{letter}. (Missing)")

            correct_ans = answers.get(qnum, 'N/A')

            data.append(
                Question(
                    number=qnum, question=question_text, choices=choices, correct_answer=correct_ans
                )
            )

    all_nums = set(q.number for q in data)
    expected = set(range(1, max_qnum + 1))
    missing = sorted(list(expected - all_nums))

    questions_with_answers = sum(1 for q in data if q.correct_answer != 'N/A')
    questions_without_answers = sum(1 for q in data if q.correct_answer == 'N/A')

    return ParseResponse(
        total_questions=len(data),
        questions_with_answers=questions_with_answers,
        questions_without_answers=questions_without_answers,
        missing_numbers=missing[:20],
        questions=data,
    )


@router.post('/flashcards/upload', status_code=status.HTTP_201_CREATED)
async def upload_flashcard(
    category: str = Form(...),
    file: UploadFile = File(...),
    session: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> Dict:
    """Upload a PDF to flashcards (admin only) and parse it on-the-fly"""
    user = await _get_user(session, db)

    if user.role != 'admin':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Only admins can upload flashcards')

    if not file.filename or not file.filename.lower().endswith('.pdf'):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Only PDF files are allowed')

    content = await file.read()
    if not content:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='File is empty')

    try:
        parse_result = parse_pdf_questions(content)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f'Failed to parse PDF: {str(e)}'
        )

    flashcard = Flashcard(
        uploader_id=user.id,
        filename=file.filename,
        category=category.strip(),
        storage_path='',
    )
    db.add(flashcard)
    await db.flush()

    date_str = datetime.now().strftime('%Y-%m-%d')
    safe_filename = _sanitize_filename(file.filename)
    storage_path = f"flashcards/{flashcard.id}/{category}/{date_str}/{safe_filename}"

    try:
        storage = get_flashcard_storage()
        if storage is not None:
            storage.upload(path=storage_path, content=content, content_type='application/pdf', upsert=True)
            flashcard.storage_path = storage_path
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f'Failed to upload file: {str(e)}')

    await db.commit()

    return {
        'id': flashcard.id,
        'filename': flashcard.filename,
        'category': flashcard.category,
        'message': 'Flashcard uploaded successfully',
        'parsedData': {
            'total_questions': parse_result.total_questions,
            'questions_with_answers': parse_result.questions_with_answers,
            'questions_without_answers': parse_result.questions_without_answers,
            'missing_numbers': parse_result.missing_numbers,
            'questions': [q.model_dump() for q in parse_result.questions],
        },
    }


@router.get('/flashcards')
async def list_flashcards(
    session: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, List[Dict]]:
    """List all flashcards (visible to all authenticated users)"""
    result = await db.execute(
        select(Flashcard).options(selectinload(Flashcard.uploader)).order_by(Flashcard.created_at.desc())
    )
    flashcards = result.scalars().all()

    storage = get_flashcard_storage()
    items = []
    for fc in flashcards:
        item = {
            'id': fc.id,
            'filename': fc.filename,
            'category': fc.category,
            'uploader': fc.uploader.username,
            'createdAt': fc.created_at.isoformat(),
            'url': storage.public_url(fc.storage_path) if storage and fc.storage_path else None,
        }
        items.append(item)

    return {'flashcards': items}


@router.get('/flashcards/{flashcard_id}')
async def get_flashcard_questions(
    flashcard_id: str,
    session: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> Dict:
    """Get parsed questions from a flashcard (parse on-demand from storage)"""
    flashcard = await db.scalar(
        select(Flashcard).where(Flashcard.id == flashcard_id).options(selectinload(Flashcard.uploader))
    )

    if not flashcard:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Flashcard not found')

    storage = get_flashcard_storage()
    if not storage or not flashcard.storage_path:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Flashcard file not found')

    try:
        pdf_content = storage.download(flashcard.storage_path)
        parse_result = parse_pdf_questions(pdf_content)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f'Failed to parse PDF: {str(e)}'
        )

    return {
        'id': flashcard.id,
        'filename': flashcard.filename,
        'category': flashcard.category,
        'uploader': flashcard.uploader.username,
        'createdAt': flashcard.created_at.isoformat(),
        'url': storage.public_url(flashcard.storage_path),
        'parsedData': {
            'total_questions': parse_result.total_questions,
            'questions_with_answers': parse_result.questions_with_answers,
            'questions_without_answers': parse_result.questions_without_answers,
            'missing_numbers': parse_result.missing_numbers,
            'questions': [q.model_dump() for q in parse_result.questions],
        },
    }


@router.delete('/flashcards/{flashcard_id}')
async def delete_flashcard(
    flashcard_id: str,
    session: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, str]:
    """Delete a flashcard (admin only, or uploader)"""
    user = await _get_user(session, db)
    flashcard = await db.scalar(select(Flashcard).where(Flashcard.id == flashcard_id))

    if not flashcard:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Flashcard not found')

    if user.role != 'admin' and flashcard.uploader_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Cannot delete this flashcard')

    try:
        storage = get_flashcard_storage()
        if storage and flashcard.storage_path:
            storage.delete(flashcard.storage_path)
    except Exception:
        pass

    await db.delete(flashcard)
    await db.commit()

    return {'message': 'Flashcard deleted successfully'}
