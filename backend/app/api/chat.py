"""AI Copilot Chat Routes — Real-time conversational interface"""

import json
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy import func as sqlfunc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.auth import get_current_user
from app.core.llm import llm_call, LLMUnavailableError
from app.models.models import User, ChatSession, ChatMessage, Scan, Finding, Target
from app.schemas.schemas import ChatMessageCreate, ChatMessageResponse, ChatSessionResponse

router = APIRouter()


# ─── Sessions ─────────────────────────────────────────────────────────

@router.get("/sessions", response_model=list[ChatSessionResponse])
async def list_sessions(scan_id: UUID | None = None, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    q = select(ChatSession).order_by(ChatSession.created_at.desc())
    if scan_id:
        q = q.where(ChatSession.scan_id == scan_id)
    result = await db.execute(q)
    sessions = result.scalars().all()
    
    # Enrich with message counts
    enriched = []
    for s in sessions:
        count_result = await db.execute(
            select(func.count()).select_from(ChatMessage).where(ChatMessage.session_id == s.id)
        )
        enriched.append(ChatSessionResponse(
            id=s.id, scan_id=s.scan_id, title=s.title,
            is_active=s.is_active, created_at=s.created_at,
            message_count=count_result.scalar() or 0,
        ))
    return enriched


@router.post("/sessions", response_model=ChatSessionResponse, status_code=201)
async def create_session(scan_id: UUID | None = None, title: str | None = None, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    session = ChatSession(
        scan_id=scan_id, title=title or "New Chat",
        user_id=user.id,
    )
    db.add(session)
    await db.commit()
    await db.refresh(session)
    return ChatSessionResponse(
        id=session.id, scan_id=session.scan_id, title=session.title,
        is_active=session.is_active, created_at=session.created_at, message_count=0,
    )


# ─── Messages ─────────────────────────────────────────────────────────

@router.get("/sessions/{session_id}/messages", response_model=list[ChatMessageResponse])
async def list_messages(
    session_id: UUID,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ChatMessage)
        .where(ChatMessage.session_id == session_id)
        .order_by(ChatMessage.created_at)
        .limit(limit).offset(offset)
    )
    return result.scalars().all()


@router.post("/sessions/{session_id}/messages", response_model=ChatMessageResponse, status_code=201)
async def send_message(session_id: UUID, data: ChatMessageCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """
    Send a user message to the AI Copilot.
    
    Slash commands are detected and routed:
      /findings critical  → query findings
      /mitre T1078        → lookup technique
      /attack-chain       → generate attack chain narrative
      /summarize          → executive summary of current scan
      /compare last-scan  → diff with previous scan
      /export pdf         → trigger report generation
      /scope add *.dev.target.com → modify scope
    """
    # Save user message
    user_msg = ChatMessage(
        session_id=session_id,
        role="user",
        content=data.content,
        slash_command=data.slash_command,
    )
    db.add(user_msg)
    await db.commit()
    await db.refresh(user_msg)

    # Detect slash command
    content = data.content.strip()
    slash_cmd = content.split(" ", 1)[0] if content.startswith("/") else None

    # Build scan context if session is linked to a scan
    session = await db.get(ChatSession, session_id)
    scan_context = ""
    if session and session.scan_id:
        scan = await db.get(Scan, session.scan_id)
        if scan:
            count_result = await db.execute(
                select(Finding.severity, sqlfunc.count(Finding.id))
                .where(Finding.scan_id == scan.id)
                .group_by(Finding.severity)
            )
            counts = {r[0].value: r[1] for r in count_result.all()}

            # Resolve target to actual domain/IP
            target = await db.get(Target, scan.target_id)
            target_name = target.target_value if target else str(scan.target_id)

            scan_context = (
                f"\nScan context — Target: {target_name}, Phase: {scan.phase.value}, "
                f"Status: {scan.status.value}, Findings: {json.dumps(counts)}"
            )

    # Handle slash commands
    if slash_cmd == "/findings":
        query = content.replace("/findings", "").strip()
        scan_context += f"\nUser is asking about findings matching: {query}"
    elif slash_cmd == "/summarize":
        scan_context += "\nUser wants an executive summary of the current scan results."
    elif slash_cmd == "/mitre":
        technique = content.replace("/mitre", "").strip()
        scan_context += f"\nUser is asking about MITRE technique: {technique}"

    # Call LLM

    system_msg = (
        "You are the Recon Sentinel AI Copilot — a security-focused assistant embedded in a reconnaissance platform. "
        "You help penetration testers analyze scan results, understand findings, and plan next steps. "
        "Be concise, technical, and actionable. Reference specific findings when possible."
        + scan_context
    )

    try:
        result = await llm_call(
            messages=[
                {"role": "system", "content": system_msg},
                {"role": "user", "content": content},
            ],
            model_tier="analysis",
            task_type="chat",
            scan_id=str(session.scan_id) if session and session.scan_id else None,
            max_tokens=1500,
        )
        ai_content = result["content"]
        model_used = result["model"]
        cost = result["cost_usd"]
        tokens_in = result["tokens_in"]
        tokens_out = result["tokens_out"]
    except LLMUnavailableError as e:
        ai_content = f"AI Copilot is temporarily unavailable: {e}"
        model_used = "unavailable"
        cost = None
        tokens_in = 0
        tokens_out = 0

    ai_msg = ChatMessage(
        session_id=session_id,
        role="ai",
        content=ai_content,
        slash_command=slash_cmd,
        model_used=model_used,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        cost_usd=cost,
    )
    db.add(ai_msg)
    await db.commit()
    await db.refresh(ai_msg)

    return ai_msg
