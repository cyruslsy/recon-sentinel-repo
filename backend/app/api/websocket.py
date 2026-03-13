"""WebSocket Routes — Real-time scan event streaming"""

from uuid import UUID

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from jose import JWTError, jwt

from app.core.config import get_settings

router = APIRouter()

settings = get_settings()


async def _authenticate_ws(websocket: WebSocket, token: str | None) -> str | None:
    """Validate JWT token from query param. Returns user_id or None."""
    if not token:
        return None
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("type") != "access":
            return None
        return payload.get("sub")
    except JWTError:
        return None

# In-memory connection manager (use Redis pub/sub in production)
class ConnectionManager:
    def __init__(self):
        self.active: dict[str, list[WebSocket]] = {}  # scan_id -> [connections]
    
    async def connect(self, websocket: WebSocket, scan_id: str):
        await websocket.accept()
        if scan_id not in self.active:
            self.active[scan_id] = []
        self.active[scan_id].append(websocket)
    
    def disconnect(self, websocket: WebSocket, scan_id: str):
        if scan_id in self.active:
            self.active[scan_id] = [ws for ws in self.active[scan_id] if ws != websocket]
            if not self.active[scan_id]:
                del self.active[scan_id]
    
    async def broadcast(self, scan_id: str, message: dict):
        """Broadcast event to all clients watching a scan."""
        if scan_id in self.active:
            disconnected = []
            for ws in self.active[scan_id]:
                try:
                    await ws.send_json(message)
                except Exception:
                    disconnected.append(ws)
            for ws in disconnected:
                self.disconnect(ws, scan_id)


manager = ConnectionManager()


@router.websocket("/scan/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: str, token: str | None = Query(None)):
    """
    WebSocket endpoint for real-time scan updates.
    Auth: pass JWT as query param: /ws/scan/{id}?token={access_token}
    """
    user_id = await _authenticate_ws(websocket, token)
    if not user_id:
        await websocket.close(code=4001, reason="Authentication required")
        return

    # Verify user has access to this scan (multi-tenant isolation)
    try:
        from app.core.database import AsyncSessionLocal
        from app.core.authorization import authorize_scan
        from app.models.models import User
        import uuid
        async with AsyncSessionLocal() as db:
            user = await db.get(User, uuid.UUID(user_id))
            if user:
                await authorize_scan(uuid.UUID(scan_id), user, db)
    except Exception:
        await websocket.close(code=4003, reason="Access denied to this scan")
        return

    await manager.connect(websocket, scan_id)
    
    try:
        # Send initial connection confirmation
        await websocket.send_json({
            "event": "connected",
            "data": {"scan_id": scan_id, "message": "Subscribed to scan events"}
        })
        
        while True:
            # Listen for client messages (gate approvals, health decisions, etc.)
            data = await websocket.receive_json()
            
            action = data.get("action")
            
            if action == "approve_gate":
                # Forward gate decision to orchestrator via Celery
                from app.tasks.orchestrator import handle_gate_decision
                gate_num = data.get("gate_number", 1)
                decision = data.get("decision", "approved")
                modifications = data.get("modifications")
                handle_gate_decision.delay(scan_id, gate_num, decision, modifications)
                await websocket.send_json({
                    "event": "gate.decision_received",
                    "data": {"gate_number": gate_num, "decision": decision}
                })
            
            elif action == "health_decision":
                # Publish decision to Redis for the waiting agent
                event_id = data.get("event_id")
                decision = data.get("decision", "continue")
                try:
                    from app.core.redis import get_redis
                    r = await get_redis()
                    await r.publish(f"health_decision:{event_id}", decision)
                except Exception:
                    pass
                await websocket.send_json({
                    "event": "health.decision_received",
                    "data": {"event_id": event_id, "decision": decision}
                })
            
            elif action == "pause_agent":
                await websocket.send_json({
                    "event": "agent.pause_received",
                    "data": {"agent_run_id": data.get("agent_run_id")}
                })
            
            elif action == "ping":
                await websocket.send_json({"event": "pong", "data": {}})
    
    except WebSocketDisconnect:
        manager.disconnect(websocket, scan_id)


@router.websocket("/chat/{session_id}")
async def chat_websocket(websocket: WebSocket, session_id: str):
    """
    WebSocket for AI Copilot Chat streaming.
    Requires JWT token via ?token= query parameter.
    """
    # Authenticate via token query param (same pattern as scan WebSocket)
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4001, reason="Missing token")
        return
    try:
        from jose import jwt, JWTError
        from app.core.config import get_settings
        s = get_settings()
        payload = jwt.decode(token, s.JWT_SECRET_KEY, algorithms=[s.JWT_ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            await websocket.close(code=4001, reason="Invalid token")
            return
    except Exception:
        await websocket.close(code=4001, reason="Authentication failed")
        return

    await websocket.accept()
    
    try:
        await websocket.send_json({
            "event": "connected",
            "data": {"session_id": session_id, "model": "claude-sonnet-4.6"}
        })
        
        while True:
            data = await websocket.receive_json()
            content = data.get("content", "")

            # Stream LLM response via LiteLLM
            try:
                import litellm
                from app.core.config import get_settings
                s = get_settings()

                MODELS = {"analysis": "anthropic/claude-sonnet-4-20250514"}
                model = MODELS.get("analysis")

                # Use streaming for real token-by-token delivery
                response = await litellm.acompletion(
                    model=model,
                    messages=[{"role": "user", "content": content}],
                    max_tokens=1000,
                    stream=True,
                )

                full_text = ""
                async for chunk in response:
                    delta = chunk.choices[0].delta
                    if delta and delta.content:
                        full_text += delta.content
                        await websocket.send_json({
                            "event": "chat.token",
                            "data": {"token": delta.content, "done": False}
                        })

                await websocket.send_json({
                    "event": "chat.complete",
                    "data": {"message_id": str(session_id), "content_length": len(full_text)}
                })

            except ImportError:
                # litellm not available — fall back to non-streaming
                from app.core.llm import llm_call
                result = await llm_call(
                    messages=[{"role": "user", "content": content}],
                    model_tier="analysis", task_type="chat", max_tokens=1000,
                )
                await websocket.send_json({
                    "event": "chat.token",
                    "data": {"token": result.get("content", ""), "done": False}
                })
                await websocket.send_json({
                    "event": "chat.complete",
                    "data": {"message_id": str(session_id), "cost_usd": float(result.get("cost_usd", 0))}
                })
            except Exception as e:
                await websocket.send_json({
                    "event": "chat.error",
                    "data": {"error": str(e)}
                })
    
    except WebSocketDisconnect:
        pass
