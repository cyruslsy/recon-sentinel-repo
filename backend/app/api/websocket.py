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
                # TODO: Forward to scan lifecycle handler
                await websocket.send_json({
                    "event": "gate.decision_received",
                    "data": {"gate_number": data.get("gate_number"), "decision": data.get("decision")}
                })
            
            elif action == "health_decision":
                # TODO: Forward to agent health handler
                await websocket.send_json({
                    "event": "health.decision_received",
                    "data": {"event_id": data.get("event_id"), "decision": data.get("decision")}
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
    
    Client sends: {"content": "user message", "slash_command": "/findings critical"}
    Server streams: {"event": "chat.token", "data": {"token": "The", "done": false}}
    Server finishes: {"event": "chat.complete", "data": {"message_id": "...", "cost_usd": 0.03}}
    """
    await websocket.accept()
    
    try:
        await websocket.send_json({
            "event": "connected",
            "data": {"session_id": session_id, "model": "claude-sonnet-4.6"}
        })
        
        while True:
            data = await websocket.receive_json()
            content = data.get("content", "")
            
            # TODO: Stream LLM response token-by-token via LiteLLM
            # For now, send placeholder
            await websocket.send_json({
                "event": "chat.token",
                "data": {"token": f"[AI processing: {content[:50]}...] ", "done": False}
            })
            await websocket.send_json({
                "event": "chat.complete",
                "data": {"message_id": "placeholder", "cost_usd": 0.03}
            })
    
    except WebSocketDisconnect:
        pass
