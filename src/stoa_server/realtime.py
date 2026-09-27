"""Authenticated realtime control-plane events."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, status
from sqlalchemy.orm import Session

from stoa_server.database import get_session
from stoa_server.rbac import resolve_principal
from stoa_shared.settings import Settings, get_settings

router = APIRouter(tags=["realtime"])


@router.websocket("/events/ws")
async def events(
    websocket: WebSocket,
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    """Open a team-bound event stream after validating the bearer credential."""

    authorization = websocket.headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.casefold() != "bearer" or not token:
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION, reason="authentication required"
        )
        return
    try:
        principal = resolve_principal(token, session, settings)
        team_id = str(principal.team.id)
        user_id = str(principal.user.id)
    except HTTPException:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="invalid credential")
        return

    await websocket.accept()
    await websocket.send_json({"type": "session.ready", "team_id": team_id, "user_id": user_id})
    try:
        while True:
            message = await websocket.receive_json()
            if message.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        return
