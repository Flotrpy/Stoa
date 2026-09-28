"""Ciphertext-only chat device and offline-envelope relay."""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from stoa_server.audit import record_audit_event
from stoa_server.database import get_session
from stoa_server.models import ChatDevice, EncryptedEnvelope
from stoa_server.rbac import Permission, Principal, require_permission
from stoa_shared.domain import (
    ChatDeviceCreate,
    ChatDeviceResponse,
    EncryptedEnvelopeCreate,
    EncryptedEnvelopeResponse,
)

router = APIRouter(tags=["chat"])


@router.post("/chat/devices", response_model=ChatDeviceResponse, status_code=201)
def register_device(
    payload: ChatDeviceCreate,
    principal: Annotated[Principal, Depends(require_permission(Permission.USE_CHAT))],
    session: Annotated[Session, Depends(get_session)],
) -> ChatDevice:
    device = ChatDevice(
        team_id=principal.team.id,
        user_id=principal.user.id,
        name=payload.name.strip(),
        identity_public_key=payload.identity_public_key,
        **({"id": payload.device_id} if payload.device_id is not None else {}),
    )
    session.add(device)
    session.flush()
    record_audit_event(
        session,
        team_id=principal.team.id,
        actor_user_id=principal.user.id,
        action="chat.device_registered",
        resource_type="chat_device",
        resource_id=str(device.id),
        event_data={"name": device.name},
    )
    session.commit()
    return device


@router.get("/chat/devices", response_model=list[ChatDeviceResponse])
def list_devices(
    principal: Annotated[Principal, Depends(require_permission(Permission.USE_CHAT))],
    session: Annotated[Session, Depends(get_session)],
) -> list[ChatDevice]:
    return list(
        session.scalars(
            select(ChatDevice)
            .where(ChatDevice.team_id == principal.team.id)
            .order_by(ChatDevice.created_at)
        )
    )


@router.post("/chat/devices/{device_id}/verify", response_model=ChatDeviceResponse)
def verify_device(
    device_id: UUID,
    principal: Annotated[Principal, Depends(require_permission(Permission.USE_CHAT))],
    session: Annotated[Session, Depends(get_session)],
) -> ChatDevice:
    device = _device(session, principal, device_id)
    device.verified_at = datetime.now(UTC)
    session.commit()
    return device


@router.post("/chat/devices/{device_id}/revoke", response_model=ChatDeviceResponse)
def revoke_device(
    device_id: UUID,
    principal: Annotated[Principal, Depends(require_permission(Permission.USE_CHAT))],
    session: Annotated[Session, Depends(get_session)],
) -> ChatDevice:
    device = _device(session, principal, device_id)
    if device.user_id != principal.user.id:
        raise HTTPException(status_code=403, detail="only the device owner can revoke it")
    device.revoked_at = datetime.now(UTC)
    session.commit()
    return device


@router.post("/chat/envelopes", response_model=EncryptedEnvelopeResponse, status_code=201)
def relay_envelope(
    payload: EncryptedEnvelopeCreate,
    principal: Annotated[Principal, Depends(require_permission(Permission.USE_CHAT))],
    session: Annotated[Session, Depends(get_session)],
) -> EncryptedEnvelope:
    sender = _device(session, principal, payload.sender_device_id)
    recipient = _device(session, principal, payload.recipient_device_id)
    if sender.user_id != principal.user.id or sender.revoked_at or recipient.revoked_at:
        raise HTTPException(status_code=403, detail="chat device is not authorized")
    if session.scalar(
        select(EncryptedEnvelope).where(EncryptedEnvelope.message_id == payload.message_id)
    ):
        raise HTTPException(status_code=409, detail="message has already been relayed")
    envelope = EncryptedEnvelope(team_id=principal.team.id, **payload.model_dump())
    session.add(envelope)
    session.commit()
    return envelope


@router.get("/chat/envelopes/{recipient_device_id}", response_model=list[EncryptedEnvelopeResponse])
def receive_envelopes(
    recipient_device_id: UUID,
    principal: Annotated[Principal, Depends(require_permission(Permission.USE_CHAT))],
    session: Annotated[Session, Depends(get_session)],
) -> list[EncryptedEnvelope]:
    device = _device(session, principal, recipient_device_id)
    if device.user_id != principal.user.id or device.revoked_at:
        raise HTTPException(status_code=403, detail="chat device is not authorized")
    envelopes = list(
        session.scalars(
            select(EncryptedEnvelope)
            .where(
                EncryptedEnvelope.team_id == principal.team.id,
                EncryptedEnvelope.recipient_device_id == recipient_device_id,
                EncryptedEnvelope.delivered_at.is_(None),
            )
            .order_by(EncryptedEnvelope.created_at)
        )
    )
    delivered = datetime.now(UTC)
    for envelope in envelopes:
        envelope.delivered_at = delivered
    session.commit()
    return envelopes


def _device(session: Session, principal: Principal, device_id: UUID) -> ChatDevice:
    device = session.scalar(
        select(ChatDevice).where(
            ChatDevice.id == device_id, ChatDevice.team_id == principal.team.id
        )
    )
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="chat device not found")
    return device
