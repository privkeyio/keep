"""Keep Agent SDK - Secure signing for AI agents."""

from typing import Optional, List, Dict, Any, Union
from dataclasses import dataclass
from datetime import datetime

try:
    from keep_agent._bindings import (
        PySessionScope as _SessionScope,
        PyRateLimit as _RateLimit,
        PyAgentSession as _AgentSession,
        PySessionInfo as _SessionInfo,
        PyRemoteSession as _RemoteSession,
        PyPendingSession as _PendingSession,
    )
    _HAS_BINDINGS = True
except ImportError:
    _HAS_BINDINGS = False


@dataclass
class SessionScope:
    operations: List[str] = None
    event_kinds: Optional[List[int]] = None
    max_amount_sats: Optional[int] = None
    address_allowlist: Optional[List[str]] = None

    def __post_init__(self):
        if self.operations is None:
            self.operations = ["sign_nostr_event", "get_public_key"]

    @classmethod
    def nostr_only(cls) -> "SessionScope":
        return cls(operations=["sign_nostr_event", "get_public_key"])

    @classmethod
    def bitcoin_only(cls) -> "SessionScope":
        return cls(operations=["sign_psbt", "get_public_key", "get_bitcoin_address"])

    @classmethod
    def full(cls) -> "SessionScope":
        return cls(operations=[
            "sign_nostr_event",
            "sign_psbt",
            "get_public_key",
            "get_bitcoin_address",
            "nip44_encrypt",
            "nip44_decrypt",
        ])

    def _to_native(self):
        if not _HAS_BINDINGS:
            raise RuntimeError("Native bindings not available")

        scope = _SessionScope(self.operations)
        if self.event_kinds:
            scope = scope.with_event_kinds(self.event_kinds)
        if self.max_amount_sats is not None:
            scope = scope.with_max_amount(self.max_amount_sats)
        if self.address_allowlist:
            scope = scope.with_address_allowlist(self.address_allowlist)
        return scope


@dataclass
class RateLimit:
    max_per_minute: int = 10
    max_per_hour: int = 100
    max_per_day: int = 1000

    @classmethod
    def conservative(cls) -> "RateLimit":
        return cls(max_per_minute=10, max_per_hour=100, max_per_day=1000)

    @classmethod
    def permissive(cls) -> "RateLimit":
        return cls(max_per_minute=60, max_per_hour=1000, max_per_day=10000)

    @classmethod
    def strict(cls) -> "RateLimit":
        return cls(max_per_minute=5, max_per_hour=50, max_per_day=500)

    def _to_native(self):
        if not _HAS_BINDINGS:
            raise RuntimeError("Native bindings not available")
        return _RateLimit(self.max_per_minute, self.max_per_hour, self.max_per_day)


@dataclass
class SessionInfo:
    session_id: str
    created_at: datetime
    expires_at: datetime
    requests_today: int
    requests_remaining: int


class AgentSession:
    """Secure session for AI agents to sign with Keep."""

    def __init__(
        self,
        scope: SessionScope = None,
        rate_limit: RateLimit = None,
        duration_hours: int = 24,
        policy: Optional[str] = None,
        secret_key: Optional[str] = None,
    ):
        if not _HAS_BINDINGS:
            raise RuntimeError("Native bindings not available. Install with: pip install keep-agent")

        scope = scope or SessionScope.nostr_only()
        rate_limit = rate_limit or RateLimit.conservative()

        self._native = _AgentSession(
            scope._to_native(),
            rate_limit._to_native(),
            duration_hours,
            policy,
            secret_key,
        )

    def get_session_info(self) -> SessionInfo:
        info = self._native.get_session_info()
        return SessionInfo(
            session_id=info.session_id,
            created_at=datetime.fromisoformat(info.created_at.replace("Z", "+00:00")),
            expires_at=datetime.fromisoformat(info.expires_at.replace("Z", "+00:00")),
            requests_today=info.requests_today,
            requests_remaining=info.requests_remaining,
        )

    def check_operation(self, operation: str) -> bool:
        return self._native.check_operation(operation)

    def check_event_kind(self, kind: int) -> bool:
        return self._native.check_event_kind(kind)

    def check_amount(self, sats: int) -> bool:
        return self._native.check_amount(sats)

    def record_request(self):
        self._native.record_request()

    def close(self):
        self._native.close()

    def sign_event(
        self,
        kind: int,
        content: str,
        tags: Optional[List[List[str]]] = None,
    ) -> Dict[str, Any]:
        """
        Sign a Nostr event.

        Args:
            kind: Nostr event kind (1=text, 4=DM, 7=reaction)
            content: Event content
            tags: Optional event tags

        Returns:
            Signed event as a dict with id, pubkey, sig, etc.
        """
        import json
        result = self._native.sign_event(kind, content, tags)
        return json.loads(result)

    def sign_psbt(self, psbt_base64: str, network: str = "testnet") -> str:
        """
        Sign a Bitcoin PSBT.

        Args:
            psbt_base64: Base64-encoded PSBT
            network: Network (mainnet, testnet, signet, regtest)

        Returns:
            Base64-encoded signed PSBT
        """
        return self._native.sign_psbt(psbt_base64, network)

    def get_public_key(self) -> str:
        """Get the Nostr public key (npub format)."""
        return self._native.get_public_key()

    def get_bitcoin_address(self, network: str = "testnet") -> str:
        """Get a Bitcoin address (p2tr taproot)."""
        return self._native.get_bitcoin_address(network)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class RemoteSession:
    """Session connected to a remote Keep signer via NIP-46."""

    def __init__(self, native):
        self._native = native

    @classmethod
    def connect(
        cls,
        bunker_url: str,
        timeout_seconds: int = 30,
    ) -> "RemoteSession":
        """
        Connect to a remote Keep signer via NIP-46.

        Args:
            bunker_url: NIP-46 bunker URL (bunker://npub...?relay=wss://...)
            timeout_seconds: Connection timeout

        Returns:
            Connected RemoteSession
        """
        if not _HAS_BINDINGS:
            raise RuntimeError("Native bindings not available")
        native = _RemoteSession.connect(bunker_url, timeout_seconds)
        return cls(native)

    def sign_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Sign a Nostr event via the remote signer."""
        import json
        event_json = json.dumps(event)
        result = self._native.sign_event(event_json)
        return json.loads(result)

    def get_public_key(self) -> str:
        """Get the public key from the remote signer."""
        return self._native.get_public_key()

    def nip44_encrypt(self, pubkey: str, plaintext: str) -> str:
        """Encrypt using NIP-44 via the remote signer."""
        return self._native.nip44_encrypt(pubkey, plaintext)

    def nip44_decrypt(self, pubkey: str, ciphertext: str) -> str:
        """Decrypt using NIP-44 via the remote signer."""
        return self._native.nip44_decrypt(pubkey, ciphertext)

    def ping(self) -> bool:
        """Ping the remote signer."""
        return self._native.ping()

    def disconnect(self):
        """Disconnect from the remote signer."""
        self._native.disconnect()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.disconnect()


class PendingSession:
    """A session request waiting for human approval."""

    def __init__(self, native):
        self._native = native

    @classmethod
    def create(
        cls,
        bunker_url: str,
        timeout_seconds: int = 30,
    ) -> "PendingSession":
        """
        Create a pending session request for human approval.

        Args:
            bunker_url: NIP-46 bunker URL (bunker://npub...?relay=wss://...)
            timeout_seconds: Connection timeout

        Returns:
            PendingSession with approval_url for the human to approve
        """
        if not _HAS_BINDINGS:
            raise RuntimeError("Native bindings not available")
        native = _PendingSession.create(bunker_url, timeout_seconds)
        return cls(native)

    @property
    def request_id(self) -> str:
        return self._native.request_id

    @property
    def approval_url(self) -> str:
        return self._native.approval_url

    def poll(self, timeout_seconds: int = 5) -> str:
        """
        Poll for approval status.

        Returns:
            "pending", "approved", or "denied"
        """
        return self._native.poll(timeout_seconds)

    def wait_for_approval(self, timeout_seconds: int = 300) -> "RemoteSession":
        """
        Block until the session is approved.

        Returns:
            RemoteSession connected to the approved signer
        """
        native_remote = self._native.wait_for_approval(timeout_seconds)
        return RemoteSession(native_remote)

    def disconnect(self):
        """Disconnect from the relay."""
        self._native.disconnect()


from .exceptions import (
    KeepAgentError,
    SessionExpired,
    SessionNotFound,
    RateLimitExceeded,
    ScopeViolation,
    PolicyDenied,
    AmountExceeded,
    AddressNotAllowed,
    EventKindNotAllowed,
    OperationNotAllowed,
    KeepAgentConnectionError,
    AuthError,
    InvalidToken,
    SessionDenied,
)


__all__ = [
    "SessionScope",
    "RateLimit",
    "SessionInfo",
    "AgentSession",
    "RemoteSession",
    "PendingSession",
    "KeepAgentError",
    "SessionExpired",
    "SessionNotFound",
    "RateLimitExceeded",
    "ScopeViolation",
    "PolicyDenied",
    "AmountExceeded",
    "AddressNotAllowed",
    "EventKindNotAllowed",
    "OperationNotAllowed",
    "KeepAgentConnectionError",
    "AuthError",
    "InvalidToken",
    "SessionDenied",
]
