"""LangChain integration for Keep Agent SDK."""

from typing import Optional, Type, Any

try:
    from langchain.tools import BaseTool
    from pydantic import BaseModel, Field
    _HAS_LANGCHAIN = True
except ImportError:
    _HAS_LANGCHAIN = False
    BaseTool = object
    BaseModel = object
    Field = lambda **kwargs: None

from . import AgentSession


class SignNostrEventInput(BaseModel if _HAS_LANGCHAIN else object):
    kind: int = Field(description="Nostr event kind (1=text, 4=DM, 7=reaction)")
    content: str = Field(description="Event content")
    tags: list = Field(default_factory=list, description="Event tags")


class SignPsbtInput(BaseModel if _HAS_LANGCHAIN else object):
    psbt: str = Field(description="Base64-encoded PSBT")
    network: str = Field(default="testnet", description="Bitcoin network (mainnet, testnet, signet, regtest)")


class KeepSignerTool(BaseTool if _HAS_LANGCHAIN else object):
    """LangChain tool for signing with Keep."""

    name: str = "keep_signer"
    description: str = """Sign Nostr events or Bitcoin transactions securely.

Use this tool when you need to:
- Post a message on Nostr (kind 1)
- Send a direct message (kind 4)
- React to a post (kind 7)
- Sign a Bitcoin transaction (PSBT)

The signing is constrained by your session permissions."""

    session: AgentSession = None

    def __init__(self, session: AgentSession, **kwargs):
        if not _HAS_LANGCHAIN:
            raise ImportError("langchain is required. Install with: pip install keep-agent[langchain]")
        super().__init__(**kwargs)
        self.session = session

    def _run(self, action: str, **kwargs) -> str:
        if action == "sign_nostr_event":
            kind = kwargs.get("kind", 1)
            content = kwargs.get("content", "")
            tags = kwargs.get("tags", [])

            try:
                signed = self.session.sign_event(kind, content, tags)
                return f"Signed event: {signed.get('id', 'unknown')}"
            except Exception as e:
                return f"Error signing event: {e}"

        elif action == "sign_psbt":
            psbt = kwargs.get("psbt", "")
            network = kwargs.get("network", "testnet")

            try:
                signed = self.session.sign_psbt(psbt, network)
                return f"Signed PSBT: {signed[:50]}..."
            except Exception as e:
                return f"Error signing PSBT: {e}"

        elif action == "get_pubkey":
            try:
                return self.session.get_public_key()
            except Exception as e:
                return f"Error getting pubkey: {e}"

        elif action == "get_address":
            network = kwargs.get("network", "testnet")
            try:
                return self.session.get_bitcoin_address(network)
            except Exception as e:
                return f"Error getting address: {e}"

        return f"Unknown action: {action}"

    async def _arun(self, action: str, **kwargs) -> str:
        return self._run(action, **kwargs)


class KeepNostrTool(BaseTool if _HAS_LANGCHAIN else object):
    """Simplified tool just for Nostr signing."""

    name: str = "nostr_sign"
    description: str = "Sign and post a Nostr event"
    args_schema: Type[BaseModel] = SignNostrEventInput if _HAS_LANGCHAIN else None

    session: AgentSession = None

    def __init__(self, session: AgentSession, **kwargs):
        if not _HAS_LANGCHAIN:
            raise ImportError("langchain is required")
        super().__init__(**kwargs)
        self.session = session

    def _run(self, kind: int, content: str, tags: list | None = None) -> str:
        try:
            signed = self.session.sign_event(kind, content, tags or [])
            return f"Posted event {signed.get('id', 'unknown')}: {content[:50]}{'...' if len(content) > 50 else ''}"
        except Exception as e:
            return f"Error signing event: {e}"


class KeepBitcoinTool(BaseTool if _HAS_LANGCHAIN else object):
    """Simplified tool just for Bitcoin signing."""

    name: str = "bitcoin_sign"
    description: str = "Sign a Bitcoin PSBT"
    args_schema: Type[BaseModel] = SignPsbtInput if _HAS_LANGCHAIN else None

    session: AgentSession = None

    def __init__(self, session: AgentSession, **kwargs):
        if not _HAS_LANGCHAIN:
            raise ImportError("langchain is required")
        super().__init__(**kwargs)
        self.session = session

    def _run(self, psbt: str, network: str = "testnet") -> str:
        try:
            signed = self.session.sign_psbt(psbt, network=network)
            return f"Signed PSBT: {signed[:50]}..."
        except Exception as e:
            return f"Error signing PSBT: {e}"
