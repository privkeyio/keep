"""CrewAI integration for Keep Agent SDK."""

import json
from typing import List, Type

try:
    from crewai.tools import BaseTool
    from pydantic import BaseModel, Field
    _HAS_CREWAI = True
except ImportError:
    _HAS_CREWAI = False
    BaseTool = object
    BaseModel = object
    Field = lambda **kwargs: None

from . import AgentSession


if _HAS_CREWAI:
    class SignNostrInput(BaseModel):
        content: str = Field(description="The content to post")

    class SignPsbtInput(BaseModel):
        psbt: str = Field(description="Base64-encoded PSBT")

    class EmptyInput(BaseModel):
        pass
else:
    class SignNostrInput:
        content: str = None

    class SignPsbtInput:
        psbt: str = None

    class EmptyInput:
        pass


class SignNostrPostTool(BaseTool if _HAS_CREWAI else object):
    name: str = "Sign Nostr Post"
    description: str = "Sign and post a text note on Nostr"
    args_schema: Type[BaseModel] = SignNostrInput if _HAS_CREWAI else None
    session: AgentSession = None

    def __init__(self, session: AgentSession, **kwargs):
        super().__init__(**kwargs)
        self.session = session

    def _run(self, content: str) -> str:
        try:
            signed_event = self.session.sign_event(kind=1, content=content)
            return json.dumps(signed_event)
        except Exception as e:
            return f"Error signing event: {e}"


class SignBitcoinTxTool(BaseTool if _HAS_CREWAI else object):
    name: str = "Sign Bitcoin Transaction"
    description: str = "Sign a Bitcoin PSBT"
    args_schema: Type[BaseModel] = SignPsbtInput if _HAS_CREWAI else None
    session: AgentSession = None

    def __init__(self, session: AgentSession, **kwargs):
        super().__init__(**kwargs)
        self.session = session

    def _run(self, psbt: str) -> str:
        try:
            signed_psbt = self.session.sign_psbt(psbt)
            return signed_psbt
        except Exception as e:
            return f"Error signing PSBT: {e}"


class GetNostrPubkeyTool(BaseTool if _HAS_CREWAI else object):
    name: str = "Get Nostr Public Key"
    description: str = "Get the npub for this agent"
    args_schema: Type[BaseModel] = EmptyInput if _HAS_CREWAI else None
    session: AgentSession = None

    def __init__(self, session: AgentSession, **kwargs):
        super().__init__(**kwargs)
        self.session = session

    def _run(self) -> str:
        try:
            return self.session.get_public_key()
        except Exception as e:
            return f"Error getting public key: {e}"


class GetBitcoinAddressTool(BaseTool if _HAS_CREWAI else object):
    name: str = "Get Bitcoin Address"
    description: str = "Get a Bitcoin address for receiving"
    args_schema: Type[BaseModel] = EmptyInput if _HAS_CREWAI else None
    session: AgentSession = None

    def __init__(self, session: AgentSession, **kwargs):
        super().__init__(**kwargs)
        self.session = session

    def _run(self) -> str:
        try:
            return self.session.get_bitcoin_address()
        except Exception as e:
            return f"Error getting Bitcoin address: {e}"


def create_keep_tools(session: AgentSession) -> List:
    """Create CrewAI tools for Keep signing.

    Example:
        from crewai import Agent, Task, Crew
        from keep_agent import AgentSession
        from keep_agent.crewai import create_keep_tools

        session = AgentSession()
        tools = create_keep_tools(session)

        agent = Agent(
            role="Social Media Manager",
            goal="Post updates on Nostr",
            tools=tools,
        )
    """
    if not _HAS_CREWAI:
        raise ImportError("crewai is required. Install with: pip install keep-agent[crewai]")

    return [
        SignNostrPostTool(session=session),
        SignBitcoinTxTool(session=session),
        GetNostrPubkeyTool(session=session),
        GetBitcoinAddressTool(session=session),
    ]
