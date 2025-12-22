export {
  SessionScopeConfig,
  RateLimitOptions,
  SessionInfoResult,
  SignedEvent,
  createNostrScope,
  createBitcoinScope,
  createFullScope,
  KeepAgentSession,
  RemoteSession,
} from "../index.js";

import type { KeepAgentSession as KeepAgentSessionType } from "../index.d.ts";

export class KeepAgentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KeepAgentError";
  }
}

export class SessionExpiredError extends KeepAgentError {
  constructor(message = "Session expired") {
    super(message);
    this.name = "SessionExpiredError";
  }
}

export class RateLimitExceededError extends KeepAgentError {
  retryAfterSecs?: number;

  constructor(message: string, retryAfterSecs?: number) {
    super(message);
    this.name = "RateLimitExceededError";
    this.retryAfterSecs = retryAfterSecs;
  }
}

export class ScopeViolationError extends KeepAgentError {
  constructor(message: string) {
    super(message);
    this.name = "ScopeViolationError";
  }
}

export class AmountExceededError extends KeepAgentError {
  requested?: number;
  limit?: number;

  constructor(message: string, requested?: number, limit?: number) {
    super(message);
    this.name = "AmountExceededError";
    this.requested = requested;
    this.limit = limit;
  }
}

export class AddressNotAllowedError extends KeepAgentError {
  constructor(message: string) {
    super(message);
    this.name = "AddressNotAllowedError";
  }
}

export class EventKindNotAllowedError extends KeepAgentError {
  kind?: number;

  constructor(message: string, kind?: number) {
    super(message);
    this.name = "EventKindNotAllowedError";
    this.kind = kind;
  }
}

export class SessionDeniedError extends KeepAgentError {
  constructor(message = "Session request was denied") {
    super(message);
    this.name = "SessionDeniedError";
  }
}

export class PendingSession {
  private _requestId: string;
  private _approvalUrl: string;

  constructor(requestId: string, approvalUrl: string) {
    this._requestId = requestId;
    this._approvalUrl = approvalUrl;
  }

  get requestId(): string {
    return this._requestId;
  }

  get approvalUrl(): string {
    return this._approvalUrl;
  }

  async poll(_timeoutMs = 5000): Promise<KeepAgentSessionType | null> {
    throw new KeepAgentError("PendingSession.poll() is not yet implemented");
  }

  async waitForApproval(_timeoutMs = 300000): Promise<KeepAgentSessionType> {
    throw new KeepAgentError("PendingSession.waitForApproval() is not yet implemented");
  }
}
