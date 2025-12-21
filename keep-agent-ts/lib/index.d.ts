export { SessionScopeConfig, RateLimitOptions, SessionInfoResult, SignedEvent, createNostrScope, createBitcoinScope, createFullScope, KeepAgentSession, } from "../index.js";
import type { KeepAgentSession as KeepAgentSessionType } from "../index.d.ts";
export declare class KeepAgentError extends Error {
    constructor(message: string);
}
export declare class SessionExpiredError extends KeepAgentError {
    constructor(message?: string);
}
export declare class RateLimitExceededError extends KeepAgentError {
    retryAfterSecs?: number;
    constructor(message: string, retryAfterSecs?: number);
}
export declare class ScopeViolationError extends KeepAgentError {
    constructor(message: string);
}
export declare class AmountExceededError extends KeepAgentError {
    requested?: number;
    limit?: number;
    constructor(message: string, requested?: number, limit?: number);
}
export declare class AddressNotAllowedError extends KeepAgentError {
    constructor(message: string);
}
export declare class EventKindNotAllowedError extends KeepAgentError {
    kind?: number;
    constructor(message: string, kind?: number);
}
export declare class SessionDeniedError extends KeepAgentError {
    constructor(message?: string);
}
export declare class PendingSession {
    private _requestId;
    private _approvalUrl;
    constructor(requestId: string, approvalUrl: string);
    get requestId(): string;
    get approvalUrl(): string;
    poll(_timeoutMs?: number): Promise<KeepAgentSessionType | null>;
    waitForApproval(_timeoutMs?: number): Promise<KeepAgentSessionType>;
}
