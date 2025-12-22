"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PendingSession = exports.SessionDeniedError = exports.EventKindNotAllowedError = exports.AddressNotAllowedError = exports.AmountExceededError = exports.ScopeViolationError = exports.RateLimitExceededError = exports.SessionExpiredError = exports.KeepAgentError = exports.KeepAgentSession = exports.createFullScope = exports.createBitcoinScope = exports.createNostrScope = void 0;
var index_js_1 = require("../index.js");
Object.defineProperty(exports, "createNostrScope", { enumerable: true, get: function () { return index_js_1.createNostrScope; } });
Object.defineProperty(exports, "createBitcoinScope", { enumerable: true, get: function () { return index_js_1.createBitcoinScope; } });
Object.defineProperty(exports, "createFullScope", { enumerable: true, get: function () { return index_js_1.createFullScope; } });
Object.defineProperty(exports, "KeepAgentSession", { enumerable: true, get: function () { return index_js_1.KeepAgentSession; } });
class KeepAgentError extends Error {
    constructor(message) {
        super(message);
        this.name = "KeepAgentError";
    }
}
exports.KeepAgentError = KeepAgentError;
class SessionExpiredError extends KeepAgentError {
    constructor(message = "Session expired") {
        super(message);
        this.name = "SessionExpiredError";
    }
}
exports.SessionExpiredError = SessionExpiredError;
class RateLimitExceededError extends KeepAgentError {
    constructor(message, retryAfterSecs) {
        super(message);
        this.name = "RateLimitExceededError";
        this.retryAfterSecs = retryAfterSecs;
    }
}
exports.RateLimitExceededError = RateLimitExceededError;
class ScopeViolationError extends KeepAgentError {
    constructor(message) {
        super(message);
        this.name = "ScopeViolationError";
    }
}
exports.ScopeViolationError = ScopeViolationError;
class AmountExceededError extends KeepAgentError {
    constructor(message, requested, limit) {
        super(message);
        this.name = "AmountExceededError";
        this.requested = requested;
        this.limit = limit;
    }
}
exports.AmountExceededError = AmountExceededError;
class AddressNotAllowedError extends KeepAgentError {
    constructor(message) {
        super(message);
        this.name = "AddressNotAllowedError";
    }
}
exports.AddressNotAllowedError = AddressNotAllowedError;
class EventKindNotAllowedError extends KeepAgentError {
    constructor(message, kind) {
        super(message);
        this.name = "EventKindNotAllowedError";
        this.kind = kind;
    }
}
exports.EventKindNotAllowedError = EventKindNotAllowedError;
class SessionDeniedError extends KeepAgentError {
    constructor(message = "Session request was denied") {
        super(message);
        this.name = "SessionDeniedError";
    }
}
exports.SessionDeniedError = SessionDeniedError;
class PendingSession {
    constructor(requestId, approvalUrl) {
        this._requestId = requestId;
        this._approvalUrl = approvalUrl;
    }
    get requestId() {
        return this._requestId;
    }
    get approvalUrl() {
        return this._approvalUrl;
    }
    async poll(_timeoutMs = 5000) {
        throw new KeepAgentError("PendingSession.poll() is not yet implemented");
    }
    async waitForApproval(_timeoutMs = 300000) {
        throw new KeepAgentError("PendingSession.waitForApproval() is not yet implemented");
    }
}
exports.PendingSession = PendingSession;
