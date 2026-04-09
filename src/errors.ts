export class NoxyGeneralError extends Error {
  readonly code: string;

  constructor(message: string, code = 'NOXY_ERROR') {
    super(message);
    this.name = 'NoxyGeneralError';
    this.code = code;
  }
}

export class NoxyInitializationError extends Error {
  readonly code: string;

  constructor(message: string, code = 'NOXY_INIT_ERROR') {
    super(message);
    this.name = 'NoxyInitializationError';
    this.code = code;
  }
}

export class NoxyIdentityError extends Error {
  readonly code: string;

  constructor(message: string, code = 'NOXY_IDENTITY_ERROR') {
    super(message);
    this.name = 'NoxyIdentityError';
    this.code = code;
  }
}

export class NoxyDecisionProcessingError extends Error {
  readonly code: string;

  constructor(message: string, code = 'NOXY_DECISION_PROCESSING_ERROR', cause?: unknown) {
    super(message, cause !== undefined ? { cause } : undefined);
    this.name = 'NoxyDecisionProcessingError';
    this.code = code;
  }
}

export class NoxyKyberProviderError extends Error {
  readonly code: string;

  constructor({ code, message }: { code?: string; message?: string } = {}) {
    super(`[noxy.kyber.error]: ${message ?? 'Unknown error'}`);
    this.name = 'NoxyKyberProviderError';
    this.code = code ?? 'UNKNOWN_ERROR';
  }
}
