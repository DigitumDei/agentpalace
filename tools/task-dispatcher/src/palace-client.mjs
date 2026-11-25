/**
 * Zero-dependency HTTP REST client for AgentPalace `/v1/coordination/*` routes.
 * Wire contracts match `crates/agentpalace-server/src/lib.rs` and
 * `crates/agentpalace-federation/src/lib.rs`.
 */
export class PalaceHttpError extends Error {
  constructor(message, { status, code, body } = {}) {
    super(message);
    this.name = 'PalaceHttpError';
    this.status = status;
    this.code = code;
    this.body = body;
  }
}

export class PalaceClient {
  constructor({ baseUrl, token = '', requestTimeoutMs = 15000, fetchImpl = globalThis.fetch }) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.token = token;
    this.requestTimeoutMs = requestTimeoutMs;
    this.fetch = fetchImpl;
  }

  async _request(method, routePath, { query, body, auth = true } = {}) {
    const url = new URL(`${this.baseUrl}${routePath}`);
    if (query) {
      for (const [key, val] of Object.entries(query)) {
        if (val !== undefined && val !== null && val !== '') {
          url.searchParams.set(key, String(val));
        }
      }
    }

    const headers = { Accept: 'application/json' };
    if (auth && this.token) {
      headers.Authorization = `Bearer ${this.token}`;
    }
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.requestTimeoutMs);

    try {
      const response = await this.fetch(url, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      const text = await response.text();
      let parsed = null;
      if (text) {
        try {
          parsed = JSON.parse(text);
        } catch {
          parsed = { raw: text };
        }
      }

      if (!response.ok) {
        const msg = parsed?.message || parsed?.error || `HTTP ${response.status} on ${method} ${routePath}`;
        throw new PalaceHttpError(msg, {
          status: response.status,
          code: parsed?.code,
          body: parsed,
        });
      }

      return parsed;
    } finally {
      clearTimeout(timer);
    }
  }

  health() {
    return this._request('GET', '/v1/health', { auth: false });
  }

  listTasks({ state, wing, owner, createdBy, parentId, limit = 50, cursor } = {}) {
    return this._request('GET', '/v1/coordination/tasks', {
      query: {
        state,
        wing,
        owner,
        created_by: createdBy,
        parent_id: parentId,
        limit,
        cursor,
      },
    });
  }

  getTask(taskId) {
    return this._request('GET', `/v1/coordination/tasks/${encodeURIComponent(taskId)}`);
  }

  claimTask(taskId, { expectedRevision, leaseSeconds, worker }) {
    return this._request('POST', `/v1/coordination/tasks/${encodeURIComponent(taskId)}/claim`, {
      body: {
        expected_revision: expectedRevision,
        lease_seconds: leaseSeconds,
        worker,
      },
    });
  }

  renewTask(taskId, { expectedRevision, leaseSeconds, worker }) {
    return this._request('POST', `/v1/coordination/tasks/${encodeURIComponent(taskId)}/renew`, {
      body: {
        expected_revision: expectedRevision,
        lease_seconds: leaseSeconds,
        worker,
      },
    });
  }

  transitionTask(taskId, { expectedRevision, state, actor, details }) {
    return this._request('POST', `/v1/coordination/tasks/${encodeURIComponent(taskId)}/transition`, {
      body: {
        expected_revision: expectedRevision,
        state,
        actor,
        details,
      },
    });
  }

  readInbox({ recipient, wing, unacknowledgedOnly = true, limit = 50, cursor }) {
    return this._request('GET', '/v1/coordination/inbox', {
      query: {
        recipient,
        wing,
        unacknowledged_only: unacknowledgedOnly,
        limit,
        cursor,
      },
    });
  }

  ackMessage(messageId, { actor } = {}) {
    return this._request('POST', `/v1/coordination/messages/${encodeURIComponent(messageId)}/ack`, {
      body: { actor },
    });
  }

  sendMessage({ taskId, recipient, kind, payload, idempotencyKey, sender }) {
    return this._request('POST', '/v1/coordination/messages', {
      body: {
        task_id: taskId,
        recipient,
        kind,
        payload,
        idempotency_key: idempotencyKey,
        sender,
      },
    });
  }

  listEvents({ taskId, wing, limit = 50, cursor } = {}) {
    return this._request('GET', '/v1/coordination/events', {
      query: {
        task_id: taskId,
        wing,
        limit,
        cursor,
      },
    });
  }
}
