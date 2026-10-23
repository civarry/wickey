import * as api from './api.ts';
import { ApiError } from './api.ts';
import type { AppState, ModelList, Proxy, SessionStatus } from './api.ts';

export type ProxyView = 'active' | 'expired';

export interface ConfirmRequest {
  tone: 'warn' | 'danger';
  title: string;
  body: string;
  /** Label of the confirm button. */
  action: string;
  /** Runs on confirm. Throw to keep the dialog open and show the message. */
  run: () => Promise<void>;
}

export interface ToastMessage {
  id: number;
  title: string;
  body: string;
}

interface PassphraseRequest {
  reason: string;
  /** True after submit, until the server answers. */
  pending: boolean;
  resolve: (value: string | null) => void;
}

export interface ModelEntry {
  status: 'loading' | 'ready' | 'error';
  data?: ModelList;
  error: string;
}

const POLL_MS = 5000;
const TOAST_MS = 4200;

class AppStore {
  data = $state<AppState | null>(null);
  /** False until the first successful poll, and again whenever a poll fails. */
  connected = $state(false);
  loaded = $state(false);
  /** Set when the server has no session for this browser; the sign-in/unlock/setup screen shows instead of data. */
  gateStatus = $state<SessionStatus | null>(null);
  /** Wall clock, ticking every second so countdowns and status flips re-render. */
  now = $state(Date.now());
  graceEndsAt = $state(0);

  toastMessage = $state<ToastMessage | null>(null);
  confirmRequest = $state<ConfirmRequest | null>(null);
  passphraseRequest = $state<PassphraseRequest | null>(null);
  changePassphraseOpen = $state(false);

  /** Model lists per credential name, kept for the session so reopening a popover is instant. */
  modelLists = $state<Record<string, ModelEntry>>({});
  private modelFlights = new Map<string, Promise<void>>();

  credentials = $derived(this.data?.credentials ?? []);
  proxies = $derived(this.data?.proxies ?? []);
  session = $derived(this.data?.session ?? null);
  graceLeft = $derived(Math.max(0, Math.ceil((this.graceEndsAt - this.now) / 1000)));
  /** 'setup' before a vault exists, 'unlock' after a restart, 'signin' when the proxy is unlocked but this browser has no session. */
  gateMode = $derived.by((): 'setup' | 'unlock' | 'signin' | null => {
    const s = this.data ? this.data.session : this.gateStatus;
    if (!s) return null;
    return !s.vault ? 'setup' : !s.unlocked ? 'unlock' : this.data ? null : 'signin';
  });

  private toastTimer: ReturnType<typeof setTimeout> | undefined;
  private toastId = 0;

  /** Expired once the server says so, or once the clock passes expiresAt between polls. */
  statusOf = (p: Proxy): ProxyView => (p.status === 'expired' || this.now >= p.expiresAt ? 'expired' : 'active');

  baseUrlOf = (p: Proxy): string => `${this.data?.proxyOrigin ?? ''}/p/${p.id}`;

  /** Starts polling and the clock. Returns a stop function. */
  start(): () => void {
    api.setSessionLostHandler(() => void this.refresh());
    api.setPassphraseAsker(
      (reason) => this.askPassphrase(reason),
      () => (this.passphraseRequest = null),
    );
    const poll = setInterval(() => void this.refresh(), POLL_MS);
    const tick = setInterval(() => (this.now = Date.now()), 1000);
    void this.refresh();
    return () => {
      clearInterval(poll);
      clearInterval(tick);
      api.setPassphraseAsker(null);
      api.setSessionLostHandler(null);
    };
  }

  private refreshing: Promise<void> | null = null;

  /** One at a time: a poll that finds the session gone must not start another poll from inside itself. */
  refresh(): Promise<void> {
    return (this.refreshing ??= this.load().finally(() => (this.refreshing = null)));
  }

  private async load(): Promise<void> {
    try {
      // Without data we are on the gate: ask the open status route, which avoids a 401 on every poll.
      if (!this.data) {
        const status = await api.sessionStatus();
        if (!status.signedIn) {
          this.gateStatus = status;
          this.connected = true;
          return;
        }
      }
      const data = await api.getState();
      this.data = data;
      this.gateStatus = null;
      this.now = Date.now();
      this.graceEndsAt = this.now + data.session.graceRemaining * 1000;
      this.connected = true;
    } catch (err) {
      if (err instanceof ApiError && err.code === 'session_required') {
        // No session (first visit, restart, Lock from elsewhere, idle expiry): drop what was loaded and ask who is here.
        try {
          this.gateStatus = await api.sessionStatus();
          this.data = null;
          this.modelLists = {};
          this.connected = true;
        } catch {
          this.connected = false;
        }
      } else {
        this.connected = false;
      }
    } finally {
      this.loaded = true;
    }
  }

  /** Loads a credential's model list once; failed loads are tried again. `force` asks the provider anew. */
  loadModels(name: string, force = false): Promise<void> {
    const have = this.modelLists[name];
    if (!force && have && have.status === 'ready') return Promise.resolve();
    const flying = this.modelFlights.get(name);
    if (flying) return flying;
    this.modelLists[name] = { status: 'loading', data: have?.data, error: '' };
    const run = (async () => {
      try {
        const data = await (force ? api.refreshModels(name) : api.getModels(name));
        this.modelLists[name] = { status: 'ready', data, error: '' };
      } catch (err) {
        // Cancelled (passphrase prompt dismissed) and real failures both leave a retry button.
        this.modelLists[name] = { status: 'error', data: have?.data, error: err instanceof api.Cancelled ? 'Unlock was cancelled. Retry and enter your passphrase.' : (err as Error).message };
      } finally {
        this.modelFlights.delete(name);
      }
    })();
    this.modelFlights.set(name, run);
    return run;
  }

  toast(title: string, body = ''): void {
    clearTimeout(this.toastTimer);
    this.toastMessage = { id: ++this.toastId, title, body };
    this.toastTimer = setTimeout(() => this.dismissToast(), TOAST_MS);
  }

  dismissToast(): void {
    clearTimeout(this.toastTimer);
    this.toastMessage = null;
  }

  confirm(request: ConfirmRequest): void {
    this.confirmRequest = request;
  }

  private askPassphrase(reason: string): Promise<string | null> {
    // A retry after a wrong passphrase reuses the open dialog and just re-arms it.
    if (this.passphraseRequest) {
      const current = this.passphraseRequest;
      return new Promise((resolve) => {
        // Not yet submitted means another request is still waiting on this dialog: answer both.
        const waiting = current.pending ? null : current.resolve;
        current.resolve = waiting ? (v) => (waiting(v), resolve(v)) : resolve;
        current.reason = reason;
        current.pending = false;
      });
    }
    return new Promise((resolve) => {
      this.passphraseRequest = { reason, pending: false, resolve };
    });
  }

  submitPassphrase(value: string): void {
    const req = this.passphraseRequest;
    if (!req || req.pending || !value) return;
    req.pending = true;
    req.resolve(value);
  }

  cancelPassphrase(): void {
    const req = this.passphraseRequest;
    if (!req) return;
    this.passphraseRequest = null;
    req.resolve(null);
  }
}

export const app = new AppStore();
