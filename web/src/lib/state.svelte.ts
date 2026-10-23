import * as api from './api.ts';
import { ApiError } from './api.ts';
import type { AppState, EventsPage, ModelList, Proxy, SessionStatus } from './api.ts';

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
  /** Why it is needed, when the default wording (minting, credentials) would be wrong. */
  purpose?: string;
  /** Set when the server will also ask for a system approval on this Mac (presence mode). */
  approval?: api.Approval;
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
  /**
   * One-time token from the setup link `start` prints (`#setup=…`). Memory only; reactive so the
   * gate swaps its link instructions for the form when the link is pasted into an open tab.
   */
  setupToken = $state('');

  /** Newest events summary for the banner (limit 1: the full list lives on the Events page). Null until loaded. */
  events = $state<EventsPage | null>(null);
  markingSeen = $state(false);

  /** Model lists per credential name, kept for the session so reopening a popover is instant. */
  modelLists = $state<Record<string, ModelEntry>>({});
  private modelFlights = new Map<string, Promise<void>>();

  credentials = $derived(this.data?.credentials ?? []);
  proxies = $derived(this.data?.proxies ?? []);
  session = $derived(this.data?.session ?? null);
  /** Presence mode is on: unlock, passphrase change and turning an alert off wait for an approval on this Mac. */
  presenceOn = $derived((this.data ? this.data.session.presence : this.gateStatus?.presence) === true);
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
      (reason, purpose, approval) => this.askPassphrase(reason, purpose, approval),
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
      void this.loadEvents();
    } catch (err) {
      if (err instanceof ApiError && err.code === 'session_required') {
        // No session (first visit, restart, Lock from elsewhere, idle expiry): drop what was loaded and ask who is here.
        try {
          this.gateStatus = await api.sessionStatus();
          this.data = null;
          this.events = null;
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

  /** Best effort: a failure leaves the banner as it was. */
  async loadEvents(): Promise<void> {
    try {
      this.events = await api.getEvents({ limit: 1 });
    } catch { /* the next poll tries again */ }
  }

  /** Moves the "last seen" marker to the newest event this tab has been told about. */
  async markSeen(): Promise<void> {
    const head = this.events?.head;
    if (head === undefined || this.markingSeen) return;
    this.markingSeen = true;
    try {
      await api.markEventsSeen(head);
      await this.loadEvents();
    } catch (err) {
      if (!(err instanceof api.Cancelled)) this.toast('Could not mark as seen', (err as Error).message);
    } finally {
      this.markingSeen = false;
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

  /** Takes the token out of the address bar, so the router never sees it and it isn't left in the URL. */
  takeSetupToken(): void {
    const m = /^#setup=([A-Za-z0-9_-]+)$/.exec(location.hash);
    if (!m) return;
    this.setupToken = m[1];
    history.replaceState(null, '', location.pathname + location.search);
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

  private askPassphrase(reason: string, purpose?: string, approval?: api.Approval): Promise<string | null> {
    // A retry after a wrong passphrase reuses the open dialog and just re-arms it.
    if (this.passphraseRequest) {
      const current = this.passphraseRequest;
      return new Promise((resolve) => {
        // Not yet submitted means another request is still waiting on this dialog: answer both.
        const waiting = current.pending ? null : current.resolve;
        current.resolve = waiting ? (v) => (waiting(v), resolve(v)) : resolve;
        current.reason = reason;
        current.purpose = purpose;
        current.approval = approval;
        current.pending = false;
      });
    }
    return new Promise((resolve) => {
      this.passphraseRequest = { reason, purpose, approval, pending: false, resolve };
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
