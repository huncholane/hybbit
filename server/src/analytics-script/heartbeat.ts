import type { Tracker } from "./tracking.js";

const MIN_INTERVAL_SECONDS = 5;
const MAX_INTERVAL_SECONDS = 300;
// A visible page with no input for this long (or one full interval, if that is
// longer) stops counting: the visitor has most likely walked away from the screen
const IDLE_TIMEOUT_MS = 60_000;
const ACTIVITY_EVENTS = ["scroll", "wheel", "pointerdown", "pointermove", "keydown", "touchstart"];

/**
 * Keeps a session's end time current while the visitor is actually on the page.
 * Every interval it sends a heartbeat, but only if the page is visible and the
 * visitor scrolled, moved the pointer, tapped or typed recently; background tabs
 * and idle screens send nothing. When the page is hidden (tab switch, app switch,
 * close) one last heartbeat stamps the moment they left, so time on the final
 * page is not cut off at the previous tick.
 */
export class HeartbeatManager {
  private tracker: Pick<Tracker, "trackHeartbeat">;
  private intervalMs: number;
  private idleTimeoutMs: number;
  private timer: ReturnType<typeof setInterval> | null = null;
  private lastActivity = Date.now();
  private lastSent = 0;

  constructor(tracker: Pick<Tracker, "trackHeartbeat">, intervalSeconds: number) {
    this.tracker = tracker;
    const seconds = Math.round(Number(intervalSeconds)) || 15;
    this.intervalMs = Math.min(MAX_INTERVAL_SECONDS, Math.max(MIN_INTERVAL_SECONDS, seconds)) * 1000;
    this.idleTimeoutMs = Math.max(IDLE_TIMEOUT_MS, this.intervalMs);
  }

  initialize(): void {
    for (const type of ACTIVITY_EVENTS) {
      // Capture on window so scrolls inside nested containers count too
      window.addEventListener(type, this.markActive, { capture: true, passive: true });
    }
    document.addEventListener("visibilitychange", this.handleVisibilityChange);
    this.timer = setInterval(this.tick, this.intervalMs);
  }

  cleanup(): void {
    for (const type of ACTIVITY_EVENTS) {
      window.removeEventListener(type, this.markActive, { capture: true });
    }
    document.removeEventListener("visibilitychange", this.handleVisibilityChange);
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  private markActive = (): void => {
    this.lastActivity = Date.now();
  };

  private isActive(now: number): boolean {
    return now - this.lastActivity < this.idleTimeoutMs;
  }

  private tick = (): void => {
    const now = Date.now();
    if (document.visibilityState === "visible" && this.isActive(now)) {
      this.send(now);
    }
  };

  private handleVisibilityChange = (): void => {
    const now = Date.now();
    if (document.visibilityState === "visible") {
      // Coming back to the tab is itself a sign the visitor is present
      this.lastActivity = now;
      return;
    }
    // Just hidden: record when they left, unless they had already gone idle or a
    // tick covered this moment
    if (this.isActive(now) && now - this.lastSent >= 1000) {
      this.send(now);
    }
  };

  private send(now: number): void {
    this.lastSent = now;
    this.tracker.trackHeartbeat();
  }
}
