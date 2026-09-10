import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { HeartbeatManager } from "./heartbeat.js";

describe("HeartbeatManager", () => {
  let visibility: DocumentVisibilityState;
  let trackHeartbeat: ReturnType<typeof vi.fn>;
  let manager: HeartbeatManager;

  const setVisibility = (state: DocumentVisibilityState) => {
    visibility = state;
    document.dispatchEvent(new Event("visibilitychange"));
  };

  beforeEach(() => {
    vi.useFakeTimers();
    visibility = "visible";
    Object.defineProperty(document, "visibilityState", { configurable: true, get: () => visibility });
    trackHeartbeat = vi.fn();
    manager = new HeartbeatManager({ trackHeartbeat }, 15);
    manager.initialize();
  });

  afterEach(() => {
    manager.cleanup();
    vi.useRealTimers();
  });

  it("sends a heartbeat every interval while the page is visible and in use", () => {
    vi.advanceTimersByTime(15_000);
    window.dispatchEvent(new Event("scroll"));
    vi.advanceTimersByTime(15_000);

    expect(trackHeartbeat).toHaveBeenCalledTimes(2);
  });

  it("sends one heartbeat when the page is hidden, then nothing until it is visible again", () => {
    vi.advanceTimersByTime(5_000);
    setVisibility("hidden");
    expect(trackHeartbeat).toHaveBeenCalledTimes(1);

    vi.advanceTimersByTime(120_000);
    expect(trackHeartbeat).toHaveBeenCalledTimes(1);

    setVisibility("visible");
    vi.advanceTimersByTime(15_000);
    expect(trackHeartbeat).toHaveBeenCalledTimes(2);
  });

  it("stops after a minute without input and resumes on the next interaction", () => {
    vi.advanceTimersByTime(60_000);
    expect(trackHeartbeat).toHaveBeenCalledTimes(3);

    vi.advanceTimersByTime(60_000);
    expect(trackHeartbeat).toHaveBeenCalledTimes(3);

    window.dispatchEvent(new Event("pointerdown"));
    vi.advanceTimersByTime(15_000);
    expect(trackHeartbeat).toHaveBeenCalledTimes(4);
  });

  it("does not stamp the moment of leaving when the visitor had already gone idle", () => {
    vi.advanceTimersByTime(90_000);
    trackHeartbeat.mockClear();

    setVisibility("hidden");

    expect(trackHeartbeat).not.toHaveBeenCalled();
  });

  it("keeps the interval between 5 and 300 seconds", () => {
    manager.cleanup();
    manager = new HeartbeatManager({ trackHeartbeat }, 1);
    manager.initialize();

    vi.advanceTimersByTime(4_999);
    expect(trackHeartbeat).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(trackHeartbeat).toHaveBeenCalledTimes(1);
  });
});
