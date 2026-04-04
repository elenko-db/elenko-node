/**
 * Schedules elenko_timer jobs: receives sync from server, posts timerFire when due.
 * Server re-validates timer doc (active) and runs the flow on the main thread.
 */
const { parentPort } = require("worker_threads");

/** @type {Map<string, { timeoutId: ReturnType<setTimeout> | null, anchorMs: number, intervalMs: number, tick: number }>} */
const timers = new Map();

function clearOne(id) {
  const s = timers.get(id);
  if (s && s.timeoutId) clearTimeout(s.timeoutId);
  timers.delete(id);
}

function clearAll() {
  for (const id of timers.keys()) clearOne(id);
}

/**
 * @param {string} id
 * @param {{ flowId: string, profileId: string, entryId: string, param: string }} spec
 * @param {{ active: boolean }} meta
 */
function scheduleNext(id, spec, meta) {
  const s = timers.get(id);
  if (!s || !meta.active) return;

  const { anchorMs, intervalMs } = s;
  const now = Date.now();
  while (s.anchorMs + s.tick * intervalMs <= now) {
    s.tick += 1;
  }
  const nextAt = s.anchorMs + s.tick * intervalMs;
  const delay = Math.max(0, nextAt - now);

  s.timeoutId = setTimeout(() => {
    s.timeoutId = null;
    parentPort.postMessage({
      type: "timerFire",
      timerId: id,
      flowId: spec.flowId,
      profileId: spec.profileId,
      entryId: spec.entryId,
      param: spec.param,
    });
    s.tick += 1;
    scheduleNext(id, spec, meta);
  }, delay);
}

parentPort.on("message", (msg) => {
  if (!msg || msg.type !== "syncTimers") return;
  clearAll();

  const list = Array.isArray(msg.timers) ? msg.timers : [];
  for (const t of list) {
    if (!t || !t.id || !t.active) continue;
    const anchorMs = Number(t.anchorMs);
    const intervalMs = Number(t.intervalMs);
    if (!Number.isFinite(anchorMs) || !Number.isFinite(intervalMs) || intervalMs < 60000) continue;

    let tick = 0;
    const now = Date.now();
    if (now > anchorMs) {
      tick = Math.ceil((now - anchorMs) / intervalMs);
    }

    timers.set(t.id, {
      timeoutId: null,
      anchorMs,
      intervalMs,
      tick,
    });

    scheduleNext(
      t.id,
      {
        flowId: typeof t.flowId === "string" ? t.flowId : "",
        profileId: typeof t.profileId === "string" ? t.profileId : "",
        entryId: typeof t.entryId === "string" ? t.entryId : "",
        param: typeof t.param === "string" ? t.param : "",
      },
      { active: true }
    );
  }
});
