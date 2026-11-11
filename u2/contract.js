/* Small, testable boundary for the 14.02 device prerequisite check. */
export const ARM_KEY = "afterglow:u2:arm:v1";
export const RESULT_KEY = "afterglow:u2:last:v1";

function shortText(value, limit) {
  const clean = String(value == null ? "" : value)
    .replace(/[\u0000-\u001f\u007f]/g, " ");
  return clean.length > limit ? clean.slice(0, limit) : clean;
}

export function makeProbeRecord(run, stage, detail, rebootRequired) {
  return {
    version: 1,
    run: shortText(run, 48),
    stage: shortText(stage, 32),
    detail: shortText(detail, 200),
    rebootRequired: !!rebootRequired,
    time: Date.now(),
  };
}

export function classifyProbeOutcome(result, functionRestored, error) {
  const reasons = [];
  if (error) reasons.push("Probe stopped: " + shortText(error.message || error, 120));
  const reported = result && Array.isArray(result.reasons) ? result.reasons : [];
  for (const reason of reported) reasons.push(shortText(reason, 120));
  if (!result || result.ok !== true) {
    if (reported.length === 0) reasons.push("Device checks did not complete");
  }
  if (result && result.pinRestored === false)
    reasons.push("Could not restore the original CPU affinity");
  if (!functionRestored)
    reasons.push("Could not restore the browser function pointer");
  return {
    pass: reasons.length === 0,
    reasons,
    rebootRequired: !!(result && result.rebootRequired) || !!error,
  };
}
