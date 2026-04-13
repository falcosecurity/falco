#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Validate Falco in multi-threaded mode with ThreadSanitizer (TSAN): 8 workers,
# no plugins (table API not thread-safe), default ruleset without container
# plugin requirement. Enables Prometheus /metrics on the webserver and scrapes it
# periodically to stress metrics collection under concurrent workers. Runs 10
# minutes under load (event-generator + stress-ng).
# Uses TSAN suppressions from build-tsan/tsan_suppressions_falco.txt and
# halt_on_error=1 to fail-fast on any data race.
#
# Prerequisites:
#   - Falco built with TSAN in build-tsan/ (see .cursor/skills/falco-build-local-libs/SKILL.md)
#   - stress-ng, Docker (for event-generator)
#
# Usage (from Falco repo root):
#   ./scripts/validate-tsan.sh
#
# Success: 10-minute run under load with no TSAN violation.

set -e

FALCO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$FALCO_ROOT"

BUILD_TSAN="${FALCO_ROOT}/build-tsan"
FALCO_BIN="${BUILD_TSAN}/userspace/falco/falco"
CONFIG="${FALCO_ROOT}/falco.yaml"
RULES_NO_CONTAINER="${BUILD_TSAN}/falco_rules_no_container.yaml"
SUPPRESSIONS="${BUILD_TSAN}/tsan_suppressions_falco.txt"
TSAN_LOG="${BUILD_TSAN}/tsan_validation.log"
RUN_DURATION_SEC="${RUN_DURATION_SEC:-600}"

# Default ruleset URL (remove container plugin requirement for no-plugin run)
RULES_URL="${FALCO_RULES_URL:-https://raw.githubusercontent.com/falcosecurity/rules/main/rules/falco_rules.yaml}"

LIBS_SUPPRESSIONS="${LIBS_SUPPRESSIONS:-/workspaces/libs/userspace/libsinsp/test/tsan_suppressions.txt}"
FALCO_TSAN_EXTRA="${FALCO_ROOT}/scripts/tsan_suppressions_falco.txt"

if [[ ! -x "$FALCO_BIN" ]]; then
  echo "Falco TSAN binary not found. Build with:"
  echo "  cmake -B build-tsan -DUSE_JEMALLOC=OFF -DCMAKE_CXX_FLAGS=\"-fsanitize=thread\" -DCMAKE_EXE_LINKER_FLAGS=\"-fsanitize=thread\" ... && cmake --build build-tsan --target falco"
  exit 1
fi

mkdir -p "$BUILD_TSAN"
{
  [[ -f "$FALCO_TSAN_EXTRA" ]] && cat "$FALCO_TSAN_EXTRA"
  [[ -f "$LIBS_SUPPRESSIONS" ]] && cat "$LIBS_SUPPRESSIONS"
} > "$SUPPRESSIONS"
if [[ ! -s "$SUPPRESSIONS" ]]; then
  echo "No TSAN suppressions assembled. Add $FALCO_TSAN_EXTRA and/or point LIBS_SUPPRESSIONS at an existing file."
  exit 1
fi
echo "TSAN suppressions: $SUPPRESSIONS (Falco: ${FALCO_TSAN_EXTRA}, libs: ${LIBS_SUPPRESSIONS})"

if [[ ! -f "$CONFIG" ]]; then
  echo "Config not found: $CONFIG"
  exit 1
fi

# Prepare config and rules: no plugins (avoid container plugin TSAN races), no config_files merge
mkdir -p "$BUILD_TSAN"
CONFIG_TSAN="${BUILD_TSAN}/falco_tsan.yaml"
cp "$CONFIG" "$CONFIG_TSAN"
# Force no plugins and no config_files so /etc/falco/config.d cannot add container plugin
sed -i '/^load_plugins:/s/.*/load_plugins: []/' "$CONFIG_TSAN"
sed -i '/^config_files:/s/.*/config_files: []/' "$CONFIG_TSAN"
# Remove the default config_files list entry so the inline config_files: [] takes effect
sed -i '\|  - /etc/falco/config.d|d' "$CONFIG_TSAN"
CONFIG="$CONFIG_TSAN"
echo "Using TSAN config $CONFIG (no plugins, no config_files merge)"

echo "Fetching default rules and removing container plugin requirement..."
if ! curl -sSLf "$RULES_URL" -o "${RULES_NO_CONTAINER}.tmp"; then
  echo "Failed to fetch rules from $RULES_URL"
  exit 1
fi
# Remove required_plugin_versions block so Falco runs without container plugin
sed -e '/required_plugin_versions/,/version: 0\.4\.0/d' \
    "${RULES_NO_CONTAINER}.tmp" > "${RULES_NO_CONTAINER}.tmp2"

# Adapt or comment out all rules/macros using container fields (no container plugin):
# - Adapt any macro that uses container.<field> to condition (never_true) so rules still load.
# - Comment out only rules that use container.<field> (macros are adapted, not removed).
# - When adapting a macro, replace the whole condition (including multi-line "condition: >" blocks).
awk '
BEGIN { n=0; has_container_ref=0 }
/^\- (macro|rule|list):/ {
  if (n>0) {
    if (has_container_ref && (block[0] ~ /^\- macro:/)) {
      for (i=0; i<n; i++) {
        if (block[i] ~ /^[[:space:]]*condition:/) {
          print "  condition: (never_true)"
          while (i+1 < n && block[i+1] ~ /^[[:space:]]/ && block[i+1] !~ /^  [a-zA-Z_]+:/) i++
        } else {
          print block[i]
        }
      }
    } else if (has_container_ref && (block[0] ~ /^\- rule:/)) {
      for (i=0; i<n; i++) print "# " block[i]
    } else {
      for (i=0; i<n; i++) print block[i]
    }
  }
  n=0; has_container_ref=0
  block[n]=$0; n++
  if ($0 ~ /container\.[a-zA-Z_]/) has_container_ref=1
  next
}
{
  block[n]=$0; n++
  if ($0 ~ /container\.[a-zA-Z_]/) has_container_ref=1
}
END {
  if (n>0) {
    if (has_container_ref && (block[0] ~ /^\- macro:/)) {
      for (i=0; i<n; i++) {
        if (block[i] ~ /^[[:space:]]*condition:/) {
          print "  condition: (never_true)"
          while (i+1 < n && block[i+1] ~ /^[[:space:]]/ && block[i+1] !~ /^  [a-zA-Z_]+:/) i++
        } else {
          print block[i]
        }
      }
    } else if (has_container_ref && (block[0] ~ /^\- rule:/)) {
      for (i=0; i<n; i++) print "# " block[i]
    } else {
      for (i=0; i<n; i++) print block[i]
    }
  }
}
' "${RULES_NO_CONTAINER}.tmp2" > "$RULES_NO_CONTAINER"
rm -f "${RULES_NO_CONTAINER}.tmp" "${RULES_NO_CONTAINER}.tmp2"
echo "Rules written to $RULES_NO_CONTAINER (container-field macros adapted to never_true, container-dependent rules commented out)"

# TSAN: suppressions + fail-fast on first data race.
# report_atomic_races=0: Folly hazptr / thread-local StaticMeta can report atomic-vs-mutex-init
# races where one stack is only pthread_mutex_lock; our race: suppressions cannot match both sides.
export TSAN_OPTIONS="suppressions=${SUPPRESSIONS} halt_on_error=1 report_atomic_races=0"
echo "TSAN_OPTIONS=$TSAN_OPTIONS"
echo "Starting Falco under TSAN with 8 workers, Prometheus /metrics, no plugins (log: $TSAN_LOG) ..."

sudo env TSAN_OPTIONS="$TSAN_OPTIONS" "$FALCO_BIN" -c "$CONFIG" -r "$RULES_NO_CONTAINER" \
  -o engine.modern_ebpf.num_worker_threads=8 \
  -o time_format_iso_8601=true \
  -o json_output=true \
  -o metrics.enabled=true \
  -o metrics.interval=5s \
  -o webserver.prometheus_metrics_enabled=true \
  > "$TSAN_LOG" 2>&1 &
FALCO_PID=$!

cleanup() {
  echo "Stopping load generators and Falco..."
  if [[ -n "${PROM_SCRAPE_PID:-}" ]]; then
    kill "$PROM_SCRAPE_PID" 2>/dev/null || true
    wait "$PROM_SCRAPE_PID" 2>/dev/null || true
  fi
  sudo pkill -P $$ 2>/dev/null || true
  sudo kill "$FALCO_PID" 2>/dev/null || true
  wait "$FALCO_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Wait for Falco to open capture and health endpoint
for i in $(seq 1 30); do
  if curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8765/healthz 2>/dev/null | grep -q 200; then
    echo "Falco is up (health check OK)."
    break
  fi
  if ! kill -0 "$FALCO_PID" 2>/dev/null; then
    echo "Falco exited early. Last lines of $TSAN_LOG:"
    tail -80 "$TSAN_LOG"
    exit 1
  fi
  sleep 1
done

if ! kill -0 "$FALCO_PID" 2>/dev/null; then
  echo "Falco exited during startup. Last lines of $TSAN_LOG:"
  tail -80 "$TSAN_LOG"
  exit 1
fi

# /metrics is registered only after inspectors open (later than /healthz)
METRICS_OK=0
for i in $(seq 1 60); do
  if curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8765/metrics 2>/dev/null | grep -q 200; then
    METRICS_OK=1
    break
  fi
  if ! kill -0 "$FALCO_PID" 2>/dev/null; then
    echo "Falco exited before /metrics became available. Last lines of $TSAN_LOG:"
    tail -80 "$TSAN_LOG"
    exit 1
  fi
  sleep 1
done
if [[ "$METRICS_OK" -ne 1 ]]; then
  echo "Prometheus /metrics did not return HTTP 200 within 60s. Last lines of $TSAN_LOG:"
  tail -80 "$TSAN_LOG"
  exit 1
fi
echo "Prometheus /metrics OK (scraping in background for ${RUN_DURATION_SEC}s)."

# Scrape /metrics concurrently with event workers to exercise metrics under TSAN
PROM_SCRAPE_LOG="${BUILD_TSAN}/prometheus_scrape.log"
(
  end=$((SECONDS + RUN_DURATION_SEC))
  while [[ $SECONDS -lt $end ]]; do
    curl -sS -o /dev/null --max-time 5 http://127.0.0.1:8765/metrics 2>/dev/null || true
    sleep 2
  done
) >> "$PROM_SCRAPE_LOG" 2>&1 &
PROM_SCRAPE_PID=$!

echo "Running load for ${RUN_DURATION_SEC}s (event-generator + stress-ng + /metrics scrapes)..."

# stress-ng for full duration
STRESS_PID=""
if command -v stress-ng &>/dev/null; then
  stress-ng --cpu 2 --timeout "${RUN_DURATION_SEC}s" >> "${BUILD_TSAN}/stress-ng.log" 2>&1 &
  STRESS_PID=$!
fi

# event-generator syscall actions in a loop for full duration
EG_PID=""
if command -v docker &>/dev/null; then
  (
    echo "Starting event-generator (Docker) syscall loop..."
    end=$((SECONDS + RUN_DURATION_SEC))
    while [[ $SECONDS -lt $end ]]; do
      docker run --rm --pid=host falcosecurity/event-generator run syscall --sleep 50ms 2>/dev/null || true
    done
  ) >> "${BUILD_TSAN}/event-generator.log" 2>&1 &
  EG_PID=$!
else
  echo "Docker not found; skipping event-generator (stress-ng only)."
fi

# Wait for the full run duration; if Falco exits early (e.g. TSAN halt_on_error), we detect it
elapsed=0
while [[ $elapsed -lt $RUN_DURATION_SEC ]]; do
  sleep 10
  elapsed=$((elapsed + 10))
  if ! kill -0 "$FALCO_PID" 2>/dev/null; then
    echo "Falco exited after ${elapsed}s. Last lines of $TSAN_LOG:"
    tail -120 "$TSAN_LOG"
    exit 1
  fi
  printf "\r  %ds / %ds ..." "$elapsed" "$RUN_DURATION_SEC"
done
echo ""

# Optional: wait for load generators to finish (they may already be done)
[[ -n "$STRESS_PID" ]] && wait "$STRESS_PID" 2>/dev/null || true
[[ -n "$EG_PID" ]] && wait "$EG_PID" 2>/dev/null || true

# Cleanup will stop Falco
sleep 2

if grep -q "ThreadSanitizer: data race" "$TSAN_LOG" 2>/dev/null; then
  echo "--- TSAN reported data race(s). Summary from $TSAN_LOG ---"
  grep -A 1 "ThreadSanitizer: data race" "$TSAN_LOG" || true
  echo "Full log: $TSAN_LOG"
  exit 1
fi

echo "Validation finished: ${RUN_DURATION_SEC}s run under load with no TSAN data races. See $TSAN_LOG for full output."
