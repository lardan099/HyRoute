// Polling that stops while the window is out of sight: hidden to the tray
// or minimized. HyRoute says so with the "window" event; WebView2 itself
// does (document.hidden) only for a window hidden to the tray. A page that
// polled on all day kept msedgewebview2.exe busy: «Соединения» redrew its
// table every second in the tray.

let hostShown = true;
const resumers = new Set<() => void>();

export function windowHidden(): boolean {
  return hostShown === false || document.hidden;
}

function wake() {
  if (windowHidden()) return;
  for (const f of [...resumers]) f();
}

document.addEventListener('visibilitychange', wake);

// setWindowShown takes the "window" event: back in sight, every poller
// runs at once instead of up to its interval later.
export function setWindowShown(on: boolean) {
  const was = windowHidden();
  hostShown = on;
  if (was) wake();
}

// every runs fn each ms while the window is in sight, and once when it
// comes back. The returned function stops it (onMount / $effect cleanup).
export function every(fn: () => void, ms: number): () => void {
  const t = setInterval(() => {
    if (!windowHidden()) fn();
  }, ms);
  const resume = () => fn();
  resumers.add(resume);
  return () => {
    clearInterval(t);
    resumers.delete(resume);
  };
}
