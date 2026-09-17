"use client";

import { useSyncExternalStore } from "react";

const subscribeNever = () => () => {};

/** False while prerendering and hydrating, true from the first render after. */
export function useHydrated() {
  return useSyncExternalStore(
    subscribeNever,
    () => true,
    () => false
  );
}

/**
 * Renders nothing in the prerendered HTML and during hydration, then its children.
 * For pages of the static export whose markup depends on the real URL (dynamic
 * segments, search params), which the build could not know: rendering them in the
 * browser only avoids hydrating HTML made for a different URL.
 */
export function ClientOnly({ children }: { children: React.ReactNode }) {
  return useHydrated() ? children : null;
}
