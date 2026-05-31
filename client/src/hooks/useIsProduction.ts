export function useAppEnv() {
  const hostname = typeof window !== "undefined" ? window.location.hostname : "";

  if (hostname === "demo.hygo.ai") {
    return "demo";
  }
  if (hostname === "app.hygo.ai") {
    return "prod";
  }

  return null;
}
