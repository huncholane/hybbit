import { ClientOnly } from "@/components/ClientOnly";

// Static export: the page reads search params (the invitation), which the prerender cannot know.
export default function Layout({ children }: { children: React.ReactNode }) {
  return <ClientOnly>{children}</ClientOnly>;
}
