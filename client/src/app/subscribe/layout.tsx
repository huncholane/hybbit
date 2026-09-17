import { ClientOnly } from "@/components/ClientOnly";

// Static export: the page reads search params (?siteId), which the prerender cannot know.
export default function Layout({ children }: { children: React.ReactNode }) {
  return <ClientOnly>{children}</ClientOnly>;
}
