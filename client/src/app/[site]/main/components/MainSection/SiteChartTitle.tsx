import Link from "next/link";
import { useGetSite } from "../../../../../api/admin/hooks/useSites";
import { Favicon } from "../../../../../components/Favicon";
import { Skeleton } from "../../../../../components/ui/skeleton";
import { authClient } from "../../../../../lib/auth";

// The site being viewed, shown in the main chart's corner: its favicon and name.
// Signed-in viewers go back to their site list; visitors of a public or shared
// dashboard go to the site itself.
export function SiteChartTitle() {
  const session = authClient.useSession();
  const { data: site, isLoading } = useGetSite();

  if (isLoading) {
    return <Skeleton className="h-5 w-32" />;
  }

  if (!site) {
    return null;
  }

  return (
    <Link
      href={session.data ? "/" : `https://${site.domain}`}
      className="flex min-w-0 max-w-[180px] items-center gap-2 md:max-w-[280px]"
      title={site.domain}
    >
      <Favicon domain={site.domain} className="h-5 w-5 shrink-0 rounded" />
      <span className="truncate text-sm font-medium text-neutral-900 dark:text-white">{site.name || site.domain}</span>
    </Link>
  );
}
