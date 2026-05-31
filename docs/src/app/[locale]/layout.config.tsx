import type { BaseLayoutProps } from "fumadocs-ui/layouts/shared";
import Image from "next/image";

/**
 * Shared layout configurations
 *
 * you can customise layouts individually from:
 * Home Layout: app/[locale]/(home)/layout.tsx
 * Docs Layout: app/[locale]/docs/layout.tsx
 */
export function baseOptions(lang: string): BaseLayoutProps {
  return {
    nav: {
      title: (
        <>
          <Image
            src="/hygo/horizontal_white.svg"
            alt="Hygo"
            width={120}
            height={0}
            style={{ height: "auto" }}
            className="mr-2 invert dark:invert-0"
          />
        </>
      ),
    },
    // see https://fumadocs.dev/docs/ui/navigation/links
    links: [
      {
        text: "Demo",
        url: "https://demo.hygo.ai/81",
        external: true,
      },
    ],
  };
}
