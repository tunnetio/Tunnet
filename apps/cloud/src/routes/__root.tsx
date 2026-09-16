import { TanStackDevtools } from "@tanstack/react-devtools";
import { createRootRoute, HeadContent, Scripts } from "@tanstack/react-router";
import { TanStackRouterDevtoolsPanel } from "@tanstack/react-router-devtools";
import { ThemeProvider } from "#/components/theme-provider";

import appCss from "../styles.css?url";

export const Route = createRootRoute({
  head: () => ({
    meta: [
      { charSet: "utf-8" },
      {
        name: "viewport",
        content: "width=device-width, initial-scale=1",
      },
      {
        title: "Tunnet - Private networking for every machine",
      },
      {
        name: "description",
        content:
          "Private networking for every machine. SSH, internal apps, and public HTTPS - without a VPN. Open source. Start for free.",
      },
      { name: "theme-color", content: "#f4f2ec" },
      {
        property: "og:title",
        content: "Tunnet - Private networking for every machine",
      },
      {
        property: "og:description",
        content:
          "Private networking for every machine. SSH, internal apps, and public HTTPS - without a VPN. Open source. Start for free.",
      },
      { property: "og:type", content: "website" },
    ],
    links: [{ rel: "stylesheet", href: appCss }],
    scripts: [
      {
        src: "https://track.orielhaim.com/api/script.js",
        "data-site-id": "37f0761a0482",
        defer: true,
      },
    ],
  }),
  shellComponent: RootDocument,
});

function RootDocument({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <HeadContent />
      </head>
      <body>
        <ThemeProvider>
          {children}
          <TanStackDevtools
            config={{ position: "bottom-right" }}
            plugins={[
              {
                name: "Tanstack Router",
                render: <TanStackRouterDevtoolsPanel />,
              },
            ]}
          />
        </ThemeProvider>
        <Scripts />
      </body>
    </html>
  );
}
