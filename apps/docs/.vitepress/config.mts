import { defineConfig } from "vitepress";

export default defineConfig({
  title: "Tunnet",
  description:
    "Open-source private mesh networking. Replace everything with a single stack.",

  head: [
    ["link", { rel: "icon", type: "image/svg+xml", href: "/favicon.svg" }],
    ["meta", { name: "og:type", content: "website" }],
    [
      "meta",
      {
        name: "og:title",
        content: "Tunnet - Open-Source Mesh Networking",
      },
    ],
    [
      "meta",
      {
        name: "og:description",
        content:
          "Private overlay networking with an open control plane. Mesh VPN, tunnels, internal services, file transfer, and SSH - all in one.",
      },
    ],

    [
      "meta",
      {
        name: "og:image",
        content: "/banner.jpg",
      },
    ],
    [
      "meta",
      {
        name: "twitter:card",
        content: "summary_large_image",
      },
    ],
    [
      "meta",
      {
        name: "twitter:image",
        content: "/banner.jpg",
      },
    ],
  ],

  themeConfig: {
    logo: "/logo.png",
    siteTitle: "Tunnet",

    nav: [
      { text: "Guide", link: "/guide/what-is-tunnet" },
      {
        text: "Products",
        items: [
          { text: "Mesh Network", link: "/products/mesh/" },
          { text: "Serve", link: "/products/serve/" },
          { text: "Tunnel", link: "/products/tunnel/" },
          { text: "Send", link: "/products/send/" },
          { text: "SSH", link: "/products/ssh/" },
          { text: "Relay", link: "/products/relay/" },
        ],
      },
      {
        text: "Modes",
        items: [
          { text: "Managed Mode", link: "/modes/managed/" },
          { text: "Direct Mode", link: "/modes/direct/" },
        ],
      },
      { text: "CLI Reference", link: "/cli/" },
      { text: "SDK", link: "/sdk/" },
      { text: "Integrations", link: "/integrations/" },
      { text: "Self-Hosting", link: "/self-hosting/" },
    ],

    sidebar: {
      "/guide/": [
        {
          text: "Introduction",
          items: [
            { text: "What is Tunnet?", link: "/guide/what-is-tunnet" },
            { text: "Why Tunnet?", link: "/guide/why-tunnet" },
            {
              text: "Comparison with Alternatives",
              link: "/guide/comparison",
            },
          ],
        },
        {
          text: "Getting Started",
          items: [
            { text: "Installation", link: "/guide/installation" },
            {
              text: "Quick Start (Managed)",
              link: "/guide/quickstart-managed",
            },
            {
              text: "Quick Start (Direct)",
              link: "/guide/quickstart-direct",
            },
            { text: "Configuration", link: "/guide/configuration" },
          ],
        },
        {
          text: "Core Concepts",
          items: [
            { text: "Networks & Peers", link: "/guide/concepts/networks" },
            {
              text: "Enrollment & Identity",
              link: "/guide/concepts/enrollment",
            },
            {
              text: "Access Policies & ACLs",
              link: "/guide/concepts/access-policies",
            },
            {
              text: "Policy as Code",
              link: "/guide/policy-as-code",
            },
            { text: "PeerDNS", link: "/guide/concepts/peerdns" },
            { text: "Routing", link: "/guide/concepts/routing" },
            {
              text: "Encryption & Secrets",
              link: "/guide/concepts/encryption",
            },
            {
              text: "Audit Logs",
              link: "/guide/concepts/audit-logs",
            },
          ],
        },
      ],

      "/products/mesh/": [
        {
          text: "Mesh Network",
          items: [
            { text: "Overview", link: "/products/mesh/" },
            { text: "How Mesh Works", link: "/products/mesh/how-it-works" },
            {
              text: "Subnet Routes",
              link: "/products/mesh/subnet-routes",
            },
            {
              text: "Hostname Routes",
              link: "/products/mesh/hostname-routes",
            },
            { text: "Exit Nodes", link: "/products/mesh/exit-nodes" },
            { text: "Split Tunnels", link: "/products/mesh/split-tunnels" },
            { text: "HA Gateways", link: "/products/mesh/ha-gateways" },
            { text: "Gossip & Presence", link: "/products/mesh/gossip" },
            { text: "Diagnostics", link: "/products/mesh/diagnostics" },
          ],
        },
      ],

      "/products/serve/": [
        {
          text: "Serve",
          items: [
            { text: "Overview", link: "/products/serve/" },
            { text: "Internal TLS & CA", link: "/products/serve/tls" },
            { text: "ACL-Protected Services", link: "/products/serve/acl" },
            {
              text: "Dashboard Management",
              link: "/products/serve/dashboard",
            },
          ],
        },
      ],

      "/products/tunnel/": [
        {
          text: "Tunnel",
          items: [
            { text: "Overview", link: "/products/tunnel/" },
            {
              text: "Path-Based Redirects",
              link: "/products/tunnel/redirects",
            },
            { text: "TCP Port Mappings", link: "/products/tunnel/tcp-ports" },
            {
              text: "Custom Domains",
              link: "/products/tunnel/custom-domains",
            },
          ],
        },
      ],

      "/products/send/": [
        {
          text: "Send",
          items: [
            { text: "Overview", link: "/products/send/" },
            { text: "Consent Modes", link: "/products/send/consent" },
            { text: "Multicast & Tags", link: "/products/send/multicast" },
          ],
        },
      ],

      "/products/ssh/": [
        {
          text: "SSH",
          items: [
            { text: "Overview", link: "/products/ssh/" },
            {
              text: "Session Recording",
              link: "/products/ssh/recording",
            },
            {
              text: "SSH Policies & Re-Auth",
              link: "/products/ssh/policies",
            },
          ],
        },
      ],

      "/products/relay/": [
        {
          text: "Relay",
          items: [
            { text: "Overview", link: "/products/relay/" },
            {
              text: "Self-Hosted Setup",
              link: "/products/relay/self-hosted",
            },
            { text: "ACME & Certificates", link: "/products/relay/acme" },
          ],
        },
      ],

      "/modes/": [
        {
          text: "Modes",
          items: [
            { text: "Managed Mode", link: "/modes/managed/" },
            { text: "Direct Mode", link: "/modes/direct/" },
            {
              text: "Upgrading Direct to Managed",
              link: "/modes/upgrade",
            },
          ],
        },
      ],

      "/cli/": [
        {
          text: "CLI Reference",
          items: [
            { text: "Overview", link: "/cli/" },
            { text: "tunnet enroll", link: "/cli/enroll" },
            { text: "tunnet run", link: "/cli/run" },
            { text: "tunnet status", link: "/cli/status" },
            { text: "tunnet ping", link: "/cli/ping" },
            { text: "tunnet serve", link: "/cli/serve" },
            { text: "tunnet tunnel", link: "/cli/tunnel" },
            { text: "tunnet send", link: "/cli/send" },
            { text: "tunnet ssh", link: "/cli/ssh" },
            { text: "tunnet route", link: "/cli/route" },
            { text: "tunnet dns", link: "/cli/dns" },
            { text: "tunnet login / logout", link: "/cli/login" },
            { text: "tunnet policy", link: "/cli/policy" },
            { text: "tunnet validate", link: "/cli/validate" },
            { text: "tunnet reload", link: "/cli/reload" },
            { text: "Direct Mode Commands", link: "/cli/direct" },
            { text: "tunnet service", link: "/cli/service" },
            { text: "tunnet update", link: "/cli/update" },
            { text: "tunnet-relay", link: "/cli/relay" },
          ],
        },
      ],

      "/sdk/": [
        {
          text: "SDK",
          items: [
            { text: "Overview", link: "/sdk/" },
            { text: "Go management SDK", link: "/sdk/#go-management-sdk" },
          ],
        },
        {
          text: "Node.js / Bun",
          items: [
            { text: "Getting Started", link: "/sdk/js/" },
            { text: "TunnetNode", link: "/sdk/node" },
            { text: "Streams & Fetch", link: "/sdk/streams" },
            { text: "File Transfer", link: "/sdk/file-transfer" },
          ],
        },
        {
          text: "Rust",
          items: [
            { text: "Getting Started", link: "/sdk/rust/" },
            { text: "TunnetNode", link: "/sdk/rust/node" },
            { text: "Streams", link: "/sdk/rust/streams" },
            { text: "File Transfer", link: "/sdk/rust/file-transfer" },
          ],
        },
      ],

      "/integrations/": [
        {
          text: "Integrations",
          items: [{ text: "Overview", link: "/integrations/" }],
        },
        {
          text: "Kubernetes",
          items: [
            { text: "Overview", link: "/integrations/kubernetes/" },
            {
              text: "Install the Operator",
              link: "/integrations/kubernetes/install",
            },
            {
              text: "Connect a Cluster",
              link: "/integrations/kubernetes/connector",
            },
            {
              text: "Expose Services",
              link: "/integrations/kubernetes/expose-services",
            },
            {
              text: "Dashboard",
              link: "/integrations/kubernetes/dashboard",
            },
          ],
        },
      ],

      "/self-hosting/": [
        {
          text: "Self-Hosting",
          items: [
            { text: "Overview", link: "/self-hosting/" },
            { text: "Docker Compose", link: "/self-hosting/docker" },
            { text: "Control Plane", link: "/self-hosting/control-plane" },
            { text: "Management Server", link: "/self-hosting/management" },
            { text: "Dashboard", link: "/self-hosting/dashboard" },
            { text: "Relay", link: "/self-hosting/relay" },
            { text: "Database", link: "/self-hosting/database" },
            { text: "Environment Variables", link: "/self-hosting/env" },
          ],
        },
      ],
    },

    socialLinks: [
      { icon: "github", link: "https://github.com/tunnetio/Tunnet" },
      { icon: "discord", link: "https://discord.gg/y5bNc3MYKz" },
    ],

    editLink: {
      pattern: "https://github.com/tunnetio/Tunnet/edit/main/apps/docs/:path",
      text: "Edit this page on GitHub",
    },

    search: {
      provider: "local",
    },

    footer: {
      message: "Released under the AGPL-3.0 License.",
      copyright: "Copyright © 2025 Tunnet.io",
    },
  },

  markdown: {
    config: (md) => {
      const defaultRender = md.renderer.rules.fence;

      md.renderer.rules.fence = (tokens, idx, options, env, self) => {
        const token = tokens[idx];

        if (token.info.trim() === "mermaid") {
          const code = token.content.trim();
          return `<MermaidCode code="${encodeURIComponent(code)}" />`;
        }

        return defaultRender?.(tokens, idx, options, env, self);
      };
    },
  },
});
