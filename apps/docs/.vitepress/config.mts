import { defineConfig } from "vitepress";

export default defineConfig({
  title: "TunTun",
  description:
    "Open-source private mesh networking. Replace everything with a single stack.",

  head: [
    ["link", { rel: "icon", type: "image/svg+xml", href: "/favicon.svg" }],
    ["meta", { name: "og:type", content: "website" }],
    [
      "meta",
      {
        name: "og:title",
        content: "TunTun - Open-Source Mesh Networking",
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
    siteTitle: "TunTun",

    nav: [
      { text: "Guide", link: "/guide/what-is-tuntun" },
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
      { text: "Self-Hosting", link: "/self-hosting/" },
    ],

    sidebar: {
      "/guide/": [
        {
          text: "Introduction",
          items: [
            { text: "What is TunTun?", link: "/guide/what-is-tuntun" },
            { text: "Why TunTun?", link: "/guide/why-tuntun" },
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
            { text: "PeerDNS", link: "/guide/concepts/peerdns" },
            { text: "Routing", link: "/guide/concepts/routing" },
            {
              text: "Encryption & Secrets",
              link: "/guide/concepts/encryption",
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
            { text: "tuntun enroll", link: "/cli/enroll" },
            { text: "tuntun run", link: "/cli/run" },
            { text: "tuntun status", link: "/cli/status" },
            { text: "tuntun ping", link: "/cli/ping" },
            { text: "tuntun serve", link: "/cli/serve" },
            { text: "tuntun tunnel", link: "/cli/tunnel" },
            { text: "tuntun send", link: "/cli/send" },
            { text: "tuntun ssh", link: "/cli/ssh" },
            { text: "tuntun route", link: "/cli/route" },
            { text: "tuntun dns", link: "/cli/dns" },
            { text: "tuntun login / logout", link: "/cli/login" },
            { text: "tuntun validate", link: "/cli/validate" },
            { text: "tuntun reload", link: "/cli/reload" },
            { text: "Direct Mode Commands", link: "/cli/direct" },
            { text: "tuntun service", link: "/cli/service" },
            { text: "tuntun update", link: "/cli/update" },
            { text: "tuntun-relay", link: "/cli/relay" },
          ],
        },
      ],

      "/sdk/": [
        {
          text: "Node SDK",
          items: [
            { text: "Overview", link: "/sdk/" },
            { text: "TunTunNode", link: "/sdk/node" },
            { text: "Streams & Fetch", link: "/sdk/streams" },
            { text: "File Transfer", link: "/sdk/file-transfer" },
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
      { icon: "github", link: "https://github.com/orielhaim/TunTun" },
      { icon: "discord", link: "https://discord.gg/y5bNc3MYKz" },
    ],

    editLink: {
      pattern: "https://github.com/orielhaim/TunTun/edit/main/apps/docs/:path",
      text: "Edit this page on GitHub",
    },

    search: {
      provider: "local",
    },

    footer: {
      message: "Released under the AGPL-3.0 License.",
      copyright: "Copyright © 2025 orielhaim",
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

        return defaultRender!(tokens, idx, options, env, self);
      };
    },
  },
});
