/**
 * White-Label Solution
 * Customizable branding system for resellers
 * Multi-tenant theming with custom domains, logos, colors
 */

import { PrismaClient } from "@prisma/client";
import { promises as fs } from "fs";
import * as path from "path";

const prisma = new PrismaClient();

/**
 * Theme configuration
 */
export interface ThemeConfig {
  tenantId: string;
  brandName: string;
  logoUrl: string;
  faviconUrl: string;
  primaryColor: string;
  secondaryColor: string;
  accentColor: string;
  fontFamily: string;
  customCSS?: string;
  customDomain?: string;
  emailFromName: string;
  emailFromAddress: string;
  supportEmail: string;
  supportPhone: string;
  termsUrl?: string;
  privacyUrl?: string;
  socialLinks?: {
    facebook?: string;
    twitter?: string;
    linkedin?: string;
    instagram?: string;
  };
}

/**
 * White-label manager
 */
export class WhiteLabelManager {
  private themesPath = path.join(__dirname, "../../themes");

  constructor() {
    fs.mkdir(this.themesPath, { recursive: true });
  }

  /**
   * Create white-label theme
   */
  async createTheme(config: ThemeConfig): Promise<ThemeConfig> {
    // Validate colors
    this.validateColor(config.primaryColor);
    this.validateColor(config.secondaryColor);
    this.validateColor(config.accentColor);

    // Save to database
    await prisma.tenant.update({
      where: { id: config.tenantId },
      data: {
        brandName: config.brandName,
        customDomain: config.customDomain,
        theme: config as any, // Store as JSON
      },
    });

    // Generate CSS file
    await this.generateThemeCSS(config);

    // Generate Next.js theme config
    await this.generateNextConfig(config);

    console.log(`✅ Theme created for ${config.brandName}`);
    return config;
  }

  /**
   * Get theme by tenant ID
   */
  async getTheme(tenantId: string): Promise<ThemeConfig | null> {
    const tenant = await prisma.tenant.findUnique({
      where: { id: tenantId },
    });

    if (!tenant || !tenant.theme) {
      return null;
    }

    return tenant.theme as any;
  }

  /**
   * Get theme by custom domain
   */
  async getThemeByDomain(domain: string): Promise<ThemeConfig | null> {
    const tenant = await prisma.tenant.findFirst({
      where: { customDomain: domain },
    });

    if (!tenant || !tenant.theme) {
      return null;
    }

    return tenant.theme as any;
  }

  /**
   * Update theme
   */
  async updateTheme(
    tenantId: string,
    updates: Partial<ThemeConfig>,
  ): Promise<ThemeConfig> {
    const current = await this.getTheme(tenantId);

    if (!current) {
      throw new Error("Theme not found");
    }

    const updated = { ...current, ...updates };

    await prisma.tenant.update({
      where: { id: tenantId },
      data: { theme: updated as any },
    });

    await this.generateThemeCSS(updated);
    await this.generateNextConfig(updated);

    return updated;
  }

  /**
   * Upload logo
   */
  async uploadLogo(
    tenantId: string,
    file: Express.Multer.File,
  ): Promise<string> {
    const logoPath = path.join(this.themesPath, tenantId, "logo.png");
    await fs.mkdir(path.dirname(logoPath), { recursive: true });
    await fs.writeFile(logoPath, file.buffer);

    const logoUrl = `/themes/${tenantId}/logo.png`;

    await this.updateTheme(tenantId, { logoUrl });

    return logoUrl;
  }

  /**
   * Upload favicon
   */
  async uploadFavicon(
    tenantId: string,
    file: Express.Multer.File,
  ): Promise<string> {
    const faviconPath = path.join(this.themesPath, tenantId, "favicon.ico");
    await fs.mkdir(path.dirname(faviconPath), { recursive: true });
    await fs.writeFile(faviconPath, file.buffer);

    const faviconUrl = `/themes/${tenantId}/favicon.ico`;

    await this.updateTheme(tenantId, { faviconUrl });

    return faviconUrl;
  }

  /**
   * Generate theme CSS
   */
  private async generateThemeCSS(config: ThemeConfig): Promise<void> {
    const css = `
:root {
  --brand-name: "${config.brandName}";
  --primary-color: ${config.primaryColor};
  --secondary-color: ${config.secondaryColor};
  --accent-color: ${config.accentColor};
  --font-family: ${config.fontFamily};
}

.btn-primary {
  background-color: var(--primary-color);
  border-color: var(--primary-color);
}

.btn-primary:hover {
  background-color: color-mix(in srgb, var(--primary-color) 80%, black);
}

.btn-secondary {
  background-color: var(--secondary-color);
  border-color: var(--secondary-color);
}

.text-primary {
  color: var(--primary-color) !important;
}

.bg-primary {
  background-color: var(--primary-color) !important;
}

.border-primary {
  border-color: var(--primary-color) !important;
}

.link-primary {
  color: var(--primary-color);
}

.link-primary:hover {
  color: color-mix(in srgb, var(--primary-color) 80%, black);
}

body {
  font-family: var(--font-family);
}

${config.customCSS || ""}
    `.trim();

    const cssPath = path.join(this.themesPath, config.tenantId, "theme.css");
    await fs.mkdir(path.dirname(cssPath), { recursive: true });
    await fs.writeFile(cssPath, css);
  }

  /**
   * Generate Next.js theme config
   */
  private async generateNextConfig(config: ThemeConfig): Promise<void> {
    const nextConfig = {
      brandName: config.brandName,
      logoUrl: config.logoUrl,
      faviconUrl: config.faviconUrl,
      colors: {
        primary: config.primaryColor,
        secondary: config.secondaryColor,
        accent: config.accentColor,
      },
      font: config.fontFamily,
      support: {
        email: config.supportEmail,
        phone: config.supportPhone,
      },
      social: config.socialLinks,
      legal: {
        terms: config.termsUrl,
        privacy: config.privacyUrl,
      },
    };

    const configPath = path.join(
      this.themesPath,
      config.tenantId,
      "config.json",
    );
    await fs.writeFile(configPath, JSON.stringify(nextConfig, null, 2));
  }

  /**
   * Validate hex color
   */
  private validateColor(color: string): void {
    if (!/^#[0-9A-F]{6}$/i.test(color)) {
      throw new Error(
        `Invalid color format: ${color}. Use hex format like #FF5733`,
      );
    }
  }

  /**
   * Generate preview HTML
   */
  async generatePreview(config: ThemeConfig): Promise<string> {
    return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>${config.brandName} - Preview</title>
  <link rel="icon" href="${config.faviconUrl}">
  <link href="/themes/${config.tenantId}/theme.css" rel="stylesheet">
  <style>
    body {
      margin: 0;
      padding: 20px;
      font-family: var(--font-family);
    }
    .preview-container {
      max-width: 1200px;
      margin: 0 auto;
    }
    .header {
      display: flex;
      align-items: center;
      padding: 20px;
      background: white;
      border-bottom: 2px solid var(--primary-color);
    }
    .logo {
      height: 50px;
    }
    .brand-name {
      font-size: 24px;
      font-weight: bold;
      color: var(--primary-color);
      margin-left: 15px;
    }
  </style>
</head>
<body>
  <div class="preview-container">
    <div class="header">
      <img src="${config.logoUrl}" alt="${config.brandName}" class="logo">
      <div class="brand-name">${config.brandName}</div>
    </div>
    <div style="padding: 40px;">
      <h1 style="color: var(--primary-color);">Welcome to ${config.brandName}</h1>
      <p>This is a preview of your white-label theme.</p>
      <button class="btn-primary">Primary Button</button>
      <button class="btn-secondary">Secondary Button</button>
    </div>
  </div>
</body>
</html>
    `.trim();
  }
}

/**
 * White-label middleware for Express
 */
export function whiteLabelMiddleware() {
  const manager = new WhiteLabelManager();

  return async (req: any, res: any, next: any) => {
    // Get domain from host header
    const domain = req.hostname;

    // Try to load theme by custom domain
    let theme = await manager.getThemeByDomain(domain);

    // Fallback to subdomain-based tenant
    if (!theme && req.tenant) {
      theme = await manager.getTheme(req.tenant.id);
    }

    // Attach theme to request
    if (theme) {
      req.theme = theme;
      res.locals.theme = theme;

      // Set custom headers
      res.setHeader("X-Brand-Name", theme.brandName);
    }

    next();
  };
}

// Export singleton
export const whiteLabelManager = new WhiteLabelManager();

/**
 * Usage:
 *
 * // Create white-label theme
 * await whiteLabelManager.createTheme({
 *   tenantId: 'acme-corp',
 *   brandName: 'ACME Logistics',
 *   logoUrl: '/themes/acme-corp/logo.png',
 *   faviconUrl: '/themes/acme-corp/favicon.ico',
 *   primaryColor: '#FF5733',
 *   secondaryColor: '#3498DB',
 *   accentColor: '#2ECC71',
 *   fontFamily: 'Inter, sans-serif',
 *   customDomain: 'logistics.acme.com',
 *   emailFromName: 'ACME Logistics',
 *   emailFromAddress: 'noreply@acme.com',
 *   supportEmail: 'support@acme.com',
 *   supportPhone: '1-800-ACME',
 * });
 *
 * // In Express app
 * app.use(whiteLabelMiddleware());
 *
 * // In React component
 * import { useTheme } from '@/hooks/useTheme';
 *
 * function Header() {
 *   const theme = useTheme();
 *
 *   return (
 *     <header style={{ backgroundColor: theme.colors.primary }}>
 *       <img src={theme.logoUrl} alt={theme.brandName} />
 *       <h1>{theme.brandName}</h1>
 *     </header>
 *   );
 * }
 *
 * // In emails
 * <p>Best regards,<br>${theme.brandName} Team</p>
 *
 * Database schema:
 *
 * model Tenant {
 *   id           String  @id @default(uuid())
 *   brandName    String?
 *   customDomain String? @unique
 *   theme        Json?
 *   // ... other fields
 * }
 *
 * Benefits:
 * - Fully customizable branding
 * - Custom domains support
 * - Theme preview
 * - Easy reselling
 * - Per-tenant customization
 * - Professional appearance
 */
