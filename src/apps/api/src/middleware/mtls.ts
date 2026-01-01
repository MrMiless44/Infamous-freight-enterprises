/**
 * mTLS (Mutual TLS) Authentication for Service-to-Service Communication
 * Ensures only authenticated services can communicate with each other
 */

import https from "https";
import fs from "fs";
import path from "path";
import axios, { AxiosInstance } from "axios";

/**
 * Create HTTPS server with mutual TLS
 * Both client and server authenticate each other
 */
export function createMTLSServer(
  app: any,
  config: {
    certPath: string;
    keyPath: string;
    caPath: string;
    port: number;
  } = {
    certPath: process.env.TLS_CERT_PATH || "/etc/ssl/certs/server-cert.pem",
    keyPath: process.env.TLS_KEY_PATH || "/etc/ssl/private/server-key.pem",
    caPath: process.env.TLS_CA_PATH || "/etc/ssl/certs/ca-cert.pem",
    port: parseInt(process.env.API_PORT || "4000", 10),
  },
) {
  try {
    // Read certificates
    const cert = fs.readFileSync(config.certPath, "utf8");
    const key = fs.readFileSync(config.keyPath, "utf8");
    const ca = fs.readFileSync(config.caPath, "utf8");

    // Create HTTPS server with mutual TLS
    const server = https.createServer(
      {
        cert,
        key,
        ca, // Require client certificate signed by this CA
        requestCert: true,
        rejectUnauthorized: true, // Reject if client cert is invalid
      },
      app,
    );

    console.log(`🔐 mTLS server listening on port ${config.port}`);
    return server;
  } catch (error) {
    console.error("Failed to load TLS certificates:", error.message);
    throw error;
  }
}

/**
 * Create authenticated HTTPS client for service-to-service calls
 */
export function createMTLSClient(
  config: {
    certPath: string;
    keyPath: string;
    caPath: string;
  } = {
    certPath: process.env.TLS_CLIENT_CERT || "/etc/ssl/certs/client-cert.pem",
    keyPath: process.env.TLS_CLIENT_KEY || "/etc/ssl/private/client-key.pem",
    caPath: process.env.TLS_CA_PATH || "/etc/ssl/certs/ca-cert.pem",
  },
): AxiosInstance {
  try {
    const cert = fs.readFileSync(config.certPath, "utf8");
    const key = fs.readFileSync(config.keyPath, "utf8");
    const ca = fs.readFileSync(config.caPath, "utf8");

    // Create HTTPS agent with mutual TLS
    const httpsAgent = new https.Agent({
      cert,
      key,
      ca,
      rejectUnauthorized: true, // Verify server certificate
    });

    // Create axios instance with mTLS
    const client = axios.create({
      httpsAgent,
      timeout: 10000,
      validateStatus: () => true, // Don't throw on non-2xx responses
    });

    console.log("✅ mTLS client configured");
    return client;
  } catch (error) {
    console.error("Failed to configure mTLS client:", error.message);
    throw error;
  }
}

/**
 * Middleware to validate mTLS certificate in requests
 */
export function validateMTLSCertificate(req: any, res: any, next: any) {
  try {
    const cert = req.socket.getPeerCertificate();

    if (!cert.subject) {
      return res.status(401).json({
        error: "Client certificate required",
      });
    }

    // Extract service identity from certificate subject
    const serviceName = cert.subject.CN || cert.subject.O;

    // Store in request for logging/authorization
    req.service = {
      name: serviceName,
      cert: cert.fingerprint,
      issuer: cert.issuer.O,
      validFrom: cert.valid_from,
      validTo: cert.valid_to,
    };

    console.log(`✓ Authenticated service: ${serviceName}`);
    next();
  } catch (error) {
    res.status(401).json({ error: "Certificate validation failed" });
  }
}

/**
 * Generate self-signed certificates for development
 * In production, use proper CA-signed certificates
 */
export function generateSelfSignedCerts(outputDir: string = "./certs"): void {
  const { execSync } = require("child_process");

  try {
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    // Generate CA certificate
    console.log("📄 Generating CA certificate...");
    execSync(`openssl genrsa -out ${outputDir}/ca-key.pem 4096 2>/dev/null`);
    execSync(
      `openssl req -new -x509 -days 365 -key ${outputDir}/ca-key.pem ` +
        `-out ${outputDir}/ca-cert.pem -subj "/O=InfamousFreight/CN=CA" 2>/dev/null`,
    );

    // Generate server certificate
    console.log("📄 Generating server certificate...");
    execSync(
      `openssl genrsa -out ${outputDir}/server-key.pem 4096 2>/dev/null`,
    );
    execSync(
      `openssl req -new -key ${outputDir}/server-key.pem ` +
        `-out ${outputDir}/server.csr -subj "/O=InfamousFreight/CN=api" 2>/dev/null`,
    );
    execSync(
      `openssl x509 -req -days 365 -in ${outputDir}/server.csr ` +
        `-CA ${outputDir}/ca-cert.pem -CAkey ${outputDir}/ca-key.pem ` +
        `-CAcreateserial -out ${outputDir}/server-cert.pem 2>/dev/null`,
    );

    // Generate client certificate
    console.log("📄 Generating client certificate...");
    execSync(
      `openssl genrsa -out ${outputDir}/client-key.pem 4096 2>/dev/null`,
    );
    execSync(
      `openssl req -new -key ${outputDir}/client-key.pem ` +
        `-out ${outputDir}/client.csr -subj "/O=InfamousFreight/CN=client" 2>/dev/null`,
    );
    execSync(
      `openssl x509 -req -days 365 -in ${outputDir}/client.csr ` +
        `-CA ${outputDir}/ca-cert.pem -CAkey ${outputDir}/ca-key.pem ` +
        `-CAcreateserial -out ${outputDir}/client-cert.pem 2>/dev/null`,
    );

    console.log(`✅ Certificates generated in ${outputDir}/`);
  } catch (error) {
    console.error("Failed to generate certificates:", error.message);
  }
}

/**
 * Usage example:
 *
 * // Generate certs (development)
 * generateSelfSignedCerts('./certs');
 *
 * // Create server
 * const app = express();
 * const server = createMTLSServer(app, {
 *   certPath: './certs/server-cert.pem',
 *   keyPath: './certs/server-key.pem',
 *   caPath: './certs/ca-cert.pem',
 *   port: 4000
 * });
 *
 * // Add validation middleware
 * app.use(validateMTLSCertificate);
 *
 * // Use authenticated client
 * const client = createMTLSClient({
 *   certPath: './certs/client-cert.pem',
 *   keyPath: './certs/client-key.pem',
 *   caPath: './certs/ca-cert.pem'
 * });
 *
 * // Make authenticated request
 * const response = await client.get('https://api.internal:4000/health');
 */
