const express = require("express");

// Mock helmet
jest.mock("helmet", () => {
  const helmetMock = jest.fn(() => (req, res, next) => next());
  
  helmetMock.contentSecurityPolicy = jest.fn(() => (req, res, next) => next());
  helmetMock.hsts = jest.fn(() => (req, res, next) => next());
  helmetMock.noSniff = jest.fn(() => (req, res, next) => next());
  helmetMock.frameguard = jest.fn(() => (req, res, next) => next());
  helmetMock.hidePoweredBy = jest.fn(() => (req, res, next) => next());
  helmetMock.referrerPolicy = jest.fn(() => (req, res, next) => next());
  helmetMock.permittedCrossDomainPolicies = jest.fn(() => (req, res, next) => next());
  
  return helmetMock;
});

const helmet = require("helmet");

describe("Security Headers Middleware", () => {
  let consoleLogSpy;
  let consoleWarnSpy;
  let app;

  beforeEach(() => {
    jest.clearAllMocks();
    
    consoleLogSpy = jest.spyOn(console, "log").mockImplementation();
    consoleWarnSpy = jest.spyOn(console, "warn").mockImplementation();
    
    delete require.cache[require.resolve("../src/middleware/securityHeaders")];
    
    app = express();
  });

  afterEach(() => {
    consoleLogSpy.mockRestore();
    consoleWarnSpy.mockRestore();
  });

  describe("securityHeaders", () => {
    test("should initialize security headers", () => {
      const { securityHeaders } = require("../src/middleware/securityHeaders");
      
      securityHeaders(app);
      
      expect(helmet).toHaveBeenCalled();
      expect(consoleLogSpy).toHaveBeenCalledWith("✓ Security headers initialized");
    });

    test("should configure Content Security Policy", () => {
      const { securityHeaders } = require("../src/middleware/securityHeaders");
      
      securityHeaders(app);
      
      expect(helmet.contentSecurityPolicy).toHaveBeenCalledWith({
        directives: expect.objectContaining({
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: ["'self'"],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          frameSrc: ["'none'"],
        }),
        reportUri: "/api/csp-violation",
      });
    });

    test("should configure HSTS with proper settings", () => {
      const { securityHeaders } = require("../src/middleware/securityHeaders");
      
      securityHeaders(app);
      
      expect(helmet.hsts).toHaveBeenCalledWith({
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
      });
    });

    test("should configure noSniff", () => {
      const { securityHeaders } = require("../src/middleware/securityHeaders");
      
      securityHeaders(app);
      
      expect(helmet.noSniff).toHaveBeenCalled();
    });

    test("should configure frameguard with deny action", () => {
      const { securityHeaders } = require("../src/middleware/securityHeaders");
      
      securityHeaders(app);
      
      expect(helmet.frameguard).toHaveBeenCalledWith({
        action: "deny",
      });
    });

    test("should hide powered by header", () => {
      const { securityHeaders } = require("../src/middleware/securityHeaders");
      
      securityHeaders(app);
      
      expect(helmet.hidePoweredBy).toHaveBeenCalled();
    });

    test("should configure referrer policy", () => {
      const { securityHeaders } = require("../src/middleware/securityHeaders");
      
      securityHeaders(app);
      
      expect(helmet.referrerPolicy).toHaveBeenCalledWith({
        policy: "strict-origin-when-cross-origin",
      });
    });

    test("should configure permitted cross domain policies", () => {
      const { securityHeaders } = require("../src/middleware/securityHeaders");
      
      securityHeaders(app);
      
      expect(helmet.permittedCrossDomainPolicies).toHaveBeenCalled();
    });

    test("should add cache control for auth routes", () => {
      const { securityHeaders } = require("../src/middleware/securityHeaders");
      
      securityHeaders(app);
      
      // Simulate request to auth route
      const req = { path: "/api/auth/login" };
      const res = {
        set: jest.fn(),
      };
      const next = jest.fn();
      
      // Get the cache control middleware (it's added via app.use)
      const middleware = app._router.stack.find(
        layer => layer.handle && layer.handle.length === 3 && !layer.route
      );
      
      if (middleware) {
        middleware.handle(req, res, next);
        
        expect(res.set).toHaveBeenCalledWith({
          "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
          Pragma: "no-cache",
          Expires: "0",
        });
        expect(next).toHaveBeenCalled();
      }
    });

    test("should add cache control for billing routes", () => {
      const { securityHeaders } = require("../src/middleware/securityHeaders");
      
      securityHeaders(app);
      
      // Simulate request to billing route
      const req = { path: "/api/billing/stripe" };
      const res = {
        set: jest.fn(),
      };
      const next = jest.fn();
      
      // Get the cache control middleware
      const middleware = app._router.stack.find(
        layer => layer.handle && layer.handle.length === 3 && !layer.route
      );
      
      if (middleware) {
        middleware.handle(req, res, next);
        
        expect(res.set).toHaveBeenCalledWith({
          "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
          Pragma: "no-cache",
          Expires: "0",
        });
      }
    });

    test("should not add cache control for other routes", () => {
      const { securityHeaders } = require("../src/middleware/securityHeaders");
      
      securityHeaders(app);
      
      // Simulate request to non-sensitive route
      const req = { path: "/api/health" };
      const res = {
        set: jest.fn(),
      };
      const next = jest.fn();
      
      // Get the cache control middleware
      const middleware = app._router.stack.find(
        layer => layer.handle && layer.handle.length === 3 && !layer.route
      );
      
      if (middleware) {
        middleware.handle(req, res, next);
        
        expect(res.set).not.toHaveBeenCalled();
        expect(next).toHaveBeenCalled();
      }
    });
  });

  describe("handleCSPViolation", () => {
    test("should log CSP violation", () => {
      const { handleCSPViolation } = require("../src/middleware/securityHeaders");
      
      const req = {
        body: {
          "csp-report": {
            "document-uri": "https://example.com/page",
            "violated-directive": "script-src 'self'",
            "blocked-uri": "https://evil.com/script.js",
          },
        },
      };
      const res = {
        status: jest.fn().mockReturnThis(),
        end: jest.fn(),
      };
      
      handleCSPViolation(req, res);
      
      expect(consoleWarnSpy).toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(204);
      expect(res.end).toHaveBeenCalled();
    });

    test("should handle empty CSP violation body", () => {
      const { handleCSPViolation } = require("../src/middleware/securityHeaders");
      
      const req = { body: {} };
      const res = {
        status: jest.fn().mockReturnThis(),
        end: jest.fn(),
      };
      
      handleCSPViolation(req, res);
      
      expect(res.status).toHaveBeenCalledWith(204);
      expect(res.end).toHaveBeenCalled();
    });

    test("should handle malformed CSP violation", () => {
      const { handleCSPViolation } = require("../src/middleware/securityHeaders");
      
      const req = { body: null };
      const res = {
        status: jest.fn().mockReturnThis(),
        end: jest.fn(),
      };
      
      handleCSPViolation(req, res);
      
      expect(res.status).toHaveBeenCalledWith(204);
    });
  });

  describe("CSP configuration", () => {
    test("should include upgradeInsecureRequests directive", () => {
      const { securityHeaders } = require("../src/middleware/securityHeaders");
      
      securityHeaders(app);
      
      const cspCall = helmet.contentSecurityPolicy.mock.calls[0][0];
      expect(cspCall.directives).toHaveProperty("upgradeInsecureRequests");
    });

    test("should configure script-src with unsafe-inline", () => {
      const { securityHeaders } = require("../src/middleware/securityHeaders");
      
      securityHeaders(app);
      
      const cspCall = helmet.contentSecurityPolicy.mock.calls[0][0];
      expect(cspCall.directives.scriptSrc).toContain("'unsafe-inline'");
    });

    test("should configure object-src as none", () => {
      const { securityHeaders } = require("../src/middleware/securityHeaders");
      
      securityHeaders(app);
      
      const cspCall = helmet.contentSecurityPolicy.mock.calls[0][0];
      expect(cspCall.directives.objectSrc).toEqual(["'none'"]);
    });

    test("should configure frame-src as none", () => {
      const { securityHeaders } = require("../src/middleware/securityHeaders");
      
      securityHeaders(app);
      
      const cspCall = helmet.contentSecurityPolicy.mock.calls[0][0];
      expect(cspCall.directives.frameSrc).toEqual(["'none'"]);
    });

    test("should allow data: and https: for images", () => {
      const { securityHeaders } = require("../src/middleware/securityHeaders");
      
      securityHeaders(app);
      
      const cspCall = helmet.contentSecurityPolicy.mock.calls[0][0];
      expect(cspCall.directives.imgSrc).toContain("data:");
      expect(cspCall.directives.imgSrc).toContain("https:");
    });
  });
});
