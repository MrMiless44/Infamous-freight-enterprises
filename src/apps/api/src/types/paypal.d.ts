declare module "@paypal/checkout-server-sdk" {
  export namespace core {
    export class SandboxEnvironment {
      constructor(clientId: string, clientSecret: string);
    }

    export class PayPalHttpClient {
      constructor(environment: SandboxEnvironment);
      execute(
        request: unknown,
      ): Promise<{ result?: { id?: string; links?: unknown[] } }>;
    }
  }

  export namespace orders {
    export class OrdersCreateRequest {
      prefer(preference: string): void;
      requestBody(body: unknown): void;
    }

    export class OrdersCaptureRequest {
      constructor(orderId: string);
      requestBody(body: unknown): void;
    }
  }
}
