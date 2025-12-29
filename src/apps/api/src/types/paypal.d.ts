declare module '@paypal/checkout-server-sdk' {
  export class core {
    static PayPalHttpClient: new (environment: any) => any;
    static SandboxEnvironment: new (clientId: string, clientSecret: string) => any;
    static LiveEnvironment: new (clientId: string, clientSecret: string) => any;
  }

  export class orders {
    static OrdersCreateRequest: new () => any;
    static OrdersCaptureRequest: new (orderId: string) => any;
  }

  export default {
    core,
    orders,
  };
}
