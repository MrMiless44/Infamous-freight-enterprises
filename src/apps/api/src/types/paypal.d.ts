declare module "@paypal/checkout-server-sdk" {
  export class core {
    static PayPalHttpClient: any;
    static SandboxEnvironment: any;
    static LiveEnvironment: any;
  }

  export class orders {
    static OrdersCreateRequest: any;
    static OrdersGetRequest: any;
    static OrdersCaptureRequest: any;
  }
}
