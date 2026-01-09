import { Router, type Request, type Response } from "express";
import config from "../config";

const billingHealthRouter = Router();

billingHealthRouter.get("/health", (_req: Request, res: Response) => {
  const stripeConfig = config.getStripeConfig();
  const payPalConfig = config.getPayPalConfig();

  const stripeReady =
    stripeConfig.enabled &&
    Boolean(stripeConfig.successUrl && stripeConfig.cancelUrl);
  const payPalReady =
    payPalConfig.enabled &&
    Boolean(payPalConfig.returnUrl && payPalConfig.cancelUrl);

  res.status(200).json({
    ok: true,
    stripe: {
      enabled: stripeConfig.enabled,
      ready: stripeReady,
    },
    paypal: {
      enabled: payPalConfig.enabled,
      ready: payPalReady,
    },
    timestamp: new Date().toISOString(),
  });
});

export default billingHealthRouter;
