# 📄 Invoice Generation System

**Status**: Ready to Implement  
**Tools**: SendGrid, PDF generation, email automation

---

## 🎯 Invoice System Architecture

### 1. Automatic Invoice Generation

**On payment success:**
```javascript
// Auto-generate invoice when payment succeeds
event: invoice.payment_succeeded

1. Create invoice record in database
2. Generate PDF with itemized breakdown
3. Store PDF in cloud storage (AWS S3, Cloudflare R2)
4. Send to customer email
5. Make available in customer portal
```

### 2. Invoice Template

**Professional HTML Template:**

```html
<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    .header { text-align: center; margin-bottom: 30px; }
    .invoice-details { margin-bottom: 20px; }
    .items-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
    .items-table th { background: #f0f0f0; padding: 10px; text-align: left; }
    .items-table td { padding: 10px; border-bottom: 1px solid #ddd; }
    .total { text-align: right; font-size: 18px; font-weight: bold; margin-top: 20px; }
  </style>
</head>
<body>
  <div class="header">
    <h1>Invoice</h1>
    <p>Invoice #INV-2026-001</p>
  </div>

  <div class="invoice-details">
    <h3>Bill To:</h3>
    <p>{{customerName}}<br>{{customerEmail}}</p>
  </div>

  <div class="invoice-details">
    <h3>Invoice Details:</h3>
    <p>Date: {{invoiceDate}}<br>
    Due Date: {{dueDate}}<br>
    Period: {{billingPeriod}}</p>
  </div>

  <table class="items-table">
    <thead>
      <tr>
        <th>Description</th>
        <th>Quantity</th>
        <th>Price</th>
        <th>Amount</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>{{planName}} Monthly Subscription</td>
        <td>1</td>
        <td>${{planPrice}}</td>
        <td>${{planPrice}}</td>
      </tr>
      {{#if taxAmount}}
      <tr>
        <td colspan="3">Sales Tax</td>
        <td>${{taxAmount}}</td>
      </tr>
      {{/if}}
    </tbody>
  </table>

  <div class="total">
    <p>Total: ${{totalAmount}}</p>
    <p style="color: green;">Status: PAID ✓</p>
  </div>

  <hr>

  <footer style="font-size: 12px; color: #666;">
    <p>Thank you for your business!<br>
    For questions, contact support@infamousfreight.com<br>
    Payment processed by Stripe | {{invoiceDate}}</p>
  </footer>
</body>
</html>
```

### 3. Invoice Generation Code

**Using Puppeteer (HTML to PDF):**

```javascript
// api/src/services/invoiceGenerator.js
const puppeteer = require('puppeteer');
const nodemailer = require('nodemailer');
const Handlebars = require('handlebars');
const fs = require('fs');

class InvoiceGenerator {
  async generateInvoice(invoiceData) {
    // 1. Load template
    const template = fs.readFileSync('./templates/invoice.html', 'utf8');
    const compiledTemplate = Handlebars.compile(template);
    
    // 2. Render template with data
    const html = compiledTemplate({
      customerName: invoiceData.customerName,
      customerEmail: invoiceData.customerEmail,
      invoiceDate: new Date().toLocaleDateString(),
      dueDate: new Date(Date.now() + 30*24*60*60*1000).toLocaleDateString(),
      planName: invoiceData.planName,
      planPrice: invoiceData.planPrice,
      totalAmount: invoiceData.totalAmount,
      invoiceNumber: invoiceData.invoiceNumber
    });

    // 3. Convert HTML to PDF
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    await page.setContent(html);
    
    const pdfBuffer = await page.pdf({
      format: 'A4',
      margin: { top: '20px', bottom: '20px' }
    });

    await browser.close();

    // 4. Save PDF to storage
    const fileName = `invoice-${invoiceData.invoiceNumber}.pdf`;
    const pdfUrl = await this.savePdfToStorage(pdfBuffer, fileName);

    // 5. Save to database
    await db.invoices.create({
      customer_id: invoiceData.customerId,
      invoice_number: invoiceData.invoiceNumber,
      pdf_url: pdfUrl,
      amount: invoiceData.totalAmount,
      status: 'paid',
      created_at: new Date()
    });

    // 6. Send email
    await this.sendInvoiceEmail(invoiceData.customerEmail, pdfBuffer, fileName);

    return { success: true, pdfUrl };
  }

  async savePdfToStorage(pdfBuffer, fileName) {
    // Option 1: AWS S3
    const AWS = require('aws-sdk');
    const s3 = new AWS.S3();
    
    const params = {
      Bucket: process.env.AWS_S3_BUCKET,
      Key: `invoices/${fileName}`,
      Body: pdfBuffer,
      ContentType: 'application/pdf'
    };

    await s3.upload(params).promise();
    return `${process.env.AWS_S3_URL}/invoices/${fileName}`;

    // Option 2: Cloudflare R2 (more affordable)
    // const AWS = require('aws-sdk');
    // const s3 = new AWS.S3({
    //   endpoint: process.env.R2_ENDPOINT,
    //   accessKeyId: process.env.R2_ACCESS_KEY,
    //   secretAccessKey: process.env.R2_SECRET_KEY,
    //   s3ForcePathStyle: true,
    //   signatureVersion: 'v4',
    // });
    // Same params as above
  }

  async sendInvoiceEmail(customerEmail, pdfBuffer, fileName) {
    const transporter = nodemailer.createTransport({
      host: 'smtp.sendgrid.net',
      port: 587,
      auth: {
        user: 'apikey',
        pass: process.env.SENDGRID_API_KEY
      }
    });

    await transporter.sendMail({
      from: 'billing@infamousfreight.com',
      to: customerEmail,
      subject: 'Your Invoice - Infamous Freight',
      html: `
        <h2>Invoice Received</h2>
        <p>Thank you for your subscription to Infamous Freight!</p>
        <p>Your invoice is attached.</p>
        <p>If you have any questions, reply to this email or contact support@infamousfreight.com</p>
      `,
      attachments: [
        {
          filename: fileName,
          content: pdfBuffer
        }
      ]
    });
  }
}

module.exports = new InvoiceGenerator();
```

---

## 📧 Email Notifications

### Invoice Sent Email

```html
<h2>Your Invoice is Ready</h2>
<p>Hi {{customerName}},</p>
<p>We've received your payment for {{planName}} (${{amount}}).</p>
<p><strong>Invoice Details:</strong></p>
<ul>
  <li>Invoice #: INV-{{invoiceNumber}}</li>
  <li>Amount: ${{amount}}</li>
  <li>Date: {{invoiceDate}}</li>
  <li>Status: ✓ PAID</li>
</ul>
<p>Your invoice is attached as a PDF for your records.</p>
<a href="{{invoiceUrl}}" style="background: #0066cc; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
  View Invoice Online
</a>
<p>Questions? <a href="mailto:billing@infamousfreight.com">Contact us</a></p>
```

### Payment Failed Email

```html
<h2>Payment Unsuccessful</h2>
<p>Hi {{customerName}},</p>
<p>We couldn't process your payment for {{planName}}.</p>
<p><strong>Reason:</strong> {{failureReason}}</p>
<p><strong>Next Steps:</strong></p>
<ol>
  <li>Update your payment method
  <li>Retry payment
  <li>Contact support if problem persists
</ol>
<a href="{{updatePaymentUrl}}" style="background: #ff6600; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
  Update Payment Method
</a>
<p>Need help? <a href="mailto:support@infamousfreight.com">Contact support</a></p>
```

### Subscription Renewal Email (10 days before)

```html
<h2>Your Subscription Renews Soon</h2>
<p>Hi {{customerName}},</p>
<p>Your {{planName}} subscription will renew on {{renewalDate}} for ${{amount}}.</p>
<p>We'll charge your card ending in {{cardLast4}}.</p>
<p>If you want to:</p>
<ul>
  <li><a href="{{manageUrl}}">Update your payment method</a></li>
  <li><a href="{{upgradeUrl}}">Upgrade to a higher plan</a></li>
  <li><a href="{{cancelUrl}}">Cancel your subscription</a></li>
</ul>
<p>Questions? <a href="mailto:billing@infamousfreight.com">Contact us</a></p>
```

---

## 💾 Invoice Storage & Retrieval

### Database Schema

```sql
CREATE TABLE invoices (
  id UUID PRIMARY KEY,
  customer_id UUID REFERENCES customers(id),
  subscription_id UUID REFERENCES subscriptions(id),
  invoice_number VARCHAR(50) UNIQUE,
  amount_subtotal DECIMAL(10, 2),
  amount_tax DECIMAL(10, 2),
  amount_total DECIMAL(10, 2),
  currency VARCHAR(3) DEFAULT 'USD',
  status VARCHAR(50), -- draft, sent, paid, void, uncollectible
  pdf_url VARCHAR(500),
  payment_intent_id VARCHAR(255), -- Stripe ID
  created_at TIMESTAMP,
  due_at TIMESTAMP,
  paid_at TIMESTAMP,
  period_start DATE,
  period_end DATE
);
```

### API Endpoints

```javascript
// Get invoice by ID
router.get('/invoices/:id', authenticate, async (req, res) => {
  const invoice = await db.invoices.findById(req.params.id);
  
  if (invoice.customer_id !== req.user.id) {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  res.json(invoice);
});

// Download invoice PDF
router.get('/invoices/:id/download', authenticate, async (req, res) => {
  const invoice = await db.invoices.findById(req.params.id);
  
  const pdfBuffer = await downloadFromStorage(invoice.pdf_url);
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'attachment; filename=invoice.pdf');
  res.send(pdfBuffer);
});

// List all invoices for customer
router.get('/invoices', authenticate, async (req, res) => {
  const invoices = await db.invoices.findByCustomerId(req.user.id);
  res.json(invoices);
});
```

---

## 📊 Invoice Analytics

**Track important metrics:**

```javascript
// Monthly invoice statistics
const stats = {
  totalInvoices: 150,
  totalRevenue: 15000,
  averageInvoiceValue: 100,
  paidInvoices: 145,
  failedInvoices: 5,
  collectionRate: 0.967, // 96.7%
  daysOutstanding: 5.2
};

// By plan
const byPlan = {
  starter: { count: 100, revenue: 2900 },
  professional: { count: 40, revenue: 3960 },
  enterprise: { count: 10, revenue: 2990 }
};

// Trends
const trend = {
  monthlyGrowth: 0.15, // 15% growth
  churnRate: 0.03, // 3% per month
  nextMonthProjection: 17250 // Based on growth
};
```

---

## ✅ Implementation Checklist

```
Setup:
  [ ] Invoice template created
  [ ] PDF generation configured
  [ ] Email templates written
  [ ] Database schema ready
  [ ] Email provider integrated (SendGrid)

Features:
  [ ] Auto-generate on payment success
  [ ] Email invoice to customer
  [ ] Store invoice PDF in cloud
  [ ] Make invoice available in dashboard
  [ ] Support viewing online
  [ ] Support PDF download

Integration:
  [ ] Webhook triggers invoice generation
  [ ] Invoice data saved to database
  [ ] Email sent successfully
  [ ] PDF accessible from dashboard
  [ ] Links in invoice work

Testing:
  [ ] Test successful payment → invoice
  [ ] Test failed payment → notification
  [ ] Test PDF generation
  [ ] Test email delivery
  [ ] Test invoice retrieval
```

---

**Status**: 🟢 Ready to Deploy  
**Setup Time**: 2-3 hours  
**Cost**: SendGrid (~$10-20/mo), PDF storage (~$1-5/mo)  
**Benefit**: Professional invoicing, legal compliance, customer trust

