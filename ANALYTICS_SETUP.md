# 📊 Analytics Integration Guide

**Status**: Ready to Implement  
**Date**: January 11, 2026  
**Email**: miless8787@gmail.com

---

## 🎯 Analytics Platforms Comparison

| Platform | Cost | Privacy | Users | Setup Time |
|----------|------|---------|-------|-----------|
| Google Analytics | Free | Tracks users | 40M+ | 5 min |
| Plausible | $11-20/mo | Privacy-first | 10K+ | 5 min |
| Matomo | Free/Self-hosted | Privacy-first | 1M+ | 10 min |
| Fathom | $14/mo | Privacy-first | 2K+ | 5 min |

**Recommendation**: **Start with Google Analytics** (free, most features)

---

## 📈 Google Analytics Setup

### Step 1: Create Account

```bash
# 1. Go to Google Analytics
https://analytics.google.com

# 2. Click "Start measuring"

# 3. Create new account:
   Account name: Infamous Freight Enterprises
   Data sharing settings: Check all that apply

# 4. Create property:
   Property name: Web
   Reporting timezone: UTC (or your timezone)
   Currency: USD
   Industry: Transportation & Logistics

# 5. Create data stream:
   Platform: Web
   Website URL: https://infamousfreight.com (or your domain)
   Stream name: Website

# 6. Get Measurement ID
   Format: G-XXXXXXXXXX
```

### Step 2: Install Tracking Code

**Option A: Using Google Tag Manager (Recommended)**

```html
<!-- Add to <head> of index.html -->
<script async src="https://www.googletagmanager.com/gtag/js?id=G-XXXXXXXXXX"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', 'G-XXXXXXXXXX', {
    'page_path': window.location.pathname,
    'anonymize_ip': true,
    'allow_google_signals': false,
    'cookie_flags': 'SameSite=None;Secure'
  });
</script>
```

**Option B: Direct Implementation**

```html
<!-- Add to <head> of index.html -->
<script async src="https://www.googletagmanager.com/gtag/js?id=G-XXXXXXXXXX"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', 'G-XXXXXXXXXX');
</script>
```

### Step 3: Configure Events

```javascript
// Track custom events
function trackEvent(eventName, eventData) {
  gtag('event', eventName, eventData);
}

// Example events to track
trackEvent('page_view', {
  'page_title': document.title,
  'page_location': window.location.href
});

trackEvent('user_signup', {
  'method': 'github'
});

trackEvent('deployment_created', {
  'platform': 'vercel'
});
```

### Step 4: View Data

```bash
# Wait 24-48 hours for data to appear

# Go to Google Analytics Dashboard
https://analytics.google.com

# Check:
- Real-time visitors
- Traffic sources
- Geographic distribution
- Device types
- User behavior
```

---

## 🛡️ Privacy-First: Plausible Analytics

**Why Plausible?**
- No cookies
- GDPR compliant
- No tracking users
- Better for privacy-conscious users
- Lighter weight than Google Analytics

### Setup (5 minutes)

```bash
# 1. Sign up
https://plausible.io

# 2. Create new site:
   Domain: infamousfreight.com
   Timezone: UTC

# 3. Add tracking code:
   <script defer data-domain="infamousfreight.com" src="https://plausible.io/js/script.js"></script>

# 4. Verify installation
   Go to Plausible dashboard → Settings → Check if data incoming

# 5. See analytics
   After 1 hour, data appears in dashboard
```

---

## 🔍 Sentry Error Tracking Setup

**Why Sentry?**
- Automatically captures JavaScript errors
- Shows where errors happen
- Tracks user sessions
- Alerts on critical errors

### Step 1: Create Account

```bash
# 1. Sign up
https://sentry.io

# 2. Create organization
Name: Infamous Freight Enterprises

# 3. Create project
Platform: React (or JavaScript)
```

### Step 2: Install SDK

```bash
# Install via npm
npm install --save @sentry/react @sentry/tracing

# If using Vite
npm install --save @sentry/vite-plugin
```

### Step 3: Initialize in Code

**In main.jsx or App.tsx:**

```javascript
import * as Sentry from "@sentry/react";
import { BrowserTracing } from "@sentry/tracing";

Sentry.init({
  dsn: "https://your-sentry-dsn@sentry.io/PROJECT_ID",
  environment: import.meta.env.VITE_SENTRY_ENVIRONMENT || "development",
  tracesSampleRate: 1.0,
  integrations: [
    new BrowserTracing(),
    new Sentry.Replay({
      maskAllText: true,
      blockAllMedia: true,
    }),
  ],
  replaysSessionSampleRate: 0.1, // 10% of sessions
  replaysOnErrorSampleRate: 1.0, // 100% of error sessions
});

// Wrap your app component
export default Sentry.withProfiler(App);
```

### Step 4: Configure Alerts

```bash
# Go to Sentry Dashboard
https://sentry.io

# Settings → Alerts → Create Alert Rule:
- Alert on: Any error
- Send to: Your email
- Frequency: For each event
- Save
```

---

## 📧 Sendgrid Email Setup (Optional)

**For transactional emails:**

```bash
# 1. Sign up
https://sendgrid.com

# 2. Verify sender email
Settings → Sender Authentication

# 3. Create API key
Settings → API Keys → Create API Key

# 4. Add to .env
VITE_SENDGRID_API_KEY=SG.xxxxxxxxxxxx
VITE_SENDGRID_FROM_EMAIL=noreply@infamousfreight.com
```

**Usage:**

```javascript
const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.VITE_SENDGRID_API_KEY);

async function sendEmail(to, subject, text) {
  try {
    await sgMail.send({
      to,
      from: process.env.VITE_SENDGRID_FROM_EMAIL,
      subject,
      text,
      html: `<p>${text}</p>`,
    });
    console.log('Email sent');
  } catch (error) {
    console.error(error);
  }
}
```

---

## 🔗 Slack Notifications

**Get alerts in Slack:**

```bash
# 1. Create Incoming Webhook
https://api.slack.com/messaging/webhooks

# 2. Create new app → From scratch
App name: Infamous Freight
Workspace: Your workspace
Create

# 3. Enable Incoming Webhooks
Incoming Webhooks → Add New Webhook to Workspace

# 4. Copy webhook URL
VITE_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

**Send message to Slack:**

```javascript
async function sendSlackNotification(message) {
  const webhook = process.env.VITE_SLACK_WEBHOOK_URL;
  
  await fetch(webhook, {
    method: 'POST',
    body: JSON.stringify({
      text: message,
      blocks: [
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: message
          }
        }
      ]
    })
  });
}

// Example: Notify deployment
sendSlackNotification(`
🚀 Deployment successful!
Platform: Vercel
Status: LIVE
URL: https://infamous-freight-enterprises.vercel.app
`);
```

---

## 📊 Setting Up Dashboards

### Google Analytics Dashboard

```bash
# Create custom dashboard:

1. Go to Reports
2. Create new dashboard
3. Add cards:
   - Real-time users
   - Sessions by traffic source
   - Page views
   - Bounce rate
   - Conversion rate (set up goals first)
   - Geographic distribution
   - Device breakdown
   - Browser usage
```

### Plausible Dashboard

```bash
# Automatic dashboard includes:
- Real-time visitors
- Top pages
- Traffic sources
- Geographic distribution
- Device breakdown
- No custom configuration needed
```

---

## 📈 Key Metrics to Track

| Metric | Target | Tools |
|--------|--------|-------|
| **Conversion Rate** | > 2% | GA, Plausible |
| **Bounce Rate** | < 50% | GA, Plausible |
| **Avg Session Duration** | > 2 min | GA, Plausible |
| **Pages per Session** | > 2 | GA, Plausible |
| **Error Rate** | < 1% | Sentry |
| **Page Load Time** | < 2s | GA, Lighthouse |
| **Core Web Vitals** | LCP<2.5s | GA, Lighthouse |
| **Uptime** | > 99.9% | UptimeRobot |

---

## 🎯 Implementation Checklist

- [ ] Create Google Analytics account
- [ ] Install tracking code
- [ ] Set up conversion goals
- [ ] Create custom dashboards
- [ ] Configure data retention
- [ ] Set up alerts for anomalies
- [ ] Add Sentry error tracking
- [ ] Configure Sentry alerts
- [ ] (Optional) Add Plausible
- [ ] (Optional) Set up Sendgrid
- [ ] (Optional) Configure Slack notifications
- [ ] Set up weekly reporting
- [ ] Review metrics monthly

---

## 📝 Email Reports

**Google Analytics:**

1. Go to Admin → Account Settings
2. Automated reports → Create automated report
3. Frequency: Weekly
4. Recipients: miless8787@gmail.com
5. Metrics: Conversion rate, bounce rate, sessions

---

## 🔗 Important Links

**Google Analytics:**
```
https://analytics.google.com
Help: https://support.google.com/analytics
```

**Plausible Analytics:**
```
https://plausible.io/register
Docs: https://plausible.io/docs
```

**Sentry:**
```
https://sentry.io
Docs: https://docs.sentry.io
```

**SendGrid:**
```
https://sendgrid.com
Docs: https://docs.sendgrid.com
```

---

## ✅ Verification Checklist

After setup:

```
Google Analytics:
  [ ] Account created
  [ ] Tracking code installed
  [ ] Data appearing in real-time
  [ ] Goals configured
  [ ] Dashboards created

Sentry:
  [ ] Project created
  [ ] SDK initialized
  [ ] Test error sent
  [ ] Alerts configured
  [ ] Email notifications working

Privacy:
  [ ] Privacy policy updated
  [ ] Cookie consent configured
  [ ] GDPR compliant
  [ ] Data retention set
```

---

## 📞 Support

**Google Analytics Help:**
```
https://support.google.com/analytics
```

**Sentry Documentation:**
```
https://docs.sentry.io
```

**Privacy & Compliance:**
```
GDPR Guide: https://gdpr-info.eu
Privacy: https://policies.google.com/privacy
```

---

**Status**: Ready to Implement  
**Time**: ~30 minutes for all platforms  
**Priority**: Medium - Implement within 1 week

