# ⚠️ Disclaimer & Liability Limitation

Use at your own risk. The code, workflows, and scripts in this repository (n8n-smtp-relay-bounce-complaint-feedback-loop) are provided for educational and architectural demonstration purposes.

* **No Liability:** The author and dhRobin Systems accept no responsibility or liability for any direct, indirect, incidental, or consequential damages that result from using, misusing, or deploying these scripts.
* **No Warranty:** All software, n8n JSON blueprints, JavaScript modules and prompts are provided "AS IS", without warranty of any kind, express or implied. This includes, but is not limited to, warranties of merchantability, fitness for a particular purpose, and non-infringement.
* **Production Testing Required:** Always test thoroughly in an isolated staging environment, such as a staging HubSpot portal or test CRM tenant and test webhook endpoints, with `SANDBOX_MODE=true` and `DRY_RUN=true` enabled, before you connect live email provider webhooks or production CRMs. Treat every automatic unsubscribe or contact suppression action as a draft that a person must verify before permanently altering production marketing consents.
* **Third-Party APIs & Compliance:** You alone are responsible for complying with the terms of service, rate limits, data privacy regulations (GDPR/CCPA/CAN-SPAM), and security policies of AWS SES, SendGrid, HubSpot, PostgreSQL and any connected services. That includes confirming a lawful basis for handling bounce/complaint feedback loops, securing webhook endpoints, and reviewing every automatically updated contact record.

The full disclaimer is also available in DISCLAIMER.md.

## License

Released under the MIT License. Copyright (c) 2026 DH Robin (dhRobin Systems). See LICENSE.

---

Full text: DISCLAIMER.md · Licensed under the MIT License. License: MIT © 2026 DH Robin (dhRobin Systems) · Provided as-is, see the disclaimer.
