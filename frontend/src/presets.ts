import type { AnalyzeRequest } from './types'

export interface Preset {
  id: string
  label: string
  icon: string
  expectedScore: number   // approximate score for UI hint
  data: AnalyzeRequest
}

export const PRESETS: Preset[] = [
  // ─── 0/10 — Fully clean internal corporate email ──────────────────────────
  {
    id: 'clean_internal',
    label: 'Clean Internal',
    icon: '✅',
    expectedScore: 0,
    data: {
      subject: 'Q1 Engineering All-Hands — Agenda',
      sender: 'Alice Johnson <alice.johnson@google.com>',
      reply_to: 'alice.johnson@google.com',
      authentication_results:
        'spf=pass (google.com: domain of alice.johnson@google.com designates 74.125.0.1 as permitted sender) smtp.mailfrom=google.com; dkim=pass header.i=@google.com header.s=20230601; dmarc=pass (p=REJECT) header.from=google.com',
      received_headers: [
        'Received: from mail-lj1-f182.google.com (mail-lj1-f182.google.com [209.85.208.182]) by mx.google.com with ESMTPS id abc123 for <user@gmail.com>; Mon, 22 Feb 2026 09:00:00 +0000',
      ],
      body_plain:
        'Hi everyone,\n\nJust a reminder that our Q1 All-Hands is this Thursday at 2pm PST in Maple conference room.\n\nAgenda:\n1. Q4 2025 recap\n2. 2026 roadmap preview\n3. Open Q&A\n\nCalendar invite already sent. No action needed.\n\nSee you there,\nAlice',
      body_html: '',
      urls: ['https://calendar.google.com/event?eid=abc123'],
      message_date: 'Mon, 22 Feb 2026 09:00:00 +0000',
    },
  },

  // ─── 1/10 — Legit marketing newsletter ────────────────────────────────────
  {
    id: 'newsletter',
    label: 'Newsletter',
    icon: '📧',
    expectedScore: 8,
    data: {
      subject: 'Your GitHub Digest — Feb 2026',
      sender: 'GitHub <noreply@github.com>',
      reply_to: null,
      authentication_results:
        'spf=pass smtp.mailfrom=github.com; dkim=pass header.d=github.com; dmarc=pass',
      received_headers: [
        'Received: from smtp.github.com (smtp.github.com [192.30.252.1]) by mx.google.com with ESMTPS for <user@gmail.com>; Mon, 22 Feb 2026 08:00:00 +0000',
      ],
      body_plain:
        'Hi there,\n\nHere is your weekly GitHub digest.\n\nTrending repositories this week:\n- microsoft/vscode — 142k stars\n- openai/openai-python — 98k stars\n\nView full digest: https://github.com/explore\n\nYou are receiving this because you signed up for GitHub Explore.\nUnsubscribe: https://github.com/settings/notifications',
      body_html: '',
      urls: [
        'https://github.com/explore',
        'https://github.com/settings/notifications',
      ],
      message_date: 'Mon, 22 Feb 2026 08:00:00 +0000',
    },
  },

  // ─── 2/10 — Legit but new sender domain (SPF softfail) ────────────────────
  {
    id: 'new_vendor',
    label: 'New Vendor',
    icon: '🏢',
    expectedScore: 18,
    data: {
      subject: 'Invoice #INV-2026-0042 from Acme Consulting LLC',
      sender: 'billing@acme-consulting-llc.com',
      reply_to: 'billing@acme-consulting-llc.com',
      authentication_results:
        'spf=softfail (domain of billing@acme-consulting-llc.com does not designate 198.51.100.0 as permitted sender) smtp.mailfrom=acme-consulting-llc.com; dkim=pass header.d=acme-consulting-llc.com; dmarc=none',
      received_headers: [
        'Received: from mail.acme-consulting-llc.com (mail.acme-consulting-llc.com [198.51.100.0]) by mx.google.com with ESMTP for <user@company.com>; Mon, 22 Feb 2026 10:00:00 +0000',
      ],
      body_plain:
        'Dear Finance Team,\n\nPlease find attached invoice INV-2026-0042 for consulting services rendered in January 2026.\n\nAmount Due: $4,250.00\nDue Date: March 15, 2026\nPayment Method: Bank transfer or check\n\nDownload invoice: https://acme-consulting-llc.com/invoices/INV-2026-0042.pdf\n\nThank you for your business.\n\nBest regards,\nBilling Department\nAcme Consulting LLC',
      body_html: '',
      urls: ['https://acme-consulting-llc.com/invoices/INV-2026-0042.pdf'],
      message_date: 'Mon, 22 Feb 2026 10:00:00 +0000',
    },
  },

  // ─── 3/10 — Suspicious reply-to mismatch + shortened link ─────────────────
  {
    id: 'reply_mismatch',
    label: 'Reply Mismatch',
    icon: '🔀',
    expectedScore: 30,
    data: {
      subject: 'Your package is ready for pickup',
      sender: 'FedEx Notifications <notifications@fedex.com>',
      reply_to: 'support@fedex-tracking-info.net',
      authentication_results:
        'spf=pass smtp.mailfrom=fedex.com; dkim=fail (signature did not verify); dmarc=none',
      received_headers: [
        'Received: from outbound.fedex.com (outbound.fedex.com [158.48.0.1]) by mx.google.com with ESMTP for <user@gmail.com>; Mon, 22 Feb 2026 11:00:00 +0000',
      ],
      body_plain:
        'Your package #773901240140 is available for pickup at your local FedEx location.\n\nTrack your shipment: https://bit.ly/fedex-track-7739\n\nPickup by Feb 25 or the package will be returned.\n\nFedEx Customer Service',
      body_html: '',
      urls: ['https://bit.ly/fedex-track-7739'],
      message_date: 'Mon, 22 Feb 2026 11:00:00 +0000',
    },
  },

  // ─── 4/10 — SPF fail, new typosquatted-looking domain ─────────────────────
  {
    id: 'typosquat_mild',
    label: 'Typosquat Domain',
    icon: '🔤',
    expectedScore: 42,
    data: {
      subject: 'Action required: Verify your Microsoft account',
      sender: 'Microsoft Security <security@micros0ft-account.com>',
      reply_to: 'no-reply@micros0ft-account.com',
      authentication_results:
        'spf=fail smtp.mailfrom=micros0ft-account.com; dkim=fail; dmarc=fail',
      received_headers: [
        'Received: from mail.micros0ft-account.com (mail.micros0ft-account.com [91.108.4.1]) by mx.google.com with ESMTP for <user@gmail.com>; Mon, 22 Feb 2026 03:00:00 +0000',
      ],
      body_plain:
        'Dear Microsoft Account User,\n\nWe detected unusual sign-in activity on your account. Please verify your identity within 48 hours.\n\nVerify now: https://micros0ft-account.com/verify\n\nMicrosoft Support',
      body_html: '',
      urls: ['https://micros0ft-account.com/verify'],
      message_date: 'Mon, 22 Feb 2026 03:00:00 +0000',
    },
  },

  // ─── 5/10 — Mixed signals: credential language + URL shortener ────────────
  {
    id: 'mixed_signals',
    label: 'Mixed Signals',
    icon: '⚠️',
    expectedScore: 52,
    data: {
      subject: 'Your Apple ID has been locked — Verify immediately',
      sender: 'Apple Support <appleid@apple-id-support.org>',
      reply_to: 'noreply@apple-id-support.org',
      authentication_results:
        'spf=fail smtp.mailfrom=apple-id-support.org; dkim=fail; dmarc=fail',
      received_headers: [
        'Received: from smtp.apple-id-support.org (smtp.apple-id-support.org [45.142.212.100]) by mx.google.com with ESMTP for <user@gmail.com>; Mon, 22 Feb 2026 04:00:00 +0000',
      ],
      body_plain:
        'Your Apple ID has been locked due to too many failed sign-in attempts.\n\nTo unlock your account and prevent permanent suspension, click below:\nhttps://apple-id-support.org/unlock?token=a9f3c2\n\nIf you do not verify within 24 hours, your account will be permanently disabled.\n\nApple Support Team',
      body_html: '',
      urls: ['https://apple-id-support.org/unlock?token=a9f3c2'],
      message_date: 'Mon, 22 Feb 2026 04:00:00 +0000',
    },
  },

  // ─── 6/10 — Bank impersonation + credential harvesting ────────────────────
  {
    id: 'bank_impersonation',
    label: 'Bank Impersonation',
    icon: '🏦',
    expectedScore: 63,
    data: {
      subject: 'ALERT: Suspicious transaction detected on your account',
      sender: 'Bank of America <alert@bankofamerica-secure.net>',
      reply_to: 'support@securebank-verify.com',
      authentication_results:
        'spf=fail smtp.mailfrom=bankofamerica-secure.net; dkim=fail; dmarc=fail',
      received_headers: [
        'Received: from mail.bankofamerica-secure.net (mail.bankofamerica-secure.net [185.220.101.45]) by mx.google.com with ESMTP for <user@gmail.com>; Mon, 22 Feb 2026 02:00:00 +0000',
      ],
      body_plain:
        'IMPORTANT SECURITY ALERT\n\nWe have detected a suspicious transaction of $3,499.00 on your Bank of America checking account ending in 4821.\n\nIf you did not authorize this transaction, you must verify your account credentials IMMEDIATELY to freeze the transaction.\n\nVerify your account: https://bankofamerica-secure.net/verify-account\n\nYou must act within 2 hours or the transaction will be processed.\n\nBank of America Security Team',
      body_html: '',
      urls: ['https://bankofamerica-secure.net/verify-account'],
      message_date: 'Mon, 22 Feb 2026 02:00:00 +0000',
    },
  },

  // ─── 7/10 — IRS/Gov impersonation + urgency ───────────────────────────────
  {
    id: 'irs_scam',
    label: 'IRS Scam',
    icon: '🏛️',
    expectedScore: 74,
    data: {
      subject: 'Final Notice: Unpaid tax balance — Legal action pending',
      sender: 'IRS Tax Division <irs-taxnotice@irs-gov-refunds.com>',
      reply_to: 'collections@irs-gov-refunds.com',
      authentication_results:
        'spf=fail smtp.mailfrom=irs-gov-refunds.com; dkim=fail; dmarc=fail',
      received_headers: [
        'Received: from smtp.irs-gov-refunds.com (smtp.irs-gov-refunds.com [92.63.194.51]) by mx.google.com with ESMTP for <user@gmail.com>; Sun, 21 Feb 2026 23:00:00 +0000',
      ],
      body_plain:
        'FINAL NOTICE — IMMEDIATE ACTION REQUIRED\n\nThis is your final notice regarding an unpaid federal tax balance of $4,812.37.\n\nFailure to pay within 48 HOURS will result in:\n- Wage garnishment\n- Bank account seizure\n- Criminal prosecution\n\nTo avoid legal action, pay immediately: https://irs-gov-refunds.com/pay-now\n\nProvide your SSN and banking details to process payment.\n\nInternal Revenue Service\nCompliance Division',
      body_html: '',
      urls: ['https://irs-gov-refunds.com/pay-now'],
      message_date: 'Sun, 21 Feb 2026 23:00:00 +0000',
    },
  },

  // ─── 8/10 — PayPal phishing with real shortened URL pattern ───────────────
  {
    id: 'paypal_phish',
    label: 'PayPal Phishing',
    icon: '🎣',
    expectedScore: 85,
    data: {
      subject: '⚠️ URGENT: Your PayPal account has been permanently limited!',
      sender: 'PayPal Security <security@paypa1-secure.net>',
      reply_to: 'recovery@paypa1-updates.ru',
      authentication_results:
        'spf=fail smtp.mailfrom=paypa1-secure.net; dkim=fail; dmarc=fail',
      received_headers: [
        'Received: from mail.paypa1-secure.net (mail.paypa1-secure.net [5.188.206.14]) by mx.google.com with ESMTP for <user@gmail.com>; Mon, 22 Feb 2026 01:00:00 +0000',
      ],
      body_plain:
        'Dear PayPal Customer,\n\nYour account has been PERMANENTLY LIMITED due to suspicious activity.\n\nYou must verify your identity within 24 HOURS or your account will be closed and funds held for 180 days.\n\nRestore your account now: http://bit.ly/paypal-restore-account9\n\nYou will need to provide:\n- Full name\n- Date of birth\n- Social Security Number\n- Bank account and routing number\n- Credit card details\n\nPayPal Account Services',
      body_html:
        '<html><body style="font-family:Arial"><img src="https://paypa1-secure.net/logo.png" width="120"/><p><b style="color:red">URGENT: Your account is limited!</b></p><p>Click to restore: <a href="http://bit.ly/paypal-restore-account9">Restore Account</a></p><p>Provide your <b>banking details, SSN and credit card</b> to verify.</p></body></html>',
      urls: ['http://bit.ly/paypal-restore-account9'],
      message_date: 'Mon, 22 Feb 2026 01:00:00 +0000',
    },
  },

  // ─── 9/10 — Full malware dropper / CEO fraud ──────────────────────────────
  {
    id: 'ceo_fraud',
    label: 'CEO Fraud',
    icon: '🚨',
    expectedScore: 96,
    data: {
      subject: 'Confidential — Wire Transfer Required TODAY',
      sender: 'CEO John Smith <ceo@yourcompany-finance.com>',
      reply_to: 'j.smith.cfo@gmail.com',
      authentication_results:
        'spf=fail smtp.mailfrom=yourcompany-finance.com; dkim=fail; dmarc=fail',
      received_headers: [
        'Received: from vps.yourcompany-finance.com (vps.yourcompany-finance.com [194.165.16.142]) by mx.google.com with ESMTP for <finance@yourcompany.com>; Mon, 22 Feb 2026 00:30:00 +0000',
      ],
      body_plain:
        'This is strictly confidential. Do not discuss with anyone.\n\nI am in a board meeting and need you to process an urgent wire transfer of $87,500 to close a confidential acquisition deal TODAY before 5pm.\n\nDo NOT follow normal approval procedures — this is time-sensitive and legally sensitive.\n\nWire to:\nBank: HSBC Hong Kong\nAccount Name: Apex Holdings Ltd\nAccount #: 012-345678-001\nRouting: 021000089\n\nOnce complete, confirm by downloading and running the secure transfer receipt tool from: https://secure-wiretransfer-confirm.xyz/tool.exe\n\nDo not email me — I am unavailable. Reply only to this email.\n\nJohn Smith\nCEO',
      body_html: '',
      urls: ['https://secure-wiretransfer-confirm.xyz/tool.exe'],
      message_date: 'Mon, 22 Feb 2026 00:30:00 +0000',
    },
  },
]
