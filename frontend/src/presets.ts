import type { AnalyzeRequest } from './types'

export interface Preset {
  id: string
  label: string
  icon: string
  expectedScore: number   // approximate score for UI hint
  data: AnalyzeRequest
}

/*
 * Scoring formula: score = min(100, round(capped_total / 150 * 100))
 * Category caps: header=45, url=55, ip=20, domain=20, behavior=10 → max=150
 *
 * Deterministic signals used (no API dependency):
 *   header:   SPF Fail(15), DKIM Fail(15), DMARC Fail(15),
 *             Reply-To Mismatch(8), Display Name Spoofing(10)
 *   url:      URL Shortener(5), Typosquat(10 each)
 *   domain:   Complete Auth Failure(20) — fires when SPF+DKIM+DMARC all fail
 *   behavior: Urgency/Threat Language(10)
 *
 * API-dependent signal (presets 9–10 only):
 *   ip:       AbuseIPDB confidence>25%(12) + >75%(+8) = 20
 *             Uses 194.165.16.11 (confirmed 100% abuse confidence)
 *
 * Presets 0–8 use private IPs (10.0.0.1) in Received headers to avoid
 * AbuseIPDB calls and keep scores fully deterministic.
 */

export const PRESETS: Preset[] = [
  // ─── Score 0 — Clean corporate email (capped=0) ───────────────────────────
  // All auth pass, no bad URLs, clean body, private IP → zero signals
  {
    id: 'score_0_clean',
    label: 'Clean (0)',
    icon: '✅',
    expectedScore: 0,
    data: {
      subject: 'Q1 Engineering All-Hands — Agenda & Calendar Invite',
      sender: 'Alice Johnson <alice.johnson@google.com>',
      reply_to: 'alice.johnson@google.com',
      authentication_results:
        'spf=pass (google.com: domain of alice.johnson@google.com designates 209.85.208.182 as permitted sender) smtp.mailfrom=google.com; dkim=pass header.d=google.com; dmarc=pass (p=REJECT) header.from=google.com',
      received_headers: [
        'Received: from mail-lj1-f182.google.com (mail-lj1-f182.google.com [10.0.0.1]) by mx.google.com with ESMTPS id abc123; Mon, 22 Feb 2026 09:00:00 +0000',
      ],
      body_plain:
        'Hi everyone,\n\nJust a reminder that our Q1 All-Hands is this Thursday at 2 pm PST in the Maple conference room.\n\nAgenda:\n1. Q4 2025 recap\n2. 2026 roadmap preview\n3. Open Q&A\n\nCalendar invite already sent. No action needed.\n\nSee you there,\nAlice',
      body_html: '',
      urls: ['https://calendar.google.com/event?eid=abc123'],
      message_date: 'Mon, 22 Feb 2026 09:00:00 +0000',
    },
  },

  // ─── Score 10 — SPF fail only (capped=15) ─────────────────────────────────
  // header: SPF Fail(15) = 15.  round(15/150*100) = 10
  {
    id: 'score_10_spf',
    label: 'SPF Fail (10)',
    icon: '📋',
    expectedScore: 10,
    data: {
      subject: 'Team standup notes — Feb 22',
      sender: 'bob.wilson@startup-corp.io',
      reply_to: 'bob.wilson@startup-corp.io',
      authentication_results:
        'spf=fail (startup-corp.io does not designate 198.51.100.5 as permitted sender) smtp.mailfrom=startup-corp.io; dkim=pass header.d=startup-corp.io; dmarc=pass',
      received_headers: [
        'Received: from mail.startup-corp.io (mail.startup-corp.io [10.0.0.1]) by mx.google.com with ESMTP id def456; Mon, 22 Feb 2026 10:00:00 +0000',
      ],
      body_plain:
        'Hi team,\n\nHere are the standup notes from today:\n\n- Backend: API refactor on track for Friday\n- Frontend: New dashboard deployed to staging\n- DevOps: CI pipeline green after config update\n\nNext standup: Wednesday 9 am.\n\nBob',
      body_html: '',
      urls: ['https://startup-corp.io/wiki/standup-notes'],
      message_date: 'Mon, 22 Feb 2026 10:00:00 +0000',
    },
  },

  // ─── Score 20 — SPF + DKIM fail (capped=30) ───────────────────────────────
  // header: SPF(15) + DKIM(15) = 30.  DMARC=pass → no domain signal.
  // round(30/150*100) = 20
  {
    id: 'score_20_auth',
    label: 'Auth Weak (20)',
    icon: '📧',
    expectedScore: 20,
    data: {
      subject: 'Invoice #INV-2026-0042 from Acme Consulting',
      sender: 'billing@acme-consulting.biz',
      reply_to: 'billing@acme-consulting.biz',
      authentication_results:
        'spf=fail smtp.mailfrom=acme-consulting.biz; dkim=none; dmarc=pass',
      received_headers: [
        'Received: from mail.acme-consulting.biz (mail.acme-consulting.biz [10.0.0.1]) by mx.google.com with ESMTP id ghi789; Mon, 22 Feb 2026 11:00:00 +0000',
      ],
      body_plain:
        'Dear Finance Team,\n\nPlease find attached invoice INV-2026-0042 for consulting services rendered in January 2026.\n\nAmount Due: $4,250.00\nDue Date: March 15, 2026\nPayment Method: Bank transfer or check\n\nDownload invoice: https://acme-consulting.biz/invoices/INV-2026-0042.pdf\n\nThank you for your business.\n\nBilling Department\nAcme Consulting',
      body_html: '',
      urls: ['https://acme-consulting.biz/invoices/INV-2026-0042.pdf'],
      message_date: 'Mon, 22 Feb 2026 11:00:00 +0000',
    },
  },

  // ─── Score 30 — Auth fail + shortener + typosquat (capped=45) ──────────────
  // header: SPF(15) + DKIM(15) = 30.  url: shortener(5) + typosquat(10) = 15.
  // round(45/150*100) = 30
  {
    id: 'score_30_urls',
    label: 'Bad URLs (30)',
    icon: '🔗',
    expectedScore: 30,
    data: {
      subject: 'Your recent order has shipped',
      sender: 'shipping@parcel-notifications.com',
      reply_to: 'shipping@parcel-notifications.com',
      authentication_results:
        'spf=fail smtp.mailfrom=parcel-notifications.com; dkim=fail; dmarc=pass',
      received_headers: [
        'Received: from mail.parcel-notifications.com (mail.parcel-notifications.com [10.0.0.1]) by mx.google.com with ESMTP id jkl012; Mon, 22 Feb 2026 12:00:00 +0000',
      ],
      body_plain:
        'Your package has shipped!\n\nTracking number: 7739-0124-0140\n\nTrack your shipment here:\nhttps://bit.ly/track-pkg-7739\n\nOr check delivery status at:\nhttps://amaz0n.com/track?id=7739\n\nExpected delivery: Feb 25, 2026.\n\nShipping Department',
      body_html: '',
      urls: [
        'https://bit.ly/track-pkg-7739',
        'https://amaz0n.com/track?id=7739',
      ],
      message_date: 'Mon, 22 Feb 2026 12:00:00 +0000',
    },
  },

  // ─── Score 40 — Header capped + URL signals (capped=60) ───────────────────
  // header: SPF(15)+DKIM(15)+Reply-To(8)+DisplayName(10) = 48 → cap 45.
  // DMARC=pass → no domain signal.
  // url: shortener(5) + typosquat(10) = 15.
  // round(60/150*100) = 40
  {
    id: 'score_40_spoof',
    label: 'Spoofed (40)',
    icon: '🎭',
    expectedScore: 40,
    data: {
      subject: 'Update your billing information',
      sender: 'PayPal <billing@paypal-billing-update.com>',
      reply_to: 'support@paypal-help-center.net',
      authentication_results:
        'spf=fail smtp.mailfrom=paypal-billing-update.com; dkim=fail; dmarc=pass',
      received_headers: [
        'Received: from mail.paypal-billing-update.com (mail.paypal-billing-update.com [10.0.0.1]) by mx.google.com with ESMTP id mno345; Mon, 22 Feb 2026 13:00:00 +0000',
      ],
      body_plain:
        'Hello,\n\nWe noticed your billing information may be out of date. Please review and update your payment method at your convenience.\n\nUpdate here:\nhttps://bit.ly/pp-billing-update\n\nOr visit:\nhttps://paypa1.com/billing\n\nThank you,\nPayPal Support',
      body_html: '',
      urls: [
        'https://bit.ly/pp-billing-update',
        'https://paypa1.com/billing',
      ],
      message_date: 'Mon, 22 Feb 2026 13:00:00 +0000',
    },
  },

  // ─── Score 50 — Header capped + 2 typosquats + behavior (capped=75) ───────
  // header: SPF(15)+DKIM(15)+Reply-To(8)+DisplayName(10) = 48 → cap 45.
  // DMARC=pass → no domain signal.
  // url: 2 typosquats(10+10) = 20.
  // behavior: urgency(10).
  // round(75/150*100) = 50
  {
    id: 'score_50_phish',
    label: 'Phishing (50)',
    icon: '⚠️',
    expectedScore: 50,
    data: {
      subject: 'Action required: Verify your Netflix account',
      sender: 'Netflix <account@netflix-verify-center.com>',
      reply_to: 'help@netflix-billing-alert.net',
      authentication_results:
        'spf=fail smtp.mailfrom=netflix-verify-center.com; dkim=none; dmarc=pass',
      received_headers: [
        'Received: from mail.netflix-verify-center.com (mail.netflix-verify-center.com [10.0.0.1]) by mx.google.com with ESMTP id pqr678; Mon, 22 Feb 2026 14:00:00 +0000',
      ],
      body_plain:
        'Dear Netflix Member,\n\nYour account will be suspended due to a billing issue. Please verify your identity within 24 hours to avoid service interruption.\n\nVerify now:\nhttps://netf1ix.com/verify-account\n\nAlternate verification link:\nhttps://paypa1.com/netflix-billing\n\nNetflix Support',
      body_html: '',
      urls: [
        'https://netf1ix.com/verify-account',
        'https://paypa1.com/netflix-billing',
      ],
      message_date: 'Mon, 22 Feb 2026 14:00:00 +0000',
    },
  },

  // ─── Score 60 — All auth fail → domain signal + URL + behavior (capped=90) ─
  // header: SPF(15)+DKIM(15)+DMARC(15) = 45.
  // domain: Complete Auth Failure(20).
  // url: shortener(5) + typosquat(10) = 15.
  // behavior: urgency(10).
  // round(90/150*100) = 60
  {
    id: 'score_60_domain',
    label: 'Domain Fail (60)',
    icon: '🔓',
    expectedScore: 60,
    data: {
      subject: 'Apple ID: Unusual sign-in from new device',
      sender: 'Apple Support <support@apple-id-verify.net>',
      reply_to: 'support@apple-id-verify.net',
      authentication_results:
        'spf=fail smtp.mailfrom=apple-id-verify.net; dkim=none; dmarc=fail',
      received_headers: [
        'Received: from mail.apple-id-verify.net (mail.apple-id-verify.net [10.0.0.1]) by mx.google.com with ESMTP id stu901; Mon, 22 Feb 2026 15:00:00 +0000',
      ],
      body_plain:
        'Your Apple ID was used to sign in on a new device. If this was not you, your account will be locked.\n\nVerify your identity within 24 hours:\nhttps://bit.ly/apple-id-verify\n\nOr visit:\nhttps://app1e.com/id-verify\n\nApple Support',
      body_html: '',
      urls: [
        'https://bit.ly/apple-id-verify',
        'https://app1e.com/id-verify',
      ],
      message_date: 'Mon, 22 Feb 2026 15:00:00 +0000',
    },
  },

  // ─── Score 70 — Auth fail + domain + 3 typosquats + behavior (capped=105) ──
  // header: SPF(15)+DKIM(15)+DMARC(15) = 45.
  // domain: Complete Auth Failure(20).
  // url: 3 typosquats(10×3) = 30.
  // behavior: urgency(10).
  // round(105/150*100) = 70
  {
    id: 'score_70_multi',
    label: 'Multi-Threat (70)',
    icon: '🔶',
    expectedScore: 70,
    data: {
      subject: 'URGENT: Multiple accounts compromised — Verify now',
      sender: 'Security Alert <alerts@account-security-center.com>',
      reply_to: 'alerts@account-security-center.com',
      authentication_results:
        'spf=fail smtp.mailfrom=account-security-center.com; dkim=none; dmarc=fail',
      received_headers: [
        'Received: from mail.account-security-center.com (mail.account-security-center.com [10.0.0.1]) by mx.google.com with ESMTP id vwx234; Mon, 22 Feb 2026 16:00:00 +0000',
      ],
      body_plain:
        'SECURITY NOTICE\n\nWe detected suspicious activity across your linked accounts. Your account will be suspended unless you re-verify each service.\n\nVerify PayPal: https://paypa1.com/verify\nVerify Amazon: https://amaz0n.com/verify\nVerify Apple: https://app1e.com/verify\n\nAction required within 24 hours.\n\nSecurity Operations Center',
      body_html: '',
      urls: [
        'https://paypa1.com/verify',
        'https://amaz0n.com/verify',
        'https://app1e.com/verify',
      ],
      message_date: 'Mon, 22 Feb 2026 16:00:00 +0000',
    },
  },

  // ─── Score 80 — Auth fail + domain + shortener + 4 typosquats + behavior (capped=120)
  // header: SPF(15)+DKIM(15)+DMARC(15) = 45.
  // domain: Complete Auth Failure(20).
  // url: shortener(5) + 4 typosquats(10×4) = 45.
  // behavior: urgency(10).
  // round(120/150*100) = 80
  {
    id: 'score_80_heavy',
    label: 'Heavy Phish (80)',
    icon: '🔴',
    expectedScore: 80,
    data: {
      subject: 'Final warning: Account termination in 24 hours',
      sender: 'Account Security <alerts@secure-account-alerts.com>',
      reply_to: 'alerts@secure-account-alerts.com',
      authentication_results:
        'spf=fail smtp.mailfrom=secure-account-alerts.com; dkim=none; dmarc=fail',
      received_headers: [
        'Received: from smtp.secure-account-alerts.com (smtp.secure-account-alerts.com [10.0.0.1]) by mx.google.com with ESMTP id yza567; Mon, 22 Feb 2026 17:00:00 +0000',
      ],
      body_plain:
        'FINAL WARNING\n\nYour linked accounts have been flagged for termination. Your account will be closed permanently unless you verify within 24 hours.\n\nVerify each account:\nhttps://bit.ly/secure-reauth-now\nhttps://paypa1.com/verify-account\nhttps://amaz0n.com/secure-login\nhttps://app1e.com/id-restore\nhttps://netf1ix.com/reactivate\n\nFailure to act will result in permanent data loss.\n\nSecurity Operations Center',
      body_html: '',
      urls: [
        'https://bit.ly/secure-reauth-now',
        'https://paypa1.com/verify-account',
        'https://amaz0n.com/secure-login',
        'https://app1e.com/id-restore',
        'https://netf1ix.com/reactivate',
      ],
      message_date: 'Mon, 22 Feb 2026 17:00:00 +0000',
    },
  },

  // ─── Score 90 — All categories + IP reputation (capped=135) ────────────────
  // header: SPF(15)+DKIM(15)+DMARC(15) = 45.
  // domain: Complete Auth Failure(20).
  // url: 4 typosquats(10×4) = 40.
  // behavior: urgency(10).
  // ip: AbuseIPDB 194.165.16.11 confidence=100% → 12+8 = 20.
  // round(135/150*100) = 90
  {
    id: 'score_90_ip',
    label: 'IP + Phish (90)',
    icon: '🚨',
    expectedScore: 90,
    data: {
      subject: 'CRITICAL: Immediate action required — Account breach detected',
      sender: 'Incident Response <security@breach-alert-center.com>',
      reply_to: 'security@breach-alert-center.com',
      authentication_results:
        'spf=fail smtp.mailfrom=breach-alert-center.com; dkim=none; dmarc=fail',
      received_headers: [
        'Received: from smtp.breach-alert-center.com (smtp.breach-alert-center.com [194.165.16.11]) by mx.google.com with ESMTP id bcd890; Mon, 22 Feb 2026 18:00:00 +0000',
      ],
      body_plain:
        'CRITICAL SECURITY ALERT\n\nA data breach has been detected on your linked accounts. Your account will be terminated unless you re-verify immediately.\n\nSecure your accounts now:\nhttps://paypa1.com/breach-verify\nhttps://amaz0n.com/incident-response\nhttps://app1e.com/security-check\nhttps://netf1ix.com/breach-alert\n\nYou have 24 hours to respond.\n\nIncident Response Team',
      body_html: '',
      urls: [
        'https://paypa1.com/breach-verify',
        'https://amaz0n.com/incident-response',
        'https://app1e.com/security-check',
        'https://netf1ix.com/breach-alert',
      ],
      message_date: 'Mon, 22 Feb 2026 18:00:00 +0000',
    },
  },

  // ─── Score 100 — All categories maxed (capped=150) ─────────────────────────
  // header: SPF(15)+DKIM(15)+DMARC(15)+Reply-To(8)+DisplayName(10) = 63 → cap 45.
  // domain: Complete Auth Failure(20).
  // url: shortener(5) + 5 typosquats(10×5) = 55.
  // behavior: urgency(10).
  // ip: AbuseIPDB 194.165.16.11 → 12+8 = 20.
  // round(150/150*100) = 100
  {
    id: 'score_100_max',
    label: 'Maximum (100)',
    icon: '💀',
    expectedScore: 100,
    data: {
      subject: '⚠️ URGENT: Verify Your PayPal Account NOW or Lose Access',
      sender: 'PayPal Security Team <service@malware.wicar.org>',
      reply_to: 'noreply@phishing-redirects.ru',
      authentication_results:
        'spf=fail (domain of malware.wicar.org does not designate 194.165.16.11 as permitted sender) smtp.mailfrom=service@malware.wicar.org; dkim=none; dmarc=fail action=none header.from=malware.wicar.org',
      received_headers: [
        'Received: from mail.malware.wicar.org (mail.malware.wicar.org [194.165.16.11]) by mx.google.com with ESMTP id x7si2034820qkj; Mon, 22 Feb 2026 19:00:00 +0000',
      ],
      body_plain:
        'URGENT: Your account will be suspended immediately.\n\nYou must verify your identity NOW or your account will be permanently deleted and funds frozen for 180 days.\n\nClick here:\nhttps://bit.ly/secure-pp-verify\nhttps://paypa1.com/verify\nhttps://amaz0n.com/secure\nhttps://app1e.com/verify\nhttps://netf1ix.com/account\nhttps://g00gle.com/verify\n\nAct within 24 hours or face permanent closure.',
      body_html: '',
      urls: [
        'https://bit.ly/secure-pp-verify',
        'https://paypa1.com/verify',
        'https://amaz0n.com/secure',
        'https://app1e.com/verify',
        'https://netf1ix.com/account',
        'https://g00gle.com/verify',
      ],
      message_date: 'Mon, 22 Feb 2026 19:00:00 +0000',
    },
  },
]
