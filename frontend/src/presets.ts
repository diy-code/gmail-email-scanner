import type { AnalyzeRequest } from '../types'

export interface Preset {
  id: string
  label: string
  icon: string
  variant: 'safe' | 'danger'
  data: AnalyzeRequest
}

export const PRESETS: Preset[] = [
  {
    id: 'clean',
    label: 'Clean Email',
    icon: '✅',
    variant: 'safe',
    data: {
      subject: 'Team standup notes — Monday',
      sender: 'Alice Johnson <alice@legitimate-corp.com>',
      reply_to: 'alice@legitimate-corp.com',
      authentication_results: 'spf=pass (sender SPF authorized) smtp.mailfrom=legitimate-corp.com; dkim=pass header.d=legitimate-corp.com; dmarc=pass',
      received_headers: [
        'Received: from mail.legitimate-corp.com (mail.legitimate-corp.com [74.125.0.1]) by mx.google.com with ESMTPS id abc123 for <user@gmail.com>; Mon, 22 Feb 2026 09:00:00 +0000',
      ],
      body_plain: 'Hi everyone,\n\nFind this week\'s standup notes below. Next session is Wednesday at 9am.\n\nAgenda items:\n- Sprint review\n- Backlog grooming\n- Demo prep\n\nBest,\nAlice',
      body_html: '',
      urls: ['https://docs.legitimate-corp.com/standup-notes/2026-02-22'],
      message_date: 'Mon, 22 Feb 2026 09:00:00 +0000',
    },
  },
  {
    id: 'phishing',
    label: 'Phishing Email',
    icon: '🎣',
    variant: 'danger',
    data: {
      subject: '⚠️ URGENT: Your PayPal account has been limited — Act Now!',
      sender: 'PayPal Security <security@paypa1-secure.net>',
      reply_to: 'attacker@catch-all.ru',
      authentication_results: 'spf=fail smtp.mailfrom=paypa1-secure.net; dkim=fail; dmarc=fail',
      received_headers: [
        'Received: from mail.paypa1-secure.net (mail.paypa1-secure.net [5.6.7.8]) by mx.google.com with ESMTP id xyz for <victim@gmail.com>; Mon, 22 Feb 2026 03:00:00 +0000',
      ],
      body_plain: 'Dear Valued Customer,\n\nYour account will be SUSPENDED within 24 hours due to suspicious activity.\n\nImmediate action required to restore access and verify your banking details.\n\nClick the link below immediately:\nhttp://bit.ly/paypal-verify123\n\nProvide your login credentials, SSN, and bank account number to confirm your identity.\n\nFailure to act will result in permanent account closure.',
      body_html: '<html><body><p>Dear Valued Customer,</p><p style="color:red"><b>URGENT: Your account will be SUSPENDED within 24 hours!</b></p><p>Click here to verify: <a href="http://bit.ly/paypal-verify123">Restore Account Now</a></p><p>Provide your <b>banking details</b> and credentials immediately.</p></body></html>',
      urls: ['http://bit.ly/paypal-verify123'],
      message_date: 'Mon, 22 Feb 2026 03:00:00 +0000',
    },
  },
]
