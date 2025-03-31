
export interface SampleText {
  id: number;
  type: 'phishing' | 'legitimate';
  content: string;
  source: string;
  features: {
    urgency: boolean;
    badGrammar: boolean;
    sensitiveInfo: boolean;
    suspiciousLinks: boolean;
    impersonation: boolean;
  };
}

export const sampleTexts: SampleText[] = [
  {
    id: 1,
    type: 'phishing',
    content: "URGENT: Your account has been compromised. Click here immediately to verify your identity: http://amaz0n-security-verify.com. Failure to verify within 24 hours will result in permanent account closure.",
    source: "Email",
    features: {
      urgency: true,
      badGrammar: false,
      sensitiveInfo: true,
      suspiciousLinks: true,
      impersonation: true
    }
  },
  {
    id: 2,
    type: 'phishing',
    content: "Dear Valued Customer, We've detected unusual sing in attempt to your BankOfAmerica account. If this wasn't you, confirm your identity by entering your details here: https://b4nkofamerica-secure.net/verify",
    source: "SMS",
    features: {
      urgency: true,
      badGrammar: true,
      sensitiveInfo: true,
      suspiciousLinks: true,
      impersonation: true
    }
  },
  {
    id: 3,
    type: 'legitimate',
    content: "Amazon: Your package with order #A28C567 has been shipped and is expected to arrive on June 15. Track your delivery at amazon.com/orders.",
    source: "SMS",
    features: {
      urgency: false,
      badGrammar: false,
      sensitiveInfo: false,
      suspiciousLinks: false,
      impersonation: false
    }
  },
  {
    id: 4,
    type: 'phishing',
    content: "NETFLIX: Your subscription payment failed. To avoid service interruption, update your billing information at: netfl1x-accounts.com/billing-update",
    source: "Email",
    features: {
      urgency: true,
      badGrammar: false,
      sensitiveInfo: true,
      suspiciousLinks: true,
      impersonation: true
    }
  },
  {
    id: 5,
    type: 'legitimate',
    content: "Your Google security code is: 347890. Don't share this code with anyone. Google will never ask you for this code by phone or email.",
    source: "SMS",
    features: {
      urgency: false,
      badGrammar: false,
      sensitiveInfo: false,
      suspiciousLinks: false,
      impersonation: false
    }
  }
];

export const phishingKeywords = [
  'urgent', 'account suspended', 'verify immediately', 'unusual activity',
  'login attempt', 'click here', 'confirm identity', 'security alert',
  'update your information', 'password expired', 'limited offer', 'act now',
  'payment failed', 'unauthorized', 'suspicious', 'immediately', 'verify'
];

export const suspiciousDomains = [
  'amaz0n', 'g00gle', 'paypa1', 'b4nk', 'netfl1x', 'apple-id', 
  'microsoft-verify', 'secure-login', 'account-verify'
];

export const commonTlds = ['.com', '.org', '.net', '.edu', '.gov'];
export const suspiciousTlds = ['.xyz', '.info', '.tk', '.ml', '.cf', '.gq', '.top', '.online'];
