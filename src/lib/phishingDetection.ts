import { phishingKeywords, suspiciousDomains, suspiciousTlds } from './sampleTexts';

export interface AnalysisResult {
  score: number;
  threatLevel: 'low' | 'medium' | 'high';
  features: {
    urgency: number;
    badGrammar: number;
    sensitiveInfo: number;
    suspiciousLinks: number;
    impersonation: number;
  };
  identifiedPatterns: string[];
  urlAnalysis: UrlAnalysisResult[];
}

export interface UrlAnalysisResult {
  url: string;
  suspicious: boolean;
  reasons: string[];
  domain: string;
  protocol: string;
  tld: string;
  riskScore: number;
  brandImpersonation: string | null;
  redirectCount: number;
  securityFeatures: {
    https: boolean;
    validCertificate: boolean;
    domainAge: string;
  };
}

// Extract domain from URL
const extractDomain = (url: string): string => {
  try {
    const hostname = new URL(url).hostname;
    return hostname;
  } catch (e) {
    return url;
  }
};

// Extract TLD from domain
const extractTld = (domain: string): string => {
  const parts = domain.split('.');
  return parts.length > 1 ? `.${parts[parts.length - 1]}` : '';
};

// Check for typosquatting (similar domain names to popular brands)
const checkForTyposquatting = (domain: string): string | null => {
  const popularBrands = [
    { name: 'Google', domains: ['google'] },
    { name: 'Amazon', domains: ['amazon'] },
    { name: 'Microsoft', domains: ['microsoft', 'outlook', 'office365', 'azure'] },
    { name: 'Apple', domains: ['apple', 'icloud'] },
    { name: 'PayPal', domains: ['paypal'] },
    { name: 'Facebook', domains: ['facebook', 'fb'] },
    { name: 'Instagram', domains: ['instagram'] },
    { name: 'Netflix', domains: ['netflix'] },
    { name: 'LinkedIn', domains: ['linkedin'] },
    { name: 'Twitter', domains: ['twitter', 'x.com'] },
    { name: 'Bank', domains: ['bank', 'chase', 'wellsfargo', 'bankofamerica', 'citibank'] }
  ];

  const levenshteinDistance = (a: string, b: string): number => {
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;

    const matrix = [];
    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }
    for (let i = 0; i <= a.length; i++) {
      matrix[0][i] = i;
    }

    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        const cost = a.charAt(j - 1) === b.charAt(i - 1) ? 0 : 1;
        matrix[i][j] = Math.min(
          matrix[i - 1][j] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j - 1] + cost
        );
      }
    }

    return matrix[b.length][a.length];
  };

  for (const brand of popularBrands) {
    for (const brandDomain of brand.domains) {
      if (domain.includes(brandDomain) && domain !== brandDomain) {
        return brand.name;
      }

      const domainWithoutTld = domain.split('.')[0];
      const distance = levenshteinDistance(domainWithoutTld, brandDomain);
      
      if (distance > 0 && distance <= 2 && domainWithoutTld !== brandDomain) {
        return brand.name;
      }
    }
  }
  
  return null;
};

// Check for homograph attack (using similar-looking characters)
const checkForHomographAttack = (domain: string): boolean => {
  const suspiciousChars = [
    'а', 'е', 'о', 'р', 'с', 'ѕ', 'і', 'ј', 'ԁ', 'ɡ', 'ʏ', // Cyrillic/similar chars
    '0', '1', '2', '5', // Digits that look like letters
    'ᴀ', 'ʙ', 'ᴄ', 'ᴅ', 'ᴇ', 'ғ', // Small capital letters
    'ṇ', 'ṃ', 'ḍ', 'ḥ', // Characters with diacritics
  ];

  for (const char of suspiciousChars) {
    if (domain.includes(char)) {
      return true;
    }
  }
  
  return false;
};

// Check if domain uses excessive subdomains
const hasExcessiveSubdomains = (domain: string): boolean => {
  return domain.split('.').length > 3;
};

// Check for short suspicious URLs (common in phishing attacks)
const isShortSuspiciousUrl = (url: string, domain: string): boolean => {
  const isShortDomain = domain.split('.')[0].length < 5;
  const hasRandomPath = url.includes('/') && /\/[a-zA-Z0-9]{6,}$/.test(url);
  const hasNumericChars = /\d/.test(domain);
  
  return (isShortDomain && hasRandomPath) || (isShortDomain && hasNumericChars && hasRandomPath);
};

// Analyze a single URL
export const analyzeUrl = (url: string): UrlAnalysisResult => {
  const analysis: UrlAnalysisResult = {
    url,
    suspicious: false,
    reasons: [],
    domain: '',
    protocol: '',
    tld: '',
    riskScore: 0,
    brandImpersonation: null,
    redirectCount: 0,
    securityFeatures: {
      https: false,
      validCertificate: false,
      domainAge: 'unknown'
    }
  };
  
  try {
    const urlObj = new URL(url);
    analysis.domain = urlObj.hostname;
    analysis.protocol = urlObj.protocol;
    analysis.tld = extractTld(urlObj.hostname);
    
    // Check for HTTPS
    analysis.securityFeatures.https = urlObj.protocol === 'https:';
    if (!analysis.securityFeatures.https) {
      analysis.suspicious = true;
      analysis.reasons.push('Uses insecure HTTP protocol instead of HTTPS');
      analysis.riskScore += 25;
    }
    
    // Check for suspicious domains
    for (const domain of suspiciousDomains) {
      if (analysis.domain.includes(domain)) {
        analysis.suspicious = true;
        analysis.reasons.push(`Contains suspicious domain pattern: "${domain}"`);
        analysis.riskScore += 20;
      }
    }
    
    // Check for suspicious TLDs
    for (const tld of suspiciousTlds) {
      if (analysis.domain.endsWith(tld)) {
        analysis.suspicious = true;
        analysis.reasons.push(`Uses suspicious top-level domain: "${tld}"`);
        analysis.riskScore += 15;
      }
    }
    
    // Enhanced URL shortener detection
    const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'ow.ly', 'buff.ly', 'rebrand.ly', 'shorturl.at', 'tiny.cc'];
    if (analysis.domain.length < 6 && /\d/.test(analysis.domain)) {
      analysis.suspicious = true;
      analysis.reasons.push('Uses suspicious short URL domain with numbers (likely a shortener)');
      analysis.riskScore += 35;
      analysis.redirectCount = 1;
    } else {
      for (const shortener of shorteners) {
        if (analysis.domain.includes(shortener)) {
          analysis.suspicious = true;
          analysis.reasons.push(`Uses URL shortener: "${shortener}" which can hide the true destination`);
          analysis.riskScore += 15;
          analysis.redirectCount = 1; // Assuming at least one redirect for shorteners
        }
      }
    }
    
    // Check for short, suspicious URLs
    if (isShortSuspiciousUrl(url, analysis.domain)) {
      analysis.suspicious = true;
      analysis.reasons.push('Uses suspicious short domain with random alphanumeric path');
      analysis.riskScore += 30;
    }
    
    // Check for IP address instead of domain name
    const ipRegex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    if (ipRegex.test(analysis.domain)) {
      analysis.suspicious = true;
      analysis.reasons.push('Uses IP address instead of domain name');
      analysis.riskScore += 30;
    }
    
    // Check for excessive subdomains
    if (hasExcessiveSubdomains(analysis.domain)) {
      analysis.suspicious = true;
      analysis.reasons.push(`Contains excessive subdomains which is unusual`);
      analysis.riskScore += 10;
    }
    
    // Check for typosquatting
    const impersonated = checkForTyposquatting(analysis.domain);
    if (impersonated) {
      analysis.suspicious = true;
      analysis.brandImpersonation = impersonated;
      analysis.reasons.push(`Possible typosquatting attempt of "${impersonated}"`);
      analysis.riskScore += 25;
    }
    
    // Check for homograph attack
    if (checkForHomographAttack(analysis.domain)) {
      analysis.suspicious = true;
      analysis.reasons.push('Possible homograph attack using deceptive characters');
      analysis.riskScore += 35;
    }
    
    // Check for suspicious URL patterns
    const suspiciousUrlPatterns = [
      { pattern: /login|signin|account|password|verify|secure|auth/, message: 'Contains sensitive authentication terms in URL' },
      { pattern: /confirm|update|alert|warning/, message: 'Contains urgent action terms in URL' },
      { pattern: /\.php$|\.aspx$|\.jsp$/, message: 'Uses executable script in URL' },
      { pattern: /\.(exe|zip|rar|dll|dat)$/, message: 'Links to executable or data file' },
      { pattern: /[^\w\-\.\/\:]/, message: 'Contains unusual characters in URL' }
    ];
    
    for (const { pattern, message } of suspiciousUrlPatterns) {
      if (pattern.test(url)) {
        analysis.suspicious = true;
        analysis.reasons.push(message);
        analysis.riskScore += 10;
      }
    }
    
    // Normalize risk score
    analysis.riskScore = Math.min(100, analysis.riskScore);
    
    // If no suspicions were found but the URL has risky characteristics
    if (!analysis.suspicious && !analysis.securityFeatures.https) {
      analysis.suspicious = true; // Mark as suspicious anyway if not using HTTPS
    }
    
  } catch (e) {
    analysis.suspicious = true;
    analysis.reasons.push('Invalid URL format');
    analysis.riskScore = 50;
  }
  
  return analysis;
};

// Enhanced URL extraction with support for common obfuscation techniques
const extractAllUrls = (text: string): string[] => {
  const urls: string[] = [];
  
  // Standard URL regex
  const standardUrlRegex = /(https?:\/\/[^\s]+)/g;
  const standardUrls = text.match(standardUrlRegex) || [];
  urls.push(...standardUrls);
  
  // Find URLs without protocol (www.example.com)
  const noProtocolRegex = /(?<!\S)(www\.[^\s]+)/g;
  const noProtocolUrls = text.match(noProtocolRegex) || [];
  urls.push(...noProtocolUrls.map(url => `http://${url}`));
  
  // Enhanced extraction for short domains with paths (common in phishing)
  const shortUrlRegex = /\b([a-z0-9]{2,5}\.[a-z]{2,3}\/[a-zA-Z0-9]{4,})\b/g;
  const shortUrls = text.match(shortUrlRegex) || [];
  urls.push(...shortUrls.map(url => `http://${url}`));
  
  // Find potential obfuscated URLs with spaces or broken into parts
  const words = text.split(/\s+/);
  for (let i = 0; i < words.length; i++) {
    // Check for domain-like strings
    if (words[i].includes('.') && !words[i].startsWith('@') && !words[i].match(/^\d+\.\d+$/)) {
      // Check if it's not an email
      if (!words[i].includes('@')) {
        const potentialUrl = words[i].replace(/[^\w\.\-\/]/g, '');
        if (potentialUrl.match(/\w+\.\w{2,}/)) {
          urls.push(`http://${potentialUrl}`);
        }
      }
    }
  }
  
  // Remove duplicates
  return [...new Set(urls)];
};

// Simplified NLP-based phishing detection
export const analyzeText = (text: string): AnalysisResult => {
  const lowerText = text.toLowerCase();
  const identifiedPatterns: string[] = [];
  
  // Extract and analyze URLs with enhanced extraction
  const urls = extractAllUrls(text);
  const urlAnalysis: UrlAnalysisResult[] = urls.map(url => analyzeUrl(url));
  
  // Initialize feature scores
  const features = {
    urgency: 0,
    badGrammar: 0,
    sensitiveInfo: 0,
    suspiciousLinks: 0,
    impersonation: 0,
  };
  
  // Check for numeric character substitution (common in phishing)
  if (/\b[a-zA-Z]*[0-9]+[a-zA-Z]*\b/.test(text)) {
    features.impersonation += 0.2;
    identifiedPatterns.push('Uses numeric character substitution (e.g., "0" for "O")');
  }
  
  // Check for urgency indicators
  const urgencyWords = ['urgent', 'immediately', 'alert', 'warning', 'now', 'quick', 'fast', 'important', 'attention', 'critical', 'limited time'];
  for (const word of urgencyWords) {
    if (lowerText.includes(word)) {
      features.urgency += 0.2;
      identifiedPatterns.push(`Urgency indicator: "${word}"`);
    }
  }
  
  // Check for money-related terms (common in phishing)
  const moneyTerms = ['money', 'cash', 'credit', 'debit', 'bank', 'account', 'payment', 'transfer', 'withdraw', 'deposit', 'rs', 'rupees', 'usd', 'euro', 'dollar', 'amount'];
  for (const term of moneyTerms) {
    if (lowerText.includes(term)) {
      features.sensitiveInfo += 0.2;
      identifiedPatterns.push(`Money-related term: "${term}"`);
    }
  }
  
  // Check for common phishing keywords
  for (const keyword of phishingKeywords) {
    if (lowerText.includes(keyword.toLowerCase())) {
      features.sensitiveInfo += 0.15;
      identifiedPatterns.push(`Suspicious keyword: "${keyword}"`);
    }
  }
  
  // Grammar and spelling errors (simplified)
  const commonMisspellings = ['acct', 'verifcation', 'verificaton', 'securty', 'informaton', 'accesing', 'acount', 'confirmaton'];
  for (const misspelling of commonMisspellings) {
    if (lowerText.includes(misspelling)) {
      features.badGrammar += 0.1;
      identifiedPatterns.push(`Possible misspelling: "${misspelling}"`);
    }
  }
  
  // Check for URL-based threats with increased weight for short suspicious URLs
  if (urlAnalysis.length > 0) {
    for (const analysis of urlAnalysis) {
      if (analysis.suspicious) {
        features.suspiciousLinks += 0.35;
        for (const reason of analysis.reasons) {
          identifiedPatterns.push(`URL issue (${analysis.url}): ${reason}`);
        }
        
        // Add brand impersonation detection
        if (analysis.brandImpersonation) {
          features.impersonation += 0.2;
          identifiedPatterns.push(`URL impersonates ${analysis.brandImpersonation}`);
        }
        
        // Special handling for short suspicious domains
        if (analysis.domain.length < 6 && /\d/.test(analysis.domain)) {
          features.suspiciousLinks += 0.25;
          features.impersonation += 0.15;
        }
      }
    }
  }
  
  // Check for impersonation of known brands
  const brands = ['amazon', 'netflix', 'paypal', 'apple', 'microsoft', 'google', 'facebook', 'bank', 'instagram', 'twitter', 'rummy'];
  for (const brand of brands) {
    const brandRegex = new RegExp(`\\b${brand}\\b`, 'i');
    if (brandRegex.test(lowerText)) {
      features.impersonation += 0.15;
      identifiedPatterns.push(`Possible brand impersonation: "${brand}"`);
    }
  }
  
  // Check for sensitive information requests
  const sensitiveInfoPatterns = [
    { pattern: /social security|ssn|national id|passport/i, message: 'Requests for SSN/national ID' },
    { pattern: /credit card|card number|cvv|expiration date/i, message: 'Requests for credit card information' },
    { pattern: /username.*?password/i, message: 'Requests for login credentials' },
    { pattern: /bank.{1,20}(account|routing)/i, message: 'Requests for banking information' },
    { pattern: /click.{1,30}(link|here|confirm)/i, message: 'Encourages clicking on links' },
    { pattern: /withdraw|deposit|transfer|credited|debited/i, message: 'References to financial transactions' }
  ];
  
  for (const { pattern, message } of sensitiveInfoPatterns) {
    if (pattern.test(text)) {
      features.sensitiveInfo += 0.2;
      identifiedPatterns.push(`Sensitive information request: ${message}`);
    }
  }
  
  // Normalize feature scores to be between 0 and 1
  Object.keys(features).forEach(key => {
    features[key as keyof typeof features] = Math.min(features[key as keyof typeof features], 1);
  });
  
  // Calculate overall phishing score (weighted sum)
  const weights = {
    urgency: 0.2,
    badGrammar: 0.15,
    sensitiveInfo: 0.25,
    suspiciousLinks: 0.3,
    impersonation: 0.1
  };
  
  let score = 0;
  for (const [key, weight] of Object.entries(weights)) {
    score += features[key as keyof typeof features] * weight;
  }
  
  // Special case for short URL domains (common in phishing)
  if (urlAnalysis.some(url => url.domain.length < 6 && /\d/.test(url.domain))) {
    score = Math.max(score, 0.7); // Ensure at least high-medium threat level
  }
  
  // Determine threat level
  let threatLevel: 'low' | 'medium' | 'high';
  if (score < 0.3) {
    threatLevel = 'low';
  } else if (score < 0.6) {
    threatLevel = 'medium';
  } else {
    threatLevel = 'high';
  }
  
  return {
    score,
    threatLevel,
    features,
    identifiedPatterns,
    urlAnalysis
  };
};
