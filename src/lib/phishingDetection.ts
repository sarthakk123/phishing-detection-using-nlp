
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

// Analyze a single URL
const analyzeUrl = (url: string): UrlAnalysisResult => {
  const analysis: UrlAnalysisResult = {
    url,
    suspicious: false,
    reasons: [],
    domain: '',
    protocol: '',
    tld: ''
  };
  
  try {
    const urlObj = new URL(url);
    analysis.domain = urlObj.hostname;
    analysis.protocol = urlObj.protocol;
    analysis.tld = extractTld(urlObj.hostname);
    
    // Check for suspicious domains
    for (const domain of suspiciousDomains) {
      if (analysis.domain.includes(domain)) {
        analysis.suspicious = true;
        analysis.reasons.push(`Contains suspicious domain pattern: "${domain}"`);
      }
    }
    
    // Check for suspicious TLDs
    for (const tld of suspiciousTlds) {
      if (analysis.domain.endsWith(tld)) {
        analysis.suspicious = true;
        analysis.reasons.push(`Uses suspicious top-level domain: "${tld}"`);
      }
    }
    
    // Check for URL shorteners
    const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'ow.ly'];
    for (const shortener of shorteners) {
      if (analysis.domain.includes(shortener)) {
        analysis.suspicious = true;
        analysis.reasons.push(`Uses URL shortener: "${shortener}" which can hide the true destination`);
      }
    }
    
    // Check for IP address instead of domain name
    const ipRegex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    if (ipRegex.test(analysis.domain)) {
      analysis.suspicious = true;
      analysis.reasons.push('Uses IP address instead of domain name');
    }
    
    // Check for HTTP instead of HTTPS
    if (analysis.protocol === 'http:') {
      analysis.suspicious = true;
      analysis.reasons.push('Uses insecure HTTP protocol instead of HTTPS');
    }
    
    // Check for many subdomains (potential phishing tactic)
    const subdomainCount = analysis.domain.split('.').length - 2;
    if (subdomainCount > 2) {
      analysis.suspicious = true;
      analysis.reasons.push(`Contains ${subdomainCount} subdomains which is unusually high`);
    }
    
  } catch (e) {
    analysis.suspicious = true;
    analysis.reasons.push('Invalid URL format');
  }
  
  return analysis;
};

// Simplified NLP-based phishing detection
export const analyzeText = (text: string): AnalysisResult => {
  const lowerText = text.toLowerCase();
  const identifiedPatterns: string[] = [];
  const urlAnalysis: UrlAnalysisResult[] = [];
  
  // Initialize feature scores
  const features = {
    urgency: 0,
    badGrammar: 0,
    sensitiveInfo: 0,
    suspiciousLinks: 0,
    impersonation: 0,
  };
  
  // Check for urgency indicators
  const urgencyWords = ['urgent', 'immediately', 'alert', 'warning', 'now', 'quick', 'fast'];
  for (const word of urgencyWords) {
    if (lowerText.includes(word)) {
      features.urgency += 0.2;
      identifiedPatterns.push(`Urgency indicator: "${word}"`);
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
  const commonMisspellings = ['acct', 'verifcation', 'verificaton', 'securty', 'informaton'];
  for (const misspelling of commonMisspellings) {
    if (lowerText.includes(misspelling)) {
      features.badGrammar += 0.1;
      identifiedPatterns.push(`Possible misspelling: "${misspelling}"`);
    }
  }
  
  // Extract and analyze URLs
  const urlRegex = /(https?:\/\/[^\s]+)/g;
  const urls = text.match(urlRegex);
  
  if (urls) {
    for (const url of urls) {
      const analysis = analyzeUrl(url);
      urlAnalysis.push(analysis);
      
      if (analysis.suspicious) {
        features.suspiciousLinks += 0.25;
        for (const reason of analysis.reasons) {
          identifiedPatterns.push(`URL issue (${url}): ${reason}`);
        }
      }
    }
  }
  
  // Check for impersonation of known brands
  const brands = ['amazon', 'netflix', 'paypal', 'apple', 'microsoft', 'google', 'facebook', 'bank'];
  for (const brand of brands) {
    const brandRegex = new RegExp(`\\b${brand}\\b`, 'i');
    if (brandRegex.test(lowerText)) {
      features.impersonation += 0.15;
      identifiedPatterns.push(`Possible brand impersonation: "${brand}"`);
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
