
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
}

// Simplified NLP-based phishing detection
export const analyzeText = (text: string): AnalysisResult => {
  const lowerText = text.toLowerCase();
  const identifiedPatterns: string[] = [];
  
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
  
  // Check for URLs and analyze them
  const urlRegex = /(https?:\/\/[^\s]+)/g;
  const urls = lowerText.match(urlRegex);
  
  if (urls) {
    for (const url of urls) {
      // Check for suspicious domains
      for (const domain of suspiciousDomains) {
        if (url.includes(domain)) {
          features.suspiciousLinks += 0.25;
          identifiedPatterns.push(`Suspicious domain: "${domain}" in ${url}`);
        }
      }
      
      // Check for suspicious TLDs
      for (const tld of suspiciousTlds) {
        if (url.endsWith(tld)) {
          features.suspiciousLinks += 0.2;
          identifiedPatterns.push(`Suspicious TLD: "${tld}" in ${url}`);
        }
      }
      
      // Check for URL obfuscation
      if (url.includes('bit.ly') || url.includes('tinyurl') || url.includes('goo.gl')) {
        features.suspiciousLinks += 0.15;
        identifiedPatterns.push(`URL shortener detected: ${url}`);
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
    identifiedPatterns
  };
};
