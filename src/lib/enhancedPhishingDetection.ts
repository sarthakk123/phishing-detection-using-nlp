
import { analyzeText as originalAnalyzeText, analyzeUrl as originalAnalyzeUrl, AnalysisResult, UrlAnalysisResult, normalizeUrl } from './phishingDetection';
import { getWeightAdjustments, getDomainReputation, checkPhishingDatabases } from './selfLearning';

// Enhanced URL analysis with historical data and external database checks
export const enhancedAnalyzeUrl = async (url: string): Promise<UrlAnalysisResult> => {
  // First, get the base analysis
  const baseAnalysis = originalAnalyzeUrl(url);
  
  // Apply enhancements
  try {
    const domain = new URL(normalizeUrl(url)).hostname;
    
    // Check domain reputation from our learning system
    const reputation = getDomainReputation(domain);
    if (reputation) {
      if (reputation.phishingCount > 0) {
        baseAnalysis.suspicious = true;
        baseAnalysis.reasons.push(`Previously reported as phishing ${reputation.phishingCount} times`);
        baseAnalysis.riskScore += Math.min(reputation.phishingCount * 5, 30); // Add up to 30 points
      } else if (reputation.legitimateCount > 2) {
        // If we've seen this domain as legitimate multiple times, reduce the risk score
        baseAnalysis.riskScore = Math.max(0, baseAnalysis.riskScore - 20);
        baseAnalysis.reasons.push(`Previously verified as legitimate ${reputation.legitimateCount} times`);
        
        // If the only reason it was marked suspicious was something minor and we have good reputation,
        // override the suspicious flag
        if (baseAnalysis.suspicious && baseAnalysis.riskScore < 40 && reputation.legitimateCount > 5) {
          baseAnalysis.suspicious = false;
        }
      }
    }
    
    // Check external phishing databases
    const isInPhishingDatabase = await checkPhishingDatabases(url);
    if (isInPhishingDatabase) {
      baseAnalysis.suspicious = true;
      baseAnalysis.reasons.push('Found in known phishing database');
      baseAnalysis.riskScore = Math.max(baseAnalysis.riskScore, 85); // Set minimum risk score to 85
    }
    
    // Apply machine learning for cases where domain is similar to popular domains but not caught by existing checks
    await applyMachineLearningInsights(baseAnalysis);
    
    // Ensure risk score is capped at 100
    baseAnalysis.riskScore = Math.min(100, baseAnalysis.riskScore);
    
  } catch (e) {
    // Error in enhancement, just return the base analysis
    console.error('Error in URL enhancement:', e);
  }
  
  return baseAnalysis;
};

// Apply machine learning insights to the URL analysis
const applyMachineLearningInsights = async (analysis: UrlAnalysisResult): Promise<void> => {
  // This is where more advanced ML techniques would be applied
  // For now, we'll use a simple simulation
  
  // Check for advanced homograph attacks (character substitutions not caught by basic check)
  if (!analysis.suspicious && analysis.domain.length > 5) {
    // Example: detect 'rnicrosoft.com' (where 'rn' looks like 'm')
    if (analysis.domain.includes('rn') && analysis.domain.toLowerCase().includes('icrosoft')) {
      analysis.suspicious = true;
      analysis.reasons.push('Possible advanced homograph attack detected (rn -> m)');
      analysis.riskScore += 35;
    }
    
    // More advanced checks would be here
  }
};

// Enhanced text analysis with self-learning weights
export const enhancedAnalyzeText = async (text: string): Promise<AnalysisResult> => {
  // First, get the base analysis
  const baseAnalysis = originalAnalyzeText(text);
  
  // Get weight adjustments from learning system
  const adjustments = getWeightAdjustments();
  
  // Recalculate overall score with adjusted weights
  const baseWeights = {
    urgency: 0.2,
    badGrammar: 0.15,
    sensitiveInfo: 0.25,
    suspiciousLinks: 0.3,
    impersonation: 0.1
  };
  
  // Apply weight adjustments
  const adjustedWeights = { ...baseWeights };
  for (const [key, adjustment] of Object.entries(adjustments)) {
    adjustedWeights[key as keyof typeof adjustedWeights] += adjustment;
    
    // Ensure weights remain positive and normalized
    adjustedWeights[key as keyof typeof adjustedWeights] = Math.max(0.05, adjustedWeights[key as keyof typeof adjustedWeights]);
  }
  
  // Normalize weights to sum to 1
  const weightSum = Object.values(adjustedWeights).reduce((sum, weight) => sum + weight, 0);
  for (const key of Object.keys(adjustedWeights)) {
    adjustedWeights[key as keyof typeof adjustedWeights] /= weightSum;
  }
  
  // Recalculate score
  let adjustedScore = 0;
  for (const [key, weight] of Object.entries(adjustedWeights)) {
    adjustedScore += baseAnalysis.features[key as keyof typeof baseAnalysis.features] * weight;
  }
  
  // Enhance URL analysis for each URL
  const enhancedUrlResults: UrlAnalysisResult[] = [];
  for (const urlAnalysis of baseAnalysis.urlAnalysis) {
    const enhancedUrlResult = await enhancedAnalyzeUrl(urlAnalysis.url);
    enhancedUrlResults.push(enhancedUrlResult);
    
    // If any URL is now suspicious that wasn't before, add to the patterns
    if (enhancedUrlResult.suspicious && !urlAnalysis.suspicious) {
      baseAnalysis.identifiedPatterns.push(`Enhanced detection: URL ${enhancedUrlResult.url} identified as suspicious`);
      
      // Also update the suspiciousLinks feature score
      baseAnalysis.features.suspiciousLinks = Math.min(1, baseAnalysis.features.suspiciousLinks + 0.2);
    }
  }
  
  // Update the URL analysis results with enhanced versions
  baseAnalysis.urlAnalysis = enhancedUrlResults;
  
  // Determine if any URLs are now highly suspicious
  const highRiskUrls = enhancedUrlResults.filter(url => url.riskScore >= 80);
  if (highRiskUrls.length > 0) {
    // Ensure the score reflects the high risk
    adjustedScore = Math.max(adjustedScore, 0.7);
  }
  
  // Update the score and recalculate threat level
  baseAnalysis.score = adjustedScore;
  
  // Determine threat level based on adjusted score
  if (adjustedScore < 0.3) {
    baseAnalysis.threatLevel = 'low';
  } else if (adjustedScore < 0.6) {
    baseAnalysis.threatLevel = 'medium';
  } else {
    baseAnalysis.threatLevel = 'high';
  }
  
  return baseAnalysis;
};
