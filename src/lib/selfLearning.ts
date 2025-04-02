interface FeedbackData {
  text: string;
  urls: string[];
  predictedThreatLevel: 'low' | 'medium' | 'high';
  actualThreatLevel: 'low' | 'medium' | 'high';
  features: {
    urgency: number;
    badGrammar: number;
    sensitiveInfo: number;
    suspiciousLinks: number;
    impersonation: number;
  };
  timestamp: string;
}

// Store for feedback data (in a real app, this would be a database)
const feedbackStore: FeedbackData[] = [];

// Weight adjustments based on learning
let weightAdjustments = {
  urgency: 0,
  badGrammar: 0,
  sensitiveInfo: 0,
  suspiciousLinks: 0,
  impersonation: 0
};

// Initialize learning weights from localStorage if available
export const initializeWeights = (): void => {
  try {
    const storedAdjustments = localStorage.getItem('phishDetectWeightAdjustments');
    if (storedAdjustments) {
      weightAdjustments = JSON.parse(storedAdjustments);
      console.log('Loaded weight adjustments:', weightAdjustments);
    }
  } catch (e) {
    console.error('Error loading stored weight adjustments:', e);
  }
};

// Get current weight adjustments
export const getWeightAdjustments = () => {
  return { ...weightAdjustments };
};

// Store feedback and learn from it
export const storeFeedback = (
  text: string,
  urls: string[],
  predictedThreatLevel: 'low' | 'medium' | 'high',
  actualThreatLevel: 'low' | 'medium' | 'high',
  features: {
    urgency: number;
    badGrammar: number;
    sensitiveInfo: number;
    suspiciousLinks: number;
    impersonation: number;
  }
): void => {
  // Store the feedback
  const feedbackEntry: FeedbackData = {
    text,
    urls,
    predictedThreatLevel,
    actualThreatLevel,
    features,
    timestamp: new Date().toISOString()
  };
  
  feedbackStore.push(feedbackEntry);
  
  // Also store to localStorage for persistence
  try {
    const storedFeedback = localStorage.getItem('phishDetectFeedback');
    const existingFeedback = storedFeedback ? JSON.parse(storedFeedback) : [];
    existingFeedback.push(feedbackEntry);
    
    // Only keep last 100 entries to prevent localStorage from getting too large
    if (existingFeedback.length > 100) {
      existingFeedback.shift();
    }
    
    localStorage.setItem('phishDetectFeedback', JSON.stringify(existingFeedback));
  } catch (e) {
    console.error('Error storing feedback:', e);
  }
  
  // Learn from this feedback
  learnFromFeedback(feedbackEntry);
};

// Domain reputation store
interface DomainReputation {
  domain: string;
  phishingCount: number;
  legitimateCount: number;
  lastSeen: string;
}

// Store known phishing and legitimate domains (in a real app, this would be a database)
const domainReputationStore: Record<string, DomainReputation> = {};

// Initialize domain reputation from localStorage if available
export const initializeDomainReputation = (): void => {
  try {
    const storedReputation = localStorage.getItem('phishDetectDomainReputation');
    if (storedReputation) {
      const parsedReputation = JSON.parse(storedReputation);
      Object.assign(domainReputationStore, parsedReputation);
      console.log(`Loaded reputation for ${Object.keys(domainReputationStore).length} domains`);
    }
  } catch (e) {
    console.error('Error loading stored domain reputation:', e);
  }
};

// Get domain reputation
export const getDomainReputation = (domain: string): DomainReputation | null => {
  return domainReputationStore[domain] || null;
};

// Update domain reputation based on feedback
export const updateDomainReputation = (
  domain: string, 
  isPhishing: boolean
): void => {
  if (!domain) return;
  
  // Create or update domain reputation
  if (!domainReputationStore[domain]) {
    domainReputationStore[domain] = {
      domain,
      phishingCount: 0,
      legitimateCount: 0,
      lastSeen: new Date().toISOString()
    };
  }
  
  // Update counts
  if (isPhishing) {
    domainReputationStore[domain].phishingCount++;
  } else {
    domainReputationStore[domain].legitimateCount++;
  }
  
  domainReputationStore[domain].lastSeen = new Date().toISOString();
  
  // Store to localStorage
  try {
    localStorage.setItem('phishDetectDomainReputation', JSON.stringify(domainReputationStore));
  } catch (e) {
    console.error('Error storing domain reputation:', e);
  }
};

// Learn from feedback by adjusting weights
const learnFromFeedback = (feedback: FeedbackData): void => {
  // Only learn if prediction was wrong
  if (feedback.predictedThreatLevel === feedback.actualThreatLevel) {
    return;
  }
  
  // Calculate adjustment direction
  // If we predicted too low, increase weights
  // If we predicted too high, decrease weights
  const threatLevels = ['low', 'medium', 'high'];
  const predictedIndex = threatLevels.indexOf(feedback.predictedThreatLevel);
  const actualIndex = threatLevels.indexOf(feedback.actualThreatLevel);
  const adjustmentDirection = predictedIndex < actualIndex ? 0.05 : -0.05;
  
  // Adjust weights based on which features were most significant
  for (const [feature, value] of Object.entries(feedback.features)) {
    if (value > 0.5) {
      // This feature was significant, so adjust it more
      weightAdjustments[feature as keyof typeof weightAdjustments] += adjustmentDirection * 1.5;
    } else if (value > 0.2) {
      // This feature was moderately significant
      weightAdjustments[feature as keyof typeof weightAdjustments] += adjustmentDirection;
    } else {
      // This feature wasn't very significant
      weightAdjustments[feature as keyof typeof weightAdjustments] += adjustmentDirection * 0.5;
    }
    
    // Cap adjustments to prevent overlearning
    weightAdjustments[feature as keyof typeof weightAdjustments] = Math.max(
      -0.3,
      Math.min(0.3, weightAdjustments[feature as keyof typeof weightAdjustments])
    );
  }
  
  // Update domain reputation for all URLs in the feedback
  for (const url of feedback.urls) {
    try {
      const domain = new URL(url).hostname;
      updateDomainReputation(domain, feedback.actualThreatLevel === 'high');
    } catch (e) {
      // Invalid URL, skip
    }
  }
  
  // Store updated weights to localStorage
  try {
    localStorage.setItem('phishDetectWeightAdjustments', JSON.stringify(weightAdjustments));
  } catch (e) {
    console.error('Error storing weight adjustments:', e);
  }
};

// Check known phishing databases (in a real implementation, this would make API calls)
export const checkPhishingDatabases = async (url: string): Promise<boolean> => {
  // Simulate an API call to phishing databases
  // This is where you'd integrate with services like PhishTank or Google Safe Browsing
  
  // For now, check our local database
  try {
    const domain = new URL(url).hostname;
    const reputation = getDomainReputation(domain);
    
    if (reputation) {
      // If domain has been reported as phishing more than legitimate
      return reputation.phishingCount > reputation.legitimateCount;
    }
  } catch (e) {
    // Invalid URL, skip
  }
  
  return false;
};

// Initialize learning data
export const initializeLearningSystem = (): void => {
  initializeWeights();
  initializeDomainReputation();
};
