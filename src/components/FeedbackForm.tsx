
import React, { useState } from 'react';
import { Button } from "@/components/ui/button";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Label } from "@/components/ui/label";
import { ThumbsUp, ThumbsDown, RotateCw } from 'lucide-react';
import { toast } from '@/components/ui/use-toast';
import { storeFeedback } from '@/lib/selfLearning';
import { AnalysisResult } from '@/lib/phishingDetection';

interface FeedbackFormProps {
  results: AnalysisResult;
  text: string;
}

const FeedbackForm: React.FC<FeedbackFormProps> = ({ results, text }) => {
  const [actualThreatLevel, setActualThreatLevel] = useState<'low' | 'medium' | 'high'>(results.threatLevel);
  const [isSending, setIsSending] = useState(false);
  const [hasSent, setHasSent] = useState(false);
  
  const handleSubmitFeedback = () => {
    setIsSending(true);
    
    // Extract URLs from the analysis
    const urls = results.urlAnalysis.map(url => url.url);
    
    // Store the feedback for learning
    storeFeedback(
      text,
      urls,
      results.threatLevel,
      actualThreatLevel,
      results.features
    );
    
    // Simulate processing delay
    setTimeout(() => {
      setIsSending(false);
      setHasSent(true);
      
      toast({
        title: "Feedback Received",
        description: "Thank you for helping improve our detection system!",
      });
    }, 600);
  };
  
  if (hasSent) {
    return (
      <div className="mt-4 p-4 bg-green-50 dark:bg-green-900/20 rounded-md border border-green-200 dark:border-green-900/30">
        <div className="flex items-center gap-2 text-green-600 dark:text-green-400">
          <ThumbsUp className="h-4 w-4" />
          <span className="text-sm font-medium">Thank you for your feedback!</span>
        </div>
        <p className="text-xs text-green-600/80 dark:text-green-400/80 mt-1">
          Your input helps improve our detection algorithms.
        </p>
      </div>
    );
  }

  return (
    <div className="mt-4 p-4 bg-card border border-border rounded-md">
      <h4 className="text-sm font-medium mb-3">Was this analysis accurate?</h4>
      
      <div className="space-y-3">
        <RadioGroup 
          value={actualThreatLevel} 
          onValueChange={(value: string) => setActualThreatLevel(value as 'low' | 'medium' | 'high')}
          className="space-y-2"
        >
          <div className="flex items-center space-x-2">
            <RadioGroupItem value="low" id="threat-low" />
            <Label htmlFor="threat-low" className="text-sm">
              Low threat (legitimate message)
            </Label>
          </div>
          
          <div className="flex items-center space-x-2">
            <RadioGroupItem value="medium" id="threat-medium" />
            <Label htmlFor="threat-medium" className="text-sm">
              Medium threat (suspicious but not definitely phishing)
            </Label>
          </div>
          
          <div className="flex items-center space-x-2">
            <RadioGroupItem value="high" id="threat-high" />
            <Label htmlFor="threat-high" className="text-sm">
              High threat (definitely phishing)
            </Label>
          </div>
        </RadioGroup>
        
        <Button
          onClick={handleSubmitFeedback}
          disabled={isSending}
          variant="outline"
          size="sm"
          className="mt-2 w-full"
        >
          {isSending ? (
            <>
              <RotateCw className="mr-2 h-3 w-3 animate-spin" />
              Submitting...
            </>
          ) : (
            <>
              {actualThreatLevel === results.threatLevel ? (
                <ThumbsUp className="mr-2 h-3 w-3" />
              ) : (
                <ThumbsDown className="mr-2 h-3 w-3" />
              )}
              Submit Feedback
            </>
          )}
        </Button>
      </div>
    </div>
  );
};

export default FeedbackForm;
