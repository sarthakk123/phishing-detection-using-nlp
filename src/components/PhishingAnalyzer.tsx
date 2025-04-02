
import React, { useState, useEffect, useRef } from 'react';
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Search, AlertTriangle, RotateCw, Bot } from 'lucide-react';
import { AnalysisResult, normalizeUrl } from '@/lib/phishingDetection';
import { enhancedAnalyzeText } from '@/lib/enhancedPhishingDetection';
import { initializeLearningSystem } from '@/lib/selfLearning';
import ResultsDisplay from './ResultsDisplay';
import FeedbackForm from './FeedbackForm';
import { useToast } from '@/hooks/use-toast';

interface PhishingAnalyzerProps {
  initialText?: string;
}

const PhishingAnalyzer: React.FC<PhishingAnalyzerProps> = ({ initialText = '' }) => {
  const [inputText, setInputText] = useState(initialText);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [results, setResults] = useState<AnalysisResult | null>(null);
  const [showResults, setShowResults] = useState(false);
  const [aiModeEnabled, setAiModeEnabled] = useState(() => {
    try {
      return localStorage.getItem('phishDetectAiMode') === 'true';
    } catch (e) {
      return true;
    }
  });
  const [toastShown, setToastShown] = useState(false);
  const toastIdRef = useRef<string | null>(null);
  const { toast, dismiss } = useToast();

  useEffect(() => {
    initializeLearningSystem();
  }, []);

  useEffect(() => {
    // Only set input text from initialText on component mount or when initialText changes
    if (initialText !== inputText) {
      setInputText(initialText);
      setResults(null);
      setShowResults(false);
      setToastShown(false);
      
      // Clear any existing toasts when input changes
      if (toastIdRef.current) {
        dismiss(toastIdRef.current);
        toastIdRef.current = null;
      }
    }
  }, [initialText, dismiss, inputText]);

  const toggleAiMode = () => {
    const newMode = !aiModeEnabled;
    setAiModeEnabled(newMode);
    
    localStorage.setItem('phishDetectAiMode', newMode.toString());
    
    toast({
      title: newMode ? "AI Mode Enabled" : "AI Mode Disabled",
      description: newMode 
        ? "Self-learning AI detection is now active." 
        : "Using standard detection algorithms only.",
    });
  };

  const handleAnalyze = async () => {
    // Dismiss any existing toasts
    if (toastIdRef.current) {
      dismiss(toastIdRef.current);
      toastIdRef.current = null;
    }

    if (!inputText.trim()) {
      toast({
        title: "Empty Input",
        description: "Please enter some text to analyze for phishing indicators.",
        variant: "destructive"
      });
      return;
    }

    let textToAnalyze = inputText;
    if (inputText.includes('.com') || inputText.includes('.org') || inputText.includes('.net') || 
        inputText.includes('http:') || inputText.includes('https:') || inputText.includes('www.')) {
      textToAnalyze = normalizeUrl(inputText);
    }

    setIsAnalyzing(true);
    setShowResults(false);
    setToastShown(false);
    
    try {
      let analysisResults: AnalysisResult;
      
      if (aiModeEnabled) {
        analysisResults = await enhancedAnalyzeText(textToAnalyze);
      } else {
        analysisResults = await enhancedAnalyzeText(textToAnalyze);
      }
      
      setResults(analysisResults);
      
      setTimeout(() => setShowResults(true), 100);
      
      if (!toastShown) {
        if (analysisResults.threatLevel === 'high') {
          const { id } = toast({
            title: "High Threat Detected!",
            description: "This message contains multiple indicators of a phishing attempt.",
            variant: "destructive"
          });
          toastIdRef.current = id;
          setToastShown(true);
        } else if (analysisResults.threatLevel === 'medium') {
          const { id } = toast({
            title: "Potential Threat Detected",
            description: "This message contains some suspicious patterns. Exercise caution.",
            variant: "default"
          });
          toastIdRef.current = id;
          setToastShown(true);
        }
      }
    } catch (error) {
      console.error('Analysis error:', error);
      toast({
        title: "Analysis Error",
        description: "An error occurred while analyzing the text.",
        variant: "destructive"
      });
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleClear = () => {
    setInputText('');
    setResults(null);
    setShowResults(false);
    setToastShown(false);
    
    // Dismiss any existing toasts
    if (toastIdRef.current) {
      dismiss(toastIdRef.current);
      toastIdRef.current = null;
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInputText(e.target.value);
    if (results) {
      setResults(null);
      setShowResults(false);
      setToastShown(false);
      
      // Dismiss any existing toasts when input changes
      if (toastIdRef.current) {
        dismiss(toastIdRef.current);
        toastIdRef.current = null;
      }
    }
  };

  return (
    <div className="w-full phishing-card">
      <div className="mb-4 flex justify-between items-start">
        <div>
          <h2 className="text-xl font-semibold mb-2 flex items-center">
            <Search className="mr-2 h-5 w-5 text-primary" />
            Text Analysis
          </h2>
          <p className="text-sm text-muted-foreground">
            Enter an email, message, or website content to analyze for phishing indicators.
          </p>
        </div>
        
        <Button
          variant="outline"
          size="sm"
          className={`flex items-center gap-1.5 ${aiModeEnabled ? 'bg-primary/10' : ''}`}
          onClick={toggleAiMode}
        >
          <Bot className={`h-3.5 w-3.5 ${aiModeEnabled ? 'text-primary' : 'text-muted-foreground'}`} />
          <span className="text-xs">AI Mode</span>
        </Button>
      </div>

      <div className="space-y-4">
        <Textarea
          value={inputText}
          onChange={handleInputChange}
          placeholder="Paste suspicious text here for analysis..."
          className="min-h-[120px] bg-background border-primary/30 focus:border-primary 
                    focus:ring-primary/20 transition-all duration-300"
        />
        
        <div className="flex flex-wrap gap-2">
          <Button 
            onClick={handleAnalyze} 
            className="cyber-button"
            disabled={isAnalyzing}
          >
            {isAnalyzing ? (
              <>
                <RotateCw className="mr-2 h-4 w-4 animate-spin" />
                <span>Analyzing...</span>
              </>
            ) : (
              <>
                <AlertTriangle className="mr-2 h-4 w-4" />
                <span>Analyze for Threats</span>
              </>
            )}
          </Button>
          
          <Button 
            variant="outline" 
            onClick={handleClear}
            className="border-primary/30 text-muted-foreground hover:text-foreground 
                      hover:border-primary transition-all duration-300"
          >
            Clear
          </Button>
        </div>
      </div>

      {results && (
        <div className={`mt-6 transition-all duration-500 ${showResults ? 'opacity-100 transform-none' : 'opacity-0 translate-y-4'}`}>
          <ResultsDisplay results={results} />
          <FeedbackForm results={results} text={inputText} />
        </div>
      )}
    </div>
  );
};

export default PhishingAnalyzer;
