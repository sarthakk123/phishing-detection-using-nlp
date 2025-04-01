import React, { useState, useEffect } from 'react';
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Search, AlertTriangle, RotateCw } from 'lucide-react';
import { analyzeText, AnalysisResult, normalizeUrl } from '@/lib/phishingDetection';
import ResultsDisplay from './ResultsDisplay';
import { toast } from '@/components/ui/use-toast';

interface PhishingAnalyzerProps {
  initialText?: string;
}

const PhishingAnalyzer: React.FC<PhishingAnalyzerProps> = ({ initialText = '' }) => {
  const [inputText, setInputText] = useState(initialText);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [results, setResults] = useState<AnalysisResult | null>(null);
  const [showResults, setShowResults] = useState(false);

  // Update inputText when initialText prop changes
  useEffect(() => {
    setInputText(initialText);
    // Clear previous results when input changes
    setResults(null);
    setShowResults(false);
  }, [initialText]);

  const handleAnalyze = () => {
    if (!inputText.trim()) {
      toast({
        title: "Empty Input",
        description: "Please enter some text to analyze for phishing indicators.",
        variant: "destructive"
      });
      return;
    }

    // Normalize URL if it appears to be a URL
    let textToAnalyze = inputText;
    if (inputText.includes('.com') || inputText.includes('.org') || inputText.includes('.net') || 
        inputText.includes('http:') || inputText.includes('https:') || inputText.includes('www.')) {
      textToAnalyze = normalizeUrl(inputText);
    }

    setIsAnalyzing(true);
    setShowResults(false);
    
    // Simulate processing time
    setTimeout(() => {
      try {
        const analysisResults = analyzeText(textToAnalyze);
        setResults(analysisResults);
        
        // Animation timing - show results after a brief delay
        setTimeout(() => setShowResults(true), 100);
        
        if (analysisResults.threatLevel === 'high') {
          toast({
            title: "High Threat Detected!",
            description: "This message contains multiple indicators of a phishing attempt.",
            variant: "destructive"
          });
        } else if (analysisResults.threatLevel === 'medium') {
          toast({
            title: "Potential Threat Detected",
            description: "This message contains some suspicious patterns. Exercise caution.",
            variant: "default"
          });
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
    }, 1500);
  };

  const handleClear = () => {
    setInputText('');
    setResults(null);
    setShowResults(false);
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInputText(e.target.value);
    // Clear previous results when input changes
    if (results) {
      setResults(null);
      setShowResults(false);
    }
  };

  return (
    <div className="w-full phishing-card">
      <div className="mb-4">
        <h2 className="text-xl font-semibold mb-2 flex items-center">
          <Search className="mr-2 h-5 w-5 text-primary" />
          Text Analysis
        </h2>
        <p className="text-sm text-muted-foreground">
          Enter an email, message, or website content to analyze for phishing indicators.
        </p>
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
        </div>
      )}
    </div>
  );
};

export default PhishingAnalyzer;
