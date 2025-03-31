
import React, { useState } from 'react';
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Search, AlertTriangle, RotateCw } from 'lucide-react';
import { analyzeText, AnalysisResult } from '@/lib/phishingDetection';
import ResultsDisplay from './ResultsDisplay';
import { toast } from '@/components/ui/use-toast';

const PhishingAnalyzer: React.FC = () => {
  const [inputText, setInputText] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [results, setResults] = useState<AnalysisResult | null>(null);

  const handleAnalyze = () => {
    if (!inputText.trim()) {
      toast({
        title: "Empty Input",
        description: "Please enter some text to analyze for phishing indicators.",
        variant: "destructive"
      });
      return;
    }

    setIsAnalyzing(true);
    
    // Simulate processing time
    setTimeout(() => {
      try {
        const analysisResults = analyzeText(inputText);
        setResults(analysisResults);
        
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
  };

  return (
    <div className="w-full phishing-card rounded-lg p-4 md:p-6">
      <div className="mb-5">
        <h2 className="text-xl font-semibold text-cyber-blue mb-2 flex items-center">
          <Search className="mr-2 h-5 w-5" />
          Text Analysis
        </h2>
        <p className="text-sm text-muted-foreground">
          Enter an email, message, or website content to analyze for phishing indicators.
        </p>
      </div>

      <div className="space-y-4">
        <Textarea
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          placeholder="Paste suspicious text here for analysis..."
          className="min-h-[120px] bg-card/50 border-cyber-blue/20"
        />
        
        <div className="flex flex-wrap gap-2">
          <Button 
            onClick={handleAnalyze} 
            className="bg-cyber-blue hover:bg-cyber-blue/80 text-white"
            disabled={isAnalyzing}
          >
            {isAnalyzing ? (
              <>
                <RotateCw className="mr-2 h-4 w-4 animate-spin" />
                Analyzing...
              </>
            ) : (
              <>
                <AlertTriangle className="mr-2 h-4 w-4" />
                Analyze for Threats
              </>
            )}
          </Button>
          
          <Button 
            variant="outline" 
            onClick={handleClear}
            className="border-cyber-blue/20 text-muted-foreground hover:text-foreground"
          >
            Clear
          </Button>
        </div>
      </div>

      {results && (
        <div className="mt-6">
          <ResultsDisplay results={results} />
        </div>
      )}
    </div>
  );
};

export default PhishingAnalyzer;
