
import React from 'react';
import { AnalysisResult } from '@/lib/phishingDetection';
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Shield, ShieldAlert, ShieldCheck, AlertTriangle, CheckCircle2, AlertCircle } from 'lucide-react';
import { cn } from '@/lib/utils';

interface ResultsDisplayProps {
  results: AnalysisResult;
}

const ResultsDisplay: React.FC<ResultsDisplayProps> = ({ results }) => {
  const { score, threatLevel, features, identifiedPatterns } = results;
  
  const getScoreColor = () => {
    if (threatLevel === 'low') return 'bg-green-500';
    if (threatLevel === 'medium') return 'bg-yellow-500';
    return 'bg-phishing';
  };
  
  const getThreatIcon = () => {
    if (threatLevel === 'low') return <ShieldCheck className="h-6 w-6 text-green-400" />;
    if (threatLevel === 'medium') return <Shield className="h-6 w-6 text-yellow-400" />;
    return <ShieldAlert className="h-6 w-6 text-phishing" />;
  };

  const getFeatureProgressColor = (value: number) => {
    if (value < 0.3) return 'bg-green-500';
    if (value < 0.6) return 'bg-yellow-500';
    return 'bg-phishing';
  };

  return (
    <div className="rounded-md bg-card p-4 border border-border space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-medium flex items-center gap-2">
            {getThreatIcon()}
            <span>Analysis Results</span>
          </h3>
          <p className="text-sm text-muted-foreground mt-1">
            {threatLevel === 'low' ? 'No significant threats detected' : 
             threatLevel === 'medium' ? 'Some suspicious patterns detected' : 
             'High likelihood of phishing attempt'}
          </p>
        </div>
        
        <Badge 
          className={cn(
            "text-white px-3 py-1 text-sm",
            threatLevel === 'low' ? 'bg-green-500' : 
            threatLevel === 'medium' ? 'bg-yellow-500' : 
            'bg-phishing animate-pulse-warning'
          )}
        >
          {threatLevel === 'low' ? 'Low Threat' : 
           threatLevel === 'medium' ? 'Medium Threat' : 
           'High Threat'}
        </Badge>
      </div>
      
      <div>
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm font-medium">Phishing Score</span>
          <span className={cn(
            "font-bold text-sm",
            `threat-level-${threatLevel}`
          )}>
            {Math.round(score * 100)}%
          </span>
        </div>
        <Progress value={score * 100} className="h-2" indicatorClassName={getScoreColor()} />
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {Object.entries(features).map(([key, value]) => (
          <div key={key} className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium capitalize">{key}</span>
              <span className="text-xs">{Math.round(value * 100)}%</span>
            </div>
            <Progress value={value * 100} className="h-1.5" indicatorClassName={getFeatureProgressColor(value)} />
          </div>
        ))}
      </div>
      
      {identifiedPatterns.length > 0 && (
        <div>
          <h4 className="text-sm font-medium mb-2">Identified Patterns</h4>
          <div className="space-y-1.5 max-h-40 overflow-y-auto text-sm">
            {identifiedPatterns.map((pattern, idx) => (
              <div 
                key={idx} 
                className="flex items-start gap-2 text-xs"
              >
                {threatLevel === 'high' ? (
                  <AlertTriangle className="h-3.5 w-3.5 text-phishing flex-shrink-0 mt-0.5" />
                ) : threatLevel === 'medium' ? (
                  <AlertCircle className="h-3.5 w-3.5 text-yellow-400 flex-shrink-0 mt-0.5" />
                ) : (
                  <CheckCircle2 className="h-3.5 w-3.5 text-green-400 flex-shrink-0 mt-0.5" />
                )}
                <span className="text-muted-foreground">{pattern}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default ResultsDisplay;
