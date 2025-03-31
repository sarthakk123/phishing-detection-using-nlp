
import React from 'react';
import { AnalysisResult, UrlAnalysisResult } from '@/lib/phishingDetection';
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Shield, ShieldAlert, ShieldCheck, AlertTriangle, CheckCircle2, AlertCircle, Globe, Link2, ExternalLink, AlertOctagon } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

interface ResultsDisplayProps {
  results: AnalysisResult;
}

const ResultsDisplay: React.FC<ResultsDisplayProps> = ({ results }) => {
  const { score, threatLevel, features, identifiedPatterns, urlAnalysis } = results;
  
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

  const getRiskScoreColor = (score: number) => {
    if (score < 30) return 'text-green-500';
    if (score < 60) return 'text-yellow-500';
    return 'text-phishing';
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
      
      {urlAnalysis && urlAnalysis.length > 0 && (
        <div>
          <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
            <Globe className="h-4 w-4" />
            URL Analysis ({urlAnalysis.length} {urlAnalysis.length === 1 ? 'URL' : 'URLs'} found)
          </h4>
          
          <div className="max-h-60 overflow-y-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[200px]">URL</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Risk Score</TableHead>
                  <TableHead>Details</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {urlAnalysis.map((url, idx) => (
                  <TableRow key={idx}>
                    <TableCell className="font-mono text-xs break-all">
                      <div className="flex items-center gap-1">
                        <Link2 className="h-3 w-3 flex-shrink-0" />
                        {url.url.length > 40 ? url.url.substring(0, 40) + '...' : url.url}
                      </div>
                      <div className="mt-1 text-xs text-muted-foreground">
                        Domain: {url.domain}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge 
                        className={cn(
                          "text-white px-2 py-0.5 text-xs",
                          url.suspicious ? 'bg-phishing' : 'bg-green-500'
                        )}
                      >
                        {url.suspicious ? 'Suspicious' : 'Safe'}
                      </Badge>
                      {url.brandImpersonation && (
                        <div className="mt-1">
                          <Badge variant="outline" className="text-xs border-yellow-500 text-yellow-500">
                            Impersonating {url.brandImpersonation}
                          </Badge>
                        </div>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className={cn("font-medium", getRiskScoreColor(url.riskScore))}>
                        {url.riskScore}%
                      </div>
                      {!url.securityFeatures.https && (
                        <Badge variant="outline" className="mt-1 text-xs border-red-500 text-red-500">
                          Not Secure
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell>
                      {url.suspicious ? (
                        <div className="space-y-1 text-xs">
                          {url.reasons.map((reason, i) => (
                            <div key={i} className="flex items-start gap-1">
                              <AlertTriangle className="h-3 w-3 text-phishing flex-shrink-0 mt-0.5" />
                              <span className="text-muted-foreground">{reason}</span>
                            </div>
                          ))}
                          {url.redirectCount > 0 && (
                            <div className="flex items-start gap-1">
                              <ExternalLink className="h-3 w-3 text-yellow-500 flex-shrink-0 mt-0.5" />
                              <span className="text-muted-foreground">
                                Contains redirects ({url.redirectCount} detected)
                              </span>
                            </div>
                          )}
                        </div>
                      ) : (
                        <div className="flex items-center gap-1 text-xs">
                          <CheckCircle2 className="h-3 w-3 text-green-400" />
                          <span className="text-muted-foreground">No suspicious patterns detected</span>
                        </div>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          
          {urlAnalysis.some(url => url.suspicious) && (
            <Alert variant="destructive" className="mt-4">
              <AlertOctagon className="h-4 w-4" />
              <AlertTitle>URL Security Alert</AlertTitle>
              <AlertDescription>
                One or more suspicious URLs were detected in this message. Be cautious about clicking any links and verify the sender's identity before taking any action.
              </AlertDescription>
            </Alert>
          )}
        </div>
      )}
      
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
