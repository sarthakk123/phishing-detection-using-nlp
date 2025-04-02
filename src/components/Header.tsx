
import React, { useEffect, useState } from 'react';
import { Shield, ShieldAlert, Robot, BarChart } from 'lucide-react';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

const Header: React.FC = () => {
  const [aiModeEnabled, setAiModeEnabled] = useState(false);
  const [detectionCount, setDetectionCount] = useState(0);
  
  // Load AI mode state and detection count from localStorage
  useEffect(() => {
    try {
      const aiMode = localStorage.getItem('phishDetectAiMode') === 'true';
      setAiModeEnabled(aiMode);
      
      const storedCount = parseInt(localStorage.getItem('phishDetectCount') || '0', 10);
      setDetectionCount(storedCount);
    } catch (e) {
      console.error('Error loading AI mode or detection count:', e);
    }
  }, []);
  
  return (
    <header className="w-full py-4 border-b border-border/40">
      <div className="container flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldAlert className="h-7 w-7 text-primary" />
          <div>
            <h1 className="text-2xl font-bold gradient-text">PhishingDetect</h1>
            <p className="text-xs text-muted-foreground">NLP-Based Phishing Detection</p>
          </div>
        </div>
        
        <div className="hidden md:flex items-center gap-4">
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <div className="flex items-center gap-2 text-sm">
                  <BarChart className="h-4 w-4 text-primary/70" />
                  <span className="text-muted-foreground">{detectionCount} analyzed</span>
                </div>
              </TooltipTrigger>
              <TooltipContent>
                <p>Total messages analyzed</p>
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
          
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <div className="flex items-center gap-2 text-sm">
                  {aiModeEnabled ? (
                    <>
                      <Robot className="h-4 w-4 text-primary animate-pulse" />
                      <span className="text-primary/90">Self-Learning AI</span>
                    </>
                  ) : (
                    <>
                      <Shield className="h-4 w-4 text-green-400" />
                      <span>Secure Mode</span>
                    </>
                  )}
                </div>
              </TooltipTrigger>
              <TooltipContent>
                <p>{aiModeEnabled 
                  ? 'Self-learning AI mode is active' 
                  : 'Standard detection mode is active'}</p>
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        </div>
      </div>
    </header>
  );
};

export default Header;
