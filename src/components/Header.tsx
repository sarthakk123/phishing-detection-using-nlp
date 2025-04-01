
import React from 'react';
import { Shield, ShieldAlert } from 'lucide-react';

const Header: React.FC = () => {
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
          <div className="flex items-center gap-1 text-sm">
            <Shield className="h-4 w-4 text-green-400" />
            <span>Secure Mode</span>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;
