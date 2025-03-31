
import React from 'react';
import { 
  ArrowRight, 
  Search, 
  Shield, 
  Database, 
  AlertTriangle, 
  Link2, 
  ShieldAlert, 
  CheckCircle, 
  Eye, 
  Braces,
  ShieldCheck
} from 'lucide-react';
import { 
  Card, 
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle 
} from "@/components/ui/card";
import { cn } from "@/lib/utils";

const PhishingFlowchart: React.FC = () => {
  return (
    <div className="w-full p-4 bg-card/30 rounded-lg border border-border/50">
      <h2 className="text-xl font-semibold mb-6 text-center">Phishing Detection System Architecture</h2>
      
      {/* Main Flowchart */}
      <div className="relative">
        {/* Input Step */}
        <FlowchartStep 
          icon={<Search className="h-6 w-6 text-cyber-blue" />}
          title="Input Text"
          description="User inputs suspicious text or email"
          position="start"
        />
        
        <FlowArrow />
        
        {/* Processing Step */}
        <FlowchartStep 
          icon={<Braces className="h-6 w-6 text-purple-500" />}
          title="Text Processing"
          description="System breaks down and prepares text for analysis"
        />
        
        {/* Analysis Branches */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-8 my-6">
          <div className="space-y-6">
            <FlowArrow direction="right" />
            <FlowchartStep 
              icon={<Eye className="h-6 w-6 text-amber-500" />}
              title="Pattern Analysis"
              description="Scans for phishing keywords, urgency indicators, poor grammar"
              variant="branch"
            />
            <div className="ml-8 space-y-3 text-sm text-muted-foreground">
              <div className="flex items-center gap-2">
                <Database className="h-4 w-4 text-muted-foreground" />
                <span>Known phishing patterns</span>
              </div>
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-yellow-500" />
                <span>Urgency indicators</span>
              </div>
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-muted-foreground" />
                <span>Sensitive information requests</span>
              </div>
            </div>
          </div>
          
          <div className="space-y-6">
            <FlowArrow direction="left" />
            <FlowchartStep 
              icon={<Link2 className="h-6 w-6 text-blue-500" />}
              title="URL Analysis"
              description="Extracts and analyzes URLs for suspicious characteristics"
              variant="branch"
            />
            <div className="ml-8 space-y-3 text-sm text-muted-foreground">
              <div className="flex items-center gap-2">
                <Database className="h-4 w-4 text-muted-foreground" />
                <span>Domain reputation check</span>
              </div>
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-red-500" />
                <span>Security features (HTTPS)</span>
              </div>
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-yellow-500" />
                <span>Typosquatting detection</span>
              </div>
            </div>
          </div>
        </div>
        
        <div className="flex justify-center my-6">
          <ArrowRight className="h-8 w-8 text-muted-foreground" />
        </div>
        
        {/* Scoring Step */}
        <FlowchartStep 
          icon={<Database className="h-6 w-6 text-emerald-500" />}
          title="Risk Scoring"
          description="Combines all indicators to calculate overall threat level"
        />
        
        <FlowArrow />
        
        {/* Decision Step */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 md:gap-6 my-6">
          <Card className="border-green-500/20 shadow-sm">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <ShieldCheck className="h-5 w-5 text-green-500" />
                Low Threat
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground">
                Few or no suspicious patterns detected
              </p>
            </CardContent>
          </Card>
          
          <Card className="border-yellow-500/20 shadow-sm">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Shield className="h-5 w-5 text-yellow-500" />
                Medium Threat
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground">
                Some suspicious patterns detected
              </p>
            </CardContent>
          </Card>
          
          <Card className="border-red-500/20 shadow-sm">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <ShieldAlert className="h-5 w-5 text-phishing" />
                High Threat
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground">
                Multiple indicators of phishing attempt
              </p>
            </CardContent>
          </Card>
        </div>
        
        <FlowArrow />
        
        {/* Output Step */}
        <FlowchartStep 
          icon={<CheckCircle className="h-6 w-6 text-green-500" />}
          title="Result Display"
          description="Shows detailed threat analysis with highlighted indicators"
          position="end"
        />
      </div>
      
      {/* Legend */}
      <div className="mt-8 border-t pt-4 border-border/30">
        <h3 className="text-sm font-medium mb-2">Key Components:</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
          <div className="flex items-center gap-2">
            <Search className="h-4 w-4 text-cyber-blue" />
            <span>User Input</span>
          </div>
          <div className="flex items-center gap-2">
            <Eye className="h-4 w-4 text-amber-500" />
            <span>Pattern Analysis</span>
          </div>
          <div className="flex items-center gap-2">
            <Link2 className="h-4 w-4 text-blue-500" />
            <span>URL Analysis</span>
          </div>
          <div className="flex items-center gap-2">
            <Database className="h-4 w-4 text-emerald-500" />
            <span>Risk Scoring</span>
          </div>
        </div>
      </div>
    </div>
  );
};

interface FlowchartStepProps {
  icon: React.ReactNode;
  title: string;
  description: string;
  position?: 'start' | 'end' | undefined;
  variant?: 'main' | 'branch';
}

const FlowchartStep: React.FC<FlowchartStepProps> = ({ 
  icon, 
  title, 
  description, 
  position,
  variant = 'main'
}) => {
  return (
    <div className={cn(
      "border rounded-lg p-4 bg-background max-w-xl mx-auto relative",
      position === 'start' && "border-cyber-blue/30",
      position === 'end' && "border-green-500/30",
      variant === 'branch' && "max-w-full"
    )}>
      <div className="flex items-center gap-3">
        <div className={cn(
          "rounded-full p-2 flex items-center justify-center",
          position === 'start' && "bg-cyber-blue/10",
          position === 'end' && "bg-green-500/10",
          !position && variant === 'main' && "bg-gray-100 dark:bg-gray-800",
          variant === 'branch' && "bg-gray-100/50 dark:bg-gray-800/50"
        )}>
          {icon}
        </div>
        <div>
          <h3 className="font-medium">{title}</h3>
          <p className="text-xs text-muted-foreground">{description}</p>
        </div>
      </div>
    </div>
  );
};

interface FlowArrowProps {
  direction?: 'down' | 'right' | 'left';
}

const FlowArrow: React.FC<FlowArrowProps> = ({ direction = 'down' }) => {
  return (
    <div className="flex justify-center my-2">
      {direction === 'down' && (
        <div className="h-8 w-0.5 bg-gray-300 dark:bg-gray-700"></div>
      )}
      {direction === 'right' && (
        <div className="flex items-center justify-end w-full">
          <ArrowRight className="h-5 w-5 text-muted-foreground rotate-45" />
        </div>
      )}
      {direction === 'left' && (
        <div className="flex items-center justify-start w-full">
          <ArrowRight className="h-5 w-5 text-muted-foreground rotate-[-45deg]" />
        </div>
      )}
    </div>
  );
};

export default PhishingFlowchart;
