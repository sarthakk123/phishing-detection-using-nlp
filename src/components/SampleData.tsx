
import React, { useState } from 'react';
import { sampleTexts, SampleText } from '@/lib/sampleTexts';
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { CheckCircle2, AlertTriangle, Copy } from 'lucide-react';
import { useToast } from "@/components/ui/use-toast";

interface SampleDataProps {
  onSelectSample: (text: string) => void;
}

const SampleData: React.FC<SampleDataProps> = ({ onSelectSample }) => {
  const { toast } = useToast();
  const [expandedId, setExpandedId] = useState<number | null>(null);
  
  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Text Copied",
      description: "Sample text copied to clipboard.",
    });
  };
  
  const handleUse = (text: string) => {
    onSelectSample(text);
    toast({
      title: "Sample Loaded",
      description: "Sample text loaded into analyzer.",
    });
  };
  
  return (
    <div className="phishing-card rounded-lg p-4 md:p-6">
      <div className="mb-5">
        <h2 className="text-xl font-semibold">Sample Dataset</h2>
        <p className="text-sm text-muted-foreground">
          Example texts for demonstration purposes.
        </p>
      </div>
      
      <div className="space-y-3">
        {sampleTexts.map((sample) => (
          <Card key={sample.id} className="bg-card/50 border-cyber-blue/20 overflow-hidden">
            <CardContent className="p-4">
              <div className="flex items-start justify-between gap-2 mb-2">
                <div className="flex items-center gap-1.5">
                  {sample.type === 'legitimate' ? (
                    <CheckCircle2 className="h-4 w-4 text-green-400" />
                  ) : (
                    <AlertTriangle className="h-4 w-4 text-phishing" />
                  )}
                  <Badge className={sample.type === 'legitimate' ? 'bg-green-500' : 'bg-phishing'}>
                    {sample.type === 'legitimate' ? 'Legitimate' : 'Phishing'}
                  </Badge>
                  <span className="text-xs text-muted-foreground">{sample.source}</span>
                </div>
                
                <div className="flex gap-1">
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-7 w-7 p-0"
                    onClick={() => handleCopy(sample.content)}
                  >
                    <Copy className="h-3.5 w-3.5" />
                    <span className="sr-only">Copy</span>
                  </Button>
                </div>
              </div>
              
              <p className="text-sm text-muted-foreground line-clamp-2 mb-2">
                {sample.content}
              </p>
              
              <div className="flex flex-wrap gap-1 mt-1">
                {Object.entries(sample.features)
                  .filter(([_, value]) => value)
                  .map(([key]) => (
                    <Badge
                      key={key}
                      variant="outline"
                      className="text-xs py-0 h-5 border-cyber-blue/20"
                    >
                      {key.replace(/([A-Z])/g, ' $1').toLowerCase()}
                    </Badge>
                  ))}
              </div>
              
              <Button
                variant="link"
                size="sm"
                className="px-0 h-6 text-cyber-blue"
                onClick={() => handleUse(sample.content)}
              >
                Use this sample
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
};

export default SampleData;
