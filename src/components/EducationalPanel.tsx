
import React from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import { LightbulbIcon, BookOpen, Zap, AlertCircle, KeyRound } from 'lucide-react';

const EducationalPanel: React.FC = () => {
  return (
    <div className="phishing-card rounded-lg p-4 md:p-6">
      <div className="mb-5 flex items-center gap-2">
        <LightbulbIcon className="h-5 w-5 text-cyber-blue" />
        <h2 className="text-xl font-semibold">Educational Resources</h2>
      </div>
      
      <Tabs defaultValue="what" className="space-y-4">
        <TabsList className="bg-card/50 border border-cyber-blue/20">
          <TabsTrigger value="what">What is Phishing?</TabsTrigger>
          <TabsTrigger value="nlp">NLP Detection</TabsTrigger>
          <TabsTrigger value="tips">Prevention Tips</TabsTrigger>
        </TabsList>
        
        <TabsContent value="what" className="space-y-4">
          <div className="flex gap-2">
            <BookOpen className="h-5 w-5 text-cyber-blue flex-shrink-0 mt-1" />
            <div>
              <h3 className="text-base font-medium">Phishing Defined</h3>
              <p className="text-sm text-muted-foreground">
                Phishing is a cybercrime where targets are contacted by email, phone, or text message by 
                someone posing as a legitimate institution to lure them into providing sensitive data.
              </p>
            </div>
          </div>
          
          <Separator className="bg-border/30" />
          
          <div className="flex gap-2">
            <AlertCircle className="h-5 w-5 text-phishing flex-shrink-0 mt-1" />
            <div>
              <h3 className="text-base font-medium">Common Signs</h3>
              <ul className="text-sm text-muted-foreground list-disc pl-5 space-y-1">
                <li>Urgent calls to action</li>
                <li>Suspicious links or domains</li>
                <li>Requests for personal information</li>
                <li>Poor grammar or spelling</li>
                <li>Impersonation of trusted organizations</li>
              </ul>
            </div>
          </div>
        </TabsContent>
        
        <TabsContent value="nlp" className="space-y-4">
          <div className="flex gap-2">
            <Zap className="h-5 w-5 text-cyber-blue flex-shrink-0 mt-1" />
            <div>
              <h3 className="text-base font-medium">How NLP Detects Phishing</h3>
              <p className="text-sm text-muted-foreground">
                Natural Language Processing (NLP) analyzes text to identify phishing attacks by:
              </p>
              <ul className="text-sm text-muted-foreground list-disc pl-5 space-y-1 mt-2">
                <li>Identifying suspicious keywords and patterns</li>
                <li>Analyzing sentiment and urgency indicators</li>
                <li>Detecting brand impersonation attempts</li>
                <li>Examining URL structures and domains</li>
                <li>Evaluating grammar and language patterns</li>
              </ul>
            </div>
          </div>
        </TabsContent>
        
        <TabsContent value="tips" className="space-y-4">
          <div className="flex gap-2">
            <KeyRound className="h-5 w-5 text-cyber-blue flex-shrink-0 mt-1" />
            <div>
              <h3 className="text-base font-medium">Prevention Best Practices</h3>
              <ul className="text-sm text-muted-foreground list-disc pl-5 space-y-1">
                <li>Never click suspicious links in emails or messages</li>
                <li>Verify sender identities through official channels</li>
                <li>Don't share personal information in response to unsolicited contacts</li>
                <li>Check email addresses carefully for subtle misspellings</li>
                <li>Use multi-factor authentication when available</li>
                <li>Keep software and security systems updated</li>
                <li>Report suspected phishing attempts to relevant organizations</li>
              </ul>
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default EducationalPanel;
