
import React, { useState } from 'react';
import Header from '@/components/Header';
import PhishingAnalyzer from '@/components/PhishingAnalyzer';
import EducationalPanel from '@/components/EducationalPanel';
import SampleData from '@/components/SampleData';
import PhishingFlowchart from '@/components/PhishingFlowchart';
import { Shield, Code, Database, AtomIcon } from 'lucide-react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

const Index = () => {
  const [inputText, setInputText] = useState('');
  const [activeTab, setActiveTab] = useState('analyzer');
  
  const handleSampleSelect = (text: string) => {
    setInputText(text);
    setActiveTab('analyzer'); // Switch to analyzer tab when sample is selected
  };

  return (
    <div className="min-h-screen flex flex-col">
      <Header />
      
      <main className="flex-1 container py-8">
        <div className="mb-8 text-center max-w-3xl mx-auto">
          <h1 className="text-3xl md:text-4xl font-bold mb-4 gradient-text">
            Advanced Phishing Attack Detection
          </h1>
          <p className="text-muted-foreground">
            Using Natural Language Processing (NLP) to detect and prevent phishing attacks in emails, messages, and websites.
          </p>
          
          <div className="flex flex-wrap justify-center gap-6 mt-6">
            <div className="flex items-center gap-2 text-sm">
              <Shield className="h-4 w-4 text-cyber-blue" />
              <span>NLP Analysis</span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <Code className="h-4 w-4 text-cyber-blue" />
              <span>Pattern Recognition</span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <Database className="h-4 w-4 text-cyber-blue" />
              <span>Sample Dataset</span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <AtomIcon className="h-4 w-4 text-cyber-blue" />
              <span>Educational Resources</span>
            </div>
          </div>
        </div>
        
        <Tabs value={activeTab} onValueChange={setActiveTab} className="mb-6">
          <TabsList className="grid w-full max-w-md mx-auto grid-cols-2">
            <TabsTrigger value="analyzer">Phishing Analyzer</TabsTrigger>
            <TabsTrigger value="flowchart">System Architecture</TabsTrigger>
          </TabsList>
          <TabsContent value="analyzer" className="mt-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2 space-y-6">
                <PhishingAnalyzer initialText={inputText} />
                <EducationalPanel />
              </div>
              
              <div>
                <SampleData onSelectSample={handleSampleSelect} />
              </div>
            </div>
          </TabsContent>
          <TabsContent value="flowchart" className="mt-6">
            <PhishingFlowchart />
          </TabsContent>
        </Tabs>
      </main>
      
      <footer className="border-t border-border/40 py-6">
        <div className="container">
          <div className="text-center text-sm text-muted-foreground">
            <p>Advanced Phishing Attack Detection System Using NLP</p>
            <p className="text-xs mt-1">
              Created for educational and research purposes only.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Index;
