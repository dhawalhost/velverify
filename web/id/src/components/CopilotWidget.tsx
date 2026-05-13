import React, { useState, useEffect, useRef } from 'react';
import { Sparkles, X, Send, Bot, User, Loader2, ShieldCheck } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { GlassCard } from '@/components/layout';
import { askAI } from '@/api';
import { cn } from '@/lib/utils';

interface Message {
  role: 'bot' | 'user';
  text: string;
}

const CopilotWidget = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [messages, setMessages] = useState<Message[]>([
    { role: 'bot', text: "Hello! I am your Security Copilot. Ask me anything about your identity posture or active requests." }
  ]);
  const [loading, setLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' });
    }
  }, [messages]);

  const handleSend = async () => {
    if (!query.trim() || loading) return;

    const userMsg = query;
    setQuery('');
    setMessages(prev => [...prev, { role: 'user', text: userMsg }]);
    setLoading(true);

    try {
      const response = await askAI(userMsg);
      setMessages(prev => [...prev, { role: 'bot', text: response.answer }]);
    } catch (error) {
      console.error('AI Query failed:', error);
      setMessages(prev => [...prev, { role: 'bot', text: "I encountered an error while analyzing the data. Please ensure the AI service is active." }]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed bottom-10 right-10 z-[100] flex flex-col items-end gap-4">
      {/* Chat Window */}
      {isOpen && (
        <GlassCard className="w-96 h-[550px] shadow-2xl flex flex-col overflow-hidden border-primary/20 animate-in slide-in-from-bottom-5 duration-300">
          <div className="h-16 flex items-center justify-between px-6 border-b bg-primary/5">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 flex items-center justify-center bg-primary rounded-lg">
                <Sparkles className="w-4.5 h-4.5 text-white" />
              </div>
              <div>
                <p className="text-sm font-bold text-on-surface leading-none">Security Copilot</p>
                <div className="flex items-center gap-1.5 mt-1">
                  <div className="w-1.5 h-1.5 bg-success rounded-full animate-pulse" />
                  <p className="text-[10px] font-bold text-success uppercase tracking-widest">Active Audit</p>
                </div>
              </div>
            </div>
            <Button variant="ghost" size="icon" onClick={() => setIsOpen(false)} className="h-8 w-8 rounded-lg hover:bg-black/5">
              <X className="w-4 h-4" />
            </Button>
          </div>

          <ScrollArea className="flex-1 p-6" viewportRef={scrollRef}>
            <div className="space-y-6">
              {messages.map((m, i) => (
                <div key={i} className={cn("flex gap-3", m.role === 'user' ? "flex-row-reverse" : "flex-row")}>
                  <div className={cn("w-8 h-8 rounded-lg flex items-center justify-center shrink-0 shadow-sm",
                    m.role === 'bot' ? "bg-primary/10 text-primary" : "bg-inverse text-on-inverse")}>
                    {m.role === 'bot' ? <Bot className="w-4 h-4" /> : <User className="w-4 h-4" />}
                  </div>
                  <div className={cn("max-w-[80%] p-4 rounded-2xl text-[13px] font-medium leading-relaxed shadow-sm",
                    m.role === 'bot'
                      ? "bg-card border text-on-surface"
                      : "bg-primary text-primary-foreground")}>
                    {m.text}
                  </div>
                </div>
              ))}
              {loading && (
                <div className="flex gap-3">
                  <div className="w-8 h-8 rounded-lg bg-primary/10 text-primary flex items-center justify-center">
                    <Loader2 className="w-4 h-4 animate-spin" />
                  </div>
                  <div className="p-4 rounded-2xl bg-card border text-[13px] font-bold italic text-on-surface-variant/40">
                    Analyzing identity graph...
                  </div>
                </div>
              )}
            </div>
          </ScrollArea>

          <div className="p-4 border-t bg-card">
            <div className="relative group">
              <Input
                placeholder="Ask a security question..."
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSend()}
                className="h-12 pr-12 rounded-xl border-none bg-surface-container font-medium text-sm focus-visible:ring-primary/20"
              />
              <Button
                onClick={handleSend}
                disabled={!query.trim() || loading}
                size="icon"
                className="absolute right-1 top-1 h-10 w-10 rounded-lg shadow-none"
              >
                <Send className="w-4 h-4" />
              </Button>
            </div>
            <p className="text-[10px] text-center text-on-surface-variant/40 mt-3 font-bold uppercase tracking-widest">
              AI can hallucinate. Verify critical insights.
            </p>
          </div>
        </GlassCard>
      )}

      {/* Trigger Button */}
      <Button
        onClick={() => setIsOpen(!isOpen)}
        className={cn(
          "w-16 h-16 rounded-2xl shadow-2xl transition-all duration-300 hover:scale-105 active:scale-95 group",
          isOpen ? "bg-on-surface" : "bg-primary"
        )}
      >
        {isOpen ? (
          <X className="w-7 h-7 text-white" />
        ) : (
          <div className="relative">
            <Sparkles className="w-7 h-7 text-white group-hover:animate-pulse" />
            <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-success rounded-full border-2 border-primary" />
          </div>
        )}
      </Button>
    </div>
  );
};

export default CopilotWidget;
