import React, { useState, useEffect, useRef } from 'react';
import { 
    Sparkles, 
    Send, 
    Bot, 
    User, 
    Loader2, 
    ShieldCheck, 
    Activity, 
    History,
    RefreshCw,
    Terminal,
    AlertCircle,
    CheckCircle2
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { 
    PageHeader, 
    GlassCard, 
    GlassCardHeader, 
    GlassCardTitle, 
    GlassCardContent,
    GlassCardDescription
} from '@/components/layout';
import { askAI, getAuditLogs } from '@/api';
import { cn } from '@/lib/utils';

interface Message {
  role: 'bot' | 'user';
  text: string;
  timestamp: string;
}

const SUGGESTED_PROMPTS = [
    "Analyze current risk profile",
    "List all high-priority pending requests",
    "Who has access to production data?",
    "Summarize recent audit logs",
];

const CopilotPage: React.FC = () => {
  const [query, setQuery] = useState('');
  const [messages, setMessages] = useState<Message[]>([
    { 
        role: 'bot', 
        text: "Hello! I am your Security Copilot. I have analyzed your identity graph and I'm ready to help you audit your organization's posture.",
        timestamp: new Date().toLocaleTimeString()
    }
  ]);
  const [loading, setLoading] = useState(false);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [logsLoading, setLogsLoading] = useState(true);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetchLogs();
  }, []);

  const fetchLogs = async () => {
    try {
        setLogsLoading(true);
        const res = await getAuditLogs({ limit: 5 });
        setAuditLogs(res.logs || []);
    } catch (err) {
        console.error("Failed to fetch logs", err);
    } finally {
        setLogsLoading(false);
    }
  }

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' });
    }
  }, [messages]);

  const handleSend = async (customQuery?: string) => {
    const activeQuery = customQuery || query;
    if (!activeQuery.trim() || loading) return;

    const userMsg = activeQuery;
    setQuery('');
    setMessages(prev => [...prev, { 
        role: 'user', 
        text: userMsg,
        timestamp: new Date().toLocaleTimeString()
    }]);
    setLoading(true);

    try {
      const response = await askAI(userMsg);
      setMessages(prev => [...prev, { 
          role: 'bot', 
          text: response.answer,
          timestamp: new Date().toLocaleTimeString()
      }]);
    } catch (error) {
      console.error('AI Query failed:', error);
      setMessages(prev => [...prev, { 
          role: 'bot', 
          text: "I encountered an error while analyzing the security context. Please ensure the backend AI service is properly configured with OpenRouter.",
          timestamp: new Date().toLocaleTimeString()
      }]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-10 animate-in fade-in duration-700 h-[calc(100vh-160px)] flex flex-col">
      <PageHeader 
        icon={<Sparkles className="w-8 h-8 text-primary shadow-sm" />}
        title="Security Copilot"
        description="Autonomous identity governance and real-time audit intelligence."
      />

      <div className="flex-1 grid grid-cols-1 lg:grid-cols-4 gap-10 overflow-hidden">
        {/* Sidebar Info */}
        <div className="lg:col-span-1 space-y-8 h-full overflow-y-auto pr-4 hidden lg:block custom-scrollbar">
            <div className="space-y-4">
                <p className="text-[10px] font-bold text-on-surface-variant/40 uppercase tracking-[0.22em] ml-1">Live Intelligence</p>
                <div className="space-y-3">
                    {[
                        { label: 'Identity Graph', status: 'Healthy', icon: <History className="w-3.5 h-3.5" /> },
                        { label: 'Access Policies', status: 'Active', icon: <ShieldCheck className="w-3.5 h-3.5" /> },
                        { label: 'Audit Stream', status: 'Recording', icon: <Activity className="w-3.5 h-3.5" /> },
                    ].map(item => (
                        <div key={item.label} className="p-4 rounded-2xl bg-card shadow-sm ring-1 ring-on-surface/5 flex items-center justify-between group hover:ring-primary/20 transition-all">
                            <div className="flex items-center gap-3">
                                <div className="text-primary/40 group-hover:text-primary transition-colors">{item.icon}</div>
                                <span className="text-[12px] font-bold text-on-surface">{item.label}</span>
                            </div>
                            <span className="text-[9px] font-black uppercase tracking-tighter text-success bg-success-subtle px-2 py-0.5 rounded-full">{item.status}</span>
                        </div>
                    ))}
                </div>
            </div>

            <div className="space-y-4">
                <p className="text-[10px] font-bold text-on-surface-variant/40 uppercase tracking-[0.22em] ml-1">Recent Activity</p>
                <div className="space-y-3">
                    {logsLoading ? (
                        [1, 2, 3].map(i => <div key={i} className="h-16 bg-surface-container/30 animate-pulse rounded-2xl" />)
                    ) : auditLogs.length === 0 ? (
                        <div className="p-4 rounded-2xl bg-surface-container/10 border border-dashed border-on-surface/10 text-center">
                            <p className="text-[11px] font-medium text-on-surface-variant/40">No activity recorded yet.</p>
                        </div>
                    ) : (
                        auditLogs.map((log, i) => (
                            <div key={log.id || i} className="p-4 rounded-2xl bg-card shadow-sm ring-1 ring-on-surface/5 space-y-1.5 transition-all hover:translate-x-1">
                                <div className="flex items-center justify-between">
                                    <span className="text-[10px] font-black uppercase tracking-tighter text-on-surface-variant/60">{log.action}</span>
                                    <span className="text-[9px] font-medium text-on-surface-variant/40">{new Date(log.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</span>
                                </div>
                                <p className="text-[11px] font-medium text-on-surface leading-tight line-clamp-2">
                                    {log.details?.reason || log.details?.user_id || "System action performed."}
                                </p>
                            </div>
                        ))
                    )}
                </div>
                <Button variant="ghost" onClick={() => window.location.href='/audit'} className="w-full text-[10px] font-bold uppercase tracking-widest text-primary/60 hover:text-primary hover:bg-primary/5">View Full Audit Log</Button>
            </div>

            <div className="space-y-4">
                <p className="text-[10px] font-bold text-on-surface-variant/40 uppercase tracking-[0.22em] ml-1">Suggested Inquiries</p>
                <div className="flex flex-col gap-2">
                    {SUGGESTED_PROMPTS.map(p => (
                        <button 
                            key={p}
                            onClick={() => handleSend(p)}
                            className="text-left p-4 rounded-xl hover:bg-primary/5 hover:text-primary transition-all group ring-1 ring-transparent hover:ring-primary/10 bg-surface-container/30"
                        >
                            <span className="text-[12px] font-bold block opacity-60 group-hover:opacity-100 transition-opacity">{p}</span>
                        </button>
                    ))}
                </div>
            </div>
        </div>

        {/* Chat Area */}
        <div className="lg:col-span-3 flex flex-col h-full bg-card rounded-[32px] shadow-2xl shadow-on-surface/5 overflow-hidden ring-1 ring-on-surface/5">
            <header className="bg-surface-container/50 px-10 py-6 border-b flex items-center justify-between shrink-0">
                <div className="flex items-center gap-4">
                    <div className="w-11 h-11 bg-primary rounded-2xl flex items-center justify-center shadow-lg shadow-primary/20">
                        <Bot className="w-6 h-6 text-white" />
                    </div>
                    <div>
                        <h4 className="text-xl font-bold tracking-tight text-on-surface">WARDSEAL_AI</h4>
                        <div className="flex items-center gap-2 mt-0.5">
                            <div className="w-2 h-2 bg-success rounded-full animate-pulse" />
                            <span className="text-[10px] font-black uppercase tracking-[0.2em] text-success">Cognitive Hub Active</span>
                        </div>
                    </div>
                </div>
                <div className="flex items-center gap-3">
                    <Button variant="ghost" size="icon" className="h-11 w-11 rounded-xl bg-card shadow-sm ring-1 ring-on-surface/5 text-on-surface-variant/40 hover:text-primary transition-all transform hover:rotate-180 duration-500" onClick={() => setMessages([{role: 'bot', text: 'Cognitive buffer cleared. Ready for new audit instructions.', timestamp: new Date().toLocaleTimeString()}])}>
                        <RefreshCw className="w-5 h-5" />
                    </Button>
                </div>
            </header>

            <ScrollArea className="flex-1 px-10 py-10 bg-card/50" viewportRef={scrollRef}>
                <div className="space-y-12 max-w-5xl mx-auto">
                    {messages.map((m, i) => (
                        <div key={i} className={cn("flex gap-6 animate-in slide-in-from-bottom-3 duration-500", m.role === 'user' ? "flex-row-reverse" : "flex-row")}>
                            <div className={cn(
                                "w-12 h-12 rounded-2xl flex items-center justify-center shrink-0 shadow-lg transition-transform hover:scale-110",
                                m.role === 'bot' ? "bg-primary text-primary-foreground" : "bg-black text-white"
                            )}>
                                {m.role === 'bot' ? <Sparkles className="w-6 h-6" /> : <User className="w-6 h-6" />}
                            </div>
                            <div className={cn("space-y-2", m.role === 'user' ? "items-end" : "items-start")}>
                                <div className={cn(
                                    "p-7 rounded-[32px] text-[15px] font-medium leading-relaxed shadow-sm ring-1 ring-on-surface/5 max-w-2xl whitespace-pre-wrap",
                                    m.role === 'bot' ? "bg-card text-on-surface" : "bg-surface-container text-on-surface"
                                )}>
                                    {m.text}
                                </div>
                                <p className={cn("text-[10px] font-bold text-on-surface-variant/30 uppercase tracking-[0.2em]", m.role === 'user' ? "mr-4" : "ml-4")}>
                                    {m.timestamp}
                                </p>
                            </div>
                        </div>
                    ))}
                    {loading && (
                        <div className="flex gap-6 animate-pulse">
                            <div className="w-12 h-12 rounded-2xl bg-primary/10 text-primary flex items-center justify-center border border-primary/20">
                                <Loader2 className="w-6 h-6 animate-spin" />
                            </div>
                            <div className="p-7 rounded-[32px] bg-card border border-dashed border-primary/20 text-[15px] font-black italic text-primary/40">
                                Retrieving identity Graph & Audit streams...
                            </div>
                        </div>
                    )}
                </div>
            </ScrollArea>

            <div className="p-10 bg-card border-t shrink-0">
                <div className="relative group max-w-5xl mx-auto ring-1 ring-on-surface/5 rounded-[24px] focus-within:ring-primary/40 transition-all shadow-inner overflow-hidden">
                    <Input
                        placeholder="Inspect organization hygiene or ask about specific governance events..."
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && handleSend()}
                        className="h-16 pr-24 border-none bg-surface-container/20 text-base font-semibold focus-visible:ring-0 px-8 text-on-surface placeholder:text-on-surface-variant/30"
                    />
                    <div className="absolute right-2 top-2">
                        <Button
                            onClick={() => handleSend()}
                            disabled={!query.trim() || loading}
                            className="h-12 w-12 rounded-2xl shadow-xl shadow-primary/20 transition-all hover:translate-y-[-2px] active:translate-y-[0px] bg-primary hover:bg-primary-hover"
                        >
                            <Send className="w-5 h-5" />
                        </Button>
                    </div>
                </div>
                <div className="max-w-5xl mx-auto mt-4 px-4 flex items-center justify-between text-on-surface-variant/20">
                    <div className="flex items-center gap-2">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span className="text-[10px] font-bold uppercase tracking-widest">End-to-End Encrypted</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <AlertCircle className="w-3.5 h-3.5" />
                        <span className="text-[10px] font-bold uppercase tracking-widest">AI Insights May require human verification</span>
                    </div>
                </div>
            </div>
        </div>
      </div>
    </div>
  );
};

export default CopilotPage;
