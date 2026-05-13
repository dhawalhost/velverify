import React from 'react';
import { RedocStandalone } from 'redoc';
import { Terminal, BookOpen, Code2, Cpu } from 'lucide-react';
import { 
    PageHeader, 
    GlassCard, 
    GlassCardHeader, 
    GlassCardTitle, 
    GlassCardContent 
} from '@/components/layout';

const Developer: React.FC = () => {
    return (
        <div className="space-y-4 animate-in fade-in duration-700">
            <PageHeader 
                icon={<BookOpen className="w-5 h-5 text-primary" />}
                title="API Documentation"
                description="Explore our API documentation and integration guides."
            />

            <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
                <div className="lg:col-span-1 space-y-4">
                    <div className="space-y-2">
                        <p className="text-[9px] font-bold text-on-surface-variant/40 uppercase tracking-[0.2em] ml-1">Resources</p>
                        <div className="space-y-1">
                            {[
                                { label: 'Go SDK Client', icon: <Cpu className="w-3.5 h-3.5" /> },
                                { label: 'CLI Reference', icon: <Terminal className="w-3.5 h-3.5" /> },
                                { label: 'OpenAPI Spec', icon: <Code2 className="w-3.5 h-3.5" /> },
                            ].map(link => (
                                <button key={link.label} className="w-full text-left p-2 rounded-lg hover:bg-surface-container/40 transition-all flex items-center gap-2 group">
                                    <div className="text-on-surface-variant/40 group-hover:text-primary transition-colors">{link.icon}</div>
                                    <span className="text-[12px] font-bold text-on-surface group-hover:translate-x-1 transition-transform">{link.label}</span>
                                </button>
                            ))}
                        </div>
                    </div>

                    <GlassCard className="bg-primary text-primary-foreground border-none shadow-xl shadow-primary/20 overflow-hidden relative rounded-xl">
                        <div className="absolute top-0 right-0 p-3 opacity-10">
                            <Terminal className="w-12 h-12 rotate-12" />
                        </div>
                        <GlassCardContent className="p-3 space-y-3 relative z-10">
                            <div className="space-y-0.5">
                                <p className="text-[8px] font-black uppercase tracking-[0.3em] opacity-60">Distribution</p>
                                <h4 className="text-md font-black italic tracking-tighter uppercase">WardSeal Go</h4>
                            </div>
                            <div className="bg-black/20 p-2 rounded-lg font-mono text-[9px] border border-on-inverse/10 backdrop-blur-sm">
                                <code>go get github.com/...</code>
                            </div>
                        </GlassCardContent>
                    </GlassCard>
                </div>

                <div className="lg:col-span-3">
                    <GlassCard className="overflow-hidden border-none shadow-xl shadow-on-surface/5 bg-card min-h-[600px] rounded-xl">
                        <GlassCardHeader className="py-3 px-5 border-b border-on-surface/5">
                            <div className="flex items-center gap-2.5">
                                <Code2 className="w-4 h-4 text-primary" />
                                <GlassCardTitle className="text-sm font-bold tracking-tight">API Reference</GlassCardTitle>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-0">
                            <div className="redoc-wrapper bg-card">
                                <RedocStandalone specUrl="/openapi.yaml" />
                            </div>
                        </GlassCardContent>
                    </GlassCard>
                </div>
            </div>

            <style>{`
                /* ReDoc Modernist Refinement */
                .redoc-wrapper { overflow: hidden; border-radius: 0.75rem; }
                [role="main"] { padding: 0 !important; }
                .menu-content { background-color: transparent !important; }
                .sc-fzoLag { font-family: inherit !important; }
            `}</style>
        </div>
    );
};

export default Developer;
