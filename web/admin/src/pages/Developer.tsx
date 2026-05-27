import React from 'react';
import { RedocStandalone } from 'redoc';
import { Terminal, BookOpen, Code2, Cpu } from 'lucide-react';
import { 
    PageHeader, 
    GlassCard, 
    GlassCardHeader, 
    GlassCardTitle, 
    GlassCardContent, PageLayout
} from '@/components/layout';

const Developer: React.FC = () => {
    return (
        <PageLayout>
        <div className="space-y-12 animate-in fade-in duration-700">
            <PageHeader 
                icon={<BookOpen className="w-8 h-8 text-primary" />}
                title="API Documentation"
                description="Explore our API documentation and integration guides."
            />

            <div className="grid grid-cols-1 lg:grid-cols-4 gap-10">
                <div className="lg:col-span-1 space-y-8">
                    <div className="space-y-4">
                        <p className="text-[10px] font-bold text-on-surface-variant/40 uppercase tracking-[0.2em]">Developer Resources</p>
                        <div className="space-y-2">
                            {[
                                { label: 'Go SDK Client', icon: <Cpu className="w-4 h-4" /> },
                                { label: 'CLI Reference', icon: <Terminal className="w-4 h-4" /> },
                                { label: 'OpenAPI Spec', icon: <Code2 className="w-4 h-4" /> },
                            ].map(link => (
                                <button key={link.label} className="w-full text-left p-4 rounded-xl hover:bg-surface-container/40 transition-all flex items-center gap-3 group">
                                    <div className="text-on-surface-variant/40 group-hover:text-primary transition-colors">{link.icon}</div>
                                    <span className="text-sm font-bold text-on-surface group-hover:translate-x-1 transition-transform">{link.label}</span>
                                </button>
                            ))}
                        </div>
                    </div>

                    <GlassCard className="bg-primary text-primary-foreground border-none shadow-xl shadow-primary/20 overflow-hidden relative">
                        <div className="absolute top-0 right-0 p-4 opacity-10">
                            <Terminal className="w-24 h-24 rotate-12" />
                        </div>
                        <GlassCardContent className="p-8 space-y-6 relative z-10">
                            <div className="space-y-1">
                                <p className="text-[10px] font-black uppercase tracking-[0.3em] opacity-60">Distribution</p>
                                <h4 className="text-xl font-black italic tracking-tighter">WARDSEAL_GO</h4>
                            </div>
                            <div className="bg-black/20 p-4 rounded-xl font-mono text-[11px] border border-on-inverse/10 backdrop-blur-sm">
                                <code>go get github.com/dhawalhost/wardseal/pkg/client</code>
                            </div>
                        </GlassCardContent>
                    </GlassCard>
                </div>

                <div className="lg:col-span-3">
                    <GlassCard className="overflow-hidden border-none shadow-xl shadow-on-surface/5 bg-card min-h-[800px]">
                        <GlassCardHeader className="py-8 px-10 border-b border-on-surface/5">
                            <div className="flex items-center gap-4">
                                <Code2 className="w-6 h-6 text-primary" />
                                <GlassCardTitle className="text-2xl font-bold tracking-tight">API Reference</GlassCardTitle>
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
                .redoc-wrapper { overflow: hidden; border-radius: 1.5rem; }
                [role="main"] { padding: 0 !important; }
                .menu-content { background-color: transparent !important; }
                .sc-fzoLag { font-family: inherit !important; }
            `}</style>
        </div>
        </PageLayout>
    );
};

export default Developer;
