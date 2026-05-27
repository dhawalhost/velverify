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

interface SidebarLinkProps {
    label: string;
    icon: React.ReactNode;
    onClick?: () => void;
}

const SidebarLink: React.FC<SidebarLinkProps> = ({ label, icon, onClick }) => {
    return (
        <button 
            onClick={onClick}
            className="w-full text-left p-2 rounded-lg hover:bg-surface-container/40 transition-all flex items-center gap-2 group"
        >
            <div className="text-on-surface-variant/40 group-hover:text-primary transition-colors">
                {icon}
            </div>
            <span className="text-caption font-bold text-on-surface group-hover:translate-x-1 transition-transform">
                {label}
            </span>
        </button>
    );
};

const Developer: React.FC = () => {
    return (
        <div className="space-y-page animate-in fade-in duration-700">
            <PageHeader 
                icon={<BookOpen className="w-5 h-5" />}
                title="API Documentation"
                description="Explore our API documentation and integration guides."
            />

            <div className="grid grid-cols-1 lg:grid-cols-4 gap-card">
                <div className="lg:col-span-1 space-y-card">
                    <div className="space-y-2">
                        <p className="text-label text-on-surface-variant/40 uppercase tracking-widest ml-1">Resources</p>
                        <div className="space-y-1">
                            {[
                                { label: 'Go SDK Client', icon: <Cpu className="w-4 h-4" /> },
                                { label: 'CLI Reference', icon: <Terminal className="w-4 h-4" /> },
                                { label: 'OpenAPI Spec', icon: <Code2 className="w-4 h-4" /> },
                            ].map(link => (
                                <SidebarLink key={link.label} label={link.label} icon={link.icon} />
                            ))}
                        </div>
                    </div>

                    <GlassCard className="bg-primary text-primary-foreground border-none shadow-xl shadow-primary/20 overflow-hidden relative rounded-xl hover:translate-y-[-2px] transition-all duration-300">
                        <div className="absolute top-0 right-0 p-3 opacity-10">
                            <Terminal className="w-12 h-12 rotate-12" />
                        </div>
                        <GlassCardContent className="p-card space-y-3 relative z-10">
                            <div className="space-y-0.5">
                                <p className="text-detail font-bold uppercase tracking-widest opacity-60">Distribution</p>
                                <h4 className="text-heading font-black italic tracking-tighter uppercase text-white">WardSeal Go</h4>
                            </div>
                            <div className="bg-black/20 p-2 rounded-lg font-mono text-detail border border-on-inverse/10 backdrop-blur-sm">
                                <code>go get github.com/...</code>
                            </div>
                        </GlassCardContent>
                    </GlassCard>
                </div>

                <div className="lg:col-span-3">
                    <GlassCard className="overflow-hidden border-none shadow-xl shadow-on-surface/5 bg-card min-h-[600px] rounded-xl">
                        <GlassCardHeader className="py-card px-card border-b border-on-surface/5">
                            <div className="flex items-center gap-2.5">
                                <Code2 className="w-4 h-4 text-primary" />
                                <GlassCardTitle className="text-body font-bold tracking-tight">API Reference</GlassCardTitle>
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
