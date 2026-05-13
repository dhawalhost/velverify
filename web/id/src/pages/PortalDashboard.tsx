import { useState, useEffect } from 'react';
import { Button } from "@/components/ui/button";
import { ExternalLink, LayoutGrid, Search, Loader2, Sparkles, Box } from "lucide-react";
import { Input } from "@/components/ui/input";
import { getUserApps } from '../api';
import { GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassCardDescription } from '@/components/layout';

interface Application {
    id: string;
    name: string;
    description: string;
    icon_url?: string;
    launch_url: string;
}

const PortalDashboard = () => {
    const [applications, setApplications] = useState<Application[]>([]);
    const [searchQuery, setSearchQuery] = useState('');
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchApplications = async () => {
            setLoading(true);
            try {
                const data = await getUserApps();
                setApplications(data.apps || []);
            } catch (error) {
                console.error('Failed to fetch applications:', error);
            } finally {
                setLoading(false);
            }
        };

        fetchApplications();
    }, []);

    const filteredApps = applications.filter(app =>
        app.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        app.description.toLowerCase().includes(searchQuery.toLowerCase())
    );

    const handleLaunch = (app: Application) => {
        window.open(app.launch_url, '_blank');
    };

    return (
        <div className="space-y-12 animate-in fade-in duration-700">
            {/* Header: Modernist */}
            <div className="flex flex-col gap-12">
                {/* Header: Modernist */}
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-10 border-b border-on-surface/5 pb-12">
                    <div className="space-y-6">
                        <div className="flex items-center gap-4">
                            <div className="w-12 h-12 flex items-center justify-center">
                                <img src="/wardseal.svg" alt="WardSeal" className="w-10 h-10" />
                            </div>
                            <div className="flex flex-col">
                                <span className="text-2xl font-bold tracking-tight text-on-surface">WardSeal</span>
                                <span className="text-[11px] font-bold tracking-widest text-primary uppercase opacity-60">Identity Portal</span>
                            </div>
                        </div>
                        <div className="space-y-4">
                            <h1 className="text-6xl font-bold tracking-tight text-on-surface leading-[0.9]">Resource<br />Registry</h1>
                            <p className="text-on-surface-variant/60 font-medium text-lg max-w-xl leading-relaxed">
                                Securely access and manage your application tunnels and enterprise resources.
                            </p>
                            {localStorage.getItem('isAdmin') === 'true' && (
                                <div className="pt-4">
                                    <Button
                                        onClick={() => {
                                            const adminUrl = window.location.hostname.endsWith('.local')
                                                ? 'http://admin.wardseal.local'
                                                : 'https://admin.wardseal.com';
                                            window.location.assign(adminUrl);
                                        }}
                                        className="h-12 px-8 rounded-2xl bg-inverse text-on-inverse font-bold text-sm hover:opacity-90 transition-all flex items-center gap-3 shadow-xl shadow-on-surface/10"
                                    >
                                        <LayoutGrid className="w-5 h-5" />
                                        Admin Console
                                    </Button>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* SEARCH: Deep Modernist */}
                    <div className="relative w-full max-w-xl group self-end">
                        <div className="absolute -inset-1 bg-gradient-to-r from-primary/20 to-transparent rounded-[32px] blur opacity-0 group-focus-within:opacity-100 transition duration-500" />
                        <div className="relative">
                            <Search className="absolute left-6 top-1/2 -translate-y-1/2 h-5 w-5 text-on-surface-variant/40 group-focus-within:text-primary transition-colors" />
                            <Input
                                placeholder="Search resource registry..."
                                value={searchQuery}
                                onChange={(e) => setSearchQuery(e.target.value)}
                                className="h-20 pl-16 pr-8 border-none rounded-[32px] font-bold text-lg bg-card/40 backdrop-blur-2xl shadow-2xl ring-1 ring-on-surface/10 focus-visible:ring-2 focus-visible:ring-primary/40 transition-all"
                            />
                        </div>
                    </div>
                </div>

                {/* Applications Grid */}
                <div className="min-h-[400px]">
                    {loading ? (
                        <div className="h-[400px] flex flex-col items-center justify-center border border-dashed rounded-[48px] bg-card/20 backdrop-blur-sm">
                            <Loader2 className="h-12 w-12 animate-spin mb-6 text-primary/40" />
                            <span className="text-[14px] font-bold tracking-widest opacity-20 uppercase italic">Synchronizing Registry...</span>
                        </div>
                    ) : filteredApps.length === 0 ? (
                        <GlassCard className="py-40 text-center border-2 border-dashed border-on-surface/5 bg-card/20 shadow-none rounded-[48px]">
                            <Box className="h-20 w-20 text-on-surface-variant/5 mb-8 mx-auto" />
                            <h3 className="text-3xl font-bold text-on-surface tracking-tight">Digital Void</h3>
                            <p className="text-on-surface-variant/40 font-medium text-lg mt-4 max-w-sm mx-auto leading-relaxed">
                                {searchQuery ? `No resources matching "${searchQuery}" located in the secure sector.` : 'No resources have been provisioned for this identity profile.'}
                            </p>
                        </GlassCard>
                    ) : (
                        <div className="grid gap-10 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                            {filteredApps.map((app) => (
                                <GlassCard key={app.id} className="group hover:ring-primary/40 hover:shadow-2xl hover:shadow-primary/10 transition-all duration-500 overflow-hidden flex flex-col bg-card/40 hover:bg-card/60">
                                    <GlassCardHeader className="p-10 pb-6">
                                        <div className="flex items-start justify-between">
                                            <div className="flex flex-col gap-6">
                                                <div className="w-16 h-16 bg-card/50 rounded-2xl flex items-center justify-center group-hover:scale-110 transition-transform ring-1 ring-on-surface/5 shadow-inner">
                                                    {app.icon_url ? (
                                                        <img src={app.icon_url} alt={app.name} className="w-10 h-10 object-contain" />
                                                    ) : (
                                                        <Sparkles className="w-8 h-8 text-primary shadow-glow" />
                                                    )}
                                                </div>
                                                <div className="flex flex-col gap-1.5">
                                                    <div className="flex items-center gap-2">
                                                        <div className="w-2 h-2 bg-success rounded-full animate-pulse shadow-glow-success" />
                                                        <span className="font-bold text-[10px] tracking-widest text-success uppercase">Protected Node</span>
                                                    </div>
                                                    <GlassCardTitle className="text-2xl font-bold tracking-tight text-on-surface group-hover:text-primary transition-colors leading-none">{app.name}</GlassCardTitle>
                                                </div>
                                            </div>
                                        </div>
                                    </GlassCardHeader>
                                    <GlassCardContent className="p-10 pt-0 space-y-10 flex-1 flex flex-col justify-between">
                                        <p className="text-[15px] font-medium text-on-surface-variant/80 leading-relaxed line-clamp-4">
                                            {app.description || 'Enterprise-grade secure resource with end-to-end identity verification enabled.'}
                                        </p>

                                        <div className="space-y-6">
                                            <div className="px-5 py-4 bg-surface-container/50 rounded-2xl font-mono text-[11px] truncate text-on-surface-variant/40 ring-1 ring-on-surface/5">
                                                <span className="opacity-40 mr-2">$</span>{app.launch_url}
                                            </div>
                                            <Button
                                                onClick={() => handleLaunch(app)}
                                                className="w-full h-14 rounded-2xl font-bold text-sm tracking-wide shadow-xl shadow-primary/10 transition-all group-hover:bg-primary group-hover:text-primary-foreground"
                                            >
                                                Establish Tunnel
                                                <ExternalLink className="ml-3 h-5 w-5 opacity-50" />
                                            </Button>
                                        </div>
                                    </GlassCardContent>
                                </GlassCard>
                            ))}
                        </div>
                    )}
                </div>

                {/* Footer Metrics */}
                <div className="mt-20 grid grid-cols-1 md:grid-cols-3 gap-10">
                    <GlassCard className="p-12 flex flex-col justify-center bg-card/20 hover:bg-card/40 transition-all group">
                        <span className="text-[11px] font-bold tracking-[0.2em] text-primary uppercase opacity-40">Resources_Index</span>
                        <div className="flex items-baseline gap-4 mt-2">
                            <p className="text-7xl font-bold text-on-surface tracking-tighter tabular-nums">{filteredApps.length.toString().padStart(2, '0')}</p>
                            <span className="text-sm font-bold text-on-surface-variant/20 italic tracking-tight">Available</span>
                        </div>
                    </GlassCard>
                    <GlassCard className="p-12 flex flex-col justify-center bg-card/20 hover:bg-card/40 transition-all">
                        <span className="text-[11px] font-bold tracking-[0.2em] text-primary uppercase opacity-40">Total_Provisioned</span>
                        <div className="flex items-baseline gap-4 mt-2">
                            <p className="text-7xl font-bold text-on-surface tracking-tighter tabular-nums">{applications.length.toString().padStart(2, '0')}</p>
                            <span className="text-[10px] font-bold text-on-surface-variant/30 mt-2 tracking-widest uppercase">All Resources</span>
                        </div>
                    </GlassCard>
                    <GlassCard className="p-12 flex flex-col justify-center bg-card/20 hover:bg-card/40 transition-all">
                        <span className="text-[11px] font-bold tracking-[0.2em] text-primary uppercase opacity-40">Session_Status</span>
                        <div className="flex items-center gap-5 mt-4">
                            <div className="w-4 h-4 rounded-full bg-success animate-pulse shadow-[0_0_20px_rgba(34,197,94,0.6)]" />
                            <p className="text-6xl font-bold text-on-surface tracking-tighter">LIVE</p>
                        </div>
                        <span className="text-[10px] font-bold text-on-surface-variant/30 mt-2 tracking-widest uppercase">Identity Verified</span>
                    </GlassCard>
                </div>
            </div>
        </div>
    );
};

export default PortalDashboard;

