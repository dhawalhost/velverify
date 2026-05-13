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
        <div className="space-y-6 animate-in fade-in duration-700">
            {/* Header: Modernist */}
            <div className="flex flex-col gap-4">
                {/* Header: Modernist */}
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-on-surface/5 pb-4">
                    <div className="space-y-4">
                        <div className="flex items-center gap-3">
                            <div className="w-8 h-8 flex items-center justify-center">
                                <img src="/wardseal.svg" alt="WardSeal" className="w-6 h-6" />
                            </div>
                            <div className="flex flex-col">
                                <span className="text-lg font-bold tracking-tight text-on-surface">WardSeal</span>
                                <span className="text-[9px] font-bold tracking-widest text-primary uppercase opacity-40">Identity Portal</span>
                            </div>
                        </div>
                        <div className="space-y-1">
                            <h1 className="text-2xl font-bold tracking-tight text-on-surface leading-none">Resource Registry</h1>
                            <p className="text-on-surface-variant/60 font-medium text-xs max-w-xl">
                                Securely access and manage your application tunnels and enterprise resources.
                            </p>
                            {localStorage.getItem('isAdmin') === 'true' && (
                                <div className="pt-2">
                                    <Button
                                        onClick={() => window.location.href = '/dashboard'}
                                        className="h-8 px-4 rounded-lg bg-inverse text-on-inverse font-bold text-[10px] hover:opacity-90 transition-all flex items-center gap-2 shadow-lg shadow-on-surface/5"
                                    >
                                        <LayoutGrid className="w-3.5 h-3.5" />
                                        Admin Console
                                    </Button>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* SEARCH: Deep Modernist */}
                    <div className="relative w-full max-w-md group self-end">
                        <div className="absolute -inset-1 bg-gradient-to-r from-primary/10 to-transparent rounded-xl blur opacity-0 group-focus-within:opacity-100 transition duration-500" />
                        <div className="relative">
                            <Search className="absolute left-4 top-1/2 -translate-y-1/2 h-4 w-4 text-on-surface-variant/40 group-focus-within:text-primary transition-colors" />
                            <Input
                                placeholder="Search registry..."
                                value={searchQuery}
                                onChange={(e) => setSearchQuery(e.target.value)}
                                className="h-9 pl-10 pr-4 border-none rounded-lg font-bold text-xs bg-card/40 backdrop-blur-2xl shadow-xl ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all"
                            />
                        </div>
                    </div>
                </div>

                {/* Applications Grid */}
                <div className="min-h-[400px]">
                    {loading ? (
                        <div className="h-[300px] flex flex-col items-center justify-center border border-dashed rounded-[32px] bg-card/20 backdrop-blur-sm">
                            <Loader2 className="h-10 w-10 animate-spin mb-4 text-primary/40" />
                            <span className="text-[12px] font-bold tracking-widest opacity-20 uppercase italic">Synchronizing...</span>
                        </div>
                    ) : filteredApps.length === 0 ? (
                        <GlassCard className="py-24 text-center border border-dashed border-on-surface/5 bg-card/20 shadow-none rounded-[32px]">
                            <Box className="h-12 w-12 text-on-surface-variant/5 mb-6 mx-auto" />
                            <h3 className="text-xl font-bold text-on-surface tracking-tight">Registry Empty</h3>
                            <p className="text-on-surface-variant/40 font-medium text-sm mt-2 max-w-xs mx-auto">
                                {searchQuery ? `No resources matching "${searchQuery}" located.` : 'No resources have been provisioned for this identity.'}
                            </p>
                        </GlassCard>
                    ) : (
                        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                            {filteredApps.map((app) => (
                                <GlassCard key={app.id} className="group hover:ring-primary/20 hover:shadow-2xl transition-all duration-300 overflow-hidden flex flex-col bg-card/40 hover:bg-card/60 rounded-xl">
                                    <GlassCardHeader className="p-4 pb-3">
                                        <div className="flex items-start justify-between">
                                            <div className="flex flex-col gap-4">
                                                <div className="w-10 h-10 bg-card/50 rounded-lg flex items-center justify-center group-hover:scale-105 transition-transform ring-1 ring-on-surface/5">
                                                    {app.icon_url ? (
                                                        <img src={app.icon_url} alt={app.name} className="w-6 h-6 object-contain" />
                                                    ) : (
                                                        <Sparkles className="w-5 h-5 text-primary" />
                                                    )}
                                                </div>
                                                <div className="flex flex-col gap-1">
                                                    <div className="flex items-center gap-1.5">
                                                        <div className="w-1.5 h-1.5 bg-success rounded-full animate-pulse shadow-glow-success" />
                                                        <span className="font-bold text-[8px] tracking-widest text-success uppercase">Active</span>
                                                    </div>
                                                    <GlassCardTitle className="text-base font-bold tracking-tight text-on-surface group-hover:text-primary transition-colors leading-none">{app.name}</GlassCardTitle>
                                                </div>
                                            </div>
                                        </div>
                                    </GlassCardHeader>
                                    <GlassCardContent className="p-4 pt-0 space-y-3 flex-1 flex flex-col justify-between">
                                        <p className="text-[12px] font-medium text-on-surface-variant/60 leading-tight line-clamp-2">
                                            {app.description || 'Enterprise secure resource with end-to-end identity verification.'}
                                        </p>

                                        <div className="space-y-2">
                                            <div className="px-2 py-1.5 bg-surface-container/50 rounded-md font-mono text-[8px] truncate text-on-surface-variant/30 ring-1 ring-on-surface/5">
                                                <span className="opacity-40 mr-1">$</span>{app.launch_url}
                                            </div>
                                            <Button
                                                onClick={() => handleLaunch(app)}
                                                className="w-full h-8 rounded-lg font-bold text-[10px] tracking-wide shadow-lg shadow-primary/5 transition-all group-hover:bg-primary group-hover:text-primary-foreground"
                                            >
                                                Launch Application
                                                <ExternalLink className="ml-1.5 h-3 w-3 opacity-50" />
                                            </Button>
                                        </div>
                                    </GlassCardContent>
                                </GlassCard>
                            ))}
                        </div>
                    )}
                </div>

                {/* Footer Metrics */}
                <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4">
                    <GlassCard className="p-4 flex flex-col justify-center bg-card/20 hover:bg-card/40 transition-all group rounded-xl">
                        <span className="text-[8px] font-bold tracking-[0.2em] text-primary uppercase opacity-40">Resources_Index</span>
                        <div className="flex items-baseline gap-2 mt-0.5">
                            <p className="text-3xl font-bold text-on-surface tracking-tighter tabular-nums">{filteredApps.length.toString().padStart(2, '0')}</p>
                            <span className="text-[9px] font-bold text-on-surface-variant/20 italic tracking-tight">Available</span>
                        </div>
                    </GlassCard>
                    <GlassCard className="p-4 flex flex-col justify-center bg-card/20 hover:bg-card/40 transition-all rounded-xl">
                        <span className="text-[8px] font-bold tracking-[0.2em] text-primary uppercase opacity-40">Total_Provisioned</span>
                        <div className="flex items-baseline gap-2 mt-0.5">
                            <p className="text-3xl font-bold text-on-surface tracking-tighter tabular-nums">{applications.length.toString().padStart(2, '0')}</p>
                            <span className="text-[8px] font-bold text-on-surface-variant/30 tracking-widest uppercase">All Resources</span>
                        </div>
                    </GlassCard>
                    <GlassCard className="p-4 flex flex-col justify-center bg-card/20 hover:bg-card/40 transition-all rounded-xl">
                        <span className="text-[8px] font-bold tracking-[0.2em] text-primary uppercase opacity-40">Session_Status</span>
                        <div className="flex items-center gap-2 mt-1">
                            <div className="w-2.5 h-2.5 rounded-full bg-success animate-pulse shadow-[0_0_15px_rgba(34,197,94,0.4)]" />
                            <p className="text-2xl font-bold text-on-surface tracking-tighter">LIVE</p>
                        </div>
                        <span className="text-[8px] font-bold text-on-surface-variant/30 tracking-widest uppercase">Identity Verified</span>
                    </GlassCard>
                </div>
            </div>
        </div>
    );
};

export default PortalDashboard;

