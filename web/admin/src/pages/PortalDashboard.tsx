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
            <div className="flex flex-col md:flex-row md:items-end justify-between gap-10">
                <div className="space-y-4">
                    <div className="flex items-center gap-4">
                        <div className="w-10 h-10 flex items-center justify-center bg-primary rounded-xl shadow-lg shadow-primary/20">
                            <img src="/wardseal.svg" alt="WardSeal" className="w-6 h-6" />
                        </div>
                        <div className="flex flex-col">
                            <span className="text-xl font-bold tracking-tight text-on-surface">WardSeal</span>
                            <span className="text-[10px] font-bold tracking-widest text-primary uppercase opacity-60">Identity Portal</span>
                        </div>
                    </div>
                    <div className="flex flex-col gap-4">
                        <h1 className="text-5xl font-bold tracking-tight text-on-surface">Resource Registry</h1>
                        <p className="text-on-surface-variant/60 font-medium text-sm max-w-xl leading-relaxed">
                            Securely access and manage your application tunnels and enterprise resources.
                        </p>
                        {localStorage.getItem('isAdmin') === 'true' && (
                            <div className="pt-2">
                                <Button
                                    onClick={() => window.location.href = '/dashboard'}
                                    className="h-10 px-6 rounded-xl bg-on-surface text-white font-bold text-xs hover:opacity-90 transition-all flex items-center gap-2 shadow-lg shadow-on-surface/10"
                                >
                                    <LayoutGrid className="w-4 h-4" />
                                    Go to Admin Console
                                </Button>
                            </div>
                        )}
                    </div>

                    {/* SEARCH: Modernist */}
                    <div className="relative w-full max-w-md group">
                        <Search className="absolute left-5 top-1/2 -translate-y-1/2 h-4.5 w-4.5 text-on-surface-variant/40 group-focus-within:text-primary transition-colors" />
                        <Input
                            placeholder="Search resource registry..."
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            className="h-14 pl-12 pr-6 border-none rounded-2xl font-medium text-sm bg-white shadow-sm ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all"
                        />
                    </div>
                </div>

                {/* Applications Grid */}
                {loading ? (
                    <div className="h-[400px] flex flex-col items-center justify-center border border-dashed rounded-3xl bg-white/50">
                        <Loader2 className="h-10 w-10 animate-spin mb-4 text-primary/40" />
                        <span className="text-[12px] font-bold tracking-tight opacity-20 italic">Synchronizing Registry...</span>
                    </div>
                ) : filteredApps.length === 0 ? (
                    <div className="py-32 text-center border border-dashed rounded-3xl bg-white/50">
                        <LayoutGrid className="h-12 w-12 text-on-surface-variant/10 mb-6 mx-auto" />
                        <h3 className="text-xl font-bold text-on-surface">No resources detected</h3>
                        <p className="text-on-surface-variant/60 font-medium text-sm mt-3">
                            {searchQuery ? 'Zero matches found for the current query.' : 'No resources have been assigned to your profile yet.'}
                        </p>
                    </div>
                ) : (
                    <div className="grid gap-8 md:grid-cols-2 lg:grid-cols-3">
                        {filteredApps.map((app) => (
                            <GlassCard key={app.id} className="group hover:border-primary/20 hover:shadow-xl hover:shadow-primary/5 transition-all duration-300 overflow-hidden flex flex-col bg-white">
                                <GlassCardHeader className="p-8 pb-5">
                                    <div className="flex items-start justify-between">
                                        <div className="flex items-center gap-5">
                                            <div className="w-14 h-14 bg-primary/5 rounded-2xl flex items-center justify-center group-hover:scale-105 transition-transform">
                                                {app.icon_url ? (
                                                    <img src={app.icon_url} alt={app.name} className="w-8 h-8 object-contain" />
                                                ) : (
                                                    <Sparkles className="w-6 h-6 text-primary" />
                                                )}
                                            </div>
                                            <div className="flex flex-col">
                                                <div className="flex items-center gap-2 mb-1.5">
                                                    <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full" />
                                                    <span className="font-bold text-[11px] tracking-tight text-emerald-600">Secure link</span>
                                                </div>
                                                <GlassCardTitle className="text-xl font-bold tracking-tight text-on-surface group-hover:text-primary transition-colors">{app.name}</GlassCardTitle>
                                            </div>
                                        </div>
                                    </div>
                                </GlassCardHeader>
                                <GlassCardContent className="p-8 pt-0 space-y-8 flex-1 flex flex-col justify-between">
                                    <p className="text-sm font-medium text-on-surface-variant/70 leading-relaxed line-clamp-3">
                                        {app.description || 'No description provided for this resource entity.'}
                                    </p>

                                    <div className="space-y-4">
                                        <div className="px-4 py-3 bg-surface-container rounded-xl font-mono text-[10px] truncate text-on-surface-variant/60">
                                            {app.launch_url}
                                        </div>
                                        <Button
                                            onClick={() => handleLaunch(app)}
                                            className="w-full h-12 rounded-xl font-bold text-xs tracking-wider shadow-sm transition-all"
                                        >
                                            Launch Secure Tunnel
                                            <ExternalLink className="ml-2.5 h-4 w-4" />
                                        </Button>
                                    </div>
                                </GlassCardContent>
                            </GlassCard>
                        ))}
                    </div>
                )}

                {/* Footer Metrics: Modernist */}
                <div className="mt-16 grid grid-cols-1 sm:grid-cols-3 gap-8">
                    <div className="p-7 rounded-2xl bg-white border border-on-surface/5 shadow-sm">
                        <span className="text-[12px] font-bold tracking-tight text-on-surface-variant/20 italic">Resource Count</span>
                        <p className="text-3xl font-bold text-on-surface mt-2">{filteredApps.length.toString().padStart(2, '0')}</p>
                    </div>
                    <div className="p-7 rounded-2xl bg-white border border-on-surface/5 shadow-sm">
                        <span className="text-[12px] font-bold tracking-tight text-on-surface-variant/20 italic">Security Posture</span>
                        <p className="text-3xl font-bold text-primary mt-2">Maximum Encryption</p>
                    </div>
                    <div className="p-7 rounded-2xl bg-white border border-on-surface/5 shadow-sm">
                        <span className="text-[12px] font-bold tracking-tight text-on-surface-variant/20 italic">Audit Logging</span>
                        <p className="text-3xl font-bold text-on-surface mt-2">Active</p>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default PortalDashboard;

