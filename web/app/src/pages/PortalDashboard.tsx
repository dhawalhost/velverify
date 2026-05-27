import { useState, useEffect } from 'react';
import { Button } from "@/components/ui/button";
import { ExternalLink, LayoutGrid, Search, Loader2, Sparkles, Box } from "lucide-react";
import { Input } from "@/components/ui/input";
import { getUserApps } from '../api';
import { GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent } from '@/components/layout';
import { RegistryAppCard, Application } from '../components/RegistryAppCard';
import { MetricCard } from '../components/MetricCard';

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
        <div className="space-y-page animate-in fade-in duration-700">
            {/* Header: Standard Modernist */}
            <div className="flex flex-col gap-card">
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-card border-b border-outline/10 pb-section">
                    <div className="space-y-card">
                        <div className="flex items-center gap-3">
                            <div className="w-8 h-8 flex items-center justify-center">
                                <img src="/wardseal.svg" alt="WardSeal" className="w-7 h-7" />
                            </div>
                            <div className="flex flex-col">
                                <span className="text-body font-bold tracking-tight text-on-surface">WardSeal</span>
                                <span className="text-detail font-bold tracking-widest text-primary uppercase opacity-40">Identity Portal</span>
                            </div>
                        </div>
                        <div className="space-y-1">
                            <h1 className="text-title font-bold tracking-tight text-on-surface leading-none">Resource Registry</h1>
                            <p className="text-on-surface-variant/60 font-medium text-caption max-w-xl">
                                Securely access and manage your application tunnels and enterprise resources.
                            </p>
                            {localStorage.getItem('isAdmin') === 'true' && (
                                <div className="pt-2">
                                    <Button
                                        onClick={() => window.location.href = '/dashboard'}
                                        className="h-9 px-4 rounded-lg bg-inverse text-on-inverse font-bold text-label hover:opacity-90 transition-all flex items-center gap-2 shadow-lg shadow-on-surface/5"
                                    >
                                        <LayoutGrid className="w-4 h-4" />
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
                                className="h-9 pl-10 pr-4 border-none rounded-lg font-bold text-caption bg-card/40 backdrop-blur-2xl shadow-xl ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all"
                            />
                        </div>
                    </div>
                </div>

                {/* Applications Grid */}
                <div className="min-h-[400px]">
                    {loading ? (
                        <div className="h-[300px] flex flex-col items-center justify-center border border-dashed border-outline/20 rounded-2xl bg-card/20 backdrop-blur-sm">
                            <Loader2 className="h-10 w-10 animate-spin mb-4 text-primary/40" />
                            <span className="text-label font-bold tracking-widest opacity-20 uppercase italic">Synchronizing...</span>
                        </div>
                    ) : filteredApps.length === 0 ? (
                        <GlassCard className="py-24 text-center border border-dashed border-outline/20 bg-card/20 shadow-none rounded-2xl">
                            <Box className="h-12 w-12 text-on-surface-variant/5 mb-6 mx-auto" />
                            <h3 className="text-heading font-bold text-on-surface tracking-tight">Registry Empty</h3>
                            <p className="text-on-surface-variant/40 font-medium text-body mt-2 max-w-xs mx-auto">
                                {searchQuery ? `No resources matching "${searchQuery}" located.` : 'No resources have been provisioned for this identity.'}
                            </p>
                        </GlassCard>
                    ) : (
                        <div className="grid gap-card md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                            {filteredApps.map((app) => (
                                <RegistryAppCard key={app.id} app={app} onLaunch={handleLaunch} />
                            ))}
                        </div>
                    )}
                </div>

                {/* Footer Metrics */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-card mt-card">
                    <MetricCard 
                        label="Resources_Index" 
                        value={filteredApps.length.toString().padStart(2, '0')} 
                        detail={<span className="text-caption font-bold text-on-surface-variant/20 italic tracking-tight">Available</span>} 
                    />
                    <MetricCard 
                        label="Total_Provisioned" 
                        value={applications.length.toString().padStart(2, '0')} 
                        detail={<span className="text-detail font-bold text-on-surface-variant/30 tracking-widest uppercase">All Resources</span>} 
                    />
                    <MetricCard label="Session_Status" value="LIVE">
                        <div className="flex items-center gap-2 mt-1">
                            <div className="w-2.5 h-2.5 rounded-full bg-success animate-pulse shadow-[0_0_15px_rgba(34,197,94,0.4)]" />
                            <p className="text-heading font-bold text-on-surface tracking-tighter">LIVE</p>
                        </div>
                        <span className="text-detail font-bold text-on-surface-variant/30 tracking-widest uppercase">Identity Verified</span>
                    </MetricCard>
                </div>
            </div>
        </div>
    );
};

export default PortalDashboard;
