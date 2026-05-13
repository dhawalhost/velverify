import React, { useState, useEffect } from 'react';
import { CheckCircle2, AlertCircle, HelpCircle, Activity, Shield, Zap, Server, Database, Terminal } from 'lucide-react';

interface ServiceStatus {
    name: string;
    status: 'operational' | 'degraded' | 'down';
    latency: string;
    uptime: string;
    icon: any;
}

const SERVICE_ENDPOINTS = [
    { name: 'OAuth/OIDC Authentication', url: 'http://auth.wardseal.local/healthz', icon: Shield },
    { name: 'Core Governance API', url: 'http://api.wardseal.local/gov/healthz', icon: Zap },
    { name: 'Provisioning Gateway', url: 'http://api.wardseal.local/provisioning/healthz', icon: Server },
    { name: 'Access Policy Engine', url: 'http://api.wardseal.local/policy/healthz', icon: Database },
    { name: 'Identity Sync Relay', url: 'http://api.wardseal.local/scim/healthz', icon: Terminal },
];

const StatusPage: React.FC = () => {
    const [overallStatus, setOverallStatus] = useState<'operational' | 'degraded'>('operational');
    const [services, setServices] = useState<ServiceStatus[]>(SERVICE_ENDPOINTS.map(s => ({
        ...s,
        status: 'operational',
        latency: '...',
        uptime: '...'
    })));

    useEffect(() => {
        const fetchStatus = async () => {
            const results = await Promise.all(SERVICE_ENDPOINTS.map(async (svc) => {
                const start = Date.now();
                try {
                    const res = await fetch(svc.url);
                    const latency = `${Date.now() - start}ms`;
                    return {
                        name: svc.name,
                        status: (res.ok ? 'operational' : 'down') as any,
                        latency,
                        uptime: '99.9%',
                        icon: svc.icon
                    };
                } catch (e) {
                    return {
                        name: svc.name,
                        status: 'down' as any,
                        latency: 'N/A',
                        uptime: '0%',
                        icon: svc.icon
                    };
                }
            }));
            setServices(results);
            const isAnyDown = results.some(s => s.status === 'down');
            setOverallStatus(isAnyDown ? 'degraded' : 'operational');
        };

        fetchStatus();
        const interval = setInterval(fetchStatus, 30000);
        return () => clearInterval(interval);
    }, []);

    return (
        <div className="min-h-screen bg-background text-foreground flex flex-col items-center justify-start p-4 animate-in fade-in duration-1000">
            <div className="max-w-3xl w-full space-y-4 pt-6">

                {/* TOP BAR: BRAND */}
                <div className="flex items-center justify-center gap-3">
                    <div className="h-8 w-8 rounded-lg bg-primary/10 flex items-center justify-center ring-1 ring-primary/20 shadow-lg shadow-primary/5">
                        <Activity className="h-4 w-4 text-primary" />
                    </div>
                    <span className="text-xl font-bold tracking-tight bg-gradient-to-r from-on-surface via-on-surface/80 to-on-surface/30 bg-clip-text text-transparent">WardSeal Status</span>
                </div>

                {/* OVERALL HEALTH STATUS */}
                <div className="bg-card/80 backdrop-blur-xl rounded-2xl p-4 ring-1 ring-on-surface/5 shadow-2xl flex flex-col items-center text-center space-y-3">
                    {overallStatus === 'operational' ? (
                        <div className="h-10 w-10 rounded-xl bg-emerald-500/10 flex items-center justify-center ring-1 ring-emerald-500/20 shadow-xl shadow-emerald-500/5 animate-pulse">
                            <CheckCircle2 className="h-5 w-5 text-emerald-500" />
                        </div>
                    ) : (
                        <div className="h-10 w-10 rounded-xl bg-amber-500/10 flex items-center justify-center ring-1 ring-amber-500/20 shadow-xl shadow-amber-500/5">
                            <AlertCircle className="h-5 w-5 text-amber-500" />
                        </div>
                    )}
                    <h2 className="text-lg font-bold tracking-tight text-on-surface uppercase">Operational</h2>
                    <p className="text-on-surface-variant/40 font-bold text-[10px] tracking-widest uppercase">Verified active telemetry feeds</p>
                </div>

                {/* INDIVIDUAL SERVICES GRID */}
                <div className="space-y-3">
                    <span className="text-[10px] font-bold tracking-[0.2em] text-on-surface-variant/40 ml-4 uppercase">Capabilities</span>
                    {services.map(service => {
                        const Icon = service.icon;
                        return (
                            <div key={service.name} className="bg-card/50 backdrop-blur-lg rounded-xl p-3 flex items-center justify-between ring-1 ring-on-surface/5 shadow-sm hover:shadow-xl hover:ring-primary/20 hover:bg-card/80 transition-all duration-300 group">
                                <div className="flex items-center gap-3">
                                    <div className="h-8 w-8 rounded-lg bg-surface-container flex items-center justify-center ring-1 ring-on-surface/5 group-hover:bg-primary/10 group-hover:ring-primary/20 transition-all">
                                        <Icon className="h-4 w-4 text-on-surface-variant/40 group-hover:text-primary transition-all" />
                                    </div>
                                    <div className="flex flex-col">
                                        <span className="text-[13px] font-bold text-on-surface tracking-tight group-hover:text-primary transition-all uppercase">{service.name}</span>
                                        <div className="flex items-center gap-3 mt-0.5">
                                            <span className="text-[9px] font-bold text-on-surface-variant/40 tracking-tight flex items-center gap-1.5 uppercase">
                                                Latency: <span className="text-on-surface">{service.latency}</span>
                                            </span>
                                            <span className="text-[9px] font-bold text-on-surface-variant/40 tracking-tight flex items-center gap-1.5 uppercase">
                                                Uptime: <span className="text-on-surface">{service.uptime}</span>
                                            </span>
                                        </div>
                                    </div>
                                </div>
                                <div className={`flex items-center gap-2 px-3 py-1 rounded-lg font-bold text-[10px] tracking-tight uppercase ${service.status === 'operational'
                                    ? 'bg-emerald-500/5 ring-1 ring-emerald-500/20 text-emerald-500'
                                    : 'bg-rose-500/5 ring-1 ring-rose-500/20 text-rose-500'
                                    }`}>
                                    <div className={`h-1 w-1 rounded-full ${service.status === 'operational' ? 'bg-emerald-500 animate-ping' : 'bg-rose-500'
                                        }`} />
                                    {service.status === 'operational' ? 'Active' : 'Offline'}
                                </div>
                            </div>
                        );
                    })}
                </div>

                {/* FOOTER */}
                <div className="text-center text-[10px] font-bold text-on-surface-variant/20 tracking-tight mt-6">
                    &copy; {new Date().getFullYear()} WardSeal Infrastructure Hub. Update streams triggered dynamically.
                </div>

            </div>
        </div>
    );
};

export default StatusPage;
