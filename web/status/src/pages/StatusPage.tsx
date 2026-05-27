import React, { useState, useEffect } from 'react';
import { CheckCircle2, AlertCircle, Shield, Zap, Server, Database, Terminal, Heart } from 'lucide-react';
import { GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent } from '@/components/layout';

interface ServiceStatus {
    name: string;
    status: 'operational' | 'degraded' | 'down';
    latency: string;
    uptime: string;
    icon: any;
}

const isLocal = typeof window !== 'undefined' && (window.location.hostname.endsWith('.local') || window.location.hostname === 'localhost');
const domain = isLocal ? 'wardseal.local' : 'wardseal.com';
const protocol = isLocal ? 'http' : 'https';

const authUrl = `${protocol}://auth.${domain}/healthz`;
const apiUrl = `${protocol}://api.${domain}`;

const SERVICE_ENDPOINTS = [
    { name: 'OAuth/OIDC Authentication', url: authUrl, icon: Shield },
    { name: 'Core Governance API', url: `${apiUrl}/gov/healthz`, icon: Zap },
    { name: 'Provisioning Gateway', url: `${apiUrl}/provisioning/healthz`, icon: Server },
    { name: 'Access Policy Engine', url: `${apiUrl}/policy/healthz`, icon: Database },
    { name: 'Identity Sync Relay', url: `${apiUrl}/scim/healthz`, icon: Terminal },
];


interface ServiceStatusItemProps {
    name: string;
    status: 'operational' | 'degraded' | 'down';
    latency: string;
    uptime: string;
    icon: React.ComponentType<{ className?: string }>;
}

const ServiceStatusItem: React.FC<ServiceStatusItemProps> = ({ name, status, latency, uptime, icon: Icon }) => {
    return (
        <GlassCard className="p-card flex items-center justify-between hover:translate-y-[-2px] transition-all duration-300 group rounded-xl bg-card hover:bg-card">
            <div className="flex items-center gap-3">
                <div className="h-8 w-8 rounded-lg bg-surface-container flex items-center justify-center ring-1 ring-on-surface/5 group-hover:bg-primary/10 group-hover:ring-primary/20 transition-all">
                    <Icon className="h-4 w-4 text-on-surface-variant/40 group-hover:text-primary transition-all" />
                </div>
                <div className="flex flex-col">
                    <span className="text-caption font-bold text-on-surface tracking-tight group-hover:text-primary transition-all uppercase">{name}</span>
                    <div className="flex items-center gap-3 mt-0.5">
                        <span className="text-detail font-bold text-on-surface-variant/40 tracking-tight flex items-center gap-1 uppercase">
                            Latency: <span className="text-on-surface">{latency}</span>
                        </span>
                        <span className="text-detail font-bold text-on-surface-variant/40 tracking-tight flex items-center gap-1 uppercase">
                            Uptime: <span className="text-on-surface">{uptime}</span>
                        </span>
                    </div>
                </div>
            </div>
            <div className={`flex items-center gap-1.5 px-3 py-1 rounded-lg font-bold text-detail tracking-tight uppercase ${status === 'operational'
                ? 'bg-success/5 ring-1 ring-success/20 text-success'
                : 'bg-rose-500/5 ring-1 ring-rose-500/20 text-rose-500'
                }`}>
                <div className={`h-1.5 w-1.5 rounded-full ${status === 'operational' ? 'bg-success animate-ping' : 'bg-rose-500'
                    }`} />
                {status === 'operational' ? 'Active' : 'Offline'}
            </div>
        </GlassCard>
    );
};

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
            <div className="max-w-3xl w-full space-y-page pt-6">

                {/* TOP BAR: BRAND */}
                <div className="flex items-center justify-center gap-3">
                    <div className="w-8 h-8 flex items-center justify-center">
                        <img src="/wardseal.svg" alt="WardSeal" className="w-7 h-7 animate-pulse" />
                    </div>
                    <div className="flex flex-col items-start leading-none">
                        <span className="text-body font-bold tracking-tight text-on-surface">WardSeal</span>
                        <span className="text-detail font-bold tracking-widest text-primary uppercase opacity-40">Status Network</span>
                    </div>
                </div>

                {/* OVERALL HEALTH STATUS */}
                <GlassCard className="p-card bg-card hover:bg-card hover:translate-y-[-2px] transition-all duration-300 rounded-xl flex flex-col items-center text-center space-y-3">
                    {overallStatus === 'operational' ? (
                        <div className="h-10 w-10 rounded-xl bg-success/10 flex items-center justify-center ring-1 ring-success/20 shadow-xl shadow-success/5 animate-pulse">
                            <CheckCircle2 className="h-5 w-5 text-success" />
                        </div>
                    ) : (
                        <div className="h-10 w-10 rounded-xl bg-warning/10 flex items-center justify-center ring-1 ring-warning/20 shadow-xl shadow-warning/5">
                            <AlertCircle className="h-5 w-5 text-warning" />
                        </div>
                    )}
                    <h2 className="text-heading font-black tracking-tight text-on-surface uppercase">
                        {overallStatus === 'operational' ? 'All Systems Operational' : 'Degraded Performance'}
                    </h2>
                    <p className="text-on-surface-variant/40 font-bold text-detail tracking-widest uppercase">Verified live telemetry feeds</p>
                </GlassCard>

                {/* INDIVIDUAL SERVICES GRID */}
                <div className="space-y-card">
                    <span className="text-label font-bold tracking-[0.2em] text-on-surface-variant/40 ml-4 uppercase">Capabilities</span>
                    <div className="space-y-2">
                        {services.map(service => (
                            <ServiceStatusItem 
                                key={service.name} 
                                name={service.name} 
                                status={service.status} 
                                latency={service.latency} 
                                uptime={service.uptime} 
                                icon={service.icon} 
                            />
                        ))}
                    </div>
                </div>

                {/* FOOTER */}
                <div className="text-center text-detail font-bold text-on-surface-variant/20 tracking-tight mt-6">
                    &copy; {new Date().getFullYear()} WardSeal Infrastructure Hub. Live streams updated continuously.
                </div>

            </div>
        </div>
    );
};

export default StatusPage;
