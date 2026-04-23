import React, { useEffect, useState, useCallback } from 'react';
import { 
    getDiscoveredResources, 
    triggerDiscoveryScan, 
    getDiscoveryJobStatus,
    DiscoveredResource,
    DiscoveryJobStatus 
} from '../api';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { TableBody, TableCell } from '@/components/ui/table';
import { 
    Loader2, 
    Activity, 
    Search, 
    RefreshCcw, 
    CheckCircle2, 
    Clock, 
    Database, 
    Globe, 
    Server, 
    ShieldPlus, 
    AlertCircle,
    Binary,
    Link2,
    Eye,
    Fingerprint
} from 'lucide-react';
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassTable, GlassTableHeader, GlassTableHead, GlassTableRow } from '@/components/layout';
import { Alert, AlertDescription } from "@/components/ui/alert";

const Discovery: React.FC = () => {
    const [resources, setResources] = useState<DiscoveredResource[]>([]);
    const [loading, setLoading] = useState(true);
    const [currentJob, setCurrentJob] = useState<DiscoveryJobStatus | null>(null);
    const [message, setMessage] = useState<{ text: string, type: 'success' | 'error' } | null>(null);

    const fetchResources = useCallback(async () => {
        try {
            setLoading(true);
            const data = await getDiscoveredResources();
            setResources(data || []);
        } catch (err) {
            console.error(err);
            setMessage({ text: "Failed to load discovered resources.", type: 'error' });
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchResources();
    }, [fetchResources]);

    // Polling logic for discovery jobs
    useEffect(() => {
        let pollInterval: NodeJS.Timeout;

        if (currentJob && (currentJob.status === 'queued' || currentJob.status === 'processing')) {
            pollInterval = setInterval(async () => {
                try {
                    const status = await getDiscoveryJobStatus(currentJob.id);
                    setCurrentJob(status);
                    
                    if (status.status === 'completed') {
                        setMessage({ text: "Infrastructure discovery successfully completed.", type: 'success' });
                        fetchResources(); // Refresh the asset list
                        clearInterval(pollInterval);
                    } else if (status.status === 'failed') {
                        setMessage({ text: `Scan failed: ${status.message || 'Unknown error'}`, type: 'error' });
                        clearInterval(pollInterval);
                    }
                } catch (err) {
                    console.error("Polling error:", err);
                    clearInterval(pollInterval);
                }
            }, 2000); 
        }

        return () => {
            if (pollInterval) clearInterval(pollInterval);
        };
    }, [currentJob, fetchResources]);

    const handleRunScan = async () => {
        try {
            setMessage(null);
            const response = await triggerDiscoveryScan();
            if (response.job_id) {
                // Initialize scan state immediately
                setCurrentJob({
                    id: response.job_id,
                    tenant_id: '',
                    status: 'processing',
                    progress: 0,
                    message: 'Initializing scan engine...',
                    started_at: new Date().toISOString()
                });
            }
        } catch (err) {
            console.error(err);
            setMessage({ text: "Could not initiate discovery orchestration.", type: 'error' });
        }
    };

    const getStatusBadge = (status: string) => {
        switch (status) {
            case 'promoted':
                return <Badge className="bg-emerald-50 text-emerald-600 border-none rounded-xl font-bold text-[10px] tracking-tight px-4 py-1.5 shadow-sm gap-2.5"><CheckCircle2 className="w-3.5 h-3.5" /> Managed</Badge>;
            default:
                return <Badge className="bg-on-surface/5 text-on-surface/40 border-none rounded-xl font-bold text-[10px] tracking-tight px-4 py-1.5 gap-2.5"><Clock className="w-3.5 h-3.5" /> Discovered</Badge>;
        }
    };

    const getSourceIcon = (source: string) => {
        if (source.toLowerCase().includes('ldap') || source.toLowerCase().includes('ad')) {
            return <Database className="w-4 h-4" />;
        }
        return <Globe className="w-4 h-4" />;
    };

    const isScanning = currentJob?.status === 'queued' || currentJob?.status === 'processing';

    if (loading && resources.length === 0) return <div className="h-[400px] flex items-center justify-center"><Loader2 className="h-10 w-10 animate-spin text-primary opacity-20" /></div>;

    return (
        <div className="space-y-12 animate-in fade-in duration-700">
            <PageHeader
                icon={<Activity className="w-10 h-10 text-primary" />}
                title="Infrastructure Discovery"
                description="Architectural asset detection and inventory orchestration. Real-time scanning of connected directory services and cloud providers."
                actions={
                    <Button 
                        onClick={handleRunScan} 
                        disabled={isScanning}
                        className="h-11 rounded-xl font-bold text-[12px] tracking-tight px-8 shadow-xl shadow-primary/20 transition-all font-semibold"
                    >
                        {isScanning ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <RefreshCcw className="w-4 h-4 mr-2" />}
                        {isScanning ? 'Scrutinizing...' : 'Trigger Discovery'}
                    </Button>
                }
            />

            {currentJob && isScanning && (
                <GlassCard className="border-none shadow-2xl shadow-primary/10 bg-white overflow-hidden rounded-[32px] relative">
                    <div 
                        className="absolute top-0 left-0 h-1.5 bg-primary transition-all duration-1000 shadow-[0_0_12px_rgba(var(--primary),0.4)]" 
                        style={{ width: `${currentJob.progress}%` }}
                    />
                    <GlassCardContent className="p-10 flex flex-col md:flex-row items-center justify-between gap-10">
                        <div className="flex items-center gap-6">
                            <div className="w-16 h-16 bg-primary/5 rounded-2xl flex items-center justify-center">
                                <Activity className="w-8 h-8 animate-pulse text-primary" />
                            </div>
                            <div className="space-y-1.5">
                                <span className="text-[11px] font-bold tracking-tight text-primary animate-pulse">Sync Protocol Active</span>
                                <h3 className="text-2xl font-bold tracking-tight text-on-surface">{currentJob.message || 'Scanning remote endpoints...'}</h3>
                                <div className="flex items-center gap-3 text-on-surface-variant/40">
                                    <Binary className="w-3.5 h-3.5" />
                                    <span className="text-[11px] font-bold tracking-tight italic">Batch ID // {currentJob.id?.substring(0, 8).toLowerCase() || 'scan-pool'}</span>
                                </div>
                            </div>
                        </div>
                        <div className="text-right">
                            <span className="text-6xl font-bold tracking-tighter tabular-nums text-on-surface">{currentJob.progress}<span className="text-2xl ml-1 opacity-20">%</span></span>
                        </div>
                    </GlassCardContent>
                </GlassCard>
            )}

            {message && (
                <Alert variant={message.type === 'error' ? 'destructive' : 'default'} className={`border-none rounded-2xl p-6 flex items-center gap-6 animate-in slide-in-from-top-4 duration-500 ${message.type === 'error' ? 'bg-red-50 text-red-600' : 'bg-emerald-50 text-emerald-600'}`}>
                    <div className={`p-2.5 rounded-xl ${message.type === 'error' ? 'bg-red-100' : 'bg-emerald-100'}`}>
                        {message.type === 'error' ? <AlertCircle className="h-5 w-5" /> : <ShieldPlus className="h-5 w-5" />}
                    </div>
                    <AlertDescription className="font-bold text-[12px] tracking-tight">{message.text}</AlertDescription>
                </Alert>
            )}

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-white overflow-hidden rounded-[32px]">
                    <GlassCardContent className="p-10 relative group">
                        <div className="absolute top-0 right-0 p-4 opacity-5 pointer-events-none group-hover:scale-110 transition-transform">
                            <Server className="w-20 h-20 -mr-4 -mt-4 text-on-surface" />
                        </div>
                        <div className="flex flex-col gap-2">
                            <span className="text-[12px] font-bold tracking-tight text-on-surface-variant/40">Discovered Nodes</span>
                            <span className="text-6xl font-bold tracking-tighter tabular-nums transition-colors group-hover:text-primary">{resources.length}</span>
                        </div>
                    </GlassCardContent>
                </GlassCard>
                
                <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-white overflow-hidden rounded-[32px]">
                    <GlassCardContent className="p-10 relative group">
                        <div className="absolute top-0 right-0 p-4 opacity-5 pointer-events-none group-hover:scale-110 transition-transform">
                            <Activity className="w-20 h-20 -mr-4 -mt-4 text-on-surface" />
                        </div>
                        <div className="flex flex-col gap-2">
                            <span className="text-[12px] font-bold tracking-tight text-on-surface-variant/40">Shadow Entropy</span>
                            <span className="text-6xl font-bold tracking-tighter tabular-nums transition-colors group-hover:text-red-500">
                                {Math.round((resources.filter(r => r.status === 'discovered').length / (resources.length || 1)) * 100)}<span className="text-2xl opacity-20 ml-1">%</span>
                            </span>
                        </div>
                    </GlassCardContent>
                </GlassCard>

                <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-white overflow-hidden rounded-[32px]">
                    <GlassCardContent className="p-10 relative group">
                        <div className="absolute top-0 right-0 p-4 opacity-5 pointer-events-none group-hover:scale-110 transition-transform">
                            <ShieldPlus className="w-20 h-20 -mr-4 -mt-4 text-emerald-500" />
                        </div>
                        <div className="flex flex-col gap-2">
                            <span className="text-[12px] font-bold tracking-tight text-on-surface-variant/40">Managed Assets</span>
                            <span className="text-6xl font-bold tracking-tighter tabular-nums text-emerald-600">
                                {resources.filter(r => r.status === 'promoted').length}
                            </span>
                        </div>
                    </GlassCardContent>
                </GlassCard>
            </div>

            <div className="space-y-8">
                <div className="flex items-center gap-6">
                    <h2 className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 italic flex-shrink-0 opacity-60">Infrastructure Index</h2>
                    <div className="h-px flex-1 bg-on-surface/5" />
                </div>

                <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-white overflow-hidden rounded-[32px]">
                    <GlassCardHeader className="py-8 px-10 border-b border-on-surface/5">
                        <div className="flex items-center gap-5">
                            <div className="p-3.5 bg-primary/5 rounded-2xl">
                                <Search className="w-7 h-7 text-primary" />
                            </div>
                            <div>
                                <GlassCardTitle className="text-2xl font-bold tracking-tight text-on-surface">Detection Registry</GlassCardTitle>
                                <p className="text-on-surface-variant/40 font-semibold text-[12px] mt-1 tracking-tight">Verified structural anomalies identified within the scanning perimeter.</p>
                            </div>
                        </div>
                    </GlassCardHeader>
                    <GlassCardContent className="p-0">
                        {resources.length === 0 ? (
                            <div className="py-32 text-center text-on-surface-variant/30 flex flex-col items-center gap-6 italic">
                                <div className="w-20 h-20 rounded-3xl bg-surface-container/50 flex items-center justify-center">
                                    <Server className="h-10 w-10 opacity-20" />
                                </div>
                                <span className="max-w-xs font-bold text-[11px] tracking-tight leading-relaxed text-on-surface-variant/40">System Vacuum // Execute discovery protocol to populate registry.</span>
                            </div>
                        ) : (
                            <div className="overflow-x-auto">
                                <GlassTable>
                                    <GlassTableHeader>
                                        <GlassTableRow className="hover:bg-transparent border-b border-on-surface/5">
                                            <GlassTableHead className="py-6 pl-10">Node Identity</GlassTableHead>
                                            <GlassTableHead>Source</GlassTableHead>
                                            <GlassTableHead>Type</GlassTableHead>
                                            <GlassTableHead>Status</GlassTableHead>
                                            <GlassTableHead className="text-right pr-10">Orchestration</GlassTableHead>
                                        </GlassTableRow>
                                    </GlassTableHeader>
                                    <TableBody>
                                        {resources.map(resource => (
                                            <GlassTableRow key={resource.id} className="hover:bg-surface-container/10 transition-all border-b border-on-surface/5 last:border-0 group">
                                                <TableCell className="py-8 pl-10">
                                                    <div className="flex items-center gap-6">
                                                        <div className="w-12 h-12 rounded-xl bg-surface-container/50 text-on-surface-variant/40 flex items-center justify-center transition-all group-hover:bg-primary group-hover:text-white">
                                                            <Fingerprint className="w-6 h-6" />
                                                        </div>
                                                        <div className="flex flex-col gap-1">
                                                            <span className="text-lg font-bold tracking-tight text-on-surface group-hover:text-primary transition-colors">{resource.name}</span>
                                                            <span className="text-[11px] font-bold font-mono tracking-tight opacity-20 italic truncate max-w-[200px]">{resource.external_id}</span>
                                                        </div>
                                                    </div>
                                                </TableCell>
                                                <TableCell className="py-8">
                                                    <div className="flex items-center gap-3">
                                                        <div className="p-2 rounded-lg bg-surface-container/50 text-on-surface-variant/60 group-hover:bg-primary/5 group-hover:text-primary transition-colors">
                                                            {getSourceIcon(resource.source)}
                                                        </div>
                                                        <span className="text-[12px] font-bold tracking-tight text-on-surface">{resource.source}</span>
                                                    </div>
                                                </TableCell>
                                                <TableCell className="py-8">
                                                    <Badge className="bg-surface-container/50 text-on-surface-variant/60 border-none rounded-lg font-bold text-[10px] tracking-tight px-3 py-1 group-hover:bg-surface-container transition-all">
                                                        {resource.resource_type}
                                                    </Badge>
                                                </TableCell>
                                                <TableCell className="py-8">
                                                    {resource.status === 'promoted' ? (
                                                        <Badge className="bg-emerald-500/10 text-emerald-600 border-none rounded-lg font-bold text-[10px] tracking-tight px-3 py-1 flex items-center gap-2 w-fit">
                                                            <CheckCircle2 className="w-3 h-3" /> Managed
                                                        </Badge>
                                                    ) : (
                                                        <Badge className="bg-surface-container/50 text-on-surface-variant/60 border-none rounded-lg font-bold text-[10px] tracking-tight px-3 py-1 flex items-center gap-2 w-fit">
                                                            <Clock className="w-3 h-3" /> Discovered
                                                        </Badge>
                                                    )}
                                                </TableCell>
                                                <TableCell className="py-8 text-right pr-10">
                                                    <Button 
                                                        size="sm" 
                                                        variant={resource.status === 'promoted' ? "ghost" : "outline"} 
                                                        disabled={resource.status === 'promoted'}
                                                        className={`h-10 rounded-xl font-bold text-[11px] tracking-tight px-6 transition-all ${resource.status === 'promoted' ? 'text-emerald-600/40' : 'bg-white ring-1 ring-on-surface/5 hover:bg-surface-container'}`}
                                                    >
                                                        {resource.status === 'promoted' ? (
                                                            <div className="flex items-center gap-2">
                                                                <CheckCircle2 className="w-4 h-4" />
                                                                Secured
                                                            </div>
                                                        ) : (
                                                            <div className="flex items-center gap-2">
                                                                <ShieldPlus className="w-4 h-4" /> 
                                                                Adopt Node
                                                            </div>
                                                        )}
                                                    </Button>
                                                </TableCell>
                                            </GlassTableRow>
                                        ))}
                                    </TableBody>
                                </GlassTable>
                            </div>
                        )}
                    </GlassCardContent>
                </GlassCard>
            </div>
        </div>
    );
};

export default Discovery;
