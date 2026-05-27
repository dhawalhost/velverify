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
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassTable, GlassTableHeader, GlassTableHead, GlassTableRow, PageLayout
} from '@/components/layout';
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
                        setMessage({ text: "Network scan completed successfully.", type: 'success' });
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
            setMessage({ text: "Could not start network scan.", type: 'error' });
        }
    };

    const getStatusBadge = (status: string) => {
        switch (status) {
            case 'promoted':
                return <Badge className="bg-success-subtle text-success border-none rounded-xl font-bold text-[10px] tracking-tight px-4 py-1.5 shadow-sm gap-2.5"><CheckCircle2 className="w-3.5 h-3.5" /> Managed</Badge>;
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
        <PageLayout>
        <div className="space-y-12 animate-in fade-in duration-700">
            <PageHeader
                icon={<Search className="w-8 h-8 text-primary" />}
                title="Discovery"
                description="Scan your network for users, groups, and applications to bring them under WardSeal protection."
                actions={
                    <Button 
                        onClick={handleRunScan} 
                        disabled={isScanning}
                        className="h-9 rounded-lg bg-primary text-primary-foreground font-bold tracking-tight text-[11px] px-6 shadow-xl shadow-primary/20 transition-all hover:scale-[1.02] active:scale-[0.98]"
                    >
                        {isScanning ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <RefreshCcw className="w-4 h-4 mr-2" />}
                        {isScanning ? 'Scanning...' : 'Start Scan'}
                    </Button>
                }
            />

            {currentJob && isScanning && (
                <GlassCard className="border-none shadow-2xl shadow-primary/10 bg-card overflow-hidden rounded-xl relative">
                    <div 
                        className="absolute top-0 left-0 h-1.5 bg-primary transition-all duration-1000 shadow-[0_0_12px_rgba(var(--primary),0.4)]" 
                        style={{ width: `${currentJob.progress}%` }}
                    />
                    <GlassCardContent className="p-6 flex flex-col md:flex-row items-center justify-between gap-6">
                        <div className="flex items-center gap-4">
                            <div className="w-12 h-12 bg-primary/5 rounded-xl flex items-center justify-center">
                                <Activity className="w-6 h-6 animate-pulse text-primary" />
                            </div>
                            <div className="space-y-1">
                                <span className="text-[10px] font-bold tracking-tight text-primary animate-pulse">Scan in Progress</span>
                                <h3 className="text-xl font-bold tracking-tight text-on-surface">{currentJob.message || 'Scanning network...'}</h3>
                                <div className="flex items-center gap-3 text-on-surface-variant/40">
                                    <Binary className="w-3.5 h-3.5" />
                                    <span className="text-[11px] font-bold tracking-tight italic">Job ID: {currentJob.id?.substring(0, 8).toLowerCase()}</span>
                                </div>
                            </div>
                        </div>
                        <div className="text-right">
                            <span className="text-4xl font-bold tracking-tighter tabular-nums text-on-surface">{currentJob.progress}<span className="text-xl ml-1 opacity-20">%</span></span>
                        </div>
                    </GlassCardContent>
                </GlassCard>
            )}

            {message && (
                <Alert variant={message.type === 'error' ? 'destructive' : 'default'} className={`border-none rounded-xl p-4 flex items-center gap-4 animate-in slide-in-from-top-4 duration-500 ${message.type === 'error' ? 'bg-destructive/10 text-destructive' : 'bg-success-subtle text-success'}`}>
                    <div className={`p-2 rounded-lg ${message.type === 'error' ? 'bg-red-100' : 'bg-emerald-100'}`}>
                        {message.type === 'error' ? <AlertCircle className="h-4 w-4" /> : <ShieldPlus className="h-4 w-4" />}
                    </div>
                    <AlertDescription className="font-bold text-[11px] tracking-tight">{message.text}</AlertDescription>
                </Alert>
            )}

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-card overflow-hidden rounded-xl">
                    <GlassCardContent className="p-6 relative group">
                        <div className="absolute top-0 right-0 p-4 opacity-5 pointer-events-none group-hover:scale-110 transition-transform">
                            <Server className="w-12 h-12 -mr-2 -mt-2 text-on-surface" />
                        </div>
                        <div className="flex flex-col gap-1">
                            <span className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 uppercase">Total Found</span>
                            <span className="text-4xl font-bold tracking-tighter tabular-nums transition-colors group-hover:text-primary">{resources.length}</span>
                        </div>
                    </GlassCardContent>
                </GlassCard>
                
                <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-card overflow-hidden rounded-xl">
                    <GlassCardContent className="p-6 relative group">
                        <div className="absolute top-0 right-0 p-4 opacity-5 pointer-events-none group-hover:scale-110 transition-transform">
                            <Activity className="w-12 h-12 -mr-2 -mt-2 text-on-surface" />
                        </div>
                        <div className="flex flex-col gap-1">
                            <span className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 uppercase">Unmanaged</span>
                            <span className="text-4xl font-bold tracking-tighter tabular-nums transition-colors group-hover:text-destructive">
                                {Math.round((resources.filter(r => r.status === 'discovered').length / (resources.length || 1)) * 100)}<span className="text-xl opacity-20 ml-1">%</span>
                            </span>
                        </div>
                    </GlassCardContent>
                </GlassCard>

                <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-card overflow-hidden rounded-xl">
                    <GlassCardContent className="p-6 relative group">
                        <div className="absolute top-0 right-0 p-4 opacity-5 pointer-events-none group-hover:scale-110 transition-transform">
                            <ShieldPlus className="w-12 h-12 -mr-2 -mt-2 text-success" />
                        </div>
                        <div className="flex flex-col gap-1">
                            <span className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 uppercase">Managed</span>
                            <span className="text-4xl font-bold tracking-tighter tabular-nums text-success">
                                {resources.filter(r => r.status === 'promoted').length}
                            </span>
                        </div>
                    </GlassCardContent>
                </GlassCard>
            </div>

            <div className="space-y-8">
                <div className="flex items-center gap-4">
                    <h2 className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 uppercase italic flex-shrink-0 opacity-60">Asset List</h2>
                    <div className="h-px flex-1 bg-on-surface/5" />
                </div>

                <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-card overflow-hidden rounded-xl">
                    <GlassCardHeader className="py-4 px-6 border-b border-on-surface/5">
                        <div className="flex items-center gap-4">
                            <div className="p-2.5 bg-primary/5 rounded-xl">
                                <Search className="w-5 h-5 text-primary" />
                            </div>
                            <div>
                                <GlassCardTitle className="text-xl font-bold tracking-tight text-on-surface">Discovered Assets</GlassCardTitle>
                                <p className="text-on-surface-variant/40 font-semibold text-[10px] mt-0.5 tracking-tight">List of users and resources found on your network.</p>
                            </div>
                        </div>
                    </GlassCardHeader>
                    <GlassCardContent className="p-0">
                        {resources.length === 0 ? (
                            <div className="py-32 text-center text-on-surface-variant/30 flex flex-col items-center gap-6 italic">
                                <div className="w-20 h-20 rounded-3xl bg-surface-container/50 flex items-center justify-center">
                                    <Server className="h-10 w-10 opacity-20" />
                                </div>
                                <span className="max-w-xs font-bold text-[11px] tracking-tight leading-relaxed text-on-surface-variant/40">No assets found. Run a scan to find users and applications.</span>
                            </div>
                        ) : (
                            <div className="overflow-x-auto">
                                <GlassTable>
                                    <GlassTableHeader>
                                        <GlassTableRow className="hover:bg-transparent border-b border-on-surface/5">
                                            <GlassTableHead className="py-3 pl-6">Name</GlassTableHead>
                                            <GlassTableHead className="py-3">Source</GlassTableHead>
                                            <GlassTableHead className="py-3">Type</GlassTableHead>
                                            <GlassTableHead className="py-3">Status</GlassTableHead>
                                            <GlassTableHead className="py-3 text-right pr-6">Actions</GlassTableHead>
                                        </GlassTableRow>
                                    </GlassTableHeader>
                                    <TableBody>
                                        {resources.map(resource => (
                                            <GlassTableRow key={resource.id} className="hover:bg-surface-container/10 transition-all border-b border-on-surface/5 last:border-0 group">
                                                <TableCell className="py-3 pl-6">
                                                    <div className="flex items-center gap-4">
                                                        <div className="w-8 h-8 rounded-lg bg-surface-container/50 text-on-surface-variant/40 flex items-center justify-center transition-all group-hover:bg-primary group-hover:text-primary-foreground">
                                                            <Fingerprint className="w-4 h-4" />
                                                        </div>
                                                        <div className="flex flex-col gap-0.5">
                                                            <span className="text-[13px] font-bold tracking-tight text-on-surface group-hover:text-primary transition-colors">{resource.name}</span>
                                                            <span className="text-[9px] font-bold font-mono tracking-tight opacity-20 italic truncate max-w-[150px]">{resource.external_id}</span>
                                                        </div>
                                                    </div>
                                                </TableCell>
                                                <TableCell className="py-3">
                                                    <div className="flex items-center gap-2.5">
                                                        <div className="p-1.5 rounded-md bg-surface-container/50 text-on-surface-variant/60 group-hover:bg-primary/5 group-hover:text-primary transition-colors">
                                                            {getSourceIcon(resource.source)}
                                                        </div>
                                                        <span className="text-[11px] font-bold tracking-tight text-on-surface">{resource.source}</span>
                                                    </div>
                                                </TableCell>
                                                <TableCell className="py-3">
                                                    <Badge className="bg-surface-container/50 text-on-surface-variant/60 border-none rounded-md font-bold text-[9px] tracking-tight px-2 py-0.5 group-hover:bg-surface-container transition-all">
                                                        {resource.resource_type}
                                                    </Badge>
                                                </TableCell>
                                                <TableCell className="py-3">
                                                    {resource.status === 'promoted' ? (
                                                        <Badge className="bg-success/10 text-success border-none rounded-md font-bold text-[9px] tracking-tight px-2 py-0.5 flex items-center gap-1.5 w-fit">
                                                            <CheckCircle2 className="w-2.5 h-2.5" /> Managed
                                                        </Badge>
                                                    ) : (
                                                        <Badge className="bg-surface-container/50 text-on-surface-variant/60 border-none rounded-md font-bold text-[9px] tracking-tight px-2 py-0.5 flex items-center gap-1.5 w-fit">
                                                            <Clock className="w-2.5 h-2.5" /> Discovered
                                                        </Badge>
                                                    )}
                                                </TableCell>
                                                <TableCell className="py-3 text-right pr-6">
                                                    <Button 
                                                        size="sm" 
                                                        variant={resource.status === 'promoted' ? "ghost" : "outline"} 
                                                        disabled={resource.status === 'promoted'}
                                                        className={`h-8 rounded-lg font-bold text-[10px] tracking-tight px-4 transition-all ${resource.status === 'promoted' ? 'text-success/40' : 'bg-card ring-1 ring-on-surface/5 hover:bg-surface-container'}`}
                                                    >
                                                        {resource.status === 'promoted' ? (
                                                            <div className="flex items-center gap-1.5">
                                                                <CheckCircle2 className="w-3.5 h-3.5" />
                                                                Secured
                                                            </div>
                                                        ) : (
                                                            <div className="flex items-center gap-1.5">
                                                                <ShieldPlus className="w-3.5 h-3.5" /> 
                                                                Protect
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
        </PageLayout>
    );
};

export default Discovery;
