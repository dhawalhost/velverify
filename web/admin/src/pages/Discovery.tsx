import React, { useEffect, useState, useCallback } from 'react';
import { 
    getDiscoveredResources, 
    triggerDiscoveryScan, 
    getDiscoveryJobStatus,
    DiscoveredResource,
    DiscoveryJobStatus 
} from '../api';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '@/components/ui/card';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { 
    Loader2, 
    Search, 
    RefreshCcw, 
    Database, 
    Globe, 
    ShieldPlus,
    Clock,
    CheckCircle2,
    Server,
    AlertCircle,
    Activity
} from 'lucide-react';
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
            }, 2000); // Poll every 2 seconds
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
                return <Badge className="bg-green-600/10 text-green-600 border-green-600/20 gap-1 rounded-sm"><CheckCircle2 className="w-3 h-3" /> Managed</Badge>;
            default:
                return <Badge variant="outline" className="gap-1 rounded-sm"><Clock className="w-3 h-3" /> Discovered</Badge>;
        }
    };

    const getSourceIcon = (source: string) => {
        if (source.toLowerCase().includes('ldap') || source.toLowerCase().includes('ad')) {
            return <Database className="w-3 h-3 text-blue-500" />;
        }
        return <Globe className="w-3 h-3 text-indigo-500" />;
    };

    const isScanning = currentJob?.status === 'queued' || currentJob?.status === 'processing';

    if (loading && resources.length === 0) {
        return (
            <div className="h-[400px] flex items-center justify-center">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
        );
    }

    return (
        <div className="space-y-8 max-w-[1400px] mx-auto">
            <div className="flex justify-between items-end">
                <div className="space-y-1">
                    <h1 className="text-4xl font-black tracking-tighter uppercase italic leading-none">Resource Discovery</h1>
                    <p className="text-muted-foreground text-sm font-medium italic">Architectural asset detection & inventory orchestration.</p>
                </div>
                <Button 
                    onClick={handleRunScan} 
                    disabled={isScanning}
                    className="bg-foreground text-background hover:bg-foreground/90 font-bold uppercase tracking-widest text-[10px] px-8 py-6 rounded-none shadow-[4px_4px_0_0_rgba(0,0,0,0.1)] h-12"
                >
                    {isScanning ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <RefreshCcw className="w-4 h-4 mr-2" />}
                    {isScanning ? 'Scan in Progress' : 'Scan Infrastructure'}
                </Button>
            </div>

            {currentJob && isScanning && (
                <Card className="border-4 border-foreground rounded-none bg-muted/30 overflow-hidden relative">
                    <div 
                        className="absolute top-0 left-0 h-full bg-foreground/5 transition-all duration-1000" 
                        style={{ width: `${currentJob.progress}%` }}
                    />
                    <CardContent className="p-8 relative z-10 flex items-center justify-between">
                        <div className="flex items-center gap-6">
                            <div className="w-16 h-16 bg-foreground text-background flex items-center justify-center">
                                <Activity className="w-8 h-8 animate-pulse" />
                            </div>
                            <div className="space-y-1">
                                <span className="text-[10px] font-black uppercase tracking-widest text-muted-foreground">Orchestration Phase</span>
                                <h3 className="text-xl font-black uppercase tracking-tight italic transition-all">{currentJob.message || 'Scanning connected directories...'}</h3>
                            </div>
                        </div>
                        <div className="text-right">
                            <span className="text-6xl font-black tracking-tighter tabular-nums">{currentJob.progress}%</span>
                        </div>
                    </CardContent>
                </Card>
            )}

            {message && (
                <Alert variant={message.type === 'error' ? 'destructive' : 'default'} className="bg-card/50 backdrop-blur-md border-2 border-foreground/10 rounded-none">
                    <AlertCircle className="h-4 w-4" />
                    <AlertDescription className="font-bold uppercase text-[10px] tracking-widest">{message.text}</AlertDescription>
                </Alert>
            )}

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <Card className="border-2 border-foreground/5 shadow-none bg-card/50 backdrop-blur-md rounded-none">
                    <CardContent className="p-8">
                        <div className="flex flex-col gap-1">
                            <span className="text-[10px] font-black uppercase tracking-[0.2em] text-muted-foreground italic">Total Assets</span>
                            <span className="text-6xl font-black tracking-tighter tabular-nums">{resources.length}</span>
                        </div>
                    </CardContent>
                </Card>
                <Card className="border-2 border-foreground/5 shadow-none bg-card/50 backdrop-blur-md rounded-none">
                    <CardContent className="p-8">
                        <div className="flex flex-col gap-1">
                            <span className="text-[10px] font-black uppercase tracking-[0.2em] text-muted-foreground italic">Shadow IT Ratio</span>
                            <span className="text-6xl font-black tracking-tighter tabular-nums">
                                {Math.round((resources.filter(r => r.status === 'discovered').length / (resources.length || 1)) * 100)}%
                            </span>
                        </div>
                    </CardContent>
                </Card>
                <Card className="border-2 border-foreground/5 shadow-none bg-card/50 backdrop-blur-md border-l-green-500 rounded-none">
                    <CardContent className="p-8">
                        <div className="flex flex-col gap-1">
                            <span className="text-[10px] font-black uppercase tracking-[0.2em] text-muted-foreground italic">Managed Hygiene</span>
                            <span className="text-6xl font-black tracking-tighter tabular-nums">
                                {resources.filter(r => r.status === 'promoted').length}
                            </span>
                        </div>
                    </CardContent>
                </Card>
            </div>

            <Card className="border-2 border-foreground/10 shadow-xl overflow-hidden rounded-none bg-card">
                <CardHeader className="bg-muted/50 border-b-2 border-foreground/5 py-10">
                    <div className="flex items-center gap-4">
                        <div className="p-2 bg-foreground text-background">
                            <Search className="w-6 h-6" />
                        </div>
                        <div>
                            <CardTitle className="text-3xl font-black uppercase tracking-tighter italic leading-none">Asset Inventory</CardTitle>
                            <CardDescription className="text-muted-foreground font-medium italic mt-1">Review architectural components detected across enterprise infrastructure.</CardDescription>
                        </div>
                    </div>
                </CardHeader>
                <CardContent className="p-0">
                    {resources.length === 0 ? (
                        <div className="py-32 text-center text-muted-foreground flex flex-col items-center gap-6">
                            <div className="w-20 h-20 rounded-full bg-muted flex items-center justify-center border-4 border-dashed border-muted-foreground/20">
                                <Server className="h-10 w-10 opacity-20" />
                            </div>
                            <div className="max-w-[300px] font-bold uppercase text-[10px] tracking-widest leading-relaxed"> No resources detected. Start a scan to discovery unmanaged assets. </div>
                        </div>
                    ) : (
                        <div className="overflow-x-auto">
                            <Table>
                                <TableHeader className="bg-muted/30 border-b-2 border-foreground/5">
                                    <TableRow className="hover:bg-transparent">
                                        <TableHead className="py-6 pl-8 font-black uppercase text-[10px] tracking-widest text-foreground">Resource Identity</TableHead>
                                        <TableHead className="font-black uppercase text-[10px] tracking-widest text-foreground">Source Provider</TableHead>
                                        <TableHead className="font-black uppercase text-[10px] tracking-widest text-foreground">Type</TableHead>
                                        <TableHead className="font-black uppercase text-[10px] tracking-widest text-foreground">Governance</TableHead>
                                        <TableHead className="font-black uppercase text-[10px] tracking-widest text-foreground">Last Detected</TableHead>
                                        <TableHead className="text-right font-black uppercase text-[10px] tracking-widest text-foreground pr-8">Context</TableHead>
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    {resources.map(resource => (
                                        <TableRow key={resource.id} className="hover:bg-muted/30 transition-all border-b border-foreground/5 group">
                                            <TableCell className="py-8 pl-8">
                                                <div className="flex items-center gap-4">
                                                    <div className="w-10 h-10 bg-foreground/5 flex items-center justify-center border border-foreground/10 group-hover:bg-foreground group-hover:text-background transition-colors">
                                                        <Server className="w-5 h-5" />
                                                    </div>
                                                    <div className="flex flex-col">
                                                        <span className="text-base font-black tracking-tight uppercase leading-none">{resource.name}</span>
                                                        <span className="text-[10px] font-mono text-muted-foreground tracking-tighter mt-1 uppercase italic">{resource.external_id}</span>
                                                    </div>
                                                </div>
                                            </TableCell>
                                            <TableCell>
                                                <div className="flex items-center gap-2">
                                                    {getSourceIcon(resource.source)}
                                                    <span className="text-[11px] font-black uppercase tracking-tight italic">{resource.source}</span>
                                                </div>
                                            </TableCell>
                                            <TableCell>
                                                <Badge variant="secondary" className="bg-foreground/5 text-foreground hover:bg-foreground/10 rounded-none font-black text-[9px] uppercase tracking-[0.1em] border-none px-2 py-0.5">
                                                    {resource.resource_type}
                                                </Badge>
                                            </TableCell>
                                            <TableCell>
                                                {getStatusBadge(resource.status)}
                                            </TableCell>
                                            <TableCell className="text-muted-foreground font-mono text-[10px] uppercase italic">
                                                {new Date(resource.discovered_at).toLocaleDateString()}
                                            </TableCell>
                                            <TableCell className="text-right pr-8">
                                                <Button 
                                                    size="sm" 
                                                    variant="ghost" 
                                                    disabled={resource.status === 'promoted'}
                                                    className="h-9 font-black uppercase text-[10px] tracking-widest hover:bg-foreground hover:text-background transition-all border border-foreground/10 rounded-none px-4"
                                                >
                                                    <ShieldPlus className="w-4 h-4 mr-2" /> 
                                                    {resource.status === 'promoted' ? 'Managed' : 'Onboard'}
                                                </Button>
                                            </TableCell>
                                        </TableRow>
                                    ))}
                                </TableBody>
                            </Table>
                        </div>
                    )}
                </CardContent>
            </Card>
        </div>
    );
};

export default Discovery;
