import React, { useState, useEffect } from 'react';
import { getGraphTraversal, getRelationships } from '../api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { TableBody, TableCell } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import {
    Search,
    Network,
    ArrowRight,
    Shield,
    User,
    Globe,
    Loader2,
    Zap,
    Maximize2,
    Database,
    Binary,
    Terminal,
    Activity,
    RefreshCcw,
    Share2
} from 'lucide-react';
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassTable, GlassTableHeader, GlassTableHead, GlassTableRow, PageLayout
} from '@/components/layout';

const GraphExplorer: React.FC = () => {
    const [subjectID, setSubjectID] = useState('');
    const [results, setResults] = useState<any[]>([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    const handleSearch = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!subjectID) return;

        setLoading(true);
        setError('');
        try {
            const data = await getGraphTraversal(subjectID);
            setResults(data || []);
        } catch (err: any) {
            console.error(err);
            setError('Traversal failed. Subject identifier not recognized in the active graph shard.');
        } finally {
            setLoading(false);
        }
    };

    const syncGraph = async () => {
        setLoading(true);
        setError('');
        try {
            const data = await getRelationships();
            setResults(data || []);
        } catch (err: any) {
            setError('Failed to load relationship graph. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        syncGraph();
    }, []);

    return (
        <PageLayout>
        <div className="space-y-12 animate-in fade-in slide-in-from-bottom-4 duration-700">
            <PageHeader
                icon={<Share2 className="w-10 h-10 text-primary" />}
                title="Access Map"
                description="Visualize how users, groups, and roles are connected to resources. Understand access paths across your organization."
                actions={
                    <Button onClick={syncGraph} className="h-11 rounded-xl bg-primary text-primary-foreground font-bold tracking-tight text-[11px] px-8 shadow-xl shadow-primary/20 transition-all hover:scale-[1.02] active:scale-[0.98]">
                        <RefreshCcw className="w-4 h-4 mr-3" /> Refresh Map
                    </Button>
                }
            />

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-12">
                <div className="lg:col-span-4 space-y-10">
                    <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-card overflow-hidden rounded-[32px]">
                        <GlassCardHeader className="py-10 px-10 border-b border-on-surface/5 bg-surface-container/10">
                            <div className="flex items-center gap-6">
                                <div className="p-3 bg-primary/5 rounded-xl">
                                    <Activity className="w-6 h-6 text-primary" />
                                </div>
                                <div>
                                    <GlassCardTitle className="text-xl font-bold tracking-tight text-on-surface">Current View</GlassCardTitle>
                                    <p className="text-[11px] font-medium text-on-surface-variant/40 mt-1 tracking-tight">Active access relationship map</p>
                                </div>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-10">
                            <form onSubmit={handleSearch} className="space-y-8">
                                <div className="space-y-4">
                                    <Label htmlFor="subject" className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Subject entity handle</Label>
                                    <div className="relative group">
                                        <div className="absolute left-4 top-1/2 -translate-y-1/2 text-on-surface-variant/40 group-focus-within:text-primary transition-colors">
                                            <Binary className="h-5 w-5" />
                                        </div>
                                        <Input
                                            id="subject"
                                            value={subjectID}
                                            onChange={e => setSubjectID(e.target.value)}
                                            placeholder="e.g. j.doe@wardseal.io"
                                            className="h-14 border-none rounded-2xl bg-surface-container/50 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-bold pl-12"
                                            required
                                        />
                                    </div>
                                    <p className="text-[10px] font-medium text-on-surface-variant/40 mt-3 ml-1 leading-relaxed italic">
                                        Select a node on the map to see its access details.
                                    </p>
                                </div>

                                <Button
                                    type="submit"
                                    disabled={loading}
                                    className="w-full h-14 rounded-2xl font-bold text-[13px] tracking-tight shadow-xl shadow-primary/20 transition-all"
                                >
                                    {loading ? <Loader2 className="mr-3 h-5 w-5 animate-spin" /> : <Zap className="mr-3 h-5 w-5" />}
                                    Execute traversal
                                </Button>
                            </form>
                        </GlassCardContent>
                    </GlassCard>

                    <div className="bg-inverse text-on-inverse p-10 rounded-[32px] space-y-6 shadow-2xl shadow-on-surface/10 relative overflow-hidden group">
                        <div className="absolute top-0 right-0 p-6 opacity-5 pointer-events-none group-hover:scale-110 transition-transform">
                            <Terminal className="w-24 h-24 -mr-4 -mt-4 text-primary" />
                        </div>
                        <div className="flex items-center gap-4 text-primary">
                            <Database className="w-6 h-6" />
                            <span className="text-[12px] font-bold tracking-tight">Graph metadata</span>
                        </div>
                        <p className="text-[12px] font-bold leading-relaxed tracking-tight text-on-inverse/40">
                            Traversing logical edges between subjects, roles, and resource shards. Cryptographic proofing enabled.
                        </p>
                        <div className="pt-4 border-t border-on-inverse/10 flex items-center justify-between">
                            <span className="text-[10px] font-bold tracking-tight opacity-40 italic">Consistency check</span>
                            <Badge className="bg-success/10 text-emerald-400 border-none rounded-lg font-bold text-[10px] tracking-tight px-3 py-1">Synchronized</Badge>
                        </div>
                    </div>
                </div>

                <div className="lg:col-span-8">
                    <div className="flex items-center gap-6 mb-10 ml-4">
                        <div className="h-2 w-2 rounded-full bg-primary animate-pulse" />
                        <h2 className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 italic">Inferred relationship matrix</h2>
                        <div className="h-px flex-1 bg-on-surface/5" />
                    </div>

                    <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-card overflow-hidden rounded-[32px]">
                        <GlassCardContent className="p-0">
                            <div className="overflow-x-auto min-h-[500px]">
                                <GlassTable>
                                    <GlassTableHeader>
                                        <GlassTableRow className="hover:bg-transparent border-b border-on-surface/5">
                                            <GlassTableHead className="py-6 pl-10">Origin class</GlassTableHead>
                                            <GlassTableHead>Vector link</GlassTableHead>
                                            <GlassTableHead>Terminal node</GlassTableHead>
                                            <GlassTableHead className="text-right pr-10">Directives</GlassTableHead>
                                        </GlassTableRow>
                                    </GlassTableHeader>
                                    <TableBody>
                                        {loading ? (
                                            <GlassTableRow>
                                                <TableCell colSpan={4} className="py-32 text-center">
                                                    <div className="flex flex-col items-center gap-6">
                                                        <Loader2 className="h-10 w-10 animate-spin text-primary opacity-20" />
                                                        <span className="text-[12px] font-bold tracking-tight opacity-20 italic">Loading map...</span>
                                                    </div>
                                                </TableCell>
                                            </GlassTableRow>
                                        ) : results.length === 0 ? (
                                            <GlassTableRow>
                                                <TableCell colSpan={4} className="py-40 text-center">
                                                    <div className="flex flex-col items-center gap-6 opacity-20 grayscale">
                                                        <Network className="h-16 w-16" />
                                                        <span className="text-[11px] font-bold tracking-tight italic">{error || 'Execute traversal to resolve relationship shards.'}</span>
                                                    </div>
                                                </TableCell>
                                            </GlassTableRow>
                                        ) : (
                                            results.map((res, i) => (
                                                <GlassTableRow key={i} className="hover:bg-surface-container/10 transition-all border-b border-on-surface/5 last:border-0 group">
                                                    <TableCell className="py-8 pl-10">
                                                        <div className="flex items-center gap-4">
                                                            <div className="w-10 h-10 rounded-2xl bg-surface-container flex items-center justify-center group-hover:bg-primary/10 group-hover:text-primary transition-all">
                                                                <User className="w-5 h-5 opacity-40" />
                                                            </div>
                                                            <div className="flex flex-col">
                                                                <span className="text-sm font-bold tracking-tight text-on-surface group-hover:text-primary transition-colors">{res.subject_name || res.subject_id}</span>
                                                                <span className="text-[10px] font-bold tracking-tight text-on-surface-variant/20 mt-1 italic">{res.subject_type}</span>
                                                            </div>
                                                        </div>
                                                    </TableCell>
                                                    <TableCell className="py-8">
                                                        <div className="flex items-center gap-4">
                                                            <div className="p-2 bg-primary/5 rounded-lg">
                                                                <ArrowRight className="w-4 h-4 text-primary" />
                                                            </div>
                                                            <Badge className="bg-card ring-1 ring-on-surface/5 text-on-surface-variant font-bold text-[10px] tracking-tight px-3 py-1 group-hover:ring-primary/20 transition-all">
                                                                {res.relation}
                                                            </Badge>
                                                        </div>
                                                    </TableCell>
                                                    <TableCell className="py-8">
                                                        <div className="flex items-center gap-4">
                                                            <div className="w-10 h-10 rounded-2xl bg-surface-container flex items-center justify-center group-hover:bg-primary/10 group-hover:text-primary transition-all">
                                                                <Shield className="w-5 h-5 opacity-40" />
                                                            </div>
                                                            <div className="flex flex-col">
                                                                <span className="text-sm font-bold tracking-tight text-on-surface group-hover:text-primary transition-colors">{res.object_name || res.object_id}</span>
                                                                <span className="text-[10px] font-bold tracking-tight text-on-surface-variant/20 mt-1 italic">{res.namespace || 'node'}</span>
                                                            </div>
                                                        </div>
                                                    </TableCell>
                                                    <TableCell className="py-8 text-right pr-10">
                                                        <Button variant="ghost" size="icon" className="rounded-xl hover:bg-surface-container text-on-surface-variant/40 hover:text-primary transition-all">
                                                            <Maximize2 className="h-4.5 w-4.5" />
                                                        </Button>
                                                    </TableCell>
                                                </GlassTableRow>
                                            ))
                                        )}
                                    </TableBody>
                                </GlassTable>
                            </div>
                        </GlassCardContent>
                        {results.length > 0 && (
                            <div className="p-8 border-t border-on-surface/5 bg-surface-container/5">
                                <h3 className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 flex items-center gap-2 mb-6">
                                    <Zap className="w-3.5 h-3.5 text-primary" />
                                    Access Details
                                </h3>
                                <div className="text-[11px] font-bold tracking-tight text-on-surface-variant/20 flex items-center gap-3 italic">
                                    <Globe className="h-4 w-4" />
                                    Resolved {results.length} unique relationship shards across the organizational cluster.
                                </div>
                            </div>
                        )}
                    </GlassCard>
                </div>
            </div>
        </div>
        </PageLayout>
    );
};

export default GraphExplorer;
