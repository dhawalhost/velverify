import React, { useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { 
    Plus, 
    Server, 
    Key, 
    Activity, 
    Trash2, 
    Cpu, 
    Loader2, 
    ShieldCheck, 
    Zap, 
    MoreHorizontal,
    Box,
    Terminal,
    Fingerprint,
    X,
    Database
} from 'lucide-react';
import { getWorkloads, createWorkload } from '../api';
import { 
    PageHeader, 
    GlassCard, 
    GlassCardHeader, 
    GlassCardTitle, 
    GlassCardContent, 
    GlassTable, 
    GlassTableHeader, 
    GlassTableHead, 
    GlassTableRow,
    GlassCardDescription 
} from '@/components/layout';
import { 
    TableBody, 
    TableCell 
} from "@/components/ui/table";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog";
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription } from '@/components/ui/alert';

const WorkloadManagement: React.FC = () => {
    const [workloads, setWorkloads] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    
    // Create state
    const [showCreate, setShowCreate] = useState(false);
    const [newName, setNewName] = useState('');
    const [newHandle, setNewHandle] = useState('');
    const [isCreating, setIsCreating] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const fetchWorkloads = async () => {
        setLoading(true);
        try {
            const data = await getWorkloads();
            setWorkloads(data || []);
        } catch (err) {
            console.error('Failed to fetch workloads', err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchWorkloads();
    }, []);

    const handleCreateWorkload = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsCreating(true);
        setError(null);
        try {
            await createWorkload({
                name: newName,
                service_handle: newHandle
            });
            setShowCreate(false);
            setNewName('');
            setNewHandle('');
            fetchWorkloads();
        } catch (err: any) {
            console.error(err);
            setError('Failed to initialize workload primitive. Please verify your handle uniqueness.');
        } finally {
            setIsCreating(false);
        }
    };

    if (loading && workloads.length === 0) return <div className="h-[400px] flex items-center justify-center"><Loader2 className="h-10 w-10 animate-spin text-primary opacity-20" /></div>;

    return (
        <div className="space-y-10 animate-in fade-in slide-in-from-bottom-4 duration-700">
            <PageHeader
                icon={<Server className="w-10 h-10 text-primary" />}
                title="Service node registry"
                description="Orchestrate non-human identities, machine vectors, and automated agent authentication clusters."
                actions={
                    <Button onClick={() => setShowCreate(true)} className="h-11 rounded-xl px-8 font-bold text-sm shadow-sm transition-all hover:scale-[1.02] active:scale-[0.98]">
                        <Plus className="w-4 h-4 mr-2" /> Initialize workload
                    </Button>
                }
            />

            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                {[
                    { label: 'Cluster capacity', value: workloads.length, icon: <Cpu className="w-5 h-5" />, color: 'bg-primary/5 text-primary' },
                    { label: 'Active vectors', value: workloads.filter(w => w.status === 'active').length, icon: <Activity className="w-5 h-5" />, color: 'bg-emerald-50 text-emerald-600' },
                    { label: 'Pending rotations', value: '2', icon: <Zap className="w-5 h-5" />, color: 'bg-amber-50 text-amber-600' },
                ].map((stat) => (
                    <GlassCard key={stat.label} className="border-none shadow-xl shadow-on-surface/5 bg-white overflow-hidden rounded-[24px]">
                        <GlassCardContent className="p-8">
                            <div className="flex items-center justify-between">
                                <div className="space-y-3">
                                    <p className="text-on-surface-variant/40 font-bold text-[12px] tracking-tight">{stat.label}</p>
                                    <p className="text-3xl font-black tracking-tighter text-on-surface">{stat.value}</p>
                                </div>
                                <div className={`p-4 rounded-2xl ${stat.color} shadow-sm`}>
                                    {stat.icon}
                                </div>
                            </div>
                        </GlassCardContent>
                    </GlassCard>
                ))}
            </div>

            <GlassCard className="overflow-hidden border-none shadow-2xl shadow-on-surface/5 bg-white rounded-[32px]">
                <GlassCardHeader className="py-10 px-10 border-b border-on-surface/5 bg-surface-container/5">
                    <div className="flex items-center gap-6">
                        <div className="p-4 bg-primary/5 rounded-2xl text-primary">
                            <ShieldCheck className="w-7 h-7" />
                        </div>
                        <div>
                            <GlassCardTitle className="text-2xl font-bold tracking-tight text-on-surface">Workload inventory</GlassCardTitle>
                            <p className="text-on-surface-variant/60 font-medium text-[11px] mt-1.5 italic">
                                Deterministic identities in active execution
                            </p>
                        </div>
                    </div>
                </GlassCardHeader>
                <GlassCardContent className="p-0">
                    <div className="overflow-x-auto min-h-[400px]">
                        <GlassTable>
                            <GlassTableHeader>
                                <GlassTableRow className="hover:bg-transparent border-b border-on-surface/5">
                                    <GlassTableHead className="py-6 pl-10 font-bold text-[12px] tracking-tight text-on-surface-variant/40">Node identity</GlassTableHead>
                                    <GlassTableHead className="font-bold text-[12px] tracking-tight text-on-surface-variant/40">Service handle</GlassTableHead>
                                    <GlassTableHead className="font-bold text-[12px] tracking-tight text-on-surface-variant/40">Status</GlassTableHead>
                                    <GlassTableHead className="font-bold text-[12px] tracking-tight text-on-surface-variant/40">Telemetry</GlassTableHead>
                                    <GlassTableHead className="text-right pr-10 font-bold text-[12px] tracking-tight text-on-surface-variant/40">Directives</GlassTableHead>
                                </GlassTableRow>
                            </GlassTableHeader>
                            <TableBody>
                                {workloads.length === 0 ? (
                                    <GlassTableRow>
                                        <TableCell colSpan={5} className="py-40 text-center">
                                            <div className="flex flex-col items-center gap-6 opacity-20">
                                                <Box className="h-16 w-16" />
                                                <span className="text-sm font-medium italic">No machine identities specialized for this cluster.</span>
                                            </div>
                                        </TableCell>
                                    </GlassTableRow>
                                ) : (
                                    workloads.map((w) => (
                                        <GlassTableRow key={w.id} className="hover:bg-surface-container/20 transition-all border-b border-on-surface/5 last:border-0 group">
                                            <TableCell className="py-8 pl-10">
                                                <div className="flex items-center gap-5">
                                                    <div className="w-11 h-11 rounded-2xl bg-surface-container flex items-center justify-center group-hover:bg-primary/10 group-hover:text-primary transition-all shadow-sm">
                                                        <Terminal className="h-5 w-5 opacity-40 group-hover:opacity-100" />
                                                    </div>
                                                    <div className="flex flex-col">
                                                        <span className="font-bold text-base tracking-tight text-on-surface group-hover:text-primary transition-colors">
                                                            {w.name}
                                                        </span>
                                                        <code className="text-[10px] font-bold text-on-surface-variant/40 mt-1 italic tracking-tight font-mono">
                                                            uid: {w.id.substring(0, 12).toLowerCase()}
                                                        </code>
                                                    </div>
                                                </div>
                                            </TableCell>
                                            <TableCell className="py-8">
                                                <Badge className="bg-white ring-1 ring-on-surface/5 text-on-surface-variant border-none rounded-xl text-[10px] font-bold py-1.5 px-4 group-hover:ring-primary/20 transition-all tracking-tight italic">
                                                    {w.service_handle}
                                                </Badge>
                                            </TableCell>
                                            <TableCell className="py-8">
                                                <div className="flex items-center gap-3">
                                                    <div className={`h-2 w-2 rounded-full ${w.status === 'active' ? 'bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.4)]' : 'bg-on-surface-variant/20'}`} />
                                                    <span className={`text-[11px] font-bold tracking-tight ${w.status === 'active' ? 'text-emerald-600' : 'text-on-surface-variant/40'}`}>
                                                        {w.status === 'active' ? 'Operational' : 'Dormant'}
                                                    </span>
                                                </div>
                                            </TableCell>
                                            <TableCell className="py-8">
                                                <div className="flex items-center gap-2.5 text-on-surface-variant/60 font-medium text-xs italic">
                                                    <Activity className="w-3.5 h-3.5 opacity-40" />
                                                    {w.last_used_at ? new Date(w.last_used_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'No Telemetry'}
                                                </div>
                                            </TableCell>
                                            <TableCell className="py-8 text-right pr-10">
                                                <DropdownMenu>
                                                    <DropdownMenuTrigger asChild>
                                                        <Button variant="ghost" size="icon" className="h-10 w-10 rounded-xl hover:bg-surface-container transition-all">
                                                            <MoreHorizontal className="h-5 w-5 text-on-surface-variant/60" />
                                                        </Button>
                                                    </DropdownMenuTrigger>
                                                    <DropdownMenuContent align="end" className="w-[200px] rounded-2xl border-none shadow-2xl shadow-on-surface/10 p-2 bg-white">
                                                        <DropdownMenuItem className="font-bold text-xs gap-3 py-3.5 px-4 cursor-pointer rounded-xl focus:bg-primary/5 focus:text-primary transition-colors">
                                                            <Key className="w-4 h-4 opacity-50" />
                                                            Rotate secret
                                                        </DropdownMenuItem>
                                                        <DropdownMenuItem className="font-bold text-xs gap-3 py-3.5 px-4 cursor-pointer rounded-xl focus:bg-primary/5 focus:text-primary transition-colors">
                                                            <Activity className="w-4 h-4 opacity-50" />
                                                            View insights
                                                        </DropdownMenuItem>
                                                        <DropdownMenuItem className="text-red-500 font-bold text-xs gap-3 py-3.5 px-4 cursor-pointer rounded-xl focus:bg-red-50 focus:text-red-600 transition-colors">
                                                            <Trash2 className="w-4 h-4" />
                                                            Decommission
                                                        </DropdownMenuItem>
                                                    </DropdownMenuContent>
                                                </DropdownMenu>
                                            </TableCell>
                                        </GlassTableRow>
                                    ))
                                )}
                            </TableBody>
                        </GlassTable>
                    </div>
                </GlassCardContent>
            </GlassCard>

            <Dialog open={showCreate} onOpenChange={setShowCreate}>
                <DialogContent className="sm:max-w-[550px] rounded-[32px] border-none p-0 overflow-hidden shadow-2xl shadow-on-surface/20">
                    <DialogHeader className="bg-surface-container/10 p-10 border-b border-on-surface/5">
                        <div className="flex items-center gap-5">
                            <div className="p-3.5 bg-primary rounded-2xl text-white shadow-lg shadow-primary/20">
                                <Plus className="w-7 h-7" />
                            </div>
                            <div>
                                <DialogTitle className="text-3xl font-bold tracking-tight text-on-surface">Initialize workload</DialogTitle>
                                <DialogDescription className="text-on-surface-variant/60 font-medium text-[11px] mt-2 italic">
                                    Specializing machine identity for cluster operations
                                </DialogDescription>
                            </div>
                        </div>
                    </DialogHeader>
                    <form onSubmit={handleCreateWorkload} className="p-10 space-y-8 bg-white">
                        {error && (
                            <Alert variant="destructive" className="rounded-2xl border-none bg-red-50 text-red-600 animate-in slide-in-from-top-2">
                                <AlertDescription className="font-bold text-xs tracking-tight flex items-center gap-3">
                                    <Fingerprint className="w-4 h-4" />
                                    Collision alert: {error}
                                </AlertDescription>
                            </Alert>
                        )}
                        
                        <div className="space-y-4">
                            <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Workload designation</Label>
                            <Input
                                value={newName}
                                onChange={e => setNewName(e.target.value)}
                                placeholder="e.g. auth-aggregator-v2"
                                className="h-14 rounded-2xl border-none bg-surface-container/50 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-bold text-sm px-6"
                                required
                            />
                        </div>

                        <div className="space-y-4">
                            <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Service handle (subject id)</Label>
                            <Input
                                value={newHandle}
                                onChange={e => setNewHandle(e.target.value)}
                                placeholder="e.g. system:service:aggregator"
                                className="h-14 rounded-2xl border-none bg-surface-container/50 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-bold text-sm px-6 font-mono"
                                required
                            />
                        </div>

                        <DialogFooter className="pt-6 gap-4">
                            <Button type="button" variant="ghost" onClick={() => setShowCreate(false)} className="h-14 px-8 rounded-2xl font-bold text-[12px] hover:bg-surface-container/20">
                                Abort
                            </Button>
                            <Button type="submit" disabled={isCreating} className="flex-1 h-14 rounded-2xl font-bold tracking-tight text-[12px] shadow-xl shadow-primary/20 transition-all">
                                {isCreating ? <Loader2 className="h-5 w-5 animate-spin" /> : 'Finalize initialization'}
                            </Button>
                        </DialogFooter>
                    </form>
                </DialogContent>
            </Dialog>
        </div>
    );
};

export default WorkloadManagement;
