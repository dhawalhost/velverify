import React, { useState, useEffect } from 'react';
import {
    getIPPolicies,
    createIPPolicy,
    deleteIPPolicy,
    IPPolicy
} from '../api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import {
    ShieldAlert,
    Globe,
    Network,
    Trash2,
    Plus,
    ShieldCheck,
    Loader2,
    Terminal,
    MapPin,
    Activity,
    Lock,
    Binary,
    Fingerprint,
    X,
    Filter,
    ChevronRight,
    Command,
    ExternalLink
} from 'lucide-react';
import {
    TableBody,
    TableCell,
} from "@/components/ui/table";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from "@/components/ui/dialog";
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";
import { Alert, AlertDescription } from '@/components/ui/alert';
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassTable, GlassTableHeader, GlassTableHead, GlassTableRow } from '@/components/layout';

const IPPolicies: React.FC = () => {
    const [policies, setPolicies] = useState<IPPolicy[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    // New Policy State
    const [showCreate, setShowCreate] = useState(false);
    const [newRuleKind, setNewRuleKind] = useState<'cidr' | 'country'>('cidr');
    const [newValue, setNewValue] = useState('');
    const [newDesc, setNewDesc] = useState('');
    const [newAction, setNewAction] = useState<'allow' | 'deny'>('allow');
    const [creating, setCreating] = useState(false);

    const fetchPolicies = async () => {
        setLoading(true);
        try {
            const data = await getIPPolicies();
            setPolicies(data || []);
        } catch (err) {
            setError('Failed to retrieve network security policies.');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchPolicies();
    }, []);

    const handleCreatePolicy = async (e: React.FormEvent) => {
        e.preventDefault();
        setCreating(true);
        try {
            await createIPPolicy({
                type: newAction as 'allow' | 'block',
                cidr: newRuleKind === 'cidr' ? newValue : undefined,
                country: newRuleKind === 'country' ? newValue : undefined,
                reason: newDesc || undefined,
            });
            setShowCreate(false);
            setNewValue('');
            setNewDesc('');
            fetchPolicies();
        } catch (err) {
            setError('Failed to commit security policy.');
        } finally {
            setCreating(false);
        }
    };

    const handleDeletePolicy = async (id: string) => {
        if (!window.confirm('Revoke this network security policy? This action is immediate and may affect user access.')) return;
        try {
            await deleteIPPolicy(id);
            fetchPolicies();
        } catch (err) {
            setError('Failed to revoke policy.');
        }
    };

    if (loading && policies.length === 0) return <div className="h-[400px] flex items-center justify-center"><Loader2 className="h-10 w-10 animate-spin text-primary opacity-20" /></div>;

    return (
        <div className="space-y-12 animate-in fade-in duration-700">
            <PageHeader
                icon={<ShieldCheck className="w-10 h-10 text-primary" />}
                title="IP Access Policies"
                description="Manage IP-based access rules. Restrict or allow access based on network locations."
                actions={
                    <Dialog open={showCreate} onOpenChange={setShowCreate}>
                        <DialogTrigger asChild>
                            <Button className="h-11 rounded-xl bg-primary text-primary-foreground font-bold tracking-tight text-[11px] px-8 shadow-xl shadow-primary/20 transition-all hover:scale-[1.02] active:scale-[0.98]">
                                <Plus className="w-4 h-4 mr-3" /> Add IP Rule
                            </Button>
                        </DialogTrigger>
                        <DialogContent className="sm:max-w-[600px] rounded-[32px] border-none p-0 overflow-hidden shadow-2xl shadow-on-surface/20">
                            <DialogHeader className="bg-surface-container/10 p-10 border-b border-on-surface/5">
                                <div className="flex items-center gap-5">
                                    <div>
                                        <DialogTitle className="text-3xl font-bold tracking-tight text-on-surface">Create New Rule</DialogTitle>
                                        <DialogDescription className="text-on-surface-variant/60 font-medium text-[11px] mt-2">
                                            Define a new IP or Geo-location access rule.
                                        </DialogDescription>
                                    </div>
                                </div>
                            </DialogHeader>
                            <form onSubmit={handleCreatePolicy} className="p-10 space-y-8 bg-card">
                                <div className="grid grid-cols-2 gap-6">
                                    <div className="space-y-2.5">
                                        <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Rule Type</Label>
                                        <Select value={newRuleKind} onValueChange={(v: any) => setNewRuleKind(v)}>
                                            <SelectTrigger className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus:ring-2 focus:ring-primary/20 font-bold text-[11px] tracking-tight transition-all">
                                                <SelectValue />
                                            </SelectTrigger>
                                            <SelectContent className="rounded-xl border-none shadow-xl font-bold text-[11px] tracking-tight">
                                                <SelectItem value="cidr">IP CIDR Range</SelectItem>
                                                <SelectItem value="country">Geo ISO Code</SelectItem>
                                            </SelectContent>
                                        </Select>
                                    </div>
                                    <div className="space-y-2.5">
                                        <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Action</Label>
                                        <Select value={newAction} onValueChange={(v: any) => setNewAction(v)}>
                                            <SelectTrigger className={`h-12 border-none rounded-xl bg-surface-container/30 ring-1 focus:ring-2 transition-all font-bold text-[11px] tracking-tight ${newAction === 'allow' ? 'text-success ring-emerald-500/20' : 'text-destructive ring-destructive/20'}`}>
                                                <SelectValue />
                                            </SelectTrigger>
                                            <SelectContent className="rounded-xl border-none shadow-xl font-bold text-[11px] tracking-tight">
                                                <SelectItem value="allow" className="text-success">Allow Traffic</SelectItem>
                                                <SelectItem value="deny" className="text-destructive">Deny Traffic</SelectItem>
                                            </SelectContent>
                                        </Select>
                                    </div>
                                </div>

                                <div className="space-y-2.5">
                                    <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">{newRuleKind === 'cidr' ? 'IP CIDR Range' : 'Country ISO Code'}</Label>
                                    <Input
                                        value={newValue}
                                        onChange={(e) => setNewValue(e.target.value)}
                                        className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-mono text-sm px-6 transition-all"
                                        placeholder={newRuleKind === 'cidr' ? 'e.g. 192.168.1.0/24' : 'ISO 3166-1 alpha-2 (e.g. CN)'}
                                        required
                                    />
                                </div>

                                <div className="space-y-2.5">
                                    <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Rule Description</Label>
                                    <Input
                                        value={newDesc}
                                        onChange={(e) => setNewDesc(e.target.value)}
                                        className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium text-sm px-6 transition-all"
                                        placeholder="Purpose of this access rule..."
                                    />
                                </div>

                                <DialogFooter className="pt-6">
                                    <Button type="submit" disabled={creating} className="w-full h-12 rounded-xl font-bold text-sm shadow-md shadow-primary/10">
                                        {creating ? <Loader2 className="h-6 w-6 animate-spin" /> : 'Create Rule'}
                                    </Button>
                                </DialogFooter>
                            </form>
                        </DialogContent>
                    </Dialog>
                }
            />

            <div className="grid grid-cols-1 lg:grid-cols-4 gap-10">
                <div className="lg:col-span-1 space-y-10">
                    <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-card overflow-hidden rounded-[24px]">
                        <GlassCardHeader className="py-8 px-8 border-b border-on-surface/5">
                            <div className="flex items-center gap-4">
                                <div className="p-2 bg-primary/5 rounded-xl">
                                    <Terminal className="w-5 h-5 text-primary" />
                                </div>
                                <GlassCardTitle className="text-xl font-bold tracking-tight">Add IP Rule</GlassCardTitle>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-8 space-y-8">
                            <div className="flex items-center justify-between">
                                <span className="text-[11px] font-bold tracking-tight text-on-surface-variant/40">System state</span>
                                <Badge className="bg-success-subtle text-success rounded-lg font-bold text-[10px] tracking-tight px-3 py-1 border-none shadow-sm animate-pulse">Enforcing</Badge>
                            </div>
                            <div className="flex items-center justify-between">
                                <span className="text-[11px] font-bold tracking-tight text-on-surface-variant/40">Rule density</span>
                                <span className="text-2xl font-bold tracking-tight text-on-surface tabular-nums">{policies.length}</span>
                            </div>
                            <div className="space-y-4 pt-4 border-t border-on-surface/5">
                                <div className="flex items-center gap-3 text-[11px] font-bold tracking-tight text-primary uppercase">
                                    <Activity className="w-4 h-4" />
                                    Real-time sync
                                </div>
                                <div className="p-4 bg-surface-container/30 rounded-xl font-mono text-[10px] text-on-surface/60 tracking-tight leading-relaxed">
                                    [SYNC] MATING_RULE: Denied from CN (Policy ID: PX_12)<br />
                                    [SYNC] MATING_RULE: Allowed CIDR 10.42.0.0/16
                                </div>
                            </div>
                        </GlassCardContent>
                    </GlassCard>

                    <div className="bg-inverse text-on-inverse p-8 rounded-[32px] flex items-start gap-6 shadow-xl shadow-on-surface/10 relative overflow-hidden group">
                        <div className="absolute top-0 right-0 p-4 opacity-5 pointer-events-none group-hover:scale-110 transition-transform">
                            <ShieldAlert className="w-20 h-20 -mr-4 -mt-4 text-primary" />
                        </div>
                        <ShieldAlert className="w-8 h-8 text-primary flex-shrink-0 opacity-80" />
                        <p className="text-[11px] font-bold leading-relaxed tracking-tight text-on-inverse/60 group-hover:text-white transition-opacity">
                            Rules are processed by specificity prioritization. Structural default: ALLOW if zero collision vectors identified.
                        </p>
                    </div>
                </div>

                <div className="lg:col-span-3">
                    <div className="flex items-center gap-6 mb-8 ml-4">
                        <div className="h-2 w-2 rounded-full bg-primary animate-pulse" />
                        <h2 className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 italic">Enforcement matrix shard</h2>
                        <div className="h-px flex-1 bg-on-surface/5" />
                    </div>

                    <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-card overflow-hidden rounded-[32px]">
                        <GlassCardHeader className="py-10 px-10 border-b border-on-surface/5">
                            <div className="flex items-center gap-5">
                                <div className="p-4 bg-primary/5 rounded-2xl">
                                    <Network className="w-8 h-8 text-primary" />
                                </div>
                                <div>
                                    <GlassCardTitle className="text-2xl font-bold tracking-tight text-on-surface">Active IP Rules</GlassCardTitle>
                                    <p className="text-on-surface-variant/40 font-bold text-[12px] mt-1 tracking-tight">
                                        {policies.length} Synchronized Rules
                                    </p>
                                </div>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-0">
                            <div className="overflow-x-auto">
                                <GlassTable>
                                    <GlassTableHeader>
                                        <GlassTableRow className="hover:bg-transparent border-b border-on-surface/5">
                                            <GlassTableHead className="py-6 pl-10 font-bold text-[12px] tracking-tight text-on-surface-variant/40">IP Rule / Location</GlassTableHead>
                                            <GlassTableHead className="font-bold text-[12px] tracking-tight text-on-surface-variant/40">Type</GlassTableHead>
                                            <GlassTableHead className="font-bold text-[12px] tracking-tight text-on-surface-variant/40">Description</GlassTableHead>
                                            <GlassTableHead className="text-right font-bold text-[12px] tracking-tight text-on-surface-variant/40 pr-10">Actions</GlassTableHead>
                                        </GlassTableRow>
                                    </GlassTableHeader>
                                    <TableBody>
                                        {policies.length === 0 ? (
                                            <GlassTableRow>
                                                <TableCell colSpan={4} className="py-40 text-center">
                                                    <div className="flex flex-col items-center gap-6 opacity-20">
                                                        <Activity className="h-16 w-16" />
                                                        <span className="text-[13px] font-bold tracking-tight italic">Null policy state // Open architecture</span>
                                                    </div>
                                                </TableCell>
                                            </GlassTableRow>
                                        ) : (
                                            policies.map((policy) => (
                                                <GlassTableRow key={policy.id} className="hover:bg-surface-container/10 transition-all border-b border-on-surface/5 last:border-0 group">
                                                    <TableCell className="py-8 pl-10">
                                                        <div className="flex items-center gap-5">
                                                            <div className="w-11 h-11 rounded-xl bg-surface-container flex items-center justify-center group-hover:bg-primary/10 group-hover:text-primary transition-all">
                                                                {policy.cidr ? <Terminal className="h-5 w-5 opacity-40" /> : <MapPin className="h-5 w-5 opacity-40" />}
                                                            </div>
                                                            <div className="flex flex-col">
                                                                <span className="text-lg font-bold tracking-tight text-on-surface group-hover:text-primary transition-colors">{policy.cidr || policy.country_code}</span>
                                                                <span className="text-[10px] font-bold font-mono tracking-tight text-on-surface-variant/30 mt-1 italic">Id: {policy.id.substring(0, 8)}</span>
                                                            </div>
                                                        </div>
                                                    </TableCell>
                                                    <TableCell className="py-8">
                                                        <Badge className={`rounded-xl font-bold text-[10px] tracking-tight px-4 py-1.5 border-none shadow-sm transition-all ${policy.type === 'allow'
                                                            ? 'bg-success-subtle text-success'
                                                            : 'bg-destructive/10 text-destructive'
                                                            }`}>
                                                            {policy.type === 'allow' ? 'Allow' : 'Block'}
                                                        </Badge>
                                                    </TableCell>
                                                    <TableCell className="py-8">
                                                        <div className="flex flex-col gap-1">
                                                            <div className="flex items-center gap-2.5 text-[11px] font-bold tracking-tight text-on-surface-variant/40 group-hover:text-on-surface transition-colors italic">
                                                                {policy.cidr ? (
                                                                    <><Network className="w-4 h-4 text-primary opacity-40 group-hover:opacity-100" /> Cidr range</>
                                                                ) : (
                                                                    <><Globe className="w-4 h-4 text-primary opacity-40 group-hover:opacity-100" /> Geo iso</>
                                                                )}
                                                            </div>
                                                            <span className="text-[12px] font-medium text-on-surface-variant/60 tracking-tight">
                                                                {policy.reason || 'No description provided'}
                                                            </span>
                                                        </div>
                                                    </TableCell>
                                                    <TableCell className="py-8 text-right pr-10">
                                                        <Button
                                                            variant="ghost"
                                                            size="sm"
                                                            className="h-9 px-4 rounded-lg bg-destructive/5 text-destructive border border-destructive/10 hover:bg-destructive hover:text-white transition-all font-bold text-[10px] uppercase tracking-wider"
                                                            onClick={() => handleDeletePolicy(policy.id)}
                                                        >
                                                            <Trash2 className="w-3.5 h-3.5 mr-2" /> Revoke
                                                        </Button>
                                                    </TableCell>
                                                </GlassTableRow>
                                            ))
                                        )}
                                    </TableBody>
                                </GlassTable>
                            </div>
                        </GlassCardContent>
                    </GlassCard>
                </div>
            </div>
        </div>
    );
};

export default IPPolicies;
