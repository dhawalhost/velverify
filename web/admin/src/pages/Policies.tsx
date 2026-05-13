import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { getPolicies, createPolicy, Policy } from '../api';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { 
    Loader2, 
    ShieldCheck, 
    ShieldAlert, 
    Plus, 
    Settings2, 
    FileJson,
    Trash2,
    X,
    AlertCircle,
    Info,
    Layout,
    Fingerprint,
    Command,
    Zap,
    ExternalLink,
    Terminal,
    Binary,
    ArrowUpRight
} from 'lucide-react';
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassTable, GlassTableHeader, GlassTableHead, GlassTableRow, GlassCardDescription, GlassCardFooter } from '@/components/layout';
import { TableBody, TableCell } from '@/components/ui/table';

const Policies: React.FC = () => {
    const navigate = useNavigate();
    const [policies, setPolicies] = useState<Policy[]>([]);
    const [loading, setLoading] = useState(true);
    const [isCreateOpen, setIsCreateOpen] = useState(false);
    const [message, setMessage] = useState<{ text: string, type: 'success' | 'error' } | null>(null);
    const [newPolicy, setNewPolicy] = useState({
        name: '',
        rule_type: 'access_control',
        rule_data: '{\n  "condition": "user.groups.contains(\'admin\')",\n  "effect": "allow"\n}'
    });

    const fetchPolicies = async () => {
        try {
            setLoading(true);
            const data = await getPolicies();
            setPolicies(data || []);
        } catch (err) {
            console.error(err);
            setMessage({ text: "Failed to load tenant security policies.", type: 'error' });
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchPolicies();
    }, []);

    const handleCreate = async () => {
        try {
            setMessage(null);
            let ruleData = {};
            try {
                ruleData = JSON.parse(newPolicy.rule_data);
            } catch (e) {
                setMessage({ text: "Rule data must be valid JSON.", type: 'error' });
                return;
            }

            await createPolicy({
                name: newPolicy.name,
                rule_type: newPolicy.rule_type,
                rule_data: ruleData,
                is_enabled: true
            });

            setMessage({ text: "The security policy has been successfully deployed.", type: 'success' });
            setIsCreateOpen(false);
            setNewPolicy({
                name: '',
                rule_type: 'access_control',
                rule_data: '{\n  "condition": "user.groups.contains(\'admin\')",\n  "effect": "allow"\n}'
            });
            fetchPolicies();
        } catch (err) {
            console.error(err);
            setMessage({ text: "Could not persist the new policy rule.", type: 'error' });
        }
    };

    if (loading && policies.length === 0) return <div className="h-[400px] flex items-center justify-center"><Loader2 className="h-12 w-12 animate-spin text-primary opacity-20" /></div>;

    return (
        <div className="max-w-6xl mx-auto space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-700 py-6">
            <PageHeader
                icon={<ShieldCheck className="w-8 h-8 text-primary" />}
                title="Security Policies"
                description="Define security rules for your organization. Control access to resources and data."
                actions={
                    <Button onClick={() => setIsCreateOpen(true)} className="h-9 rounded-lg bg-primary text-primary-foreground font-bold tracking-tight text-[11px] px-6 shadow-xl shadow-primary/20 transition-all hover:scale-[1.02] active:scale-[0.98]">
                        <Plus className="w-3.5 h-3.5 mr-2" /> Create Policy
                    </Button>
                }
            />

            {message && (
                <Alert variant={message.type === 'error' ? 'destructive' : 'default'} className="rounded-xl border-none bg-surface-container/50 backdrop-blur-md">
                    <AlertDescription className="font-bold text-xs tracking-tight flex items-center gap-3">
                        {message.type === 'error' ? <ShieldAlert className="w-4 h-4 text-destructive" /> : <ShieldCheck className="w-4 h-4 text-success" />}
                        {message.text}
                    </AlertDescription>
                </Alert>
            )}

            {isCreateOpen && (
                <GlassCard className="border-none shadow-2xl shadow-on-surface/10 bg-card overflow-hidden rounded-xl animate-in slide-in-from-top-12 duration-700">
                    <GlassCardHeader className="py-6 px-8 border-b border-on-surface/5 bg-surface-container/10">
                        <div className="flex justify-between items-center">
                            <div className="flex items-center gap-4">
                                <div className="p-3 bg-primary/10 rounded-xl text-primary">
                                    <Fingerprint className="w-6 h-6" />
                                </div>
                                <div>
                                    <GlassCardTitle className="text-xl font-bold tracking-tight text-on-surface">Deploy policy logic</GlassCardTitle>
                                    <p className="text-on-surface-variant/40 font-bold text-[10px] mt-0.5 tracking-tight italic">Architectural perimeter definition protocol</p>
                                </div>
                            </div>
                            <Button variant="ghost" size="icon" onClick={() => setIsCreateOpen(false)} className="rounded-lg h-9 w-9 hover:bg-destructive/10 hover:text-destructive transition-all">
                                <X className="w-5 h-5" />
                            </Button>
                        </div>
                    </GlassCardHeader>
                    <GlassCardContent className="p-8 space-y-6">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div className="space-y-3">
                                <Label htmlFor="name" className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Policy identifier</Label>
                                <Input 
                                    id="name" 
                                    placeholder="e.g. SOC2_CORE_ACCESS" 
                                    className="h-10 rounded-lg border-none bg-surface-container/50 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-bold text-sm px-4 italic"
                                    value={newPolicy.name}
                                    onChange={(e) => setNewPolicy({...newPolicy, name: e.target.value})}
                                />
                            </div>
                            <div className="space-y-3">
                                <Label htmlFor="type" className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Rule engine kernel</Label>
                                <Input 
                                    id="type" 
                                    value={newPolicy.rule_type}
                                    className="h-10 rounded-lg border-none bg-surface-container ring-1 ring-on-surface/5 font-bold text-sm px-4 select-none tracking-tight opacity-50"
                                    readOnly
                                />
                            </div>
                        </div>
                        <div className="space-y-3">
                            <Label htmlFor="rule" className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Behavioral definition json</Label>
                            <div className="relative group">
                                <Textarea 
                                    id="rule" 
                                    rows={8} 
                                    className="font-mono text-sm rounded-xl border-none bg-on-surface text-primary p-6 focus-visible:ring-2 focus-visible:ring-primary/20 resize-none shadow-2xl transition-all"
                                    value={newPolicy.rule_data}
                                    onChange={(e) => setNewPolicy({...newPolicy, rule_data: e.target.value})}
                                />
                                <div className="absolute right-6 top-6 opacity-10 pointer-events-none group-hover:opacity-40 transition-opacity">
                                    <Binary className="w-8 h-8 text-primary" />
                                </div>
                            </div>
                        </div>
                        
                        <div className="flex flex-col md:flex-row justify-end gap-4 pt-4 italic">
                            <Button variant="ghost" onClick={() => setIsCreateOpen(false)} className="h-10 px-6 rounded-lg font-bold text-xs tracking-tight text-on-surface-variant/40 hover:bg-surface-container transition-all">Discard logic</Button>
                            <Button onClick={handleCreate} className="h-10 px-10 rounded-lg font-bold text-xs tracking-tight shadow-2xl shadow-primary/30 transition-all hover:scale-[1.02] active:scale-[0.98]">Commit deployment</Button>
                        </div>
                    </GlassCardContent>
                </GlassCard>
            )}

            <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-card overflow-hidden rounded-xl">
                <GlassCardHeader className="py-5 px-6 border-b border-on-surface/5 bg-surface-container/5">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-primary/10 rounded-lg text-primary">
                            <Zap className="w-5 h-5" />
                        </div>
                        <div>
                            <GlassCardTitle className="text-lg font-bold tracking-tight text-on-surface">Policy List</GlassCardTitle>
                            <p className="text-on-surface-variant/40 font-bold text-[10px] mt-0.5 tracking-tight">
                                {policies.length} Active Policies
                            </p>
                        </div>
                    </div>
                </GlassCardHeader>
                <GlassCardContent className="p-0">
                    <div className="overflow-x-auto min-h-[500px]">
                        <GlassTable>
                            <GlassTableHeader>
                                <GlassTableRow className="hover:bg-transparent border-b border-on-surface/5">
                                    <GlassTableRow className="hover:bg-transparent border-b border-on-surface/5">
                                        <GlassTableHead className="py-3 pl-6 font-bold text-[10px] tracking-tight text-on-surface-variant/40 uppercase">Policy Name</GlassTableHead>
                                        <GlassTableHead className="py-3 font-bold text-[10px] tracking-tight text-on-surface-variant/40 uppercase">Rules</GlassTableHead>
                                        <GlassTableHead className="py-3 text-center font-bold text-[10px] tracking-tight text-on-surface-variant/40 uppercase">Enforcement state</GlassTableHead>
                                        <GlassTableHead className="py-3 font-bold text-[10px] tracking-tight text-on-surface-variant/40 uppercase">Created</GlassTableHead>
                                        <GlassTableHead className="py-3 text-right font-bold text-[10px] tracking-tight text-on-surface-variant/40 pr-6 uppercase">Actions</GlassTableHead>
                                    </GlassTableRow>
                                </GlassTableRow>
                            </GlassTableHeader>
                            <TableBody>
                                {policies.length === 0 ? (
                                    <GlassTableRow>
                                        <TableCell colSpan={5} className="py-40 text-center">
                                            <div className="flex flex-col items-center gap-6 opacity-20 italic">
                                                <div className="w-24 h-24 rounded-[32px] bg-surface-container flex items-center justify-center p-6 border-2 border-dashed border-on-surface/10">
                                                    <FileJson className="h-full w-full" />
                                                </div>
                                                <span className="text-[12px] font-bold tracking-tight text-on-surface-variant opacity-60">Null policy cell // Directory clear</span>
                                            </div>
                                        </TableCell>
                                    </GlassTableRow>
                                ) : (
                                    policies.map(policy => (
                                        <GlassTableRow key={policy.id} className="hover:bg-surface-container/10 transition-all border-b border-on-surface/5 last:border-0 group">
                                            <TableCell className="py-3 pl-6">
                                                <div className="flex items-center gap-4">
                                                    <div className="w-9 h-9 rounded-lg bg-surface-container flex items-center justify-center shadow-md group-hover:bg-primary/10 group-hover:text-primary transition-all duration-500">
                                                        <FileJson className="w-4 h-4 opacity-40 group-hover:opacity-100" />
                                                    </div>
                                                    <div className="flex flex-col">
                                                        <span className="text-sm font-bold tracking-tight text-on-surface group-hover:text-primary transition-all duration-300">{policy.name}</span>
                                                        <span className="text-[9px] font-bold text-on-surface-variant/20 tracking-tight mt-0.5 opacity-60 italic">ID: {policy.id.substring(0, 12)}...</span>
                                                    </div>
                                                </div>
                                            </TableCell>
                                            <TableCell className="py-3 text-[10px] font-bold tracking-tight text-on-surface-variant/40 italic">
                                                {policy.rule_type}
                                            </TableCell>
                                            <TableCell className="text-center py-3">
                                                {policy.is_enabled ? 
                                                    <Badge className="bg-success/10 text-success border-none rounded-md font-bold text-[9px] tracking-tight px-3 py-1 italic">Enforcement active</Badge> : 
                                                    <Badge className="bg-surface-container text-on-surface-variant/40 border-none rounded-md font-bold text-[9px] tracking-tight px-3 py-1 italic">Rules halted</Badge>
                                                }
                                            </TableCell>
                                            <TableCell className="py-3">
                                                <span className="text-[10px] font-medium text-on-surface-variant/40 italic flex items-center gap-2">
                                                    <div className="w-1.5 h-1.5 bg-on-surface/5 rounded-full" />
                                                    {new Date(policy.updated_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}
                                                </span>
                                            </TableCell>
                                            <TableCell className="py-3 text-right pr-6">
                                                <div className="flex justify-end gap-2 opacity-20 group-hover:opacity-100 transition-opacity">
                                                    <Button 
                                                        variant="ghost" 
                                                        onClick={() => navigate(`/policies/${policy.id}`)}
                                                        className="h-8 rounded-lg px-3 font-bold text-[10px] tracking-tight text-primary border border-primary/10 hover:bg-primary/5 hover:border-primary/20 transition-all"
                                                    >
                                                        <ArrowUpRight className="w-3.5 h-3.5 mr-1.5" /> View Policy
                                                    </Button>
                                                    <Button size="icon" variant="ghost" className="h-8 w-8 border border-transparent hover:border-destructive/20 hover:bg-destructive/10 hover:text-destructive rounded-lg transition-all">
                                                        <Trash2 className="w-3.5 h-3.5" />
                                                    </Button>
                                                </div>
                                            </TableCell>
                                        </GlassTableRow>
                                    ))
                                )}
                            </TableBody>
                        </GlassTable>
                    </div>
                </GlassCardContent>
            </GlassCard>

            <div className="bg-inverse text-on-inverse p-8 rounded-3xl shadow-2xl shadow-on-surface/10 relative overflow-hidden group">
                <div className="absolute top-0 right-0 p-6 opacity-5 pointer-events-none group-hover:scale-110 transition-transform duration-700">
                    <Command className="w-32 h-32 -mr-10 -mt-10 text-primary-foreground" />
                </div>
                <div className="flex flex-col lg:flex-row items-center gap-8 relative z-10">
                    <div className="p-4 bg-card/5 rounded-2xl backdrop-blur-xl border border-on-inverse/10 shadow-inner">
                        <Terminal className="w-8 h-8 text-primary-foreground animate-pulse" />
                    </div>
                    <div className="space-y-2 flex-1 text-center lg:text-left">
                        <h3 className="text-2xl font-bold tracking-tight">Post-login policy engine</h3>
                        <p className="text-xs font-medium opacity-60 max-w-2xl leading-relaxed italic tracking-tight">
                            Policy sync triggers real-time event propagation across all active identity cells. Ensure structural JSON compliance to prevent enforcement lockout. 
                        </p>
                    </div>
                    <div className="flex gap-3">
                        <Button variant="outline" onClick={() => navigate('/policies')} className="h-10 px-6 rounded-lg border-on-inverse/10 bg-card/5 hover:bg-card/10 text-white font-bold tracking-tight text-[10px]">
                            View Policies
                        </Button>
                        <Button onClick={() => navigate('/audit')} className="h-10 px-6 rounded-lg font-bold tracking-tight text-[10px] shadow-2xl shadow-primary/20">
                            Audit Logs
                        </Button>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Policies;
