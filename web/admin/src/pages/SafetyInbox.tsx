import React, { useEffect, useState } from 'react';
import { getSafetyActions, confirmSafetyAction, rejectSafetyAction } from '../api';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '@/components/ui/card';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Check, X, ShieldAlert, History, Activity } from 'lucide-react';
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassTable, GlassTableHeader, GlassTableHead, GlassTableRow, PageLayout
} from '@/components/layout';

const SafetyInbox: React.FC = () => {
    const [actions, setActions] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    const fetchActions = async () => {
        try {
            setLoading(true);
            const data = await getSafetyActions('pending');
            setActions(data.actions || []);
        } catch (err: any) {
            console.error(err);
            setError('Failed to fetch safety actions');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchActions();
    }, []);

    const handleConfirm = async (id: string) => {
        try {
            await confirmSafetyAction(id, 'Confirmed via Dashboard');
            fetchActions(); // Refresh list
        } catch (err) {
            alert('Failed to confirm safety action');
        }
    };

    const handleReject = async (id: string) => {
        try {
            await rejectSafetyAction(id, 'Cancelled via Dashboard');
            fetchActions();
        } catch (err) {
            alert('Failed to reject safety action');
        }
    };

    if (loading) return <div className="p-8 text-center text-muted-foreground">Loading security alerts...</div>;

    return (
        <PageLayout>
        <div className="space-y-12 animate-in fade-in duration-700">
            <PageHeader
                icon={<ShieldAlert className="w-10 h-10 text-destructive" />}
                title="Security Alerts"
                description="Review and approve automated security actions. Stop unauthorized access or lock accounts in response to threats."
                actions={
                    <Button
                        variant="outline"
                        onClick={() => fetchActions()}
                        className="h-11 rounded-xl bg-card ring-1 ring-on-surface/5 font-bold tracking-tight text-[11px] px-8 shadow-sm transition-all hover:bg-surface-container"
                    >
                        <History className="mr-2 h-4 w-4" /> Refresh
                    </Button>
                }
            />

            {error && (
                <div className="bg-destructive/10 text-destructive px-6 py-4 rounded-2xl flex items-center gap-4 text-[12px] font-bold tracking-tight border border-destructive/20 animate-in slide-in-from-top-2">
                    <ShieldAlert className="h-4 w-4" />
                    Error: {error}
                </div>
            )}

            <div className="grid grid-cols-1 gap-8">
                <GlassCard className="border-none shadow-2xl shadow-destructive/5 bg-card overflow-hidden rounded-[32px]">
                    <GlassCardHeader className="bg-destructive/10/30 border-b border-destructive/20 py-8 px-10">
                        <div className="flex items-center gap-5">
                            <div className="p-3 bg-destructive rounded-2xl text-white shadow-lg shadow-destructive/20">
                                <Activity className="h-6 w-6" />
                            </div>
                            <div>
                                <GlassCardTitle className="text-2xl font-bold tracking-tight text-on-surface">Priority Alerts</GlassCardTitle>
                                <p className="text-destructive/60 font-bold text-[12px] mt-1 tracking-tight">Pending security actions ({actions.length})</p>
                            </div>
                        </div>
                    </GlassCardHeader>
                    <GlassCardContent className="p-0">
                        <GlassTable>
                            <GlassTableHeader>
                                 <GlassTableRow className="hover:bg-transparent border-b border-on-surface/5">
                                    <GlassTableHead className="py-6 pl-10 font-bold text-[12px] tracking-tight text-on-surface-variant/40">Action Type</GlassTableHead>
                                    <GlassTableHead className="font-bold text-[12px] tracking-tight text-on-surface-variant/40">Target User/Resource</GlassTableHead>
                                    <GlassTableHead className="font-bold text-[12px] tracking-tight text-on-surface-variant/40">Reason</GlassTableHead>
                                    <GlassTableHead className="font-bold text-[12px] tracking-tight text-on-surface-variant/40">Details</GlassTableHead>
                                    <GlassTableHead className="font-bold text-[12px] tracking-tight text-on-surface-variant/40">Time</GlassTableHead>
                                    <GlassTableHead className="text-right font-bold text-[12px] tracking-tight text-on-surface-variant/40 pr-10">Actions</GlassTableHead>
                                </GlassTableRow>
                            </GlassTableHeader>
                            <TableBody>
                                {actions.length === 0 ? (
                                    <GlassTableRow>
                                        <TableCell colSpan={6} className="text-center py-32 text-on-surface-variant/30 italic">
                                            <div className="flex flex-col items-center gap-6">
                                                <div className="w-20 h-20 rounded-3xl bg-success-subtle flex items-center justify-center">
                                                    <Check className="h-10 w-10 text-success opacity-40" />
                                                </div>
                                                <span className="max-w-xs font-bold text-[12px] tracking-tight text-on-surface-variant/40 italic">No pending security alerts.</span>
                                            </div>
                                        </TableCell>
                                    </GlassTableRow>
                                ) : (
                                    actions.map((action) => (
                                        <GlassTableRow key={action.id} className="hover:bg-destructive/10/10 transition-all border-b border-on-surface/5 last:border-0 group">
                                            <TableCell className="py-8 pl-10">
                                                <Badge className="bg-destructive/100/10 text-destructive border-none rounded-lg font-bold text-[11px] tracking-tight px-3 py-1 group-hover:bg-destructive/100 group-hover:text-white transition-all">
                                                    {action.action_type ? (action.action_type.charAt(0).toUpperCase() + action.action_type.slice(1).toLowerCase()).replaceAll('_', ' ') : 'Unknown Action'}
                                                </Badge>
                                            </TableCell>
                                            <TableCell className="py-8 font-mono text-xs font-bold text-on-surface">{action.target_id}</TableCell>
                                            <TableCell className="py-8 max-w-xs text-xs font-medium italic text-on-surface-variant/60">{action.reason}</TableCell>
                                            <TableCell className="py-8">
                                                <div className="flex gap-1.5 flex-wrap">
                                                    {Array.isArray(action.metadata?.org_ids) && action.metadata.org_ids.map((org: string) => (
                                                        <Badge key={org} className="bg-surface-container text-on-surface-variant/40 border-none rounded-lg font-bold text-[10px] tracking-tight px-2 py-0.5 h-5">
                                                            {org}
                                                        </Badge>
                                                    ))}
                                                </div>
                                            </TableCell>
                                            <TableCell className="py-8">
                                                <div className="flex flex-col gap-1">
                                                    <span className="text-[11px] font-bold text-on-surface">{new Date(action.created_at).toLocaleDateString()}</span>
                                                    <span className="text-[10px] font-mono font-bold text-on-surface-variant/20 tracking-tight">{new Date(action.created_at).toLocaleTimeString()}</span>
                                                </div>
                                            </TableCell>
                                            <TableCell className="py-8 text-right pr-10">
                                                <div className="flex justify-end gap-3">
                                                     <Button
                                                        size="sm"
                                                        className="h-10 rounded-xl bg-destructive hover:bg-red-700 text-white font-bold tracking-tight text-[11px] px-5 shadow-lg shadow-destructive/20 transition-all active:scale-95"
                                                        onClick={() => handleConfirm(action.id)}
                                                    >
                                                        <Check className="h-3.5 w-3.5 mr-2" /> Confirm
                                                    </Button>
                                                    <Button
                                                        variant="outline"
                                                        size="sm"
                                                        className="h-10 rounded-xl bg-card ring-1 ring-on-surface/5 font-bold tracking-tight text-[11px] px-5 shadow-sm transition-all hover:bg-surface-container active:scale-95 text-on-surface-variant/40"
                                                        onClick={() => handleReject(action.id)}
                                                    >
                                                        <X className="h-3.5 w-3.5 mr-2" /> Reject
                                                    </Button>
                                                </div>
                                            </TableCell>
                                        </GlassTableRow>
                                    ))
                                )}
                            </TableBody>
                        </GlassTable>
                    </GlassCardContent>
                </GlassCard>
            </div>
        </div>
        </PageLayout>
    );
};

export default SafetyInbox;
