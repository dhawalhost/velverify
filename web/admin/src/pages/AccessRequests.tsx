import React, { useEffect, useState } from 'react';
import { getAccessRequests, approveAccessRequest, rejectAccessRequest } from '../api';
import { Link } from 'react-router-dom';
import { TableBody, TableCell } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Check, X, ShieldAlert, Plus, GitPullRequest, Activity, Terminal, ExternalLink, ShieldCheck, Clock, Fingerprint, Loader2 } from 'lucide-react';
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassTable, GlassTableHeader, GlassTableHead, GlassTableRow } from '@/components/layout';

const AccessRequests: React.FC = () => {
    const [requests, setRequests] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    const fetchRequests = async () => {
        try {
            setLoading(true);
            const data = await getAccessRequests();
            setRequests(data.requests || []);
        } catch (err: any) {
            console.error(err);
            setError('Failed to fetch requests');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchRequests();
    }, []);

    const handleApprove = async (id: string) => {
        try {
            await approveAccessRequest(id, 'Approved by admin');
            fetchRequests();
        } catch (err) {
            console.error(err);
        }
    };

    const handleReject = async (id: string) => {
        try {
            await rejectAccessRequest(id, 'Rejected by admin');
            fetchRequests();
        } catch (err) {
            console.error(err);
        }
    };

    if (loading && requests.length === 0) return <div className="h-[400px] flex items-center justify-center"><Loader2 className="h-10 w-10 animate-spin text-primary opacity-20" /></div>;

    return (
        <div className="space-y-10 animate-in fade-in duration-700">
            <PageHeader
                icon={<GitPullRequest className="w-8 h-8 text-primary" />}
                title="Access Requests"
                description="Review and manage requests for temporary access to restricted resources."
                actions={
                     <Link to="/request-access">
                        <Button className="rounded-xl font-bold text-sm h-11 px-8 shadow-md shadow-primary/10">
                            <Plus className="mr-2 h-4 w-4" /> New Request
                        </Button>
                    </Link>
                }
            />

            {error && (
                <div className="bg-destructive/5 text-destructive px-6 py-4 rounded-xl border border-destructive/10 text-sm font-semibold flex items-center gap-3">
                    <ShieldAlert className="h-4 w-4" />
                    {error}
                </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-card overflow-hidden rounded-[24px]">
                    <GlassCardContent className="p-8 relative group">
                         <div className="flex flex-col gap-2">
                             <span className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 leading-none">Pending Requests</span>
                            <div className="mt-4 flex items-end gap-3 leading-none">
                                <span className="text-4xl font-bold tracking-tight text-on-surface">{requests.filter(r => r.status === 'pending').length}</span>
                                <GitPullRequest className="h-5 w-5 text-on-surface/10 mb-1" />
                            </div>
                        </div>
                    </GlassCardContent>
                </GlassCard>

                <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-card overflow-hidden rounded-[24px]">
                    <GlassCardContent className="p-8 relative group">
                         <div className="flex flex-col gap-2">
                             <span className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 leading-none">Approved Requests</span>
                            <div className="mt-4 flex items-end gap-3 leading-none">
                                <span className="text-4xl font-bold tracking-tight text-on-surface">{requests.filter(r => r.status === 'approved').length}</span>
                                <ShieldCheck className="h-5 w-5 text-success/20 mb-1" />
                            </div>
                        </div>
                    </GlassCardContent>
                </GlassCard>

                <GlassCard className="md:col-span-2 border-none shadow-xl shadow-primary/5 bg-primary overflow-hidden rounded-[24px] text-white">
                    <GlassCardContent className="p-8 h-full flex flex-col justify-center relative overflow-hidden">
                        <div className="absolute -right-8 -bottom-8 opacity-10 rotate-12">
                            <Activity className="w-48 h-48" />
                        </div>
                          <h3 className="text-xl font-bold tracking-tight relative z-10">Temporary Access</h3>
                        <p className="text-[11px] font-bold tracking-tight text-on-inverse/40 mt-2 relative z-10 italic">
                            All access decisions are logged for compliance auditing.
                        </p>
                    </GlassCardContent>
                </GlassCard>
            </div>

            <div className="space-y-8">
                 <div className="flex items-center gap-6">
                    <h2 className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 italic flex-shrink-0">Requests Queue</h2>
                    <div className="h-px flex-1 bg-on-surface/5" />
                </div>

                <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-card overflow-hidden rounded-[32px]">
                    <GlassCardHeader className="py-10 px-10 border-b border-on-surface/5">
                        <div className="flex items-center gap-5">
                            <div className="p-4 bg-primary/5 rounded-2xl">
                                <Activity className="w-8 h-8 text-primary" />
                            </div>
                             <div>
                                <GlassCardTitle className="text-2xl font-bold tracking-tight text-on-surface">Request Details</GlassCardTitle>
                                <p className="text-on-surface-variant/40 font-bold text-[12px] mt-1 tracking-tight">List of active requests and their status.</p>
                            </div>
                        </div>
                    </GlassCardHeader>
                    <GlassCardContent className="p-0">
                        {requests.length === 0 ? (
                            <div className="py-40 text-center">
                                <div className="flex flex-col items-center gap-6 opacity-20">
                                     <GitPullRequest className="h-16 w-16" />
                                    <span className="text-[11px] font-bold tracking-tight italic opacity-40">No pending requests.</span>
                                </div>
                            </div>
                        ) : (
                            <div className="overflow-x-auto">
                                <GlassTable>
                                     <GlassTableHeader>
                                        <GlassTableRow className="hover:bg-transparent border-b border-on-surface/5">
                                            <GlassTableHead className="py-6 pl-10">User</GlassTableHead>
                                            <GlassTableHead>Resource</GlassTableHead>
                                            <GlassTableHead>Duration</GlassTableHead>
                                            <GlassTableHead>Status</GlassTableHead>
                                            <GlassTableHead className="text-right pr-10">Actions</GlassTableHead>
                                        </GlassTableRow>
                                    </GlassTableHeader>
                                    <TableBody>
                                        {requests.map(req => (
                                            <GlassTableRow key={req.id} className="hover:bg-surface-container/10 transition-all border-b border-on-surface/5 last:border-0 group">
                                                <TableCell className="py-8 pl-10">
                                                    <div className="flex items-center gap-5">
                                                        <div className="w-11 h-11 rounded-xl bg-surface-container flex items-center justify-center group-hover:bg-primary/10 group-hover:text-primary transition-all">
                                                            <Fingerprint className="h-5 w-5 opacity-40" />
                                                        </div>
                                                         <div className="flex flex-col">
                                                            <span className="text-lg font-bold tracking-tight text-on-surface group-hover:text-primary transition-colors">{req.requester_id}</span>
                                                            <span className="text-[9px] font-bold font-mono tracking-tight text-on-surface-variant/30 mt-1 italic">ID: {req.id.substring(0, 8).toLowerCase()}</span>
                                                        </div>
                                                    </div>
                                                </TableCell>
                                                <TableCell className="py-8">
                                                    <div className="flex flex-col gap-2">
                                                         <div className="flex items-center gap-2">
                                                            <Badge className="bg-surface-container text-on-surface-variant border-none rounded-lg font-bold text-[9px] px-2.5 py-1 tracking-tight">{req.resource_type}</Badge>
                                                            <span className="text-[11px] font-bold text-on-surface-variant/60 tracking-tight flex items-center gap-2 italic">
                                                                <Terminal className="w-3.5 h-3.5" />
                                                                {req.resource_id}
                                                            </span>
                                                        </div>
                                                        <span className="text-[10px] font-medium text-on-surface-variant/40 truncate max-w-[200px]" title={req.reason}>
                                                            {req.reason}
                                                        </span>
                                                    </div>
                                                </TableCell>
                                                <TableCell className="py-8">
                                                     {req.duration ? (
                                                        <div className="flex items-center gap-2 text-[11px] font-bold text-primary tracking-tight">
                                                            <Clock className="w-3.5 h-3.5 opacity-40" />
                                                            {req.duration}
                                                        </div>
                                                    ) : (
                                                        <span className="text-[10px] font-bold text-on-surface-variant/20 tracking-tight italic">Permanent</span>
                                                    )}
                                                </TableCell>
                                                <TableCell className="py-8">
                                                     <Badge
                                                        className={`rounded-xl font-bold text-[9px] tracking-tight px-4 py-1.5 border-none shadow-sm transition-all ${req.status === 'pending' ? 'bg-amber-50 text-amber-600' :
                                                            req.status === 'approved' ? 'bg-success-subtle text-success' :
                                                                'bg-destructive/10 text-destructive'
                                                            }`}
                                                    >
                                                        {req.status.charAt(0).toUpperCase() + req.status.slice(1)}
                                                    </Badge>
                                                </TableCell>
                                                <TableCell className="py-8 text-right pr-10">
                                                    {req.status === 'pending' && (
                                                         <div className="flex justify-end gap-3">
                                                            <Button
                                                                size="sm"
                                                                className="h-10 rounded-xl bg-success text-success-foreground hover:bg-emerald-600 font-bold text-[11px] px-5 shadow-lg shadow-emerald-500/10 transition-all border-none"
                                                                onClick={() => handleApprove(req.id)}
                                                            >
                                                                Approve
                                                            </Button>
                                                            <Button
                                                                size="sm"
                                                                variant="ghost"
                                                                className="h-10 rounded-xl text-destructive hover:bg-destructive/10 font-bold text-[11px] px-5 transition-all"
                                                                onClick={() => handleReject(req.id)}
                                                            >
                                                                Reject
                                                            </Button>
                                                        </div>
                                                    )}
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

export default AccessRequests;
