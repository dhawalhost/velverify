import React, { useState, useEffect } from 'react';
import {
    getOrganizations,
    createOrganization,
    deleteOrganization,
    generateDomainToken,
    getOrganizationDomains,
    verifyDomain
} from '../api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { TableBody, TableCell } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Loader2, Plus, Building2, Trash2, Globe, CheckCircle, AlertTriangle, Fingerprint } from 'lucide-react';
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassTable, GlassTableHeader, GlassTableHead, GlassTableRow } from '@/components/layout';

interface Organization {
    id: string;
    name: string;
    display_name?: string;
    domain?: string;
    domain_verified: boolean;
    created_at: string;
}

// Domain verification interfaces
interface VerificationDetails {
    domain: string;
    token: string;
    txt_record: string;
}

const Organizations: React.FC = () => {
    const [orgs, setOrgs] = useState<Organization[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [creating, setCreating] = useState(false);
    const [newOrg, setNewOrg] = useState({ name: '', display_name: '', domain: '' });

    // Domain Verification State
    const [verifyModal, setVerifyModal] = useState<string | null>(null);
    const [verifyDetails, setVerifyDetails] = useState<VerificationDetails | null>(null);
    const [verifyLoading, setVerifyLoading] = useState(false);
    const [verifyResult, setVerifyResult] = useState<string>('');

    useEffect(() => { fetchOrgs(); }, []);

    const fetchOrgs = async () => {
        setLoading(true);
        try {
            const res = await getOrganizations();
            setOrgs(res.organizations || []);
        } catch (err: any) {
            setError(err.response?.data?.error || err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleCreate = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setCreating(true);
        try {
            await createOrganization({
                name: newOrg.name,
                display_name: newOrg.display_name || undefined, 
                domain: newOrg.domain || undefined,
            });
            setNewOrg({ name: '', display_name: '', domain: '' });
            fetchOrgs(); 
        } catch (err: any) {
            console.error(err);
            setError(err.response?.data?.error || 'Failed to create organization');
        } finally {
            setCreating(false);
        }
    };

    const handleDelete = async (id: string) => {
        if (!window.confirm('Are you sure you want to delete this organization?')) return;
        try {
            await deleteOrganization(id);
            fetchOrgs();
        } catch (err: any) {
            setError(err.response?.data?.error || err.message);
        }
    };

    const openVerifyModal = async (orgId: string) => {
        setVerifyModal(orgId);
        setVerifyDetails(null);
        setVerifyResult('');
        setVerifyLoading(true);
        try {
            try {
                const data = await generateDomainToken(orgId);
                setVerifyDetails(data);
            } catch (err) {
                const data = await getOrganizationDomains(orgId);
                setVerifyDetails(data);
            }
        } catch (err) {
            console.error(err);
        } finally {
            setVerifyLoading(false);
        }
    };

    const handleVerify = async () => {
        if (!verifyModal) return;
        setVerifyLoading(true);
        setVerifyResult('');
        try {
            const data = await verifyDomain(verifyModal);
            if (data.verified) {
                setVerifyResult('✅ Domain verified successfully!');
                fetchOrgs();
            } else {
                setVerifyResult(`❌ ${data.message}`);
            }
        } catch (err: any) {
            setVerifyResult('Error verifying domain');
        } finally {
            setVerifyLoading(false);
        }
    };

    if (loading && orgs.length === 0) return <div className="h-[400px] flex items-center justify-center"><Loader2 className="h-10 w-10 animate-spin text-primary opacity-20" /></div>;

    return (
        <div className="space-y-12 animate-in fade-in duration-700">
            <PageHeader
                icon={<Building2 className="w-8 h-8 text-primary" />}
                title="Sectors and organizations"
                description="Manage multi-tenant enterprise shards and domain verification protocols. Orchestrate the architectural foundations of the tenant matrix."
            />

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 items-start">
                {/* Create Form */}
                <div className="lg:col-span-4 lg:sticky lg:top-8">
                    <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-card overflow-hidden rounded-xl">
                        <GlassCardHeader className="bg-primary p-5 text-white">
                            <div className="flex items-center gap-3">
                                <div className="p-2 bg-card/20 rounded-lg backdrop-blur-md">
                                    <Plus className="w-4 h-4 text-white" />
                                </div>
                                <GlassCardTitle className="text-lg font-bold">Provision sector</GlassCardTitle>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-5">
                            <form onSubmit={handleCreate} className="space-y-5">
                                <div className="space-y-2">
                                    <Label className="text-[10px] font-bold text-on-surface-variant/40 ml-1">Sector system slug</Label>
                                    <Input
                                        placeholder="e.g. acme-corp"
                                        value={newOrg.name}
                                        onChange={(e) => setNewOrg({ ...newOrg, name: e.target.value })}
                                        className="h-10 border-none rounded-lg bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium transition-all text-sm"
                                        required
                                    />
                                </div>
                                <div className="space-y-2">
                                    <Label className="text-[10px] font-bold text-on-surface-variant/40 ml-1">Visual identity</Label>
                                    <Input
                                        placeholder="Acme Corporation"
                                        value={newOrg.display_name}
                                        onChange={(e) => setNewOrg({ ...newOrg, display_name: e.target.value })}
                                        className="h-10 border-none rounded-lg bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium transition-all text-sm"
                                    />
                                </div>
                                <div className="space-y-2">
                                    <Label className="text-[10px] font-bold text-on-surface-variant/40 ml-1">Root architectural range</Label>
                                    <Input
                                        placeholder="acme.com"
                                        value={newOrg.domain}
                                        onChange={(e) => setNewOrg({ ...newOrg, domain: e.target.value })}
                                        className="h-10 border-none rounded-lg bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium transition-all text-sm"
                                    />
                                </div>
                                <Button type="submit" className="w-full h-10 rounded-lg font-bold text-[13px] shadow-md shadow-primary/10 transition-all" disabled={creating}>
                                    {creating ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Initialize sector'}
                                </Button>
                            </form>
                        </GlassCardContent>
                    </GlassCard>
                </div>

                {/* List */}
                <div className="lg:col-span-8">
                    <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-card overflow-hidden rounded-xl">
                        <GlassCardHeader className="py-5 px-6 border-b border-on-surface/5">
                            <div className="flex items-center gap-4">
                                <div className="p-2.5 bg-primary/5 rounded-xl">
                                    <Building2 className="w-5 h-5 text-primary" />
                                </div>
                                <div>
                                    <GlassCardTitle className="text-xl font-bold text-on-surface">Operational sectors</GlassCardTitle>
                                    <p className="text-on-surface-variant/40 font-bold text-[10px] mt-0.5">Verified enterprise shards ({orgs.length}) established within the identity matrix.</p>
                                </div>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-0">
                            {orgs.length === 0 ? (
                                <div className="py-32 text-center text-sm font-medium text-on-surface-variant/30 italic">No sectors established in local directory. Awaiting provisioning.</div>
                            ) : (
                                <div className="overflow-x-auto">
                                    <GlassTable>
                                        <GlassTableHeader>
                                            <GlassTableRow className="hover:bg-transparent border-b border-on-surface/5">
                                                <GlassTableHead className="py-3 pl-6">Sector identity</GlassTableHead>
                                                <GlassTableHead>Root range</GlassTableHead>
                                                <GlassTableHead>Status</GlassTableHead>
                                                <GlassTableHead className="text-right pr-6">Actions</GlassTableHead>
                                            </GlassTableRow>
                                        </GlassTableHeader>
                                        <TableBody>
                                            {orgs.map(org => (
                                                <GlassTableRow key={org.id} className="hover:bg-surface-container/10 transition-all border-b border-on-surface/5 last:border-0 group">
                                                    <TableCell className="py-3 pl-6">
                                                        <div className="flex items-center gap-4">
                                                            <div className="w-9 h-9 rounded-lg bg-surface-container flex items-center justify-center group-hover:bg-primary/10 group-hover:text-primary transition-all">
                                                                <Fingerprint className="w-4 h-4 opacity-40 group-hover:opacity-100" />
                                                            </div>
                                                            <div className="flex flex-col">
                                                                <span className="text-base font-bold text-on-surface group-hover:text-primary transition-colors">{org.name}</span>
                                                                {org.display_name && <span className="text-[10px] font-bold text-on-surface-variant/40 mt-0.5">{org.display_name}</span>}
                                                            </div>
                                                        </div>
                                                    </TableCell>
                                                    <TableCell className="py-3">
                                                        <span className="font-mono text-[10px] font-bold text-on-surface-variant/60">
                                                            {org.domain || 'Unbound'}
                                                        </span>
                                                    </TableCell>
                                                    <TableCell className="py-3">
                                                        {org.domain_verified ? (
                                                            <Badge className="bg-success-subtle text-success border-none rounded-lg font-bold text-[9px] px-3 py-1 shadow-sm">Verified root</Badge>
                                                        ) : org.domain ? (
                                                            <Button 
                                                                size="sm"
                                                                variant="ghost"
                                                                className="h-8 rounded-lg bg-orange-50 text-orange-600 hover:bg-orange-100 font-bold text-[9px] px-3 transition-all" 
                                                                onClick={() => openVerifyModal(org.id)}
                                                            >
                                                                Run validation
                                                            </Button>
                                                        ) : (
                                                            <span className="text-[10px] font-bold opacity-20 italic">Pending bind</span>
                                                        )}
                                                    </TableCell>
                                                    <TableCell className="py-3 text-right pr-6">
                                                        <Button 
                                                            size="icon" 
                                                            variant="ghost" 
                                                            className="h-9 w-9 rounded-lg text-on-surface-variant/30 hover:text-destructive hover:bg-destructive/10 transition-all" 
                                                            onClick={() => handleDelete(org.id)}
                                                        >
                                                            <Trash2 className="h-4 w-4" />
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

            {/* Verification Modal */}
            {verifyModal && (
                <div className="fixed inset-0 bg-on-surface/20 backdrop-blur-sm flex justify-center items-center z-50 p-6 animate-in fade-in duration-500">
                    <GlassCard className="w-full max-w-2xl border-none shadow-2xl shadow-on-surface/20 bg-card overflow-hidden rounded-xl">
                        <GlassCardHeader className="py-6 px-8 border-b border-on-surface/5 bg-surface-container/10">
                            <div className="flex items-center gap-4">
                                <div className="p-3 bg-primary rounded-xl text-white shadow-lg shadow-primary/20">
                                    <Globe className="w-5 h-5" />
                                </div>
                                <div>
                                    <GlassCardTitle className="text-xl font-bold text-on-surface">Domain verification</GlassCardTitle>
                                    <p className="text-on-surface-variant/40 font-bold text-[10px] mt-0.5">Scanner protocol for DNS root synchronization.</p>
                                </div>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="space-y-6 p-8">
                            <div className="flex flex-col gap-1.5">
                                <span className="text-[10px] font-bold text-on-surface-variant/40 ml-1">Target resource vector</span>
                                <div className="bg-surface-container/50 rounded-xl p-4 ring-1 ring-on-surface/5">
                                    <span className="text-xl font-bold text-on-surface">{verifyDetails?.domain}</span>
                                </div>
                            </div>

                            {verifyLoading ? (
                                <div className="flex flex-col items-center justify-center py-12 gap-4 bg-surface-container/20 rounded-xl border-2 border-dashed border-on-surface/5">
                                    <Loader2 className="h-8 w-8 animate-spin text-primary opacity-40" />
                                    <span className="text-[10px] font-bold text-on-surface-variant/20 italic animate-pulse">Scanning DNS atmosphere...</span>
                                </div>
                            ) : verifyDetails ? (
                                <>
                                    <div className="space-y-4">
                                        <span className="text-[10px] font-bold text-on-surface-variant/40 ml-1">DNS manifest entry (TXT)</span>
                                        <div className="bg-inverse text-on-inverse p-6 rounded-xl space-y-6 shadow-xl shadow-on-surface/20">
                                            <div className="grid grid-cols-[80px_1fr] gap-4 items-center">
                                                <span className="font-mono text-[9px] font-bold text-on-inverse/40">Host</span>
                                                <div className="bg-card/5 border border-on-inverse/10 px-4 py-2 rounded font-mono text-[11px] text-primary font-bold">
                                                    {verifyDetails.txt_record}
                                                </div>
                                                <span className="font-mono text-[9px] font-bold text-on-inverse/40">Token</span>
                                                <div className="bg-card/5 border border-on-inverse/10 px-4 py-2 rounded font-mono text-[11px] text-on-inverse/90 break-all leading-relaxed">
                                                    {verifyDetails.token}
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    {verifyResult && (
                                        <div className={`p-6 rounded-2xl flex items-center gap-4 animate-in slide-in-from-bottom-4 duration-500 ring-1 shadow-sm ${verifyResult.includes('✅') ? 'bg-success-subtle ring-emerald-100 text-emerald-700' : 'bg-destructive/10 ring-red-100 text-red-700'}`}>
                                            {verifyResult.includes('✅') ? <CheckCircle className="h-5 w-5" /> : <AlertTriangle className="h-5 w-5" />}
                                            <span className="text-xs font-bold">{verifyResult.replace('✅', '').replace('❌', '').trim()}</span>
                                        </div>
                                    )}

                                    <div className="flex justify-end gap-3 pt-4">
                                        <Button 
                                            variant="ghost" 
                                            onClick={() => setVerifyModal(null)}
                                            className="h-10 px-6 rounded-lg font-bold text-[10px] text-on-surface-variant/40 hover:text-on-surface hover:bg-surface-container transition-all"
                                        >
                                            Abort protocol
                                        </Button>
                                        <Button 
                                            onClick={handleVerify} 
                                            disabled={verifyLoading}
                                            className="h-10 bg-primary text-primary-foreground hover:opacity-90 rounded-lg font-bold text-[11px] px-8 shadow-lg shadow-primary/20 transition-all flex items-center gap-2"
                                        >
                                            {verifyLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Globe className="h-4 w-4" />}
                                            Execute validation
                                        </Button>
                                    </div>
                                </>
                            ) : (
                                <div className="p-10 rounded-[32px] bg-destructive/10 border-2 border-dashed border-red-200 text-red-700 flex flex-col items-center gap-4 text-center">
                                    <AlertTriangle className="h-10 w-10 opacity-40" />
                                    <span className="text-sm font-bold tracking-tight">Failed to establish synchronized link with verification engine.</span>
                                </div>
                            )}
                        </GlassCardContent>
                    </GlassCard>
                </div>
            )}
        </div>
    );
};

export default Organizations;
