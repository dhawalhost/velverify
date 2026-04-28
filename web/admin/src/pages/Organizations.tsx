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
                icon={<Building2 className="w-10 h-10 text-primary" />}
                title="Sectors and organizations"
                description="Manage multi-tenant enterprise shards and domain verification protocols. Orchestrate the architectural foundations of the tenant matrix."
            />

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 items-start">
                {/* Create Form */}
                <div className="lg:col-span-4 lg:sticky lg:top-8">
                    <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-card overflow-hidden rounded-[24px]">
                        <GlassCardHeader className="bg-primary p-8 text-white">
                            <div className="flex items-center gap-4">
                                <div className="p-2.5 bg-card/20 rounded-xl backdrop-blur-md">
                                    <Plus className="w-5 h-5 text-white" />
                                </div>
                                <GlassCardTitle className="text-xl font-bold">Provision sector</GlassCardTitle>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-8">
                            <form onSubmit={handleCreate} className="space-y-8">
                                <div className="space-y-2.5">
                                    <Label className="text-[12px] font-bold text-on-surface-variant/40 ml-1">Sector system slug</Label>
                                    <Input
                                        placeholder="e.g. acme-corp"
                                        value={newOrg.name}
                                        onChange={(e) => setNewOrg({ ...newOrg, name: e.target.value })}
                                        className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium transition-all"
                                        required
                                    />
                                </div>
                                <div className="space-y-2.5">
                                    <Label className="text-[12px] font-bold text-on-surface-variant/40 ml-1">Visual identity</Label>
                                    <Input
                                        placeholder="Acme Corporation"
                                        value={newOrg.display_name}
                                        onChange={(e) => setNewOrg({ ...newOrg, display_name: e.target.value })}
                                        className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium transition-all"
                                    />
                                </div>
                                <div className="space-y-2.5">
                                    <Label className="text-[12px] font-bold text-on-surface-variant/40 ml-1">Root architectural range</Label>
                                    <Input
                                        placeholder="acme.com"
                                        value={newOrg.domain}
                                        onChange={(e) => setNewOrg({ ...newOrg, domain: e.target.value })}
                                        className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium transition-all"
                                    />
                                </div>
                                {error && (
                                    <div className="text-[11px] font-bold text-destructive bg-destructive/10/50 p-4 rounded-xl ring-1 ring-red-100 flex items-center gap-3">
                                        <AlertTriangle className="h-4 w-4" />
                                        {error}
                                    </div>
                                )}
                                <Button type="submit" className="w-full h-12 rounded-xl font-bold text-sm shadow-md shadow-primary/10 transition-all" disabled={creating}>
                                    {creating ? <Loader2 className="w-5 h-5 animate-spin" /> : 'Initialize sector'}
                                </Button>
                            </form>
                        </GlassCardContent>
                    </GlassCard>
                </div>

                {/* List */}
                <div className="lg:col-span-8">
                    <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-card overflow-hidden rounded-[32px]">
                        <GlassCardHeader className="py-8 px-10 border-b border-on-surface/5">
                            <div className="flex items-center gap-5">
                                <div className="p-3.5 bg-primary/5 rounded-2xl">
                                    <Building2 className="w-7 h-7 text-primary" />
                                </div>
                                <div>
                                    <GlassCardTitle className="text-2xl font-bold text-on-surface">Operational sectors</GlassCardTitle>
                                    <p className="text-on-surface-variant/40 font-bold text-[12px] mt-1">Verified enterprise shards ({orgs.length}) established within the identity matrix.</p>
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
                                                <GlassTableHead className="py-6 pl-10">Sector identity</GlassTableHead>
                                                <GlassTableHead>Root range</GlassTableHead>
                                                <GlassTableHead>Status</GlassTableHead>
                                                <GlassTableHead className="text-right pr-10">Actions</GlassTableHead>
                                            </GlassTableRow>
                                        </GlassTableHeader>
                                        <TableBody>
                                            {orgs.map(org => (
                                                <GlassTableRow key={org.id} className="hover:bg-surface-container/10 transition-all border-b border-on-surface/5 last:border-0 group">
                                                    <TableCell className="py-8 pl-10">
                                                        <div className="flex items-center gap-5">
                                                            <div className="w-11 h-11 rounded-xl bg-surface-container flex items-center justify-center group-hover:bg-primary/10 group-hover:text-primary transition-all">
                                                                <Fingerprint className="w-5 h-5 opacity-40 group-hover:opacity-100" />
                                                            </div>
                                                            <div className="flex flex-col">
                                                                <span className="text-lg font-bold text-on-surface group-hover:text-primary transition-colors">{org.name}</span>
                                                                {org.display_name && <span className="text-[11px] font-bold text-on-surface-variant/40 mt-1">{org.display_name}</span>}
                                                            </div>
                                                        </div>
                                                    </TableCell>
                                                    <TableCell className="py-8">
                                                        <span className="font-mono text-[11px] font-bold text-on-surface-variant/60">
                                                            {org.domain || 'Unbound'}
                                                        </span>
                                                    </TableCell>
                                                    <TableCell className="py-8">
                                                        {org.domain_verified ? (
                                                            <Badge className="bg-success-subtle text-success border-none rounded-xl font-bold text-[10px] px-4 py-1.5 shadow-sm">Verified root</Badge>
                                                        ) : org.domain ? (
                                                            <Button 
                                                                size="sm"
                                                                variant="ghost"
                                                                className="h-9 rounded-xl bg-orange-50 text-orange-600 hover:bg-orange-100 font-bold text-[10px] px-4 transition-all" 
                                                                onClick={() => openVerifyModal(org.id)}
                                                            >
                                                                Run validation
                                                            </Button>
                                                        ) : (
                                                            <span className="text-[11px] font-bold opacity-20 italic">Pending bind</span>
                                                        )}
                                                    </TableCell>
                                                    <TableCell className="py-8 text-right pr-10">
                                                        <Button 
                                                            size="icon" 
                                                            variant="ghost" 
                                                            className="h-11 w-11 rounded-xl text-on-surface-variant/30 hover:text-destructive hover:bg-destructive/10 transition-all" 
                                                            onClick={() => handleDelete(org.id)}
                                                        >
                                                            <Trash2 className="h-5 w-5" />
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
                    <GlassCard className="w-full max-w-2xl border-none shadow-2xl shadow-on-surface/20 bg-card overflow-hidden rounded-[40px]">
                        <GlassCardHeader className="py-12 px-10 border-b border-on-surface/5 bg-surface-container/10">
                            <div className="flex items-center gap-6">
                                <div className="p-4 bg-primary rounded-2xl text-white shadow-lg shadow-primary/20">
                                    <Globe className="w-7 h-7" />
                                </div>
                                <div>
                                    <GlassCardTitle className="text-3xl font-bold text-on-surface">Domain verification</GlassCardTitle>
                                    <p className="text-on-surface-variant/40 font-bold text-[12px] mt-1">Scanner protocol for DNS root synchronization.</p>
                                </div>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="space-y-10 p-10">
                            <div className="flex flex-col gap-2">
                                <span className="text-[12px] font-bold text-on-surface-variant/40 ml-1">Target resource vector</span>
                                <div className="bg-surface-container/50 rounded-2xl p-6 ring-1 ring-on-surface/5">
                                    <span className="text-2xl font-bold text-on-surface">{verifyDetails?.domain}</span>
                                </div>
                            </div>

                            {verifyLoading ? (
                                <div className="flex flex-col items-center justify-center py-20 gap-6 bg-surface-container/20 rounded-[32px] border-2 border-dashed border-on-surface/5">
                                    <Loader2 className="h-12 w-12 animate-spin text-primary opacity-40" />
                                    <span className="text-[11px] font-bold text-on-surface-variant/20 italic animate-pulse">Scanning DNS atmosphere...</span>
                                </div>
                            ) : verifyDetails ? (
                                <>
                                    <div className="space-y-6">
                                        <span className="text-[12px] font-bold text-on-surface-variant/40 ml-1">DNS manifest entry (TXT)</span>
                                        <div className="bg-inverse text-on-inverse p-8 rounded-[32px] space-y-8 shadow-xl shadow-on-surface/20">
                                            <div className="grid grid-cols-[100px_1fr] gap-6 items-center">
                                                <span className="font-mono text-[10px] font-bold text-on-inverse/40">Host</span>
                                                <div className="bg-card/5 border border-on-inverse/10 px-5 py-3 rounded-xl font-mono text-xs text-primary font-bold">
                                                    {verifyDetails.txt_record}
                                                </div>
                                                <span className="font-mono text-[10px] font-bold text-on-inverse/40">Token</span>
                                                <div className="bg-card/5 border border-on-inverse/10 px-5 py-3 rounded-xl font-mono text-xs text-on-inverse/90 break-all leading-relaxed">
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

                                    <div className="flex justify-end gap-4 pt-6">
                                        <Button 
                                            variant="ghost" 
                                            onClick={() => setVerifyModal(null)}
                                            className="h-14 px-10 rounded-2xl font-bold text-[11px] text-on-surface-variant/40 hover:text-on-surface hover:bg-surface-container transition-all"
                                        >
                                            Abort protocol
                                        </Button>
                                        <Button 
                                            onClick={handleVerify} 
                                            disabled={verifyLoading}
                                            className="h-14 bg-primary text-primary-foreground hover:opacity-90 rounded-2xl font-bold text-[13px] px-12 shadow-xl shadow-primary/20 transition-all flex items-center gap-3"
                                        >
                                            {verifyLoading ? <Loader2 className="h-5 w-5 animate-spin" /> : <Globe className="h-5 w-5" />}
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
