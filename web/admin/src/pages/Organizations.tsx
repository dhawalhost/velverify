import React, { useState, useEffect } from 'react';
import {
    getOrganizations, createOrganization, deleteOrganization,
    generateDomainToken, getOrganizationDomains, verifyDomain
} from '../api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import {
    Loader2, Plus, Building2, Trash2, Globe, CheckCircle,
    AlertTriangle, X, ChevronRight, Search, Calendar, Hash
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface Organization {
    id: string;
    name: string;
    display_name?: string;
    domain?: string;
    domain_verified: boolean;
    created_at: string;
}

interface VerificationDetails {
    domain: string;
    token: string;
    txt_record: string;
}

const Organizations: React.FC = () => {
    const [orgs, setOrgs] = useState<Organization[]>([]);
    const [loading, setLoading] = useState(true);
    const [creating, setCreating] = useState(false);
    const [error, setError] = useState('');
    const [newOrg, setNewOrg] = useState({ name: '', display_name: '', domain: '' });
    const [searchTerm, setSearchTerm] = useState('');

    const [selectedOrg, setSelectedOrg] = useState<Organization | null>(null);
    const [verifyDetails, setVerifyDetails] = useState<VerificationDetails | null>(null);
    const [verifyLoading, setVerifyLoading] = useState(false);
    const [verifyResult, setVerifyResult] = useState('');

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
            setError(err.response?.data?.error || 'Failed to create organization');
        } finally {
            setCreating(false);
        }
    };

    const handleDelete = async (id: string) => {
        if (!window.confirm('Delete this organization?')) return;
        try {
            await deleteOrganization(id);
            if (selectedOrg?.id === id) setSelectedOrg(null);
            fetchOrgs();
        } catch (err: any) {
            setError(err.response?.data?.error || err.message);
        }
    };

    const handleSelectOrg = async (org: Organization) => {
        if (selectedOrg?.id === org.id) { setSelectedOrg(null); return; }
        setSelectedOrg(org);
        setVerifyDetails(null);
        setVerifyResult('');
        if (org.domain) {
            setVerifyLoading(true);
            try {
                try {
                    const data = await generateDomainToken(org.id);
                    setVerifyDetails(data);
                } catch {
                    const data = await getOrganizationDomains(org.id);
                    setVerifyDetails(data);
                }
            } catch { } finally {
                setVerifyLoading(false);
            }
        }
    };

    const handleVerify = async () => {
        if (!selectedOrg) return;
        setVerifyLoading(true);
        setVerifyResult('');
        try {
            const data = await verifyDomain(selectedOrg.id);
            if (data.verified) {
                setVerifyResult('verified');
                fetchOrgs();
            } else {
                setVerifyResult('failed: ' + data.message);
            }
        } catch {
            setVerifyResult('error');
        } finally {
            setVerifyLoading(false);
        }
    };

    const filteredOrgs = orgs.filter(o =>
        o.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        o.display_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        o.domain?.toLowerCase().includes(searchTerm.toLowerCase())
    );

    return (
        <div className="flex h-full gap-0 animate-in fade-in duration-500">
            {/* ── Master: org list ───────────────────────────────────── */}
            <div className={cn(
                "flex flex-col border-r border-on-surface/5 transition-all duration-300",
                selectedOrg ? "w-[380px] min-w-[380px]" : "w-[380px] min-w-[380px]"
            )}>
                {/* Create form */}
                <div className="p-4 border-b border-on-surface/5 bg-card/30">
                    <p className="text-[9px] font-bold tracking-widest text-on-surface-variant/30 uppercase mb-3">New Organization</p>
                    <form onSubmit={handleCreate} className="space-y-2">
                        <Input
                            placeholder="Slug (e.g. acme-corp)"
                            value={newOrg.name}
                            onChange={(e) => setNewOrg({ ...newOrg, name: e.target.value })}
                            className="h-8 border-none rounded-lg bg-surface-container/40 ring-1 ring-on-surface/5 focus-visible:ring-primary/20 text-[11px] font-medium"
                            required
                        />
                        <Input
                            placeholder="Display name (e.g. Acme Corp)"
                            value={newOrg.display_name}
                            onChange={(e) => setNewOrg({ ...newOrg, display_name: e.target.value })}
                            className="h-8 border-none rounded-lg bg-surface-container/40 ring-1 ring-on-surface/5 focus-visible:ring-primary/20 text-[11px] font-medium"
                        />
                        <Input
                            placeholder="Domain (e.g. acme.com)"
                            value={newOrg.domain}
                            onChange={(e) => setNewOrg({ ...newOrg, domain: e.target.value })}
                            className="h-8 border-none rounded-lg bg-surface-container/40 ring-1 ring-on-surface/5 focus-visible:ring-primary/20 text-[11px] font-medium"
                        />
                        {error && <p className="text-[10px] text-destructive font-semibold">{error}</p>}
                        <Button type="submit" disabled={creating} className="w-full h-8 rounded-lg text-[10px] font-bold shadow-sm shadow-primary/10">
                            {creating ? <Loader2 className="w-3 h-3 animate-spin" /> : <><Plus className="w-3 h-3 mr-1.5" /> Create Organization</>}
                        </Button>
                    </form>
                </div>

                {/* Search */}
                <div className="px-4 py-2 border-b border-on-surface/5">
                    <div className="relative group">
                        <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3 w-3 text-on-surface-variant/30 group-focus-within:text-primary transition-colors" />
                        <Input
                            placeholder="Filter organizations..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="h-7 pl-7 border-none rounded-lg bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-primary/20 text-[11px] font-medium"
                        />
                    </div>
                </div>

                {/* Org list */}
                <div className="flex-1 overflow-y-auto custom-scrollbar divide-y divide-on-surface/5">
                    {loading ? (
                        <div className="h-40 flex items-center justify-center">
                            <Loader2 className="h-5 w-5 animate-spin text-primary/30" />
                        </div>
                    ) : filteredOrgs.length === 0 ? (
                        <div className="py-16 text-center text-[11px] text-on-surface-variant/30 font-medium">
                            No organizations found
                        </div>
                    ) : filteredOrgs.map(org => {
                        const isSelected = selectedOrg?.id === org.id;
                        return (
                            <div
                                key={org.id}
                                onClick={() => handleSelectOrg(org)}
                                className={cn(
                                    "flex items-center gap-3 px-4 py-3.5 cursor-pointer transition-all group",
                                    isSelected
                                        ? "bg-primary/5 border-l-2 border-primary"
                                        : "hover:bg-surface-container/40 border-l-2 border-transparent"
                                )}
                            >
                                <div className={cn(
                                    "w-8 h-8 rounded-lg flex items-center justify-center shrink-0 transition-colors",
                                    isSelected ? "bg-primary/15" : "bg-surface-container/80 group-hover:bg-primary/8"
                                )}>
                                    <Building2 className={cn("w-4 h-4 transition-colors", isSelected ? "text-primary" : "text-on-surface-variant/40")} />
                                </div>
                                <div className="flex-1 min-w-0">
                                    <p className={cn("text-[12px] font-semibold truncate", isSelected ? "text-primary" : "text-on-surface")}>{org.display_name || org.name}</p>
                                    <p className="text-[10px] text-on-surface-variant/30 truncate font-medium mt-0.5">{org.domain || 'No domain configured'}</p>
                                </div>
                                <div className="flex items-center gap-2 shrink-0">
                                    <Badge className={cn(
                                        "text-[8px] font-bold px-1.5 py-0 rounded border-none",
                                        org.domain_verified
                                            ? "bg-success/10 text-success"
                                            : "bg-amber-500/10 text-amber-500"
                                    )}>
                                        {org.domain_verified ? 'Verified' : 'Unverified'}
                                    </Badge>
                                    <button
                                        onClick={(e) => { e.stopPropagation(); handleDelete(org.id); }}
                                        className="opacity-0 group-hover:opacity-100 h-6 w-6 rounded-md flex items-center justify-center hover:bg-destructive/10 hover:text-destructive transition-all text-on-surface-variant/20"
                                    >
                                        <Trash2 className="w-3 h-3" />
                                    </button>
                                </div>
                            </div>
                        );
                    })}
                </div>
            </div>

            {/* ── Detail panel ──────────────────────────────────────── */}
            {selectedOrg ? (
                <div className="flex-1 flex flex-col overflow-hidden bg-card animate-in slide-in-from-right-4 duration-300">
                    {/* Header */}
                    <div className="bg-primary px-6 py-5 text-primary-foreground shrink-0">
                        <div className="flex items-start justify-between">
                            <div className="flex items-center gap-4">
                                <div className="w-10 h-10 bg-black/10 rounded-xl flex items-center justify-center">
                                    <Building2 className="w-5 h-5 text-primary-foreground" />
                                </div>
                                <div>
                                    <h2 className="text-base font-bold text-primary-foreground">
                                        {selectedOrg.display_name || selectedOrg.name}
                                    </h2>
                                    <p className="text-primary-foreground/60 text-[11px] font-medium mt-0.5">
                                        {selectedOrg.domain || 'No domain configured'}
                                    </p>
                                    <Badge className={cn(
                                        "mt-2 text-[8px] font-bold px-2 py-0.5 border-none",
                                        selectedOrg.domain_verified
                                            ? "bg-black/10 text-primary-foreground"
                                            : "bg-black/15 text-primary-foreground/70"
                                    )}>
                                        {selectedOrg.domain_verified ? '✓ Domain Verified' : '⚠ Domain Unverified'}
                                    </Badge>
                                </div>
                            </div>
                            <Button variant="ghost" size="icon" className="h-7 w-7 rounded-lg bg-black/10 hover:bg-black/20 text-primary-foreground" onClick={() => setSelectedOrg(null)}>
                                <X className="w-3.5 h-3.5" />
                            </Button>
                        </div>
                    </div>

                    {/* Body */}
                    <div className="flex-1 overflow-y-auto custom-scrollbar p-5 space-y-5">
                        {/* Details */}
                        <section>
                            <h3 className="text-[9px] font-bold tracking-widest text-on-surface-variant/30 uppercase mb-2">Organization Details</h3>
                            <div className="bg-surface-container/30 rounded-xl divide-y divide-on-surface/5">
                                {[
                                    { icon: Hash, label: 'Slug', value: selectedOrg.name },
                                    { icon: Building2, label: 'Display Name', value: selectedOrg.display_name || '—' },
                                    { icon: Globe, label: 'Domain', value: selectedOrg.domain || '—' },
                                    { icon: Calendar, label: 'Created', value: new Date(selectedOrg.created_at).toLocaleDateString() },
                                ].map(({ icon: Icon, label, value }) => (
                                    <div key={label} className="flex items-center gap-3 px-3 py-2.5">
                                        <Icon className="w-3.5 h-3.5 text-on-surface-variant/30 shrink-0" />
                                        <span className="text-[10px] font-semibold text-on-surface-variant/40 w-28 shrink-0">{label}</span>
                                        <span className="text-[11px] font-semibold text-on-surface truncate">{value}</span>
                                    </div>
                                ))}
                            </div>
                        </section>

                        {/* Domain verification */}
                        {selectedOrg.domain && (
                            <section className="border-t border-on-surface/5 pt-5">
                                <h3 className="text-[9px] font-bold tracking-widest text-on-surface-variant/30 uppercase mb-3 flex items-center gap-2">
                                    <Globe className="w-3 h-3" /> Domain Verification
                                </h3>

                                {verifyLoading ? (
                                    <div className="flex items-center justify-center py-8">
                                        <Loader2 className="h-5 w-5 animate-spin text-primary/30" />
                                    </div>
                                ) : verifyDetails ? (
                                    <div className="space-y-3">
                                        <div className="bg-inverse text-on-inverse p-4 rounded-xl space-y-3">
                                            <p className="text-[9px] font-bold tracking-widest text-on-inverse/40 uppercase">Add this TXT record to your DNS</p>
                                            <div className="space-y-2">
                                                <div className="grid grid-cols-[60px_1fr] gap-2 items-start">
                                                    <span className="font-mono text-[9px] font-bold text-on-inverse/40 pt-1.5">Host</span>
                                                    <code className="bg-white/5 border border-white/10 px-2 py-1.5 rounded font-mono text-[10px] text-primary font-bold break-all">{verifyDetails.txt_record}</code>
                                                </div>
                                                <div className="grid grid-cols-[60px_1fr] gap-2 items-start">
                                                    <span className="font-mono text-[9px] font-bold text-on-inverse/40 pt-1.5">Value</span>
                                                    <code className="bg-white/5 border border-white/10 px-2 py-1.5 rounded font-mono text-[10px] text-on-inverse/80 break-all">{verifyDetails.token}</code>
                                                </div>
                                            </div>
                                        </div>

                                        {verifyResult && (
                                            <div className={cn(
                                                "p-3 rounded-xl flex items-center gap-3 text-[11px] font-bold animate-in slide-in-from-bottom-2",
                                                verifyResult === 'verified'
                                                    ? "bg-success/10 text-success"
                                                    : "bg-destructive/10 text-destructive"
                                            )}>
                                                {verifyResult === 'verified'
                                                    ? <><CheckCircle className="w-4 h-4 shrink-0" /> Domain verified successfully!</>
                                                    : <><AlertTriangle className="w-4 h-4 shrink-0" /> {verifyResult.replace('failed: ', '').replace('error', 'Verification failed')}</>
                                                }
                                            </div>
                                        )}

                                        <Button
                                            onClick={handleVerify}
                                            disabled={verifyLoading}
                                            className="w-full h-9 rounded-lg font-bold text-[11px] shadow-md shadow-primary/10"
                                        >
                                            {verifyLoading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <><Globe className="h-3.5 w-3.5 mr-2" /> Verify Domain Now</>}
                                        </Button>
                                    </div>
                                ) : (
                                    <div className="py-6 bg-surface-container/20 rounded-xl border-2 border-dashed border-on-surface/5 text-center">
                                        <Globe className="w-5 h-5 text-on-surface-variant/10 mx-auto mb-2" />
                                        <p className="text-[10px] text-on-surface-variant/30 font-medium">No domain verification token yet</p>
                                    </div>
                                )}
                            </section>
                        )}

                        {/* Danger zone */}
                        <section className="border-t border-on-surface/5 pt-4">
                            <h3 className="text-[9px] font-bold tracking-widest text-destructive/40 uppercase mb-2">Danger Zone</h3>
                            <Button
                                variant="outline"
                                size="sm"
                                onClick={() => handleDelete(selectedOrg.id)}
                                className="w-full h-8 rounded-lg text-[10px] font-bold border-destructive/20 text-destructive hover:bg-destructive/5 transition-all"
                            >
                                <Trash2 className="w-3 h-3 mr-1.5" /> Delete Organization
                            </Button>
                        </section>
                    </div>
                </div>
            ) : (
                <div className="flex-1 flex flex-col items-center justify-center text-center p-8 bg-surface/30">
                    <div className="w-14 h-14 bg-primary/5 rounded-2xl flex items-center justify-center mb-4">
                        <Building2 className="h-6 w-6 text-primary/20" />
                    </div>
                    <h3 className="text-sm font-bold text-on-surface mb-1">Select an Organization</h3>
                    <p className="text-[11px] text-on-surface-variant/30 font-medium max-w-xs">
                        Click an organization on the left to view its details and manage domain verification.
                    </p>
                </div>
            )}
        </div>
    );
};

export default Organizations;
