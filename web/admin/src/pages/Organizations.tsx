import React, { useState, useEffect } from 'react';
import {
    getOrganizations,
    createOrganization,
    deleteOrganization,
    generateDomainToken,
    getOrganizationDomains,
    verifyDomain
} from '../api';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Loader2, Plus, Building2, Trash2, Globe, CheckCircle, AlertTriangle } from 'lucide-react';

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
                display_name: newOrg.display_name || undefined, // Send undefined if empty string
                domain: newOrg.domain || undefined,
            });
            setNewOrg({ name: '', display_name: '', domain: '' });
            fetchOrgs(); // Reload list
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
            // Try to generate a new token
            try {
                const data = await generateDomainToken(orgId);
                setVerifyDetails(data);
            } catch (err) {
                // If generation fails (e.g. already verified or exists), try fetching existing
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

    if (loading && orgs.length === 0) return <div className="p-8 flex justify-center"><Loader2 className="h-8 w-8 animate-spin text-muted-foreground" /></div>;

    return (
        <div className="space-y-6">
            <div className="flex justify-between items-center">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Organizations</h1>
                    <p className="text-muted-foreground mt-1">Manage enterprise customers and their settings.</p>
                </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-start">
                {/* Create Form */}
                <div className="md:col-span-4">
                    <Card>
                        <CardHeader>
                            <CardTitle className="text-lg">New Organization</CardTitle>
                            <CardDescription>Create a new customer account.</CardDescription>
                        </CardHeader>
                        <CardContent>
                            <form onSubmit={handleCreate} className="space-y-4">
                                <div className="space-y-2">
                                    <Label>Organization Name</Label>
                                    <Input
                                        placeholder="e.g. acme-corp"
                                        value={newOrg.name}
                                        onChange={(e) => setNewOrg({ ...newOrg, name: e.target.value })}
                                        required
                                    />
                                    <span className="text-xs text-muted-foreground">Unique identifier (slug)</span>
                                </div>
                                <div className="space-y-2">
                                    <Label>Display Name</Label>
                                    <Input
                                        placeholder="e.g. Acme Corp Inc."
                                        value={newOrg.display_name}
                                        onChange={(e) => setNewOrg({ ...newOrg, display_name: e.target.value })}
                                    />
                                </div>
                                <div className="space-y-2">
                                    <Label>Domain</Label>
                                    <Input
                                        placeholder="e.g. acme.com"
                                        value={newOrg.domain}
                                        onChange={(e) => setNewOrg({ ...newOrg, domain: e.target.value })}
                                    />
                                </div>
                                {error && <div className="text-sm text-destructive">{error}</div>}
                                <Button type="submit" className="w-full" disabled={creating}>
                                    {creating ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Plus className="mr-2 h-4 w-4" />}
                                    Create Organization
                                </Button>
                            </form>
                        </CardContent>
                    </Card>
                </div>

                {/* List */}
                <div className="md:col-span-8">
                    <Card>
                        <CardHeader>
                            <CardTitle>All Organizations</CardTitle>
                        </CardHeader>
                        <CardContent className="p-0">
                            {orgs.length === 0 ? (
                                <div className="p-8 text-center text-muted-foreground">No organizations found.</div>
                            ) : (
                                <Table>
                                    <TableHeader>
                                        <TableRow>
                                            <TableHead>Name</TableHead>
                                            <TableHead>Domain</TableHead>
                                            <TableHead>Status</TableHead>
                                            <TableHead className="text-right">Actions</TableHead>
                                        </TableRow>
                                    </TableHeader>
                                    <TableBody>
                                        {orgs.map(org => (
                                            <TableRow key={org.id}>
                                                <TableCell>
                                                    <div className="font-medium flex items-center gap-2">
                                                        <Building2 className="h-4 w-4 text-muted-foreground" />
                                                        {org.name}
                                                    </div>
                                                    {org.display_name && <div className="text-xs text-muted-foreground ml-6">{org.display_name}</div>}
                                                </TableCell>
                                                <TableCell>{org.domain || '-'}</TableCell>
                                                <TableCell>
                                                    {org.domain_verified ? (
                                                        <Badge variant="default" className="bg-green-600 hover:bg-green-700">Verified</Badge>
                                                    ) : org.domain ? (
                                                        <Button size="sm" variant="outline" className="h-6 text-xs" onClick={() => openVerifyModal(org.id)}>
                                                            Verify
                                                        </Button>
                                                    ) : (
                                                        <span className="text-muted-foreground text-sm">-</span>
                                                    )}
                                                </TableCell>
                                                <TableCell className="text-right">
                                                    <Button size="icon" variant="ghost" className="h-8 w-8 text-destructive hover:bg-destructive/10" onClick={() => handleDelete(org.id)}>
                                                        <Trash2 className="h-4 w-4" />
                                                    </Button>
                                                </TableCell>
                                            </TableRow>
                                        ))}
                                    </TableBody>
                                </Table>
                            )}
                        </CardContent>
                    </Card>
                </div>
            </div>

            {/* Verification Modal */}
            {verifyModal && (
                <div className="fixed inset-0 bg-background/80 backdrop-blur-sm flex justify-center items-center z-50">
                    <Card className="w-full max-w-md shadow-lg">
                        <CardHeader>
                            <CardTitle className="text-xl">Domain Verification</CardTitle>
                            <CardDescription>{verifyDetails?.domain}</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            {verifyLoading ? (
                                <div className="flex justify-center p-4"><Loader2 className="h-8 w-8 animate-spin" /></div>
                            ) : verifyDetails ? (
                                <>
                                    <div className="bg-muted p-4 rounded-md space-y-2 text-sm">
                                        <p className="font-medium">Add TXT record to DNS:</p>
                                        <div className="grid grid-cols-[60px_1fr] gap-2 items-center">
                                            <span className="font-mono text-muted-foreground">Name:</span>
                                            <code className="bg-background px-2 py-1 rounded border">{verifyDetails.txt_record}</code>
                                            <span className="font-mono text-muted-foreground">Value:</span>
                                            <code className="bg-background px-2 py-1 rounded border break-all">{verifyDetails.token}</code>
                                        </div>
                                    </div>
                                    {verifyResult && (
                                        <div className={`p-3 rounded-md text-sm flex items-center gap-2 ${verifyResult.includes('✅') ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300' : 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300'}`}>
                                            {verifyResult.includes('✅') ? <CheckCircle className="h-4 w-4" /> : <AlertTriangle className="h-4 w-4" />}
                                            {verifyResult}
                                        </div>
                                    )}
                                    <div className="flex justify-end gap-2 pt-2">
                                        <Button variant="outline" onClick={() => setVerifyModal(null)}>Close</Button>
                                        <Button onClick={handleVerify} disabled={verifyLoading}>
                                            {verifyLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Globe className="mr-2 h-4 w-4" />}
                                            Verify Now
                                        </Button>
                                    </div>
                                </>
                            ) : (
                                <div className="text-destructive">Failed to load verification details.</div>
                            )}
                        </CardContent>
                    </Card>
                </div>
            )}
        </div>
    );
};

export default Organizations;
