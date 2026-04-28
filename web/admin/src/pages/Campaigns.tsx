import React, { useState, useEffect } from 'react';
import { getCampaigns, createCampaign, startCampaign, completeCampaign, getCampaignItems, addCampaignItem, approveItem, revokeItem, getReviewItems, getSCIMUsers } from '../api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { TableBody, TableCell } from '@/components/ui/table';
import {
    Loader2,
    Plus,
    Play,
    CheckCircle,
    XCircle,
    Search,
    Target,
    Layout,
    Square,
    Award,
    Filter,
    ShieldCheck,
    Box,
    Activity,
    Terminal,
    Fingerprint,
    ChevronRight,
    Command
} from 'lucide-react';
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassTable, GlassTableHeader, GlassTableHead, GlassTableRow } from '@/components/layout';
import { Label } from '@/components/ui/label';
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";

interface Campaign {
    id: string;
    name: string;
    description: string;
    status: string;
    reviewer_id: string;
    created_at: string;
}

interface CertificationItem {
    id: string;
    campaign_id?: string;
    user_id: string;
    resource_type: string;
    resource_id: string;
    resource_name: string;
    decision: string | null;
}

export default function Campaigns() {
    const [campaigns, setCampaigns] = useState<Campaign[]>([]);
    const [selectedCampaign, setSelectedCampaign] = useState<Campaign | null>(null);
    const [items, setItems] = useState<CertificationItem[]>([]);
    const [loading, setLoading] = useState(true);
    const [newCampaign, setNewCampaign] = useState({ name: '', description: '', reviewerId: '' });
    const [statusFilter, setStatusFilter] = useState('');
    const [allUsers, setAllUsers] = useState<any[]>([]);

    const [activeTab, setActiveTab] = useState<'all' | 'reviews'>('all');
    const [reviewerId, setReviewerId] = useState('');
    const [myReviewItems, setMyReviewItems] = useState<CertificationItem[]>([]);

    const [showAddItem, setShowAddItem] = useState(false);
    const [newItem, setNewItem] = useState({ user_id: '', resource_type: 'role', resource_id: '', resource_name: '' });

    useEffect(() => { loadCampaigns(); }, [statusFilter]);
    useEffect(() => {
        getSCIMUsers().then(d => setAllUsers(d.Resources || [])).catch(() => {});
    }, []);

    useEffect(() => {
        if (selectedCampaign) {
            loadItems(selectedCampaign.id);
        }
    }, [selectedCampaign]);

    const loadCampaigns = async () => {
        try {
            const res = await getCampaigns(statusFilter);
            setCampaigns(res.campaigns || []);
        } catch (error) {
            console.error('Failed to load campaigns:', error);
        } finally {
            setLoading(false);
        }
    };

    const loadItems = async (campaignId: string) => {
        try {
            const res = await getCampaignItems(campaignId);
            setItems(res.items || []);
        } catch (error) {
            console.error('Failed to load items:', error);
        }
    };

    const handleCreateCampaign = async (e: React.FormEvent) => {
        e.preventDefault();
        try {
            await createCampaign(newCampaign.name, newCampaign.description, newCampaign.reviewerId);
            setNewCampaign({ name: '', description: '', reviewerId: '' });
            loadCampaigns();
        } catch (error) {
            console.error('Failed to create campaign:', error);
        }
    };

    const handleStartCampaign = async (id: string) => {
        try {
            await startCampaign(id);
            loadCampaigns();
        } catch (error) {
            console.error('Failed to start campaign:', error);
        }
    };

    const handleCompleteCampaign = async (id: string) => {
        try {
            await completeCampaign(id);
            loadCampaigns();
            if (selectedCampaign?.id === id) {
                setSelectedCampaign(null);
            }
        } catch (error) {
            console.error('Failed to complete campaign:', error);
        }
    };

    const handleAction = async (itemId: string, action: 'approve' | 'revoke') => {
        if (!selectedCampaign) return;
        try {
            if (action === 'approve') {
                await approveItem(selectedCampaign.id, itemId, 'Approved via Admin UI');
            } else {
                await revokeItem(selectedCampaign.id, itemId, 'Revoked via Admin UI');
            }
            loadItems(selectedCampaign.id);
        } catch (error) {
            console.error('Action failed:', error);
        }
    };

    const handleAddItem = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!selectedCampaign) return;
        try {
            await addCampaignItem(selectedCampaign.id, newItem);
            setNewItem({ user_id: '', resource_type: 'role', resource_id: '', resource_name: '' });
            setShowAddItem(false);
            loadItems(selectedCampaign.id);
        } catch (error) {
            console.error('Failed to add item:', error);
        }
    };

    const loadMyReviews = async (id: string) => {
        if (!id) return;
        setLoading(true);
        try {
            const res = await getReviewItems(id);
            setMyReviewItems(res.items || []);
        } catch (error) {
            console.error('Failed to load reviews:', error);
        } finally {
            setLoading(false);
        }
    };

    const handleMyReviewAction = async (item: CertificationItem, action: 'approve' | 'revoke') => {
        if (!item.campaign_id) return;
        try {
            if (action === 'approve') {
                await approveItem(item.campaign_id, item.id, 'Approved by reviewer');
            } else {
                await revokeItem(item.campaign_id, item.id, 'Revoked by reviewer');
            }
            loadMyReviews(reviewerId);
        } catch (error) {
            console.error('Action failed:', error);
        }
    };

    if (loading && campaigns.length === 0) return <div className="h-[400px] flex items-center justify-center"><Loader2 className="h-10 w-10 animate-spin text-primary opacity-20" /></div>;

    return (
        <div className="space-y-10 animate-in fade-in duration-700">
            <PageHeader
                icon={<Award className="w-8 h-8 text-primary" />}
                title="Access Reviews"
                description="Run periodic reviews to certify user access to critical resources and maintain security compliance."
                actions={
                    <div className="flex bg-surface-container/50 p-1 rounded-2xl ring-1 ring-on-surface/5">
                         <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setActiveTab('all')}
                            className={`rounded-xl font-bold text-[11px] h-10 px-6 transition-all ${activeTab === 'all' ? 'bg-card text-primary shadow-sm' : 'text-on-surface-variant/40 hover:text-on-surface'}`}
                        >
                            All Campaigns
                        </Button>
                        <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setActiveTab('reviews')}
                            className={`rounded-xl font-bold text-[11px] h-10 px-6 transition-all ${activeTab === 'reviews' ? 'bg-card text-primary shadow-sm' : 'text-on-surface-variant/40 hover:text-on-surface'}`}
                        >
                            Review Terminal
                        </Button>
                    </div>
                }
            />

            <div className="grid grid-cols-1 md:grid-cols-12 gap-10 items-start">
                {activeTab === 'all' ? (
                    <>
                        <div className="md:col-span-4 space-y-10">
                            <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-card overflow-hidden rounded-[24px]">
                                <GlassCardHeader className="bg-primary p-8 text-white">
                                     <div className="flex items-center gap-4">
                                        <div className="p-2.5 bg-card/20 rounded-xl backdrop-blur-md">
                                            <Plus className="w-5 h-5 text-white" />
                                        </div>
                                        <GlassCardTitle className="text-xl font-bold tracking-tight">New Campaign</GlassCardTitle>
                                    </div>
                                </GlassCardHeader>
                                <GlassCardContent className="p-8">
                                    <form onSubmit={handleCreateCampaign} className="space-y-8">
                                         <div className="space-y-2.5">
                                            <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/50 ml-1">Campaign Name</Label>
                                            <Input
                                                placeholder="e.g. q3_privilege_audit"
                                                className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium transition-all"
                                                value={newCampaign.name}
                                                onChange={(e) => setNewCampaign({ ...newCampaign, name: e.target.value })}
                                                required
                                            />
                                        </div>
                                         <div className="space-y-2.5">
                                            <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/50 ml-1">Reviewer</Label>
                                            <Select
                                                value={newCampaign.reviewerId}
                                                onValueChange={(v) => setNewCampaign({ ...newCampaign, reviewerId: v })}
                                                required
                                            >
                                                <SelectTrigger className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus:ring-2 focus:ring-primary/20 font-medium transition-all text-sm">
                                                    <SelectValue placeholder="Select a reviewer..." />
                                                </SelectTrigger>
                                                <SelectContent className="rounded-xl border-none shadow-xl">
                                                    {allUsers.map((u: any) => {
                                                        const email = u.emails?.[0]?.value || u.userName || u.id;
                                                        return (
                                                            <SelectItem key={u.id} value={u.id} className="font-medium text-sm">
                                                                {email}
                                                            </SelectItem>
                                                        );
                                                    })}
                                                </SelectContent>
                                            </Select>
                                        </div>
                                         <Button type="submit" className="w-full h-12 rounded-xl font-bold text-sm shadow-md shadow-primary/10">
                                            Create Campaign
                                        </Button>
                                    </form>
                                </GlassCardContent>
                            </GlassCard>

                            <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-card overflow-hidden flex flex-col h-[600px] rounded-[24px]">
                                <GlassCardHeader className="py-8 px-8 border-b border-on-surface/5">
                                         <div className="flex items-center justify-between">
                                        <GlassCardTitle className="text-lg font-bold tracking-tight text-on-surface">Campaign List</GlassCardTitle>
                                        <div className="flex items-center gap-2.5 bg-surface-container/50 px-3 py-1.5 rounded-xl ring-1 ring-on-surface/5">
                                            <Filter className="w-3.5 h-3.5 text-on-surface-variant/40" />
                                            <select
                                                className="text-[11px] font-bold bg-transparent border-none p-0 h-4 focus:ring-0 cursor-pointer text-on-surface-variant/60"
                                                value={statusFilter}
                                                onChange={(e) => setStatusFilter(e.target.value)}
                                            >
                                                <option value="">All Status</option>
                                                <option value="draft">draft</option>
                                                <option value="active">active</option>
                                                <option value="completed">complete</option>
                                            </select>
                                        </div>
                                    </div>
                                </GlassCardHeader>
                                <div className="flex-1 overflow-y-auto p-4 space-y-2 custom-scrollbar">
                                    {campaigns.map(campaign => (
                                        <div
                                            key={campaign.id}
                                            onClick={() => setSelectedCampaign(campaign)}
                                            className={`
                                                group flex items-center justify-between p-5 cursor-pointer transition-all rounded-2xl
                                                ${selectedCampaign?.id === campaign.id
                                                    ? 'bg-primary/5 ring-1 ring-primary/20'
                                                    : 'bg-card hover:bg-surface-container/30 ring-1 ring-on-surface/5 hover:ring-on-surface/10'}
                                            `}
                                        >
                                            <div className="min-w-0 pr-4">
                                                <div className={`font-bold text-sm tracking-tight truncate flex items-center gap-3 transition-colors ${selectedCampaign?.id === campaign.id ? 'text-primary' : 'text-on-surface'}`}>
                                                    <Target className={`h-4 w-4 opacity-40 ${selectedCampaign?.id === campaign.id ? 'text-primary' : ''}`} />
                                                    {campaign.name}
                                                </div>
                                                 <div className="flex items-center gap-3 mt-1.5">
                                                    <Badge className={`rounded-xl font-bold text-[10px] px-2.5 py-0.5 border-none shadow-sm transition-all ${campaign.status === 'active' ? 'bg-success-subtle text-success' :
                                                        campaign.status === 'completed' ? 'bg-blue-50 text-blue-600' :
                                                            'bg-amber-50 text-amber-600'
                                                        }`}>
                                                        {campaign.status}
                                                    </Badge>
                                                    <span className="text-[10px] font-medium text-on-surface-variant/40 italic">
                                                        {campaign.created_at ? new Date(campaign.created_at).toLocaleDateString() : 'initialized'}
                                                    </span>
                                                </div>
                                            </div>
                                            <div className="flex items-center gap-2">
                                                {campaign.status === 'draft' && (
                                                    <Button size="icon" variant="ghost" className="h-9 w-9 rounded-xl text-success hover:bg-success-subtle transition-all" onClick={(e) => { e.stopPropagation(); handleStartCampaign(campaign.id); }}>
                                                        <Play className="h-4 w-4" />
                                                    </Button>
                                                )}
                                                {campaign.status === 'active' && (
                                                    <Button size="icon" variant="ghost" className="h-9 w-9 rounded-xl text-destructive hover:bg-destructive/10 transition-all" onClick={(e) => { e.stopPropagation(); handleCompleteCampaign(campaign.id); }}>
                                                        <Square className="h-4 w-4" />
                                                    </Button>
                                                )}
                                                {selectedCampaign?.id === campaign.id && <ChevronRight className="h-5 w-5 text-primary/40 animate-in fade-in slide-in-from-left-2" />}
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </GlassCard>
                        </div>

                        <div className="md:col-span-8">
                            {selectedCampaign ? (
                                <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-card overflow-hidden min-h-[850px] flex flex-col rounded-[32px]">
                                    <GlassCardHeader className="bg-surface-container p-12 ">
                                        <div className="flex items-center justify-between">
                                            <div className="space-y-5">
                                                <div className="flex items-center gap-5">
                                                     <div className="p-4 bg-primary/10 rounded-2xl">
                                                        <Target className="w-8 h-8 text-primary" />
                                                    </div>
                                                    <h2 className="text-4xl font-bold tracking-tight text-on-surface">{selectedCampaign.name}</h2>
                                                </div>
                                                <p className="text-[11px] font-bold text-on-surface-variant/40 italic">Assigned Reviewer: <span className="text-primary">{selectedCampaign.reviewer_id.toLowerCase()}</span></p>
                                            </div>
                                            <div className="flex flex-col items-end gap-5">
                                                 <Badge className="bg-card text-on-surface-variant border-none rounded-xl h-10 px-6 text-xs font-bold shadow-sm italic">
                                                    {selectedCampaign.status}
                                                </Badge>
                                                {selectedCampaign.status === 'draft' && (
                                                    <Button
                                                        onClick={() => setShowAddItem(!showAddItem)}
                                                        className="h-12 rounded-xl font-bold text-sm shadow-md shadow-primary/10 px-6 transition-all"
                                                        variant={showAddItem ? "ghost" : "default"}
                                                    >
                                                        {showAddItem ? <XCircle className="h-4 w-4 mr-2" /> : <Plus className="h-4 w-4 mr-2" />}
                                                        {showAddItem ? 'Cancel' : 'Add Items'}
                                                    </Button>
                                                )}
                                            </div>
                                        </div>
                                    </GlassCardHeader>

                                    {showAddItem && selectedCampaign.status === 'draft' && (
                                        <div className="bg-surface-container/30 border-b border-on-surface/5 p-10 animate-in slide-in-from-top-4 duration-500">
                                            <form onSubmit={handleAddItem} className="grid grid-cols-1 md:grid-cols-4 gap-6 items-end">
                                                 <div className="space-y-2.5">
                                                    <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/50 ml-1">User ID</Label>
                                                    <Input
                                                        placeholder="usr_vec_772"
                                                        className="h-12 border-none rounded-xl bg-card shadow-sm ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-medium"
                                                        value={newItem.user_id}
                                                        onChange={(e) => setNewItem({ ...newItem, user_id: e.target.value })}
                                                        required
                                                    />
                                                </div>
                                                 <div className="space-y-2.5">
                                                    <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/50 ml-1">Resource Type</Label>
                                                    <select
                                                        className="flex h-12 w-full border-none rounded-xl bg-card shadow-sm ring-1 ring-on-surface/5 focus:ring-2 focus:ring-primary/20 font-bold text-[11px] px-4 cursor-pointer"
                                                        value={newItem.resource_type}
                                                        onChange={(e) => setNewItem({ ...newItem, resource_type: e.target.value })}
                                                    >
                                                        <option value="role">Role</option>
                                                        <option value="group">Group</option>
                                                        <option value="application">Application</option>
                                                        <option value="permission">Permission</option>
                                                    </select>
                                                </div>
                                                 <div className="space-y-2.5">
                                                    <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/50 ml-1">Resource id</Label>
                                                    <Input
                                                        placeholder="admin_override"
                                                        className="h-12 border-none rounded-xl bg-card shadow-sm ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-medium"
                                                        value={newItem.resource_id}
                                                        onChange={(e) => setNewItem({ ...newItem, resource_id: e.target.value })}
                                                        required
                                                    />
                                                </div>
                                                <Button type="submit" className="h-12 rounded-xl font-bold text-sm shadow-md shadow-primary/10">
                                                    Add to Review
                                                </Button>
                                            </form>
                                        </div>
                                    )}

                                    <GlassCardContent className="p-0 flex-1 overflow-y-auto bg-card">
                                        {items.length === 0 ? (
                                             <div className="py-40 text-center">
                                                <div className="flex flex-col items-center gap-6 opacity-20">
                                                    <Activity className="h-16 w-16" />
                                                    <span className="text-[11px] font-bold italic">No items in this campaign.</span>
                                                </div>
                                            </div>
                                        ) : (
                                            <div className="overflow-x-auto">
                                                 <GlassTable>
                                                    <GlassTableHeader>
                                                        <GlassTableRow className="hover:bg-transparent border-b border-on-surface/5">
                                                            <GlassTableHead className="py-6 pl-10 font-bold text-[12px] text-on-surface-variant/40">User</GlassTableHead>
                                                            <GlassTableHead className="font-bold text-[12px] text-on-surface-variant/40">Resource</GlassTableHead>
                                                            <GlassTableHead className="font-bold text-[12px] text-on-surface-variant/40">Status</GlassTableHead>
                                                            <GlassTableHead className="text-right font-bold text-[12px] text-on-surface-variant/40 pr-10">Actions</GlassTableHead>
                                                        </GlassTableRow>
                                                    </GlassTableHeader>
                                                    <TableBody>
                                                        {items.map(item => (
                                                            <GlassTableRow key={item.id} className="hover:bg-surface-container/10 transition-all border-b border-on-surface/5 last:border-0 group">
                                                                <TableCell className="py-8 pl-10">
                                                                     <div className="flex items-center gap-5">
                                                                        <div className="w-10 h-10 rounded-xl bg-surface-container flex items-center justify-center font-bold text-xs group-hover:bg-primary/10 group-hover:text-primary transition-all">@</div>
                                                                        <div className="flex flex-col">
                                                                            <span className="text-lg font-bold text-on-surface group-hover:text-primary transition-colors">{item.user_id}</span>
                                                                            <span className="text-[9px] font-bold text-on-surface-variant/40 mt-1 italic">Review Subject</span>
                                                                        </div>
                                                                    </div>
                                                                </TableCell>
                                                                <TableCell className="py-8">
                                                                    <div className="flex items-center gap-3">
                                                                        <Badge className="bg-surface-container text-on-surface-variant border-none rounded-lg font-bold text-[8px] px-2.5 py-1 uppercase">{item.resource_type}</Badge>
                                                                        <span className="text-[11px] font-bold text-on-surface-variant/60 uppercase transition-opacity group-hover:text-on-surface">[{item.resource_name || item.resource_id}]</span>
                                                                    </div>
                                                                </TableCell>
                                                                 <TableCell className="py-8">
                                                                    {item.decision ? (
                                                                        <Badge className={`rounded-xl font-bold text-[10px] px-4 py-1.5 border-none shadow-sm transition-all italic ${item.decision === 'approve' ? 'bg-success-subtle text-success' : 'bg-destructive/10 text-destructive'}`}>
                                                                            {item.decision}_persisted
                                                                        </Badge>
                                                                    ) : (
                                                                        <div className="flex items-center gap-3 text-[10px] font-bold text-amber-600/60 italic">
                                                                            <Activity className="h-3.5 w-3.5 animate-pulse" />
                                                                            Pending Review
                                                                        </div>
                                                                    )}
                                                                </TableCell>
                                                                <TableCell className="py-8 text-right pr-10">
                                                                     {!item.decision && selectedCampaign.status === 'active' && (
                                                                        <div className="flex items-center justify-end gap-3">
                                                                            <Button size="sm" onClick={() => handleAction(item.id, 'approve')} className="h-10 rounded-xl bg-success text-success-foreground hover:bg-emerald-600 font-bold text-[10px] px-5 shadow-lg shadow-emerald-500/10 transition-all border-none">
                                                                                Approve
                                                                            </Button>
                                                                            <Button size="sm" variant="ghost" onClick={() => handleAction(item.id, 'revoke')} className="h-10 rounded-xl text-destructive hover:bg-destructive/10 font-bold text-[10px] px-5 transition-all">
                                                                                Revoke
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
                            ) : (
                                <div className="h-full flex flex-col items-center justify-center border-2 border-dashed rounded-[40px] border-on-surface/5 bg-surface-container/10 min-h-[850px] animate-in fade-in duration-1000">
                                    <div className="p-16 bg-card rounded-[32px] shadow-2xl shadow-on-surface/5 flex flex-col items-center text-center max-w-lg mx-auto">
                                         <div className="w-24 h-24 bg-primary/5 rounded-[32px] flex items-center justify-center mb-10">
                                            <Target className="h-12 w-12 text-primary/20 animate-pulse" />
                                        </div>
                                        <h3 className="text-2xl font-bold tracking-tight text-on-surface mb-4">Select a Campaign</h3>
                                        <p className="text-sm font-medium text-on-surface-variant/40 leading-relaxed max-w-xs transition-opacity opacity-60">Choose a campaign from the list to view its details and items.</p>
                                    </div>
                                </div>
                            )}
                        </div>
                    </>
                ) : (
                    <div className="col-span-full max-w-6xl mx-auto w-full space-y-12 py-10">
                        <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-card overflow-hidden rounded-[40px]">
                            <GlassCardHeader className="bg-primary p-16 text-white text-center">
                                <div className="flex flex-col items-center gap-8">
                                    <div className="p-6 bg-card/20 rounded-[32px] backdrop-blur-xl">
                                        <Terminal className="w-12 h-12 text-white" />
                                    </div>
                                     <div className="space-y-4">
                                        <GlassCardTitle className="text-5xl font-bold tracking-tighter">Access Review Portal</GlassCardTitle>
                                        <p className="text-on-inverse/60 font-bold text-[12px] italic">Review and certify access for users assigned to you.</p>
                                    </div>
                                </div>
                            </GlassCardHeader>
                            <GlassCardContent className="p-16 space-y-16">
                                 <div className="flex flex-col md:flex-row gap-8 max-w-3xl mx-auto">
                                    <div className="flex-1 space-y-3">
                                        <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-2">Enter your User ID</Label>
                                        <Input
                                            placeholder="USR_VEC_772"
                                            className="h-16 font-mono tracking-widest text-lg border-none rounded-[24px] bg-surface-container/50 px-10 ring-1 ring-on-surface/5 focus:ring-2 focus:ring-primary/20 transition-all text-center"
                                            value={reviewerId}
                                            onChange={(e) => setReviewerId(e.target.value)}
                                        />
                                    </div>
                                     <Button
                                        className="h-16 rounded-[24px] px-12 font-bold text-sm shadow-xl shadow-primary/20 transition-all self-end"
                                        onClick={() => loadMyReviews(reviewerId)}
                                    >
                                        <Search className="mr-3 h-5 w-5" /> View My Reviews
                                    </Button>
                                </div>

                                <div className="border-none bg-card overflow-hidden ring-1 ring-on-surface/5 rounded-[32px] shadow-2xl shadow-on-surface/5">
                                    {myReviewItems.length === 0 ? (
                                         <div className="py-40 text-center">
                                            <div className="flex flex-col items-center gap-6 opacity-10">
                                                <ShieldCheck className="h-20 w-20" />
                                                <p className="text-[11px] font-bold italic">No reviews assigned to this User ID.</p>
                                            </div>
                                        </div>
                                    ) : (
                                        <GlassTable>
                                             <GlassTableHeader>
                                                <GlassTableRow className="bg-primary/5 hover:bg-primary/5 border-none">
                                                    <GlassTableHead className="py-8 pl-12">Resource</GlassTableHead>
                                                    <GlassTableHead className="py-8 px-12">User</GlassTableHead>
                                                    <GlassTableHead className="py-8 px-12 text-right">Decisions</GlassTableHead>
                                                </GlassTableRow>
                                            </GlassTableHeader>
                                            <TableBody>
                                                {myReviewItems.map(item => (
                                                    <GlassTableRow key={item.id} className="border-b border-on-surface/5 last:border-0 group hover:bg-surface-container/20 transition-all">
                                                        <TableCell className="py-12 pl-12">
                                                            <div className="flex items-center gap-8">
                                                                <div className="w-14 h-14 bg-surface-container rounded-2xl flex items-center justify-center group-hover:bg-primary group-hover:text-primary-foreground transition-all shadow-sm">
                                                                    <Command className="h-6 w-6 opacity-40 group-hover:opacity-100" />
                                                                </div>
                                                                 <div className="flex flex-col">
                                                                    <span className="text-2xl font-bold tracking-tight text-on-surface group-hover:text-primary transition-all">{item.resource_name || item.resource_id}</span>
                                                                    <span className="text-[10px] font-bold text-on-surface-variant/40 mt-1 italic">{item.resource_type}</span>
                                                                </div>
                                                            </div>
                                                        </TableCell>
                                                        <TableCell className="py-12 px-12 font-bold font-mono text-[13px] tracking-widest uppercase text-on-surface-variant/30 group-hover:text-on-surface-variant transition-colors">
                                                            {item.user_id}
                                                        </TableCell>
                                                         <TableCell className="py-12 px-12 text-right">
                                                            <div className="flex justify-end gap-4">
                                                                <Button className="h-14 rounded-2xl bg-success text-success-foreground hover:bg-emerald-600 font-bold text-[11px] px-10 shadow-lg shadow-emerald-500/10 transition-all border-none" onClick={() => handleMyReviewAction(item, 'approve')}>
                                                                    Approve
                                                                </Button>
                                                                <Button className="h-14 rounded-2xl bg-destructive text-destructive-foreground hover:bg-red-700 font-bold text-[11px] px-10 shadow-lg shadow-destructive/10 transition-all border-none" onClick={() => handleMyReviewAction(item, 'revoke')}>
                                                                    Revoke
                                                                </Button>
                                                            </div>
                                                        </TableCell>
                                                    </GlassTableRow>
                                                ))}
                                            </TableBody>
                                        </GlassTable>
                                    )}
                                </div>
                            </GlassCardContent>
                        </GlassCard>
                    </div>
                )}
            </div>
        </div>
    );
}
