import { useState, useEffect } from 'react';
import { getCampaigns, createCampaign, startCampaign, completeCampaign, getCampaignItems, addCampaignItem, approveItem, revokeItem, getReviewItems } from '../api';
import { Card, CardHeader, CardTitle, CardContent, CardDescription, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '@/components/ui/table';
import { Loader2, Plus, Play, CheckCircle, XCircle, Search, Target, Layout, Square } from 'lucide-react';
import { Separator } from '@/components/ui/separator';

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

    // My Reviews State
    const [activeTab, setActiveTab] = useState<'all' | 'reviews'>('all');
    const [reviewerId, setReviewerId] = useState('');
    const [myReviewItems, setMyReviewItems] = useState<CertificationItem[]>([]);
    const [selectedItem, setSelectedItem] = useState<CertificationItem | null>(null);

    // Add Review Item State
    const [showAddItem, setShowAddItem] = useState(false);
    const [newItem, setNewItem] = useState({ user_id: '', resource_type: 'role', resource_id: '', resource_name: '' });

    useEffect(() => {
        loadCampaigns();
    }, [statusFilter]);

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

    const handleApprove = async (itemId: string) => {
        if (!selectedCampaign) return;
        try {
            await approveItem(selectedCampaign.id, itemId, 'Approved via Admin UI');
            loadItems(selectedCampaign.id);
        } catch (error) {
            console.error('Failed to approve:', error);
        }
    };

    const handleRevoke = async (itemId: string) => {
        if (!selectedCampaign) return;
        try {
            await revokeItem(selectedCampaign.id, itemId, 'Revoked via Admin UI');
            loadItems(selectedCampaign.id);
        } catch (error) {
            console.error('Failed to revoke:', error);
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
            setSelectedItem(null);
        } catch (error) {
            console.error('Action failed:', error);
        }
    };

    const getStatusVariant = (status: string) => {
        switch (status) {
            case 'active': return 'default'; // dark/primary
            case 'completed': return 'secondary';
            case 'cancelled': return 'destructive';
            default: return 'outline';
        }
    };

    if (loading) return <div className="p-8 flex items-center justify-center h-96"><Loader2 className="h-8 w-8 animate-spin text-muted-foreground" /></div>;

    return (
        <div className="space-y-6">
            <div className="flex justify-between items-center">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Certification Campaigns</h1>
                    <p className="text-muted-foreground mt-1">
                        Manage usage certification campaigns and reviews.
                    </p>
                </div>
                <div className="flex bg-muted p-1 rounded-lg">
                    <Button
                        variant={activeTab === 'all' ? 'default' : 'ghost'}
                        size="sm"
                        onClick={() => setActiveTab('all')}
                        className="rounded-md"
                    >
                        <Target className="mr-2 h-4 w-4" />
                        Campaigns
                    </Button>
                    <Button
                        variant={activeTab === 'reviews' ? 'default' : 'ghost'}
                        size="sm"
                        onClick={() => setActiveTab('reviews')}
                        className="rounded-md"
                    >
                        <Layout className="mr-2 h-4 w-4" />
                        My Reviews
                    </Button>
                </div>
            </div>

            <Separator />

            {/* MAIN CONTENT AREA */}
            <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-start">

                {activeTab === 'all' ? (
                    <>
                        {/* LEFT COLUMN: LIST & CREATE */}
                        <div className="md:col-span-4 space-y-6">
                            <Card>
                                <CardHeader>
                                    <CardTitle className="text-lg">Create Campaign</CardTitle>
                                </CardHeader>
                                <CardContent>
                                    <form onSubmit={handleCreateCampaign} className="space-y-4">
                                        <div className="space-y-2">
                                            <Input
                                                placeholder="Campaign Name"
                                                value={newCampaign.name}
                                                onChange={(e) => setNewCampaign({ ...newCampaign, name: e.target.value })}
                                                required
                                            />
                                            <Input
                                                placeholder="Reviewer ID (User ID)"
                                                value={newCampaign.reviewerId}
                                                onChange={(e) => setNewCampaign({ ...newCampaign, reviewerId: e.target.value })}
                                                required
                                            />
                                            <Button type="submit" className="w-full">
                                                <Plus className="mr-2 h-4 w-4" /> Create
                                            </Button>
                                        </div>
                                    </form>
                                </CardContent>
                            </Card>

                            <Card className="h-[calc(100vh-400px)] flex flex-col">
                                <CardHeader className="pb-3 border-b">
                                    <div className="flex items-center justify-between">
                                        <CardTitle className="text-lg">Campaigns</CardTitle>
                                        <select
                                            className="text-sm bg-transparent border-none text-muted-foreground focus:ring-0 cursor-pointer"
                                            value={statusFilter}
                                            onChange={(e) => setStatusFilter(e.target.value)}
                                        >
                                            <option value="">All Status</option>
                                            <option value="draft">Draft</option>
                                            <option value="active">Active</option>
                                            <option value="completed">Completed</option>
                                        </select>
                                    </div>
                                </CardHeader>
                                <div className="flex-1 overflow-y-auto p-2 space-y-2">
                                    {campaigns.map(campaign => (
                                        <div
                                            key={campaign.id}
                                            onClick={() => setSelectedCampaign(campaign)}
                                            className={`
                                                flex items-center justify-between p-3 rounded-md cursor-pointer transition-colors border
                                                ${selectedCampaign?.id === campaign.id
                                                    ? 'bg-primary/5 border-primary/20 shadow-sm'
                                                    : 'hover:bg-muted border-transparent hover:border-border'}
                                            `}
                                        >
                                            <div className="min-w-0 flex-1 mr-2">
                                                <div className="font-medium truncate">{campaign.name}</div>
                                                <div className="flex items-center gap-2 mt-1">
                                                    <Badge variant={getStatusVariant(campaign.status) as any} className="text-[10px] uppercase px-1.5 py-0 h-5">
                                                        {campaign.status}
                                                    </Badge>
                                                    <span className="text-xs text-muted-foreground">
                                                        {new Date(campaign.created_at).toLocaleDateString()}
                                                    </span>
                                                </div>
                                            </div>
                                            {campaign.status === 'draft' && (
                                                <Button
                                                    size="icon"
                                                    variant="ghost"
                                                    className="h-8 w-8 text-green-600 hover:text-green-700 hover:bg-green-50"
                                                    onClick={(e) => { e.stopPropagation(); handleStartCampaign(campaign.id); }}
                                                    title="Start Campaign"
                                                >
                                                    <Play className="h-4 w-4" />
                                                </Button>
                                            )}
                                            {campaign.status === 'active' && (
                                                <Button
                                                    size="icon"
                                                    variant="ghost"
                                                    className="h-8 w-8 text-blue-600 hover:text-blue-700 hover:bg-blue-50"
                                                    onClick={(e) => { e.stopPropagation(); handleCompleteCampaign(campaign.id); }}
                                                    title="Complete Campaign"
                                                >
                                                    <Square className="h-4 w-4" />
                                                </Button>
                                            )}
                                        </div>
                                    ))}
                                </div>
                            </Card>
                        </div>

                        {/* RIGHT COLUMN: DETAILS */}
                        <div className="md:col-span-8">
                            {selectedCampaign ? (
                                <Card className="h-full">
                                    <CardHeader className="border-b">
                                        <div className="flex items-center justify-between">
                                            <div>
                                                <CardTitle>{selectedCampaign.name}</CardTitle>
                                                <CardDescription className="mt-1">Review Items</CardDescription>
                                            </div>
                                            <Badge variant={getStatusVariant(selectedCampaign.status) as any}>
                                                {selectedCampaign.status}
                                            </Badge>
                                            {selectedCampaign.status === 'draft' && (
                                                <Button size="sm" variant="outline" onClick={() => setShowAddItem(!showAddItem)}>
                                                    <Plus className="h-4 w-4 mr-1" /> Add Item
                                                </Button>
                                            )}
                                        </div>
                                    </CardHeader>
                                    {showAddItem && selectedCampaign.status === 'draft' && (
                                        <div className="border-b p-4 bg-muted/30">
                                            <form onSubmit={handleAddItem} className="grid grid-cols-1 md:grid-cols-5 gap-3 items-end">
                                                <div className="space-y-1">
                                                    <label className="text-xs font-medium text-muted-foreground">User ID</label>
                                                    <Input
                                                        placeholder="user-uuid"
                                                        value={newItem.user_id}
                                                        onChange={(e) => setNewItem({ ...newItem, user_id: e.target.value })}
                                                        required
                                                    />
                                                </div>
                                                <div className="space-y-1">
                                                    <label className="text-xs font-medium text-muted-foreground">Resource Type</label>
                                                    <select
                                                        className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                                                        value={newItem.resource_type}
                                                        onChange={(e) => setNewItem({ ...newItem, resource_type: e.target.value })}
                                                    >
                                                        <option value="role">Role</option>
                                                        <option value="group">Group</option>
                                                        <option value="application">Application</option>
                                                        <option value="permission">Permission</option>
                                                    </select>
                                                </div>
                                                <div className="space-y-1">
                                                    <label className="text-xs font-medium text-muted-foreground">Resource ID</label>
                                                    <Input
                                                        placeholder="resource-uuid"
                                                        value={newItem.resource_id}
                                                        onChange={(e) => setNewItem({ ...newItem, resource_id: e.target.value })}
                                                        required
                                                    />
                                                </div>
                                                <div className="space-y-1">
                                                    <label className="text-xs font-medium text-muted-foreground">Display Name</label>
                                                    <Input
                                                        placeholder="Optional name"
                                                        value={newItem.resource_name}
                                                        onChange={(e) => setNewItem({ ...newItem, resource_name: e.target.value })}
                                                    />
                                                </div>
                                                <Button type="submit">Add</Button>
                                            </form>
                                        </div>
                                    )}
                                    <CardContent className="p-0">
                                        {items.length === 0 ? (
                                            <div className="p-12 text-center text-muted-foreground">
                                                No items found for this campaign.
                                            </div>
                                        ) : (
                                            <Table>
                                                <TableHeader>
                                                    <TableRow>
                                                        <TableHead>User</TableHead>
                                                        <TableHead>Resource</TableHead>
                                                        <TableHead>Status</TableHead>
                                                        <TableHead className="text-right">Actions</TableHead>
                                                    </TableRow>
                                                </TableHeader>
                                                <TableBody>
                                                    {items.map(item => (
                                                        <TableRow key={item.id}>
                                                            <TableCell className="font-medium">{item.user_id}</TableCell>
                                                            <TableCell>
                                                                <div className="flex flex-col">
                                                                    <span>{item.resource_name || item.resource_id}</span>
                                                                    <span className="text-xs text-muted-foreground uppercase tracking-wider">{item.resource_type}</span>
                                                                </div>
                                                            </TableCell>
                                                            <TableCell>
                                                                {item.decision ? (
                                                                    <Badge variant={item.decision === 'approve' ? 'default' : 'destructive'} className={item.decision === 'approve' ? 'bg-green-600 hover:bg-green-700' : ''}>
                                                                        {item.decision}
                                                                    </Badge>
                                                                ) : (
                                                                    <Badge variant="outline" className="text-yellow-600 border-yellow-200 bg-yellow-50">Pending</Badge>
                                                                )}
                                                            </TableCell>
                                                            <TableCell className="text-right">
                                                                {!item.decision && selectedCampaign.status === 'active' && (
                                                                    <div className="flex items-center justify-end gap-2">
                                                                        <Button size="sm" variant="ghost" className="h-8 text-green-600 hover:bg-green-50" onClick={() => handleApprove(item.id)}>
                                                                            <CheckCircle className="h-4 w-4 mr-1" /> Approve
                                                                        </Button>
                                                                        <Button size="sm" variant="ghost" className="h-8 text-destructive hover:bg-destructive/10" onClick={() => handleRevoke(item.id)}>
                                                                            <XCircle className="h-4 w-4 mr-1" /> Revoke
                                                                        </Button>
                                                                    </div>
                                                                )}
                                                            </TableCell>
                                                        </TableRow>
                                                    ))}
                                                </TableBody>
                                            </Table>
                                        )}
                                    </CardContent>
                                </Card>
                            ) : (
                                <div className="h-full flex flex-col items-center justify-center border-2 border-dashed rounded-lg p-12 text-muted-foreground bg-muted/20">
                                    <Target className="h-12 w-12 mb-4 opacity-20" />
                                    <p>Select a campaign to view details</p>
                                </div>
                            )}
                        </div>
                    </>
                ) : (
                    // MY REVIEWS TAB
                    <div className="md:col-span-12 max-w-4xl mx-auto w-full space-y-6">
                        <Card>
                            <CardHeader>
                                <CardTitle>My Reviews</CardTitle>
                                <CardDescription>Enter your user ID to find items assigned to you for review.</CardDescription>
                            </CardHeader>
                            <CardContent className="space-y-6">
                                <div className="flex gap-2 max-w-md">
                                    <Input
                                        placeholder="Enter your User ID"
                                        value={reviewerId}
                                        onChange={(e) => setReviewerId(e.target.value)}
                                    />
                                    <Button onClick={() => loadMyReviews(reviewerId)}>
                                        <Search className="mr-2 h-4 w-4" /> Load
                                    </Button>
                                </div>

                                <div className="border rounded-md">
                                    {myReviewItems.length === 0 ? (
                                        <div className="p-12 text-center text-muted-foreground">
                                            No pending reviews found.
                                        </div>
                                    ) : (
                                        <Table>
                                            <TableHeader>
                                                <TableRow>
                                                    <TableHead>Resource</TableHead>
                                                    <TableHead>User</TableHead>
                                                    <TableHead>Action</TableHead>
                                                </TableRow>
                                            </TableHeader>
                                            <TableBody>
                                                {myReviewItems.map(item => (
                                                    <TableRow key={item.id}>
                                                        <TableCell>
                                                            <div className="font-medium">{item.resource_name || item.resource_id}</div>
                                                            <div className="text-xs text-muted-foreground uppercase">{item.resource_type}</div>
                                                        </TableCell>
                                                        <TableCell>{item.user_id}</TableCell>
                                                        <TableCell>
                                                            <div className="flex gap-2">
                                                                <Button size="sm" className="bg-green-600 hover:bg-green-700" onClick={() => handleMyReviewAction(item, 'approve')}>
                                                                    Approve
                                                                </Button>
                                                                <Button size="sm" variant="destructive" onClick={() => handleMyReviewAction(item, 'revoke')}>
                                                                    Revoke
                                                                </Button>
                                                            </div>
                                                        </TableCell>
                                                    </TableRow>
                                                ))}
                                            </TableBody>
                                        </Table>
                                    )}
                                </div>
                            </CardContent>
                        </Card>
                    </div>
                )}
            </div>
        </div>
    );
}
