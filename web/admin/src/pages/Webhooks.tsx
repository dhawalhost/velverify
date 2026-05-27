import React, { useEffect, useState } from 'react';
import { getWebhooks, createWebhook, deleteWebhook } from '../api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { TableBody, TableCell } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { 
    Loader2, 
    Plus, 
    Trash2, 
    Webhook as WebhookIcon, 
    Check, 
    Activity, 
    Globe, 
    ShieldCheck, 
    Terminal, 
    ExternalLink, 
    Fingerprint, 
    Link2, 
    Binary,
    Lock
} from 'lucide-react';
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassTable, GlassTableHeader, GlassTableHead, GlassTableRow, PageLayout
} from '@/components/layout';
import { WebhookTableRow } from '../components/WebhookTableRow';


interface Webhook {
    id: string;
    url: string;
    events: string[];
    active: boolean;
    created_at: string;
}

const Webhooks: React.FC = () => {
    const [webhooks, setWebhooks] = useState<Webhook[]>([]);
    const [newUrl, setNewUrl] = useState('');
    const [selectedEvents, setSelectedEvents] = useState<string[]>([]);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(true);
    const [creating, setCreating] = useState(false);

    const availableEvents = ['user.created', 'user.deleted', 'access.requested', 'access.approved'];

    const fetchData = async () => {
        try {
            const data = await getWebhooks();
            if (data && data.webhooks) {
                setWebhooks(data.webhooks);
            } else if (Array.isArray(data)) {
                setWebhooks(data);
            } else {
                setWebhooks([]);
            }
        } catch (err) {
            console.error("Failed to fetch webhooks", err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
    }, []);

    const handleCreate = async () => {
        if (!newUrl) {
            setError('URL is required');
            return;
        }
        if (selectedEvents.length === 0) {
            setError('Select at least one event');
            return;
        }
        setCreating(true);
        try {
            await createWebhook(newUrl, selectedEvents);
            setNewUrl('');
            setSelectedEvents([]);
            setError('');
            fetchData();
        } catch (err: any) {
            setError(err.response?.data?.error || 'Failed to create webhook');
        } finally {
            setCreating(false);
        }
    };

    const handleDelete = async (id: string) => {
        if (!window.confirm("Delete this webhook?")) return;
        try {
            await deleteWebhook(id);
            fetchData();
        } catch (err) {
            console.error(err);
        }
    };

    const toggleEvent = (e: string) => {
        if (selectedEvents.includes(e)) {
            setSelectedEvents(selectedEvents.filter(ev => ev !== e));
        } else {
            setSelectedEvents([...selectedEvents, e]);
        }
    };

    if (loading && webhooks.length === 0) return <div className="h-[400px] flex items-center justify-center"><Loader2 className="h-10 w-10 animate-spin text-primary opacity-20" /></div>;

    return (
        <PageLayout>
        <div className="space-y-12 animate-in fade-in duration-700">
            <PageHeader
                icon={<WebhookIcon className="w-10 h-10 text-primary" />}
                title="Event Tunnels"
                description="Synchronous and asynchronous outbound data pipelines. Orchestrating lifecycle notifications across the external digital architecture."
            />

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-start">
                <div className="lg:col-span-4 space-y-8">
                    <GlassCard className="border-none shadow-2xl shadow-on-surface/10 bg-card overflow-hidden rounded-[32px]">
                        <GlassCardHeader className="bg-surface-container/10 border-b border-on-surface/5 py-8 px-8">
                            <div className="flex items-center gap-4">
                                <div className="p-3 bg-primary rounded-xl text-primary-foreground shadow-lg shadow-primary/20">
                                    <Activity className="w-5 h-5" />
                                </div>
                                <GlassCardTitle className="text-xl font-bold tracking-tight text-on-surface">Provision tunnel</GlassCardTitle>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-8 space-y-8">
                            <div className="space-y-4">
                                <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Endpoint vector</Label>
                                <div className="relative">
                                    <div className="absolute left-4 top-1/2 -translate-y-1/2 text-on-surface-variant/40">
                                        <Globe className="h-5 w-5" />
                                    </div>
                                    <Input
                                        placeholder="https://api.external.service/hook"
                                        className="h-14 border-none rounded-2xl bg-surface-container/50 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-mono text-xs pl-12"
                                        value={newUrl}
                                        onChange={(e) => setNewUrl(e.target.value)}
                                    />
                                </div>
                            </div>

                            <div className="space-y-4">
                                <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Event subscription</Label>
                                <div className="grid grid-cols-1 gap-3 bg-surface-container/30 rounded-2xl p-6 ring-1 ring-on-surface/5">
                                    {availableEvents.map(ev => (
                                        <div key={ev} className="flex items-center space-x-4 group cursor-pointer select-none" onClick={() => toggleEvent(ev)}>
                                            <div
                                                className={`w-5 h-5 rounded-lg border-2 flex items-center justify-center transition-all ${selectedEvents.includes(ev) ? 'bg-primary border-primary' : 'border-on-surface/10 bg-card group-hover:border-primary/50'}`}
                                            >
                                                {selectedEvents.includes(ev) && <Check className="h-3 w-3 text-primary-foreground" />}
                                            </div>
                                            <span className={`text-[12px] font-bold tracking-tight transition-colors ${selectedEvents.includes(ev) ? 'text-on-surface' : 'text-on-surface-variant/40'}`}>{ev.replace('.', ' ')}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            {error && (
                                <div className="bg-destructive/10 text-destructive p-4 rounded-xl border border-destructive/20 font-bold text-[11px] tracking-tight animate-in slide-in-from-top-2">
                                    Vector crash: {error}
                                </div>
                            )}

                            <Button
                                onClick={handleCreate}
                                className="w-full h-14 rounded-2xl font-bold text-sm tracking-tight shadow-xl shadow-primary/20 transition-all"
                                disabled={creating}
                            >
                                {creating ? <Loader2 className="mr-3 h-5 w-5 animate-spin" /> : <Plus className="mr-3 h-5 w-5" />}
                                Establish linkage
                            </Button>
                        </GlassCardContent>
                    </GlassCard>

                    <div className="bg-surface-container/30 p-8 rounded-[32px] ring-1 ring-on-surface/5 flex items-start gap-6 relative overflow-hidden group">
                        <div className="absolute top-0 right-0 p-4 opacity-5 pointer-events-none transition-transform group-hover:scale-110">
                            <Binary className="w-20 h-20 -mr-4 -mt-4 text-primary" />
                        </div>
                        <div className="p-3 bg-card rounded-2xl shadow-sm ring-1 ring-on-surface/5">
                            <Lock className="w-6 h-6 text-primary" />
                        </div>
                        <div className="space-y-2">
                            <h4 className="text-[12px] font-bold tracking-tight text-on-surface">Security protocol</h4>
                            <p className="text-[11px] font-medium leading-relaxed text-on-surface-variant/60 tracking-tight">
                                All outbound vectors are cryptographically signed with HMAC-SHA256 for structural integrity.
                            </p>
                        </div>
                    </div>
                </div>

                <div className="lg:col-span-8 space-y-8">
                    <div className="flex items-center gap-6">
                        <h2 className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 italic flex-shrink-0 opacity-60">Infrastructure index</h2>
                        <div className="h-px flex-1 bg-on-surface/5" />
                    </div>

                    <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-card overflow-hidden rounded-[32px]">
                        <GlassCardHeader className="py-8 px-10 border-b border-on-surface/5">
                            <div className="flex items-center gap-5">
                                <div className="p-3.5 bg-primary/5 rounded-2xl">
                                    <ShieldCheck className="w-7 h-7 text-primary" />
                                </div>
                                <div>
                                    <GlassCardTitle className="text-2xl font-bold tracking-tight text-on-surface">Tunnel registry</GlassCardTitle>
                                    <p className="text-on-surface-variant/40 font-semibold text-[12px] mt-1 tracking-tight italic">Active orchestration pipelines ({webhooks.length})</p>
                                </div>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-0">
                            {webhooks.length === 0 ? (
                                <div className="py-32 text-center text-on-surface-variant/30 flex flex-col items-center gap-6 italic">
                                    <div className="w-20 h-20 rounded-3xl bg-surface-container/50 flex items-center justify-center">
                                        <WebhookIcon className="h-10 w-10 opacity-20" />
                                    </div>
                                    <span className="max-w-xs font-bold text-[11px] tracking-tight leading-relaxed opacity-60">System silence // Zero communication vectors established.</span>
                                </div>
                            ) : (
                                <div className="overflow-x-auto">
                                    <GlassTable>
                                        <GlassTableHeader>
                                            <GlassTableRow className="hover:bg-transparent border-b border-on-surface/5">
                                                <GlassTableHead className="py-6 pl-10">Endpoint identity</GlassTableHead>
                                                <GlassTableHead>Subscription</GlassTableHead>
                                                <GlassTableHead>Status</GlassTableHead>
                                                <GlassTableHead className="text-right pr-10">Actions</GlassTableHead>
                                            </GlassTableRow>
                                        </GlassTableHeader>
                                        <TableBody>
                                            {webhooks.map(wh => (
                                                <WebhookTableRow 
                                                    key={wh.id} 
                                                    webhook={wh} 
                                                    handleDelete={handleDelete} 
                                                />
                                            ))}
                                        </TableBody>
                                    </GlassTable>
                                </div>
                            )}
                        </GlassCardContent>
                    </GlassCard>
                </div>
            </div>
        </div>
        </PageLayout>
    );
};

export default Webhooks;
