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
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassTable, GlassTableHeader, GlassTableHead, GlassTableRow } from '@/components/layout';

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
        <div className="space-y-6 animate-in fade-in duration-700">
            <PageHeader
                icon={<WebhookIcon className="w-6 h-6 text-primary" />}
                title="Event Tunnels"
                description="Synchronous and asynchronous outbound data pipelines."
            />

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
                <div className="lg:col-span-4 space-y-4">
                    <GlassCard className="border-none shadow-2xl shadow-on-surface/10 bg-card overflow-hidden rounded-xl">
                        <GlassCardHeader className="bg-surface-container/10 border-b border-on-surface/5 py-3 px-4">
                            <div className="flex items-center gap-3">
                                <div className="p-2 bg-primary rounded-lg text-white shadow-lg shadow-primary/20">
                                    <Activity className="w-4 h-4" />
                                </div>
                                <GlassCardTitle className="text-base font-bold tracking-tight text-on-surface">Provision Tunnel</GlassCardTitle>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-4 space-y-4">
                            <div className="space-y-2">
                                <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1 uppercase">Endpoint vector</Label>
                                <div className="relative">
                                    <div className="absolute left-3.5 top-1/2 -translate-y-1/2 text-on-surface-variant/40">
                                        <Globe className="h-4 w-4" />
                                    </div>
                                    <Input
                                        placeholder="https://api.external.service/hook"
                                        className="h-9 border-none rounded-lg bg-surface-container/50 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-mono text-[10px] pl-9"
                                        value={newUrl}
                                        onChange={(e) => setNewUrl(e.target.value)}
                                    />
                                </div>
                            </div>

                            <div className="space-y-2">
                                <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1 uppercase">Subscription</Label>
                                <div className="grid grid-cols-1 gap-1.5 bg-surface-container/30 rounded-lg p-3 ring-1 ring-on-surface/5">
                                    {availableEvents.map(ev => (
                                        <div key={ev} className="flex items-center space-x-3 group cursor-pointer select-none" onClick={() => toggleEvent(ev)}>
                                            <div
                                                className={`w-4 h-4 rounded border flex items-center justify-center transition-all ${selectedEvents.includes(ev) ? 'bg-primary border-primary' : 'border-on-surface/10 bg-card group-hover:border-primary/50'}`}
                                            >
                                                {selectedEvents.includes(ev) && <Check className="h-2.5 w-2.5 text-white" />}
                                            </div>
                                            <span className={`text-[11px] font-bold tracking-tight transition-colors uppercase ${selectedEvents.includes(ev) ? 'text-on-surface' : 'text-on-surface-variant/40'}`}>{ev.replace('.', ' ')}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            {error && (
                                <div className="text-destructive text-[10px] font-bold uppercase tracking-tight bg-destructive/5 p-2 rounded-lg border border-destructive/10">
                                    {error}
                                </div>
                            )}

                            <Button
                                onClick={handleCreate}
                                className="w-full h-9 rounded-lg font-bold text-xs tracking-tight shadow-xl shadow-primary/20 transition-all"
                                disabled={creating}
                            >
                                {creating ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Plus className="mr-2 h-4 w-4" />}
                                Establish linkage
                            </Button>
                        </GlassCardContent>
                    </GlassCard>

                    <div className="bg-surface-container/30 p-4 rounded-xl ring-1 ring-on-surface/5 flex items-start gap-4 relative overflow-hidden group">
                        <div className="absolute top-0 right-0 p-2 opacity-5 pointer-events-none transition-transform group-hover:scale-110">
                            <Binary className="w-12 h-12 -mr-2 -mt-2 text-primary" />
                        </div>
                        <div className="p-2 bg-card rounded-lg shadow-sm ring-1 ring-on-surface/5">
                            <Lock className="w-4 h-4 text-primary" />
                        </div>
                        <div className="space-y-1">
                            <h4 className="text-[11px] font-bold tracking-tight text-on-surface uppercase">Security protocol</h4>
                            <p className="text-[10px] font-medium leading-relaxed text-on-surface-variant/60 tracking-tight">
                                HMAC-SHA256 signed.
                            </p>
                        </div>
                    </div>
                </div>
            </div>

            <div className="lg:col-span-8 space-y-4">
                <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-card overflow-hidden rounded-xl">
                    <GlassCardHeader className="py-4 px-6 border-b border-on-surface/5">
                        <div className="flex items-center gap-4">
                            <div className="p-2.5 bg-primary/5 rounded-xl">
                                <ShieldCheck className="w-5 h-5 text-primary" />
                            </div>
                            <div>
                                <GlassCardTitle className="text-base font-bold tracking-tight text-on-surface uppercase">Tunnel Registry</GlassCardTitle>
                                <p className="text-on-surface-variant/40 font-bold text-[10px] mt-0.5 tracking-tight uppercase">Active orchestration pipelines ({webhooks.length})</p>
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
                                            <GlassTableHead className="py-3 pl-5 text-[10px] uppercase">Identity</GlassTableHead>
                                            <GlassTableHead className="text-[10px] uppercase">Subscription</GlassTableHead>
                                            <GlassTableHead className="text-[10px] uppercase">Status</GlassTableHead>
                                            <GlassTableHead className="text-right pr-5 text-[10px] uppercase">Actions</GlassTableHead>
                                        </GlassTableRow>
                                    </GlassTableHeader>
                                    <TableBody>
                                        {webhooks.map(wh => (
                                            <GlassTableRow key={wh.id} className="hover:bg-surface-container/10 transition-all border-b border-on-surface/5 last:border-0 group">
                                                <TableCell className="py-2 pl-5">
                                                    <div className="flex items-center gap-3">
                                                        <div className="w-7 h-7 rounded-lg bg-surface-container/50 text-on-surface-variant/40 flex items-center justify-center transition-all group-hover:bg-primary group-hover:text-primary-foreground">
                                                            <ExternalLink className="h-3.5 w-3.5" />
                                                        </div>
                                                        <div className="flex flex-col">
                                                            <span className="text-xs font-bold tracking-tight text-on-surface group-hover:text-primary transition-colors truncate max-w-[180px]">{wh.url}</span>
                                                            <span className="text-[8px] font-bold font-mono tracking-tight text-on-surface-variant/20 uppercase">id // {wh.id?.substring(0, 8)}</span>
                                                        </div>
                                                    </div>
                                                </TableCell>
                                                <TableCell className="py-3">
                                                    <div className="flex flex-wrap gap-1.5">
                                                        {wh.events.map(ev => (
                                                            <Badge key={ev} className="bg-surface-container/50 text-on-surface-variant/60 border-none rounded-md font-bold text-[9px] tracking-tight px-2 py-0.5 group-hover:bg-primary/5 group-hover:text-primary transition-all uppercase">
                                                                {ev.split('.')[1]}
                                                            </Badge>
                                                        ))}
                                                    </div>
                                                </TableCell>
                                                <TableCell className="py-3">
                                                    <div className="flex items-center gap-2">
                                                        <div className={`h-1.5 w-1.5 rounded-full transition-all ${wh.active ? 'bg-success' : 'bg-on-surface/20'}`} />
                                                        <span className={`text-[10px] font-bold tracking-tight uppercase transition-all ${wh.active ? 'text-success' : 'text-on-surface-variant/40'}`}>
                                                            {wh.active ? 'Active' : 'Dormant'}
                                                        </span>
                                                    </div>
                                                </TableCell>
                                                <TableCell className="py-3 text-right pr-6">
                                                    <Button
                                                        variant="ghost"
                                                        size="icon"
                                                        className="h-8 w-8 rounded-lg text-on-surface-variant/40 hover:text-destructive hover:bg-destructive/10 transition-all"
                                                        onClick={() => handleDelete(wh.id)}
                                                    >
                                                        <Trash2 className="w-4 h-4" />
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
    );
};

export default Webhooks;
