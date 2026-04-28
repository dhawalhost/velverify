import React, { useState, useEffect } from 'react';
import { getSlackStatus, configureSlack, disconnectSlack, SlackIntegration as SlackIntegType } from '../api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { 
    Slack, 
    ShieldCheck, 
    ShieldAlert, 
    Loader2, 
    ExternalLink, 
    RefreshCcw, 
    Trash2,
    Lock,
    Webhook,
    Zap,
    Cpu,
    MessageSquare,
    Activity,
    Terminal,
    Link2,
    Binary,
    Monitor,
    Hash,
    Command,
    X,
    Layout
} from 'lucide-react';
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassCardFooter, GlassCardDescription } from '@/components/layout';
import { Alert, AlertDescription } from '@/components/ui/alert';

const SlackIntegration: React.FC = () => {
    const [status, setStatus] = useState<SlackIntegType | null>(null);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [success, setSuccess] = useState<string | null>(null);

    const [form, setForm] = useState({
        team_id: '',
        app_id: '',
        bot_token: '',
        signing_secret: '',
        webhook_url: '',
        enabled: true
    });

    const fetchStatus = async () => {
        setLoading(true);
        try {
            const data = await getSlackStatus();
            setStatus(data);
            if (data.status === 'ready') {
                setForm({
                    team_id: data.team_id || '',
                    app_id: data.app_id || '',
                    bot_token: '', 
                    signing_secret: '', 
                    webhook_url: data.webhook_url || '',
                    enabled: data.enabled
                });
            }
        } catch (err: any) {
            console.error('Failed to fetch Slack status', err);
            setError('Could not retrieve Slack integration status.');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchStatus();
    }, []);

    const handleSave = async (e: React.FormEvent) => {
        e.preventDefault();
        setSaving(true);
        setError(null);
        setSuccess(null);
        try {
            await configureSlack(form);
            setSuccess('Slack integration successfully configured.');
            fetchStatus();
        } catch (err: any) {
            setError(err.response?.data?.error || 'Failed to update Slack configuration.');
        } finally {
            setSaving(false);
        }
    };

    const handleDisconnect = async () => {
        if (!window.confirm('Are you sure you want to disconnect Slack? This will disable all ChatOps functionality.')) return;
        setLoading(true);
        try {
            await disconnectSlack();
            setSuccess('Slack workspace disconnected.');
            fetchStatus();
        } catch (err) {
            setError('Failed to disconnect Slack.');
        } finally {
            setLoading(false);
        }
    };

    if (loading && !status) return <div className="h-[400px] flex items-center justify-center"><Loader2 className="h-10 w-10 animate-spin text-primary opacity-20" /></div>;

    const isConfigured = status?.status === 'ready';

    return (
        <div className="max-w-6xl mx-auto space-y-12 animate-in fade-in slide-in-from-bottom-4 duration-700 py-12">
            <PageHeader
                icon={<Slack className="w-10 h-10 text-[#4A154B]" />}
                title="ChatOps Intelligence"
                description="Orchestrate organizational identity lifecycle through real-time enterprise messaging clusters."
                actions={
                    isConfigured && (
                        <Badge className="bg-success/10 text-success border-none rounded-xl font-bold text-[11px] tracking-tight px-6 py-2.5 flex items-center gap-3">
                            <ShieldCheck className="w-4 h-4" />
                            Core link active
                        </Badge>
                    )
                }
            />

             {(error || success) && (
                <div className="space-y-6">
                    {error && (
                        <Alert variant="destructive" className="rounded-2xl border-none bg-destructive/10 text-destructive">
                            <AlertDescription className="font-bold text-xs tracking-tight flex items-center gap-3">
                                <ShieldAlert className="w-4 h-4" />
                                Configuration alert: {error}
                            </AlertDescription>
                        </Alert>
                    )}
                    {success && (
                        <Alert className="rounded-2xl border-none bg-success-subtle text-success">
                            <AlertDescription className="font-bold text-xs tracking-tight flex items-center gap-3">
                                <ShieldCheck className="w-4 h-4" />
                                Event success: {success}
                            </AlertDescription>
                        </Alert>
                    )}
                </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-12">
                <div className="lg:col-span-4 space-y-10">
                    <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-card overflow-hidden rounded-[32px]">
                        <GlassCardHeader className="py-10 px-10 border-b border-on-surface/5 bg-surface-container/10">
                            <div className="flex items-center gap-6">
                                <div className="p-4 bg-primary/5 rounded-2xl text-primary">
                                    <Zap className="w-7 h-7" />
                                </div>
                                <div>
                                    <GlassCardTitle className="text-xl font-bold tracking-tight text-on-surface">Node cluster</GlassCardTitle>
                                    <p className="text-on-surface-variant/40 font-bold text-[12px] mt-1 tracking-tight italic">Live integration state</p>
                                </div>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-10 flex flex-col items-center text-center space-y-10">
                            {isConfigured ? (
                                <>
                                    <div className="relative group">
                                        <div className="w-28 h-28 rounded-[28px] bg-[#4A154B]/5 flex items-center justify-center transition-all group-hover:scale-105 duration-500">
                                            <Slack className="w-14 h-14 text-[#4A154B]" />
                                        </div>
                                        <div className="absolute -bottom-2 -right-2 w-10 h-10 bg-card border border-on-surface/5 rounded-2xl shadow-lg flex items-center justify-center">
                                            <Activity className="w-5 h-5 text-success animate-pulse" />
                                        </div>
                                    </div>
                                    <div className="space-y-3">
                                        <h3 className="font-bold text-xl tracking-tight text-on-surface">Synchronized</h3>
                                        <div className="flex flex-col gap-1.5 pt-2">
                                            <code className="text-[10px] font-bold text-on-surface-variant/20 tracking-tight italic">Team: {status?.team_id}</code>
                                            <code className="text-[10px] font-bold text-on-surface-variant/20 tracking-tight italic">App: {status?.app_id}</code>
                                        </div>
                                    </div>
                                    <div className="w-full space-y-4 pt-4">
                                        <Button 
                                            variant="outline" 
                                            className="w-full h-14 rounded-2xl border-none bg-surface-container/50 ring-1 ring-on-surface/5 font-bold tracking-tight text-sm transition-all hover:bg-surface-container shadow-sm" 
                                            onClick={fetchStatus}
                                        >
                                            <RefreshCcw className="w-4 h-4 mr-3" /> Audit integrity
                                        </Button>
                                        <Button 
                                            variant="ghost" 
                                            className="w-full h-12 text-destructive font-bold tracking-tight text-[11px] hover:bg-destructive/10 hover:text-destructive rounded-2xl transition-all" 
                                            onClick={handleDisconnect}
                                        >
                                            <Trash2 className="w-4 h-4 mr-2.5" /> Terminate link
                                        </Button>
                                    </div>
                                </>
                            ) : (
                                <>
                                    <div className="w-28 h-28 rounded-[28px] bg-surface-container/50 flex items-center justify-center opacity-20">
                                        <Slack className="w-14 h-14" />
                                    </div>
                                    <div className="space-y-6">
                                        <p className="text-[11px] font-bold tracking-tight opacity-40 leading-relaxed max-w-[200px]">
                                            Zero activity vectors detected in current manifest
                                        </p>
                                        <Button variant="outline" className="h-12 rounded-2xl border-none bg-surface-container ring-1 ring-on-surface/5 font-bold tracking-tight text-[11px] px-8" asChild>
                                            <a href="https://api.slack.com/apps" target="_blank" rel="noreferrer">
                                                <ExternalLink className="w-4 h-4 mr-3" /> API portal
                                            </a>
                                        </Button>
                                    </div>
                                </>
                            )}
                        </GlassCardContent>
                    </GlassCard>

                    <div className="bg-inverse text-on-inverse p-10 rounded-[40px] flex items-start gap-6 shadow-2xl shadow-on-surface/10 relative overflow-hidden group">
                        <div className="absolute top-0 right-0 p-6 opacity-5 pointer-events-none group-hover:scale-110 transition-transform">
                            <Binary className="w-24 h-24 -mr-4 -mt-4 text-primary" />
                        </div>
                        <Activity className="w-8 h-8 text-primary flex-shrink-0 opacity-80" />
                        <p className="text-[12px] font-bold leading-relaxed tracking-tight text-on-inverse/40">
                            Telemetry: Event propagation is handled via structural WebSocket clusters, ensuring latency-free identity auditing.
                        </p>
                    </div>
                </div>

                <div className="lg:col-span-8">
                    <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-card overflow-hidden rounded-[32px]">
                        <GlassCardHeader className="py-10 px-10 border-b border-on-surface/5 bg-surface-container/10">
                            <div className="flex items-center gap-6">
                                <div className="p-4 bg-primary/10 text-primary rounded-2xl">
                                    <Layout className="w-7 h-7" />
                                </div>
                                <div>
                                    <GlassCardTitle className="text-3xl font-bold tracking-tight text-on-surface">Configuration manifest</GlassCardTitle>
                                    <p className="text-on-surface-variant/40 font-bold text-[12px] mt-1 tracking-tight italic">Structural handshake parameters</p>
                                </div>
                            </div>
                        </GlassCardHeader>
                        <form onSubmit={handleSave}>
                            <GlassCardContent className="p-10 space-y-10">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-10">
                                    <div className="space-y-4">
                                        <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1 flex items-center gap-2">
                                            <Hash className="w-3.5 h-3.5" />
                                            Team identifier
                                        </Label>
                                        <Input 
                                            placeholder="e.g. T0123ABC"
                                            className="h-14 rounded-2xl border-none bg-surface-container/50 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-bold text-sm px-6 font-mono"
                                            value={form.team_id}
                                            onChange={e => setForm({...form, team_id: e.target.value})}
                                            required
                                        />
                                    </div>
                                    <div className="space-y-4">
                                        <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1 flex items-center gap-2">
                                            <Monitor className="w-3.5 h-3.5" />
                                            App identifier
                                        </Label>
                                        <Input 
                                            placeholder="e.g. A0123XYZ"
                                            className="h-14 rounded-2xl border-none bg-surface-container/50 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-bold text-sm px-6 font-mono"
                                            value={form.app_id}
                                            onChange={e => setForm({...form, app_id: e.target.value})}
                                            required
                                        />
                                    </div>
                                </div>

                                <div className="space-y-4">
                                    <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1 flex items-center gap-2">
                                        <Lock className="w-3.5 h-3.5" />
                                        Bot user token (OAuth)
                                    </Label>
                                    <Input 
                                        type="password"
                                        placeholder={isConfigured ? "• • • • • • • • • • • • • • • •" : "xoxb-xxxx-xxxx-xxxx"}
                                        className="h-14 rounded-2xl border-none bg-surface-container/50 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-bold text-sm px-6"
                                        value={form.bot_token}
                                        onChange={e => setForm({...form, bot_token: e.target.value})}
                                        required={!isConfigured}
                                    />
                                    <p className="text-[10px] font-bold tracking-tight text-on-surface-variant/20 ml-1 flex items-center gap-2 italic">
                                        AES-256 symmetric encryption applied // Redacted in interface
                                    </p>
                                </div>

                                <div className="space-y-4">
                                    <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1 flex items-center gap-2">
                                        <ShieldCheck className="w-3.5 h-3.5" />
                                        Signing cryptographic secret
                                    </Label>
                                    <Input 
                                        type="password"
                                        placeholder={isConfigured ? "• • • • • • • • • • • • • • • •" : "Raw hex secret from Slack portal"}
                                        className="h-14 rounded-2xl border-none bg-surface-container/50 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-bold text-sm px-6"
                                        value={form.signing_secret}
                                        onChange={e => setForm({...form, signing_secret: e.target.value})}
                                        required={!isConfigured}
                                    />
                                </div>

                                <div className="space-y-4">
                                    <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1 flex items-center gap-2">
                                        <Webhook className="w-3.5 h-3.5" />
                                        Inbound webhook endpoint
                                    </Label>
                                    <Input 
                                        placeholder="https://hooks.slack.com/services/..."
                                        className="h-14 rounded-2xl border-none bg-surface-container/50 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-bold text-sm px-6 font-mono"
                                        value={form.webhook_url}
                                        onChange={e => setForm({...form, webhook_url: e.target.value})}
                                    />
                                </div>
                            </GlassCardContent>
                            <GlassCardFooter className="py-10 px-10 border-t border-on-surface/5 bg-surface-container/5 flex flex-col md:flex-row items-center justify-between gap-6">
                                <div className="flex items-center gap-6">
                                    <div className={`w-3 h-3 rounded-full transition-all ${form.enabled ? 'bg-success shadow-[0_0_12px_rgba(16,185,129,0.5)]' : 'bg-on-surface/10'}`} />
                                    <div className="flex flex-col">
                                        <span className="text-[12px] font-bold tracking-tight text-on-surface italic">State: {form.enabled ? 'Active Enforcement' : 'Dormant'}</span>
                                        <span className="text-[10px] font-bold tracking-tight text-on-surface-variant/20 mt-0.5">Deterministic clusters synchronized</span>
                                    </div>
                                </div>
                                <Button type="submit" disabled={saving} className="h-16 rounded-[24px] font-bold tracking-tight text-sm px-12 shadow-2xl shadow-primary/30 transition-all hover:scale-[1.01] active:scale-[0.99] w-full md:w-auto">
                                    {saving ? <Loader2 className="w-5 h-5 animate-spin" /> : 'Commit orchestration'}
                                </Button>
                            </GlassCardFooter>
                        </form>
                    </GlassCard>
                </div>
            </div>

            <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-inverse text-on-inverse overflow-hidden rounded-[40px] p-12">
                <div className="flex flex-col lg:flex-row items-start gap-12">
                    <div className="p-5 bg-card/5 rounded-3xl backdrop-blur-xl border border-on-inverse/5">
                        <MessageSquare className="w-10 h-10 text-primary" />
                    </div>
                    <div className="space-y-10 flex-1">
                        <div className="space-y-4">
                            <h3 className="text-3xl font-bold tracking-tight">Manual routing matrix</h3>
                            <p className="text-[12px] tracking-tight font-bold opacity-40 leading-relaxed max-w-2xl italic">
                                Route organizational command clusters to this service's deterministic endpoint for verified execution.
                            </p>
                        </div>
                        
                        <div className="bg-card/5 p-8 rounded-3xl border border-on-inverse/5 backdrop-blur-md group transition-all hover:bg-card/[0.07] cursor-pointer">
                            <div className="flex items-center gap-6">
                                <div className="p-2 bg-primary/10 rounded-xl">
                                    <Terminal className="h-5 w-5 text-primary-foreground" />
                                </div>
                                <code className="font-mono text-base font-bold text-primary-foreground select-all">
                                    {window.location.origin}/integrations/slack/commands
                                </code>
                            </div>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-2">
                            {['/wardseal-whoami', '/wardseal-lock', '/wardseal-audit'].map(cmd => (
                                <div key={cmd} className="flex items-center gap-4 py-4 px-6 rounded-2xl bg-card/[0.03] border border-on-inverse/5 transition-all hover:bg-card/[0.08] hover:border-on-inverse/10 group cursor-default">
                                    <Command className="h-4 w-4 opacity-20 group-hover:opacity-100 group-hover:text-primary-foreground transition-all" />
                                    <span className="font-mono text-[11px] font-bold tracking-tight text-primary-foreground/40 group-hover:text-primary-foreground transition-all">{cmd}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </GlassCard>
        </div>
    );
};

export default SlackIntegration;
