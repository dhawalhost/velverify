import React, { useState, useEffect } from 'react';
import { getDeveloperAnalytics } from '../api';
import { Activity, BarChart2, Clock, Terminal, AlertCircle, RefreshCw, Loader2, Zap } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Button } from '@/components/ui/button';
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent } from '@/components/layout';

interface AnalyticPoint {
    date: string;
    total_calls: number;
    avg_latency: number;
    errors: number;
}

export function DeveloperAnalytics() {
    const [analytics, setAnalytics] = useState<AnalyticPoint[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        fetchAnalytics();
    }, []);

    const fetchAnalytics = async () => {
        setLoading(true);
        setError(null);
        try {
            const data = await getDeveloperAnalytics();
            setAnalytics(data.analytics || []);
        } catch (err: any) {
            setError(err.response?.data?.error || 'Failed to load API analytics.');
        } finally {
            setLoading(false);
        }
    };

    const totalCalls = analytics.reduce((sum, p) => sum + p.total_calls, 0);
    const totalErrors = analytics.reduce((sum, p) => sum + p.errors, 0);
    const avgLatency = analytics.length
        ? (analytics.reduce((sum, p) => sum + p.avg_latency, 0) / analytics.length).toFixed(0)
        : 0;

    const formatDate = (dateStr: string) => {
        const d = new Date(dateStr);
        return `${d.getMonth() + 1}/${d.getDate()}`;
    };

    return (
        <div className="space-y-10 animate-in fade-in duration-700">
            <PageHeader
                icon={<BarChart2 className="w-10 h-10 text-primary" />}
                title="API Analytics"
                description="Monitor your API usage, latency, and error rates across the platform over the last 7 days."
                actions={
                    <Button
                        onClick={fetchAnalytics}
                        variant="outline"
                        className="h-11 rounded-xl font-bold text-[11px] px-6 border-none ring-1 ring-on-surface/10 hover:bg-surface-container transition-all"
                        disabled={loading}
                    >
                        {loading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <RefreshCw className="h-4 w-4 mr-2" />}
                        Refresh
                    </Button>
                }
            />

            {error && (
                <div className="bg-destructive/10 text-destructive p-5 rounded-2xl flex items-center gap-3 font-bold text-sm">
                    <AlertCircle className="h-5 w-5 shrink-0" />
                    {error}
                </div>
            )}

            {/* KPI Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-card rounded-[24px] overflow-hidden">
                    <GlassCardContent className="p-8 flex flex-col gap-3">
                        <div className="flex items-center gap-3">
                            <div className="p-2.5 bg-primary/10 rounded-xl">
                                <Activity className="h-5 w-5 text-primary" />
                            </div>
                            <span className="text-[12px] font-bold tracking-tight text-on-surface-variant/40">Total Calls (7d)</span>
                        </div>
                        <p className="text-5xl font-bold tracking-tight text-on-surface tabular-nums">{loading ? '—' : totalCalls.toLocaleString()}</p>
                    </GlassCardContent>
                </GlassCard>

                <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-card rounded-[24px] overflow-hidden">
                    <GlassCardContent className="p-8 flex flex-col gap-3">
                        <div className="flex items-center gap-3">
                            <div className="p-2.5 bg-primary/10 rounded-xl">
                                <Clock className="h-5 w-5 text-primary" />
                            </div>
                            <span className="text-[12px] font-bold tracking-tight text-on-surface-variant/40">Avg Latency</span>
                        </div>
                        <p className="text-5xl font-bold tracking-tight text-on-surface tabular-nums">
                            {loading ? '—' : <>{avgLatency}<span className="text-2xl ml-2 text-on-surface-variant/40">ms</span></>}
                        </p>
                    </GlassCardContent>
                </GlassCard>

                <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-card rounded-[24px] overflow-hidden">
                    <GlassCardContent className="p-8 flex flex-col gap-3">
                        <div className="flex items-center gap-3">
                            <div className="p-2.5 bg-destructive/10 rounded-xl">
                                <AlertCircle className="h-5 w-5 text-destructive" />
                            </div>
                            <span className="text-[12px] font-bold tracking-tight text-on-surface-variant/40">Total Errors (7d)</span>
                        </div>
                        <p className={`text-5xl font-bold tracking-tight tabular-nums ${totalErrors > 0 ? 'text-destructive' : 'text-on-surface'}`}>
                            {loading ? '—' : totalErrors.toLocaleString()}
                        </p>
                    </GlassCardContent>
                </GlassCard>
            </div>

            {/* Traffic Chart */}
            <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-card rounded-[32px] overflow-hidden">
                <GlassCardHeader className="py-8 px-10 border-b border-on-surface/5">
                    <div className="flex items-center gap-4">
                        <div className="p-3 bg-primary/10 rounded-xl">
                            <Zap className="w-5 h-5 text-primary" />
                        </div>
                        <GlassCardTitle className="text-xl font-bold tracking-tight text-on-surface">API Traffic</GlassCardTitle>
                    </div>
                </GlassCardHeader>
                <GlassCardContent className="p-10">
                    {loading ? (
                        <div className="h-[300px] flex items-center justify-center">
                            <Loader2 className="h-10 w-10 animate-spin text-primary opacity-20" />
                        </div>
                    ) : analytics.length === 0 ? (
                        <div className="h-[300px] flex flex-col items-center justify-center gap-4 opacity-20">
                            <BarChart2 className="h-16 w-16" />
                            <p className="text-sm font-bold tracking-tight text-center">No API traffic recorded yet.</p>
                        </div>
                    ) : (
                        <div className="h-[300px] w-full">
                            <ResponsiveContainer width="100%" height="100%">
                                <LineChart data={analytics}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" vertical={false} />
                                    <XAxis dataKey="date" tickFormatter={formatDate} stroke="#888888" fontSize={12} tickLine={false} axisLine={false} />
                                    <YAxis stroke="#888888" fontSize={12} tickLine={false} axisLine={false} tickFormatter={(v: any) => `${v}`} />
                                    <Tooltip
                                        contentStyle={{ backgroundColor: 'hsl(var(--card))', borderColor: 'hsl(var(--border))', borderRadius: '12px' }}
                                        itemStyle={{ color: 'hsl(var(--foreground))' }}
                                        labelStyle={{ color: 'hsl(var(--muted-foreground))' }}
                                        labelFormatter={(label: any) => `Date: ${formatDate(label)}`}
                                    />
                                    <Line type="monotone" dataKey="total_calls" name="Total Calls" stroke="hsl(var(--primary))" strokeWidth={2} dot={{ r: 4 }} activeDot={{ r: 6 }} />
                                    <Line type="monotone" dataKey="errors" name="Errors" stroke="#ef4444" strokeWidth={2} dot={{ r: 4 }} />
                                </LineChart>
                            </ResponsiveContainer>
                        </div>
                    )}
                </GlassCardContent>
            </GlassCard>

            {/* Guidance */}
            <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-primary/5 rounded-[24px] overflow-hidden">
                <GlassCardContent className="p-8 flex gap-6 items-start">
                    <div className="p-3 bg-primary/10 rounded-xl shrink-0">
                        <Terminal className="h-6 w-6 text-primary" />
                    </div>
                    <div>
                        <h4 className="font-bold text-base tracking-tight text-on-surface">Interactive API Logs</h4>
                        <p className="text-sm text-on-surface-variant/60 mt-1 leading-relaxed">
                            Looking for specific request payloads? Go to{' '}
                            <a href="/developer/apps" className="text-primary hover:underline font-bold">OAuth Apps</a>{' '}
                            or your API Keys to view detailed, interactive logs tied to each credential.
                        </p>
                    </div>
                </GlassCardContent>
            </GlassCard>
        </div>
    );
}

export default DeveloperAnalytics;
