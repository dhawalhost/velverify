import React, { useState, useEffect } from 'react';
import { getDeveloperAnalytics, getAppLogs, getAPIKeyLogs } from '../api';
import { Activity, BarChart2, Clock, Terminal, AlertCircle, RefreshCw } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

interface AnalyticPoint {
    date: string;
    total_calls: number;
    avg_latency: number;
    errors: number;
}

interface APILog {
    id: string;
    client_id: string;
    method: string;
    path: string;
    status_code: number;
    latency_ms: number;
    ip_address: string;
    request_payload: string;
    response_payload: string;
    created_at: string;
}

export function DeveloperAnalytics() {
    const [analytics, setAnalytics] = useState<AnalyticPoint[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    // Selected entry for viewing raw payloads
    const [selectedLog, setSelectedLog] = useState<APILog | null>(null);

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
            setError(err.response?.data?.error || 'Failed to load analytics platform');
        } finally {
            setLoading(false);
        }
    };

    const getStatusColor = (status: number) => {
        if (status >= 200 && status < 300) return 'text-green-500 bg-green-500/10 font-medium px-2 py-0.5 rounded';
        if (status >= 400 && status < 500) return 'text-yellow-500 bg-yellow-500/10 font-medium px-2 py-0.5 rounded';
        return 'text-red-500 bg-red-500/10 font-medium px-2 py-0.5 rounded';
    };

    const formatJSON = (payload: string) => {
        try {
            const parsed = JSON.parse(payload);
            return JSON.stringify(parsed, null, 2);
        } catch {
            return payload;
        }
    };

    if (loading) {
        return <div className="p-8 flex items-center justify-center"><RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" /></div>;
    }

    if (error) {
        return (
            <div className="p-8">
                <div className="bg-red-500/10 text-red-500 p-4 rounded flex items-center gap-2">
                    <AlertCircle className="h-5 w-5" />
                    {error}
                </div>
            </div>
        );
    }

    const totalCalls = analytics.reduce((sum, p) => sum + p.total_calls, 0);
    const totalErrors = analytics.reduce((sum, p) => sum + p.errors, 0);
    const avgLatency = analytics.length ? (analytics.reduce((sum, p) => sum + p.avg_latency, 0) / analytics.length).toFixed(0) : 0;

    // Formatting date helper
    const formatDate = (dateStr: string) => {
        const d = new Date(dateStr);
        return `${d.getMonth() + 1}/${d.getDate()}`;
    };

    return (
        <div className="space-y-6">
            <div className="flex justify-between items-center">
                <h1 className="text-2xl font-bold tracking-tight">API Analytics</h1>
                <button onClick={fetchAnalytics} className="flex items-center gap-2 px-3 py-1.5 text-sm rounded bg-accent hover:bg-accent/80 transition-colors">
                    <RefreshCw className="h-4 w-4" /> Refresh
                </button>
            </div>

            {/* KPI Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="bg-card border rounded-lg p-6">
                    <div className="flex items-center justify-between">
                        <h3 className="text-sm font-medium text-muted-foreground flex items-center gap-2"><Activity className="h-4 w-4 text-primary" /> Total Calls (7d)</h3>
                    </div>
                    <div className="mt-2 text-3xl font-bold">{totalCalls.toLocaleString()}</div>
                </div>

                <div className="bg-card border rounded-lg p-6">
                    <div className="flex items-center justify-between">
                        <h3 className="text-sm font-medium text-muted-foreground flex items-center gap-2"><Clock className="h-4 w-4 text-primary" /> Avg Latency</h3>
                    </div>
                    <div className="mt-2 text-3xl font-bold">{avgLatency} ms</div>
                </div>

                <div className="bg-card border rounded-lg p-6">
                    <div className="flex items-center justify-between">
                        <h3 className="text-sm font-medium text-muted-foreground flex items-center gap-2"><AlertCircle className="h-4 w-4 text-primary" /> Total Errors (7d)</h3>
                    </div>
                    <div className="mt-2 text-3xl font-bold">{totalErrors.toLocaleString()}</div>
                </div>
            </div>

            {/* Chart */}
            <div className="bg-card border rounded-lg p-6">
                <h3 className="text-sm font-medium text-muted-foreground flex items-center gap-2 mb-6"><BarChart2 className="h-4 w-4" /> API Traffic</h3>
                {analytics.length === 0 ? (
                    <div className="text-center py-10 text-muted-foreground">No traffic recorded yet. Make some API requests to see data here.</div>
                ) : (
                    <div className="h-[300px] w-full">
                        <ResponsiveContainer width="100%" height="100%">
                            <LineChart data={analytics}>
                                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" vertical={false} />
                                <XAxis dataKey="date" tickFormatter={formatDate} stroke="#888888" fontSize={12} tickLine={false} axisLine={false} />
                                <YAxis stroke="#888888" fontSize={12} tickLine={false} axisLine={false} tickFormatter={(value: any) => `${value}`} />
                                <Tooltip
                                    contentStyle={{ backgroundColor: 'hsl(var(--card))', borderColor: 'hsl(var(--border))', borderRadius: '8px' }}
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
            </div>

            {/* Guidance box on finding the interactive logs */}
            <div className="bg-primary/5 border border-primary/20 rounded-lg p-4 flex gap-4">
                <Terminal className="h-6 w-6 text-primary shrink-0" />
                <div>
                    <h4 className="font-medium">Interactive API Logs</h4>
                    <p className="text-sm text-muted-foreground mt-1">
                        Looking for specific request payloads? Navigate to <a href="/developer/apps" className="text-primary hover:underline">OAuth Apps</a> or your API Keys to view detailed, interactive logs specific to those credentials.
                    </p>
                </div>
            </div>

        </div>
    );
}

export default DeveloperAnalytics;
