import React, { useState, useEffect } from 'react';
import { getAuditLogs, exportAuditLogs, getAuditStats } from '../api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { TableBody, TableCell } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import {
    Loader2,
    Download,
    Search,
    Filter,
    ChevronLeft,
    ChevronRight,
    Activity,
    ShieldAlert,
    BarChart3,
    Eye,
    ChevronDown,
    ChevronUp,
    Terminal,
    RefreshCw,
    Database,
    Binary,
    FileText
} from 'lucide-react';
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassTable, GlassTableHeader, GlassTableHead, GlassTableRow, GlassCardDescription } from '@/components/layout';
import {
    LineChart,
    Line,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
    AreaChart,
    Area
} from 'recharts';
import { chartTooltipStyle, chartGridStyle, chartAxisTickStyle } from '@/components/theme';

interface AuditEvent {
    id: string;
    timestamp: string;
    actor_id: string;
    actor_type: string;
    action: string;
    resource_type: string;
    resource_id: string;
    resource_name: string;
    outcome: string;
    details: Record<string, unknown>;
}

interface AuditStats {
    total_events: number;
    failure_count: number;
    activity_trend: { date: string; count: number }[];
    action_distribution: Record<string, number>;
    resource_distribution: Record<string, number>;
}

export default function AuditLogs() {
    const [events, setEvents] = useState<AuditEvent[]>([]);
    const [stats, setStats] = useState<AuditStats | null>(null);
    const [total, setTotal] = useState(0);
    const [loading, setLoading] = useState(true);
    const [statsLoading, setStatsLoading] = useState(true);
    const [filters, setFilters] = useState({
        action: '',
        resource_type: '',
        limit: 25,
        offset: 0
    });
    const [expandedEventId, setExpandedEventId] = useState<string | null>(null);

    useEffect(() => {
        loadLogs();
        loadStats();
    }, [filters.limit, filters.offset]);

    const loadLogs = async () => {
        setLoading(true);
        try {
            const params: Record<string, unknown> = { limit: filters.limit, offset: filters.offset };
            if (filters.action) params.action = filters.action;
            if (filters.resource_type) params.resource_type = filters.resource_type;

            const res = await getAuditLogs(params);
            setEvents(res.events || []);
            setTotal(res.total || 0);
        } catch (error) {
            console.error('Failed to load audit logs:', error);
        } finally {
            setLoading(false);
        }
    };

    const loadStats = async () => {
        setStatsLoading(true);
        try {
            const data = await getAuditStats(14);
            setStats(data);
        } catch (error) {
            console.error('Failed to load audit stats:', error);
        } finally {
            setStatsLoading(false);
        }
    };

    const handleFilterSubmit = (e?: React.FormEvent) => {
        if (e) e.preventDefault();
        setFilters(f => ({ ...f, offset: 0 }));
        loadLogs();
    };

    const formatDate = (dateStr: string) => {
        return new Date(dateStr).toLocaleString(undefined, {
            month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit'
        });
    };

    const handlePageChange = (direction: 'prev' | 'next') => {
        if (direction === 'prev' && filters.offset > 0) {
            setFilters({ ...filters, offset: filters.offset - filters.limit });
        } else if (direction === 'next' && filters.offset + filters.limit < total) {
            setFilters({ ...filters, offset: filters.offset + filters.limit });
        }
    };

    const handleExport = async () => {
        try {
            const params: Record<string, unknown> = {};
            if (filters.action) params.action = filters.action;
            if (filters.resource_type) params.resource_type = filters.resource_type;

            const blob = await exportAuditLogs(params);
            const url = window.URL.createObjectURL(new Blob([blob]));
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', `audit_logs_${new Date().toISOString().split('T')[0]}.csv`);
            document.body.appendChild(link);
            link.click();
            link.parentNode?.removeChild(link);
        } catch (error) {
            console.error('Failed to export logs:', error);
        }
    };

    return (
        <div className="space-y-12 animate-in fade-in duration-700">
            <PageHeader
                icon={<FileText className="w-10 h-10 text-primary" />}
                title="Audit Logs"
                description="Track and review all activities across your system for security and compliance. Maintain a complete record of system events."
                actions={
                    <div className="flex bg-surface-container/50 p-1 rounded-2xl ring-1 ring-on-surface/5">
                        <Button
                            variant="ghost"
                            size="sm"
                            onClick={loadStats}
                            className="rounded-xl font-bold tracking-tight text-[11px] h-10 px-6 transition-all"
                        >
                            <RefreshCw className="mr-3 h-4 w-4" /> Refresh
                        </Button>
                        <Button
                            size="sm"
                            onClick={handleExport}
                            className="bg-primary text-primary-foreground rounded-xl h-10 px-6 font-bold tracking-tight text-[11px] transition-all ml-1 shadow-md shadow-primary/10"
                        >
                            <Download className="mr-3 h-4 w-4" /> Export
                        </Button>
                    </div>
                }
            />

            <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
                <GlassCard className="flex-1 shadow-on-surface/5">
                    <GlassCardContent className="p-8">
                        <div className="flex flex-col gap-2">
                            <span className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 leading-none">Total Events (14d)</span>
                            <div className="mt-4 flex items-end gap-3 leading-none">
                                <span className="text-4xl font-bold tracking-tight text-on-surface">{statsLoading ? '---' : stats?.total_events.toLocaleString()}</span>
                                <Database className="h-5 w-5 text-on-surface/10 mb-1" />
                            </div>
                        </div>
                    </GlassCardContent>
                </GlassCard>

                <GlassCard className="flex-1 shadow-destructive/5 bg-destructive/10 ring-destructive/10">
                    <GlassCardContent className="p-8">
                        <div className="flex flex-col gap-2">
                            <span className="text-[12px] font-bold tracking-tight text-destructive/40 leading-none">Failures</span>
                            <div className="mt-4 flex items-end gap-4 leading-none">
                                <span className="text-4xl font-bold tracking-tight text-destructive">{statsLoading ? '--' : stats?.failure_count}</span>
                                <ShieldAlert className="h-8 w-8 text-destructive/20 mb-1" />
                            </div>
                        </div>
                    </GlassCardContent>
                </GlassCard>

                <GlassCard className="lg:col-span-2 shadow-on-surface/5 bg-surface-container/10">
                    <GlassCardContent className="h-full flex items-center px-10">
                        <div className="flex-1 pr-12 border-r border-on-surface/5">
                            <p className="text-[11px] font-medium text-on-surface-variant/60 leading-relaxed italic">"Audit logs provide the necessary visibility to ensure system integrity and security compliance across all operations."</p>
                        </div>
                        <div className="flex flex-col items-center gap-4 pl-10 opacity-10">
                            <Binary className="w-10 h-10" />
                            <span className="text-[10px] font-bold tracking-tight italic">Monitoring</span>
                        </div>
                    </GlassCardContent>
                </GlassCard>
            </div>

            {/* Visual Analytics */}
            <GlassCard className="shadow-on-surface/5">
                <GlassCardHeader className="py-8 px-10">
                    <div className="flex items-center gap-5">
                        <div className="p-3 bg-primary/5 rounded-xl">
                            <Activity className="w-6 h-6 text-primary" />
                        </div>
                        <div>
                            <GlassCardTitle className="text-xl font-bold tracking-tight text-on-surface">Activity Stream</GlassCardTitle>
                            <p className="text-[11px] font-medium text-on-surface-variant/40 mt-1 tracking-tight">System activity logs</p>
                        </div>
                    </div>
                </GlassCardHeader>
                <GlassCardContent className="p-10">
                    <div className="h-[300px] w-full">
                        {statsLoading ? (
                            <div className="h-full flex flex-col items-center justify-center gap-6">
                                <Loader2 className="h-10 w-10 animate-spin text-primary opacity-20" />
                                <span className="text-[12px] font-bold tracking-tight opacity-20 italic">Loading data...</span>
                            </div>
                        ) : (
                            <ResponsiveContainer width="100%" height="100%">
                                <AreaChart data={stats?.activity_trend || []} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                                    <defs>
                                        <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="hsl(var(--primary))" stopOpacity={0.1} />
                                            <stop offset="95%" stopColor="hsl(var(--primary))" stopOpacity={0} />
                                        </linearGradient>
                                    </defs>
                                    <CartesianGrid {...chartGridStyle} />
                                    <XAxis
                                        dataKey="date"
                                        axisLine={false}
                                        tickLine={false}
                                        tick={chartAxisTickStyle}
                                        dy={15}
                                        interval={1}
                                    />
                                    <YAxis
                                        axisLine={false}
                                        tickLine={false}
                                        tick={chartAxisTickStyle}
                                    />
                                    <Tooltip
                                        {...chartTooltipStyle}
                                    />
                                    <Area
                                        type="monotone"
                                        dataKey="count"
                                        stroke="hsl(var(--primary))"
                                        fillOpacity={1}
                                        fill="url(#colorCount)"
                                        strokeWidth={3}
                                    />
                                </AreaChart>
                            </ResponsiveContainer>
                        )}
                    </div>
                </GlassCardContent>
            </GlassCard>

            {/* Log Explorer */}
            <div className="space-y-8">
                <div className="flex items-center gap-6">
                    <h2 className="text-[12px] font-bold tracking-tight text-on-surface-variant/20 italic flex-shrink-0">Event Logs</h2>
                    <div className="h-px flex-1 bg-on-surface/5" />
                </div>

                <GlassCard className="shadow-2xl shadow-on-surface/5">
                    <GlassCardHeader className="py-8 px-10 border-b border-on-surface/5 bg-surface-container/10">
                        <form onSubmit={handleFilterSubmit} className="flex flex-col md:flex-row gap-6 w-full">
                            <div className="relative w-80 group">
                                <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-on-surface-variant/40 group-focus-within:text-primary transition-colors" />
                                <Input
                                    placeholder="Search logs..."
                                    className="h-10 border-none rounded-xl bg-surface-container/50 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium text-[11px] pl-10"
                                    value={filters.action}
                                    onChange={(e) => setFilters({ ...filters, action: e.target.value })}
                                />
                            </div>
                            <Button type="submit" className="h-12 rounded-2xl px-10 font-bold text-[12px] tracking-tight shadow-md shadow-primary/10 transition-all">
                                <Filter className="mr-2 h-4 w-4" /> Filter
                            </Button>
                        </form>
                    </GlassCardHeader>
                    <GlassCardContent className="p-0">
                        {loading ? (
                            <div className="py-32 flex flex-col items-center justify-center gap-8">
                                <Loader2 className="h-12 w-12 animate-spin text-primary opacity-20" />
                                <span className="text-[13px] font-bold tracking-tight text-on-surface-variant/20 italic">Loading logs...</span>
                            </div>
                        ) : (
                            <div className="overflow-x-auto">
                                <GlassTable>
                                    <GlassTableHeader>
                                        <GlassTableRow className="hover:bg-transparent border-b border-on-surface/5">
                                            <GlassTableHead className="py-6 pl-10 font-bold text-[12px] tracking-tight text-on-surface-variant/40">Timestamp</GlassTableHead>
                                            <GlassTableHead className="font-bold text-[12px] tracking-tight text-on-surface-variant/40">Action</GlassTableHead>
                                            <GlassTableHead className="font-bold text-[12px] tracking-tight text-on-surface-variant/40">Resource</GlassTableHead>
                                            <GlassTableHead className="font-bold text-[12px] tracking-tight text-on-surface-variant/40">Actor</GlassTableHead>
                                            <GlassTableHead className="font-bold text-[12px] tracking-tight text-on-surface-variant/40">Result</GlassTableHead>
                                            <GlassTableHead className="w-[100px] text-right pr-10 font-bold text-[12px] tracking-tight text-on-surface-variant/40">Details</GlassTableHead>
                                        </GlassTableRow>
                                    </GlassTableHeader>
                                    <TableBody>
                                        {events.length === 0 ? (
                                            <GlassTableRow>
                                                <TableCell colSpan={6} className="py-32 text-center text-sm font-medium text-on-surface-variant/30 italic">
                                                    No activities found.
                                                </TableCell>
                                            </GlassTableRow>
                                        ) : (
                                            events.map(event => (
                                                <React.Fragment key={event.id}>
                                                    <GlassTableRow className={`hover:bg-surface-container/20 transition-all border-b border-on-surface/5 last:border-0 group ${expandedEventId === event.id ? 'bg-primary/5' : ''}`}>
                                                        <TableCell className="py-6 pl-10">
                                                            <div className="flex items-center gap-4">
                                                                <div className={`h-1.5 w-1.5 rounded-full transition-all ${event.outcome === 'success' ? 'bg-success' : 'bg-destructive/100'}`} />
                                                                <span className="text-[11px] font-bold text-on-surface-variant/40 group-hover:text-on-surface transition-colors">
                                                                    {formatDate(event.timestamp)}
                                                                </span>
                                                            </div>
                                                        </TableCell>
                                                        <TableCell className="py-6 text-sm font-bold tracking-tight text-on-surface group-hover:text-primary transition-colors">
                                                            {event.action}
                                                        </TableCell>
                                                        <TableCell className="py-6 font-medium text-xs text-on-surface-variant">
                                                            <div className="flex flex-col">
                                                                <span className="text-[10px] font-bold tracking-tight text-primary mb-0.5 opacity-60 italic">{event.resource_type}</span>
                                                                <span className="truncate max-w-[200px]" title={event.resource_name || event.resource_id}>
                                                                    {event.resource_name || event.resource_id}
                                                                </span>
                                                            </div>
                                                        </TableCell>
                                                        <TableCell className="py-6">
                                                            <div className="flex items-center gap-2.5">
                                                                <div className="w-7 h-7 flex items-center justify-center bg-surface-container/50 rounded-lg text-on-surface-variant/40 group-hover:bg-primary group-hover:text-primary-foreground transition-all">
                                                                    <Terminal className="h-3.5 w-3.5" />
                                                                </div>
                                                                <code className="text-[11px] font-bold text-on-surface-variant/40 tracking-tight">
                                                                    {event.actor_id ? event.actor_id.substring(0, 12) : "system"}
                                                                </code>
                                                            </div>
                                                        </TableCell>
                                                        <TableCell className="py-6">
                                                            <Badge
                                                                className={`rounded-lg font-bold text-[10px] tracking-tight px-3 py-1 shadow-none border-none ${event.outcome === 'success' ? 'bg-success-subtle text-success' : 'bg-destructive/10 text-destructive'}`}
                                                            >
                                                                {event.outcome === 'success' ? 'success' : 'failure'}
                                                            </Badge>
                                                        </TableCell>
                                                        <TableCell className="py-6 text-right pr-6">
                                                            <Button
                                                                variant="ghost"
                                                                size="icon"
                                                                className={`h-9 w-9 rounded-xl transition-all ${expandedEventId === event.id ? 'bg-primary text-primary-foreground' : 'hover:bg-surface-container'}`}
                                                                onClick={() => setExpandedEventId(expandedEventId === event.id ? null : event.id)}
                                                            >
                                                                {expandedEventId === event.id ? <ChevronUp className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                                                            </Button>
                                                        </TableCell>
                                                    </GlassTableRow>
                                                    {expandedEventId === event.id && (
                                                        <GlassTableRow className="bg-surface-container/30 border-none select-text">
                                                            <TableCell colSpan={6} className="p-0">
                                                                <div className="p-10 space-y-10 animate-in slide-in-from-top-4 duration-500">
                                                                    <div className="flex items-center justify-between border-b border-on-surface/5 pb-6">
                                                                        <div className="space-y-1.5">
                                                                            <h4 className="text-[13px] font-bold tracking-tight text-primary flex items-center gap-3">
                                                                                <Binary className="w-4.5 h-4.5" />
                                                                                Event Details
                                                                            </h4>
                                                                            <p className="text-on-surface-variant/20 font-bold tracking-tight text-[10px] italic">Captured at {new Date(event.timestamp).toISOString()}</p>
                                                                        </div>
                                                                        <div className="bg-card p-2 px-4 rounded-xl ring-1 ring-on-surface/5 text-[10px] font-bold text-on-surface-variant/40 tracking-tight shadow-sm italic">
                                                                            ID: {event.id.substring(0, 8)}
                                                                        </div>
                                                                    </div>

                                                                    <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                                                                        <div className="md:col-span-2">
                                                                            <div className="bg-card rounded-3xl ring-1 ring-on-surface/5 p-8 relative overflow-hidden shadow-xl shadow-on-surface/5 group/payload">
                                                                                <div className="relative z-10 space-y-6">
                                                                                    <span className="text-[10px] font-bold tracking-tight text-primary/20 italic">// Raw Data</span>
                                                                                    <pre className="text-on-surface font-mono text-[11px] leading-relaxed overflow-auto max-h-[400px] custom-scrollbar p-6 bg-surface-container/30 rounded-2xl ring-1 ring-on-surface/5">
                                                                                        {JSON.stringify(event.details, null, 4)}
                                                                                    </pre>
                                                                                </div>
                                                                            </div>
                                                                        </div>
                                                                        <div className="space-y-6">
                                                                            <div className="bg-card rounded-2xl ring-1 ring-on-surface/5 p-6 space-y-4 shadow-lg shadow-on-surface/5">
                                                                                <span className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 italic">Actor</span>
                                                                                <div className="flex flex-col gap-3">
                                                                                    <div className="flex items-center gap-3">
                                                                                        <div className="w-8 h-8 rounded-xl bg-primary/5 text-primary flex items-center justify-center font-bold text-xs">@</div>
                                                                                        <span className="text-sm font-bold text-on-surface truncate">{event.actor_id || 'System'}</span>
                                                                                    </div>
                                                                                </div>
                                                                            </div>
                                                                            <div className="bg-card rounded-2xl ring-1 ring-on-surface/5 p-6 space-y-4 shadow-lg shadow-on-surface/5">
                                                                                <span className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 italic">Resource</span>
                                                                                <div className="flex flex-col gap-3">
                                                                                    <div className="flex items-center gap-3">
                                                                                        <div className="w-8 h-8 rounded-xl bg-primary/5 text-primary flex items-center justify-center font-bold text-xs">#</div>
                                                                                        <span className="text-sm font-bold text-on-surface truncate">{event.resource_id}</span>
                                                                                    </div>
                                                                                </div>
                                                                            </div>
                                                                            <Button
                                                                                variant="ghost"
                                                                                className="w-full rounded-2xl ring-1 ring-on-surface/5 hover:bg-card hover:text-primary font-bold tracking-tight text-[11px] h-12 transition-all shadow-sm"
                                                                                onClick={() => setExpandedEventId(null)}
                                                                            >
                                                                                Minimize artifact
                                                                            </Button>
                                                                        </div>
                                                                    </div>
                                                                </div>
                                                            </TableCell>
                                                        </GlassTableRow>
                                                    )}
                                                </React.Fragment>
                                            ))
                                        )}
                                    </TableBody>
                                </GlassTable>
                            </div>
                        )}
                    </GlassCardContent>
                    <div className="p-8 flex flex-col md:flex-row items-center justify-between bg-surface-container/10 border-t border-on-surface/5 gap-8">
                        <div className="text-[12px] font-bold tracking-tight text-on-surface-variant/20 order-2 md:order-1 italic">
                            Manifest block: <span className="text-on-surface/40">{filters.offset + 1} — {Math.min(filters.offset + filters.limit, total)}</span> // Total: <span className="text-on-surface/40">{total}</span>_entries
                        </div>
                        <div className="flex gap-3 order-1 md:order-2">
                            <Button
                                variant="outline"
                                className="h-11 rounded-xl px-8 font-bold tracking-tight text-[11px] transition-all bg-card shadow-sm ring-1 ring-on-surface/5 hover:bg-primary/5 hover:text-primary hover:ring-primary/20 disabled:opacity-30"
                                onClick={() => handlePageChange('prev')}
                                disabled={filters.offset === 0}
                            >
                                <ChevronLeft className="h-4 w-4 mr-2" /> Previous
                            </Button>
                            <Button
                                variant="outline"
                                className="h-11 rounded-xl px-8 font-bold tracking-tight text-[11px] transition-all bg-card shadow-sm ring-1 ring-on-surface/5 hover:bg-primary/5 hover:text-primary hover:ring-primary/20 disabled:opacity-30"
                                onClick={() => handlePageChange('next')}
                                disabled={filters.offset + filters.limit >= total}
                            >
                                Next <ChevronRight className="h-4 w-4 ml-2" />
                            </Button>
                        </div>
                    </div>
                </GlassCard>
            </div>
        </div>
    );
}
