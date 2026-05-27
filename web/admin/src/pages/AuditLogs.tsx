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
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassTable, GlassTableHeader, GlassTableHead, GlassTableRow, GlassCardDescription, PageLayout
} from '@/components/layout';
import { AuditEventRow } from '../components/AuditEventRow';

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
        <PageLayout>
        <div className="space-y-4 animate-in fade-in duration-700">
            <PageHeader
                icon={<FileText className="w-5 h-5 text-primary" />}
                title="Audit Logs"
                description="Track and review all activities across your system for security and compliance."
                actions={
                    <div className="flex bg-surface-container/50 p-1 rounded-lg ring-1 ring-on-surface/5">
                        <Button
                            variant="ghost"
                            size="sm"
                            onClick={loadStats}
                            className="rounded-md font-bold tracking-tight text-[10px] h-7 px-4 transition-all"
                        >
                            <RefreshCw className="mr-2 h-3.5 w-3.5" /> Refresh
                        </Button>
                        <Button
                            size="sm"
                            onClick={handleExport}
                            className="bg-primary text-primary-foreground rounded-md h-7 px-4 font-bold tracking-tight text-[10px] transition-all ml-1 shadow-md shadow-primary/10"
                        >
                            <Download className="mr-2 h-3.5 w-3.5" /> Export
                        </Button>
                    </div>
                }
            />

            <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
                <GlassCard className="flex-1 shadow-on-surface/5">
                    <GlassCardContent className="p-4">
                        <div className="flex flex-col gap-1">
                            <span className="text-[9px] font-bold tracking-tight text-on-surface-variant/40 leading-none uppercase">Total Events (14d)</span>
                            <div className="mt-1 flex items-end gap-2 leading-none">
                                <span className="text-2xl font-bold tracking-tight text-on-surface">{statsLoading ? '---' : stats?.total_events.toLocaleString()}</span>
                                <Database className="h-4 w-4 text-on-surface/10 mb-1" />
                            </div>
                        </div>
                    </GlassCardContent>
                </GlassCard>

                <GlassCard className="flex-1 shadow-destructive/5 bg-destructive/10 ring-destructive/10">
                    <GlassCardContent className="p-4">
                        <div className="flex flex-col gap-1">
                            <span className="text-[9px] font-bold tracking-tight text-destructive/40 leading-none uppercase">Failures</span>
                            <div className="mt-1 flex items-end gap-2 leading-none">
                                <span className="text-2xl font-bold tracking-tight text-destructive">{statsLoading ? '--' : stats?.failure_count}</span>
                                <ShieldAlert className="h-5 w-5 text-destructive/20 mb-1" />
                            </div>
                        </div>
                    </GlassCardContent>
                </GlassCard>

                <GlassCard className="lg:col-span-2 shadow-on-surface/5 bg-surface-container/10">
                    <GlassCardContent className="h-full flex items-center px-4 py-2">
                        <div className="flex-1 pr-4 border-r border-on-surface/5">
                            <p className="text-[9px] font-medium text-on-surface-variant/60 leading-relaxed italic line-clamp-2">"Audit logs provide the necessary visibility to ensure system integrity across all operations."</p>
                        </div>
                        <div className="flex items-center gap-2 pl-4 opacity-10">
                            <Binary className="w-4 h-4" />
                            <span className="text-[7px] font-bold tracking-tight italic uppercase">Monitoring</span>
                        </div>
                    </GlassCardContent>
                </GlassCard>
            </div>

            {/* Visual Analytics */}
            <GlassCard className="shadow-on-surface/5">
                <GlassCardHeader className="py-3 px-5">
                    <div className="flex items-center gap-3">
                        <div className="p-1.5 bg-primary/5 rounded-lg">
                            <Activity className="w-4 h-4 text-primary" />
                        </div>
                        <div>
                            <GlassCardTitle className="text-base font-bold tracking-tight text-on-surface">Activity Stream</GlassCardTitle>
                            <p className="text-[9px] font-bold text-on-surface-variant/40 mt-0.5 tracking-tight uppercase">System activity logs</p>
                        </div>
                    </div>
                </GlassCardHeader>
                <GlassCardContent className="p-4">
                    <div className="h-[160px] w-full">
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
            <div className="space-y-3">
                <div className="flex items-center gap-4">
                    <h2 className="text-[10px] font-bold tracking-widest text-on-surface-variant/20 uppercase flex-shrink-0">Event Logs</h2>
                    <div className="h-px flex-1 bg-on-surface/5" />
                </div>

                <GlassCard className="shadow-2xl shadow-on-surface/5">
                    <GlassCardHeader className="py-2 px-4 border-b border-on-surface/5 bg-surface-container/5">
                        <form onSubmit={handleFilterSubmit} className="flex flex-col md:flex-row gap-3 w-full">
                            <div className="relative w-64 group">
                                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-on-surface-variant/40 group-focus-within:text-primary transition-colors" />
                                <Input
                                    placeholder="Search logs..."
                                    className="h-8 border-none rounded-lg bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-bold text-[10px] pl-9"
                                    value={filters.action}
                                    onChange={(e) => setFilters({ ...filters, action: e.target.value })}
                                />
                            </div>
                            <Button type="submit" className="h-8 rounded-lg px-6 font-bold text-[10px] tracking-tight shadow-md shadow-primary/10 transition-all">
                                <Filter className="mr-1.5 h-3.5 w-3.5" /> Filter
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
                                            <GlassTableHead className="py-2 pl-4 font-bold text-[8px] tracking-widest text-on-surface-variant/40 uppercase">Timestamp</GlassTableHead>
                                            <GlassTableHead className="font-bold text-[8px] tracking-widest text-on-surface-variant/40 uppercase">Action</GlassTableHead>
                                            <GlassTableHead className="font-bold text-[8px] tracking-widest text-on-surface-variant/40 uppercase">Resource</GlassTableHead>
                                            <GlassTableHead className="font-bold text-[8px] tracking-widest text-on-surface-variant/40 uppercase">Actor</GlassTableHead>
                                            <GlassTableHead className="font-bold text-[8px] tracking-widest text-on-surface-variant/40 uppercase">Result</GlassTableHead>
                                            <GlassTableHead className="w-[80px] text-right pr-4 font-bold text-[8px] tracking-widest text-on-surface-variant/40 uppercase">Details</GlassTableHead>
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
                                                <AuditEventRow 
                                                    key={event.id}
                                                    event={event}
                                                    expandedEventId={expandedEventId}
                                                    setExpandedEventId={setExpandedEventId}
                                                    formatDate={formatDate}
                                                />
                                            ))
                                        )}
                                    </TableBody>
                                </GlassTable>
                            </div>
                        )}
                    </GlassCardContent>
                    <div className="p-3 flex flex-col md:flex-row items-center justify-between bg-surface-container/5 border-t border-on-surface/5 gap-3">
                        <div className="text-[10px] font-bold tracking-widest text-on-surface-variant/20 order-2 md:order-1 uppercase">
                            Manifest block: <span className="text-on-surface/40">{filters.offset + 1} — {Math.min(filters.offset + filters.limit, total)}</span> // Total: <span className="text-on-surface/40">{total}</span>_entries
                        </div>
                        <div className="flex gap-2 order-1 md:order-2">
                            <Button
                                variant="outline"
                                className="h-8 rounded-lg px-6 font-bold tracking-tight text-[10px] transition-all bg-card shadow-sm ring-1 ring-on-surface/5 hover:bg-primary/5 hover:text-primary hover:ring-primary/20 disabled:opacity-30"
                                onClick={() => handlePageChange('prev')}
                                disabled={filters.offset === 0}
                            >
                                <ChevronLeft className="h-3.5 w-3.5 mr-1.5" /> Previous
                            </Button>
                            <Button
                                variant="outline"
                                className="h-8 rounded-lg px-6 font-bold tracking-tight text-[10px] transition-all bg-card shadow-sm ring-1 ring-on-surface/5 hover:bg-primary/5 hover:text-primary hover:ring-primary/20 disabled:opacity-30"
                                onClick={() => handlePageChange('next')}
                                disabled={filters.offset + filters.limit >= total}
                            >
                                Next <ChevronRight className="h-3.5 w-3.5 ml-1.5" />
                            </Button>
                        </div>
                    </div>
                </GlassCard>
            </div>
        </div>
        </PageLayout>
    );
}
