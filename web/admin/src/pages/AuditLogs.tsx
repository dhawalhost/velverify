import { useState, useEffect } from 'react';
import { getAuditLogs, exportAuditLogs, getAuditStats } from '../api';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { 
    Loader2, 
    Download, 
    Search, 
    Filter, 
    ChevronLeft, 
    ChevronRight, 
    FileText,
    Activity,
    ShieldAlert,
    BarChart3
} from 'lucide-react';
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
            const data = await getAuditStats(14); // 14 day lookback
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
            month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
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
        <div className="space-y-8">
            <div className="flex justify-between items-center">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Audit & Observability</h1>
                    <p className="text-muted-foreground mt-1">Real-time intelligence and system forensics.</p>
                </div>
                <div className="flex gap-2">
                    <Button variant="outline" size="sm" onClick={loadStats}>
                        <Activity className="mr-2 h-4 w-4" /> Refresh Stats
                    </Button>
                    <Button variant="default" size="sm" onClick={handleExport}>
                        <Download className="mr-2 h-4 w-4" /> Export CSV
                    </Button>
                </div>
            </div>

            {/* Quick Stats Grid */}
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                <Card className="bg-primary/5 border-primary/20 shadow-none">
                    <CardHeader className="pb-2">
                        <CardDescription className="text-xs uppercase font-bold tracking-wider">Total Events (14d)</CardDescription>
                        <CardTitle className="text-2xl font-mono">{statsLoading ? '--' : stats?.total_events.toLocaleString()}</CardTitle>
                    </CardHeader>
                </Card>
                <Card className="bg-red-500/5 border-red-500/20 shadow-none">
                    <CardHeader className="pb-2">
                        <CardDescription className="text-xs uppercase font-bold tracking-wider text-red-600">Failures / Alerts</CardDescription>
                        <CardTitle className="text-2xl font-mono text-red-600">{statsLoading ? '--' : stats?.failure_count}</CardTitle>
                    </CardHeader>
                </Card>
                <Card className="lg:col-span-2 shadow-none border-dashed">
                     <div className="h-full flex items-center px-6">
                        <div className="flex-1">
                            <p className="text-xs text-muted-foreground italic">"Transparency is the foundation of zero trust architecture."</p>
                        </div>
                        <BarChart3 className="text-muted-foreground/20 w-12 h-12" />
                     </div>
                </Card>
            </div>

            {/* Visual Analytics */}
            <Card className="shadow-sm overflow-hidden border-none bg-muted/20">
                <CardHeader className="bg-background/40 backdrop-blur-sm border-b">
                    <CardTitle className="text-sm font-semibold flex items-center gap-2">
                        <Activity className="w-4 h-4 text-primary" />
                        Activity Projection (Daily Volume)
                    </CardTitle>
                </CardHeader>
                <CardContent className="p-6">
                    <div className="h-[200px] w-full mt-4">
                        {statsLoading ? (
                            <div className="h-full flex items-center justify-center text-muted-foreground text-sm italic">
                                Quantifying system state...
                            </div>
                        ) : (
                            <ResponsiveContainer width="100%" height="100%">
                                <AreaChart data={stats?.activity_trend || []}>
                                    <defs>
                                        <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                                            <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                                        </linearGradient>
                                    </defs>
                                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                                    <XAxis 
                                        dataKey="date" 
                                        axisLine={false} 
                                        tickLine={false} 
                                        tick={{fontSize: 10}} 
                                        dy={10}
                                        interval={2}
                                    />
                                    <YAxis axisLine={false} tickLine={false} tick={{fontSize: 10}} />
                                    <Tooltip 
                                        contentStyle={{ backgroundColor: '#fff', borderRadius: '8px', border: '1px solid #e2e8f0', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
                                    />
                                    <Area type="monotone" dataKey="count" stroke="#3b82f6" fillOpacity={1} fill="url(#colorCount)" strokeWidth={2} />
                                </AreaChart>
                            </ResponsiveContainer>
                        )}
                    </div>
                </CardContent>
            </Card>

            {/* Log Explorer */}
            <div className="space-y-4">
                 <div className="flex items-center gap-4">
                    <h2 className="text-lg font-semibold tracking-tight flex items-center gap-2">
                        <FileText className="w-4 h-4" />
                        Raw Event Stream
                    </h2>
                 </div>
                
                <Card className="shadow-none border-muted/60">
                    <CardHeader className="px-6 py-4 border-b bg-muted/10">
                        <form onSubmit={handleFilterSubmit} className="flex flex-col md:flex-row gap-4">
                            <div className="flex-1 max-w-sm relative">
                                <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                                <Input
                                    placeholder="Search events (e.g. login_success)..."
                                    className="pl-9 h-9"
                                    value={filters.action}
                                    onChange={(e) => setFilters({ ...filters, action: e.target.value })}
                                />
                            </div>
                            <Button type="submit" variant="secondary" size="sm">
                                <Filter className="mr-2 h-4 w-4" /> Apply Filters
                            </Button>
                        </form>
                    </CardHeader>
                    <CardContent className="p-0">
                        {loading ? (
                            <div className="p-12 flex justify-center"><Loader2 className="h-8 w-8 animate-spin text-muted-foreground" /></div>
                        ) : (
                            <Table>
                                <TableHeader className="bg-muted/30">
                                    <TableRow>
                                        <TableHead className="w-[180px]">Timestamp</TableHead>
                                        <TableHead>Event Action</TableHead>
                                        <TableHead>Resource</TableHead>
                                        <TableHead>Actor</TableHead>
                                        <TableHead>Result</TableHead>
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    {events.length === 0 ? (
                                        <TableRow>
                                            <TableCell colSpan={5} className="text-center text-muted-foreground h-32 italic">
                                                No logs captured for this period.
                                            </TableCell>
                                        </TableRow>
                                    ) : (
                                        events.map(event => (
                                            <TableRow key={event.id} className="hover:bg-muted/50 transition-colors cursor-default">
                                                <TableCell className="text-[10px] text-muted-foreground font-mono">
                                                    {formatDate(event.timestamp)}
                                                </TableCell>
                                                <TableCell className="font-medium text-sm">
                                                    {event.action.toUpperCase()}
                                                </TableCell>
                                                <TableCell>
                                                    <div className="flex flex-col">
                                                        <span className="text-[9px] uppercase text-muted-foreground font-bold leading-none mb-1">{event.resource_type}</span>
                                                        <span className="text-xs truncate max-w-[180px]" title={event.resource_name || event.resource_id}>
                                                            {event.resource_name || event.resource_id}
                                                        </span>
                                                    </div>
                                                </TableCell>
                                                <TableCell className="text-xs text-muted-foreground">
                                                    <Badge variant="secondary" className="font-mono text-[10px] py-0 px-1 border-none bg-muted-foreground/10">
                                                        {event.actor_id.substring(0, 8)}
                                                    </Badge>
                                                </TableCell>
                                                <TableCell>
                                                    <Badge 
                                                        variant={event.outcome === 'success' ? 'outline' : 'destructive'}
                                                        className={`text-[10px] h-5 ${event.outcome === 'success' ? 'border-green-500/50 text-green-600 bg-green-500/5' : ''}`}
                                                    >
                                                        {event.outcome.toUpperCase()}
                                                    </Badge>
                                                </TableCell>
                                            </TableRow>
                                        ))
                                    )}
                                </TableBody>
                            </Table>
                        )}
                    </CardContent>
                    <div className="p-4 flex items-center justify-between bg-muted/5 border-t">
                        <div className="text-[11px] text-muted-foreground">
                            Viewing {filters.offset + 1}—{Math.min(filters.offset + filters.limit, total)} of {total} events
                        </div>
                        <div className="flex gap-2">
                            <Button
                                variant="outline"
                                size="sm"
                                className="h-7 text-xs"
                                onClick={() => handlePageChange('prev')}
                                disabled={filters.offset === 0}
                            >
                                <ChevronLeft className="h-3 w-3 mr-1" /> Prev
                            </Button>
                            <Button
                                variant="outline"
                                size="sm"
                                className="h-7 text-xs"
                                onClick={() => handlePageChange('next')}
                                disabled={filters.offset + filters.limit >= total}
                            >
                                Next <ChevronRight className="h-3 w-3 ml-1" />
                            </Button>
                        </div>
                    </div>
                </Card>
            </div>
        </div>
    );
}
