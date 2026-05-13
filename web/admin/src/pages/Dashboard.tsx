import React, { useEffect, useState } from 'react';
import { getSCIMUsers } from '../api';
import { useNavigate } from 'react-router-dom';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '@/components/ui/card';
import { TableBody, TableCell } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import {
    Users,
    ShieldCheck,
    Activity,
    UserPlus,
    MoreHorizontal,
    Database,
    Clock,
    Globe,
    AlertTriangle
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { getGovernanceStats, DashboardStats } from '../api';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend, BarChart, Bar, XAxis, YAxis } from 'recharts';
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassTable, GlassTableHeader, GlassTableHead, GlassTableRow } from '@/components/layout';
import { cn } from '@/lib/utils';
import { colors, chartTooltipStyle } from '@/components/theme';
// import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';

const Dashboard: React.FC = () => {
    const [users, setUsers] = useState<any[]>([]);
    const [stats, setStats] = useState<DashboardStats | null>(null);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(true);
    const navigate = useNavigate();

    const fetchData = async () => {
        try {
            const [usersData, statsData] = await Promise.all([
                getSCIMUsers(),
                getGovernanceStats()
            ]);
            setUsers(usersData.Resources || []);
            setStats(statsData);
            setError('');
        } catch (err: any) {
            console.error(err);
            setError('Failed to refresh dashboard data');
            if (err.response?.status === 401) {
                navigate('/login');
            }
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, 30000); // 30s Polling
        return () => clearInterval(interval);
    }, [navigate]);

    // Risk levels for chart
    const riskData = stats?.risk_profile ? Object.entries(stats.risk_profile).map(([name, value]) => ({
        name: name.toUpperCase(),
        value
    })) : [];

    const COLORS = colors.chart;

    return (
        <div className="space-y-4 animate-in fade-in duration-700">
            <PageHeader
                icon={
                    <div className="p-1.5 bg-primary/5 rounded-lg">
                        <img src="/wardseal.svg" alt="WardSeal" className="w-5 h-5" />
                    </div>
                }
                title="Dashboard"
                description="Overview of your identity infrastructure — users, access requests, policies, and security posture."
                actions={
                    <Button
                        onClick={() => navigate('/users/new')}
                        className="h-8 rounded-lg bg-primary text-primary-foreground font-bold text-[10px] tracking-tight px-4 shadow-xl shadow-primary/20 transition-all hover:scale-[1.02] active:scale-[0.98]"
                    >
                        <UserPlus className="mr-1.5 h-3.5 w-3.5" /> Add user
                    </Button>
                }
            />

            {error && (
                <div className="bg-destructive/5 text-destructive px-5 py-3 rounded-xl border border-destructive/10 text-xs font-semibold">
                    {error}
                </div>
            )}

            {/* Stats Cards */}
            <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
                <GlassCard className="shadow-on-surface/5 border-none bg-card">
                    <GlassCardHeader className="flex flex-row items-center justify-between pb-1 pt-2.5 px-3">
                        <GlassCardTitle className="text-[9px] font-bold tracking-tight text-on-surface-variant/40 uppercase">Total Users</GlassCardTitle>
                        <div className="p-1 bg-primary/5 rounded-md">
                            <Users className="h-2.5 w-2.5 text-primary" />
                        </div>
                    </GlassCardHeader>
                    <GlassCardContent className="px-3 pb-2.5">
                        <div className="text-lg font-bold tracking-tight text-on-surface tabular-nums">{stats?.active_users ?? users.length}</div>
                        <p className="text-[8px] font-bold text-success mt-0.5 tracking-tight italic">Active accounts</p>
                    </GlassCardContent>
                </GlassCard>

                <GlassCard className="bg-primary text-primary-foreground shadow-lg shadow-primary/10 border-none">
                    <GlassCardHeader className="flex flex-row items-center justify-between pb-1 pt-2.5 px-3">
                        <GlassCardTitle className="text-[9px] font-bold tracking-tight text-on-inverse/40 uppercase">Pending Approvals</GlassCardTitle>
                        <div className="p-1 bg-card/10 rounded-md">
                            <Clock className="h-2.5 w-2.5 text-white" />
                        </div>
                    </GlassCardHeader>
                    <GlassCardContent className="px-3 pb-2.5">
                        <div className="text-lg font-bold tracking-tight tabular-nums">{stats?.pending_requests ?? '--'}</div>
                        <p className="text-[8px] font-bold text-on-inverse/40 mt-0.5 tracking-tight italic">Needs attention</p>
                    </GlassCardContent>
                </GlassCard>

                <GlassCard className="shadow-on-surface/5 border-none bg-card">
                    <GlassCardHeader className="flex flex-row items-center justify-between pb-1 pt-2.5 px-3">
                        <GlassCardTitle className="text-[9px] font-bold tracking-tight text-on-surface-variant/40 uppercase">IP Policies</GlassCardTitle>
                        <div className="p-1 bg-primary/5 rounded-md">
                            <Globe className="h-2.5 w-2.5 text-primary" />
                        </div>
                    </GlassCardHeader>
                    <GlassCardContent className="px-3 pb-2.5">
                        <div className="text-lg font-bold tracking-tight text-on-surface tabular-nums">{stats?.active_ip_policies ?? '--'}</div>
                        <p className="text-[8px] font-bold text-primary mt-0.5 tracking-tight italic">Security rules</p>
                    </GlassCardContent>
                </GlassCard>

                <GlassCard className="shadow-on-surface/5 border-none bg-card">
                    <GlassCardHeader className="flex flex-row items-center justify-between pb-1 pt-2.5 px-3">
                        <GlassCardTitle className="text-[9px] font-bold tracking-tight text-on-surface-variant/40 uppercase">Security Score</GlassCardTitle>
                        <div className="p-1 bg-primary/5 rounded-md">
                            <ShieldCheck className="h-2.5 w-2.5 text-primary" />
                        </div>
                    </GlassCardHeader>
                    <GlassCardContent className="px-3 pb-2.5">
                        <div className="text-lg font-bold tracking-tight text-on-surface tabular-nums">{stats?.hygiene_score ?? '--'}<span className="text-[10px] ml-0.5 opacity-20">%</span></div>
                        <p className="text-[8px] font-bold text-success mt-0.5 tracking-tight italic">Overall health</p>
                    </GlassCardContent>
                </GlassCard>
            </div>

            <div className="grid gap-3 md:grid-cols-7">
                <GlassCard className="col-span-4 border-none bg-card">
                    <GlassCardHeader className="py-2.5 px-4 border-b border-on-surface/5">
                        <GlassCardTitle className="flex items-center gap-2 text-xs font-bold tracking-tight">
                            <Database className="w-3.5 h-3.5 opacity-20 text-primary" />
                            System Activity
                        </GlassCardTitle>
                    </GlassCardHeader>
                    <GlassCardContent className="p-3">
                        <div className="h-[180px] w-full">
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={[
                                    { name: 'Identities', value: stats?.active_users ?? 0 },
                                    { name: 'Groups', value: stats?.total_groups ?? 0 },
                                    { name: 'Workloads', value: stats?.active_workloads ?? 0 },
                                    { name: 'Policies', value: stats?.active_ip_policies ?? 0 },
                                ]}>
                                    <XAxis dataKey="name" fontSize={9} fontWeight="600" tickLine={false} axisLine={false} dy={5} />
                                    <YAxis fontSize={9} fontWeight="600" tickLine={false} axisLine={false} />
                                    <Bar dataKey="value" fill="currentColor" className="text-primary" radius={[3, 3, 0, 0]} barSize={32} />
                                </BarChart>
                            </ResponsiveContainer>
                        </div>
                    </GlassCardContent>
                </GlassCard>

                <GlassCard className="col-span-3 border-none bg-card">
                    <GlassCardHeader className="py-2.5 px-4 border-b border-on-surface/5">
                        <GlassCardTitle className="flex items-center gap-2 text-xs font-bold tracking-tight">
                            <AlertTriangle className="w-3.5 h-3.5 opacity-20 text-warning" />
                            Security Risks
                        </GlassCardTitle>
                    </GlassCardHeader>
                    <GlassCardContent className="p-3">
                        <div className="h-[180px] w-full">
                            <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                    <Pie
                                        data={riskData}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={60}
                                        outerRadius={80}
                                        paddingAngle={4}
                                        dataKey="value"
                                        stroke="none"
                                    >
                                        {riskData.map((entry, index) => (
                                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                        ))}
                                    </Pie>
                                    <Tooltip {...chartTooltipStyle} />
                                    <Legend iconType="circle" iconSize={6} verticalAlign="bottom" height={32} formatter={(value) => <span className="text-[10px] font-semibold text-on-surface-variant pl-1.5">{value}</span>} />
                                </PieChart>
                            </ResponsiveContainer>
                        </div>
                    </GlassCardContent>
                </GlassCard>
            </div>

            {/* Content Table */}
            <GlassCard className="shadow-on-surface/5 border-none bg-card overflow-hidden">
                <GlassCardHeader className="py-2.5 px-4 border-b border-on-surface/5">
                    <div className="flex items-center gap-3">
                        <div className="p-1.5 bg-primary/5 rounded-lg">
                            <Users className="w-4 h-4 text-primary" />
                        </div>
                        <div>
                            <GlassCardTitle className="text-sm font-bold tracking-tight text-on-surface">Recent Users</GlassCardTitle>
                            <p className="text-on-surface-variant/40 font-semibold text-[8px] mt-0.5 tracking-tight uppercase">Latest identity updates</p>
                        </div>
                    </div>
                </GlassCardHeader>
                <GlassCardContent className="p-0">
                    <div className="overflow-x-auto">
                        <GlassTable>
                            <GlassTableHeader>
                                <GlassTableRow className="hover:bg-transparent border-b border-on-surface/5">
                                    <GlassTableHead className="py-2 pl-4 font-bold text-[9px] tracking-tight text-on-surface-variant/40 uppercase">User</GlassTableHead>
                                    <GlassTableHead className="font-bold text-[9px] tracking-tight text-on-surface-variant/40 uppercase">Status</GlassTableHead>
                                    <GlassTableHead className="font-bold text-[9px] tracking-tight text-on-surface-variant/40 uppercase">Date Added</GlassTableHead>
                                    <GlassTableHead className="text-right pr-4 font-bold text-[9px] tracking-tight text-on-surface-variant/40 uppercase">Actions</GlassTableHead>
                                </GlassTableRow>
                            </GlassTableHeader>
                            <TableBody>
                                {users.length === 0 ? (
                                    <GlassTableRow>
                                        <TableCell colSpan={4} className="py-20 text-center text-xs font-medium text-on-surface-variant/40">
                                            No users found.
                                        </TableCell>
                                    </GlassTableRow>
                                ) : (
                                    users.map((user) => (
                                        <GlassTableRow key={user.id} className="hover:bg-surface-container/20 transition-all border-b border-on-surface/5 last:border-0 group">
                                            <TableCell className="py-1.5 pl-4">
                                                <div className="flex items-center gap-2.5">
                                                    <Avatar className="h-6 w-6 border-none ring-1 ring-on-surface/5 rounded-md overflow-hidden group-hover:scale-105 transition-transform">
                                                        <AvatarImage src={`https://avatar.vercel.sh/${user.userName}`} />
                                                        <AvatarFallback className="bg-primary/5 text-[8px] font-bold text-primary">{user.userName?.substring(0, 2).toUpperCase() || '??'}</AvatarFallback>
                                                    </Avatar>
                                                    <div className="flex flex-col">
                                                        <span className="font-bold text-[11px] tracking-tight text-on-surface group-hover:text-primary transition-colors">{user.userName}</span>
                                                        <span className="text-[7px] text-on-surface-variant/40 font-mono tracking-tight">{user.id}</span>
                                                    </div>
                                                </div>
                                            </TableCell>
                                            <TableCell className="py-1.5">
                                                <Badge className={cn("rounded-md font-bold text-[7px] tracking-tight px-1 py-0 shadow-none border-none", user.active ? "bg-success-subtle text-success" : "bg-destructive/10 text-destructive")}>
                                                    {user.active ? 'Active' : 'Inactive'}
                                                </Badge>
                                            </TableCell>
                                            <TableCell className="py-1.5 text-on-surface-variant text-[9px] font-medium">
                                                {user.meta?.created ? new Date(user.meta.created).toLocaleDateString() : 'Initial Link'}
                                            </TableCell>
                                            <TableCell className="py-1.5 text-right pr-4">
                                                <Button
                                                    variant="ghost"
                                                    size="sm"
                                                    onClick={() => navigator.clipboard.writeText(user.id)}
                                                    className="h-7 w-7 rounded-lg hover:bg-surface-container transition-all"
                                                >
                                                    <MoreHorizontal className="h-3 w-3 opacity-40" />
                                                </Button>
                                            </TableCell>
                                        </GlassTableRow>
                                    ))
                                )}< /TableBody>
                        </GlassTable>
                    </div>
                </GlassCardContent>
            </GlassCard>
        </div>
    );
};

export default Dashboard;
