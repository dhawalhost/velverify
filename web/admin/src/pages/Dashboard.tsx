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
        <div className="space-y-12 animate-in fade-in duration-700">
            <PageHeader
                icon={
                    <div className="p-3">
                        {/* <ShieldCheck className="w-8 h-8 text-primary-foreground" /> */}
                        <img src="/wardseal.svg" alt="WardSeal" className="w-12 h-12" />
                    </div>
                }
                title="Dashboard"
                description="Overview of your identity infrastructure — users, access requests, policies, and security posture."
                actions={
                    <Button
                        onClick={() => navigate('/users/new')}
                        className="h-11 rounded-xl bg-primary text-primary-foreground font-bold text-[12px] tracking-tight px-8 shadow-xl shadow-primary/20 transition-all hover:scale-[1.02] active:scale-[0.98]"
                    >
                        <UserPlus className="mr-3 h-4 w-4" /> Add user
                    </Button>
                }
            />

            {error && (
                <div className="bg-destructive/5 text-destructive px-6 py-4 rounded-xl border border-destructive/10 text-sm font-semibold">
                    {error}
                </div>
            )}

            {/* Stats Cards */}
            <div className="grid gap-8 md:grid-cols-2 lg:grid-cols-4">
                <GlassCard className="shadow-on-surface/5">
                    <GlassCardHeader className="flex flex-row items-center justify-between pb-4">
                        <GlassCardTitle className="text-sm font-bold tracking-tight text-on-surface-variant/40">Total Users</GlassCardTitle>
                        <div className="p-2 bg-primary/5 rounded-lg">
                            <Users className="h-4 w-4 text-primary" />
                        </div>
                    </GlassCardHeader>
                    <GlassCardContent>
                        <div className="text-5xl font-bold tracking-tighter text-on-surface tabular-nums">{stats?.active_users ?? users.length}</div>
                        <p className="text-[11px] font-bold text-success mt-4 tracking-tight italic">Active accounts</p>
                    </GlassCardContent>
                </GlassCard>

                <GlassCard className="bg-primary text-primary-foreground shadow-primary/20 ring-primary/20">
                    <GlassCardHeader className="flex flex-row items-center justify-between pb-4">
                        <GlassCardTitle className="text-sm font-bold tracking-tight text-on-inverse/40">Pending Approvals</GlassCardTitle>
                        <div className="p-2 bg-card/10 rounded-lg">
                            <Clock className="h-4 w-4 text-white" />
                        </div>
                    </GlassCardHeader>
                    <GlassCardContent>
                        <div className="text-5xl font-bold tracking-tighter tabular-nums">{stats?.pending_requests ?? '--'}</div>
                        <p className="text-[11px] font-bold text-on-inverse/40 mt-4 tracking-tight italic">Needs your attention</p>
                    </GlassCardContent>
                </GlassCard>

                <GlassCard className="shadow-on-surface/5">
                    <GlassCardHeader className="flex flex-row items-center justify-between pb-4">
                        <GlassCardTitle className="text-sm font-bold tracking-tight text-on-surface-variant/40">IP Policies</GlassCardTitle>
                        <div className="p-2 bg-primary/5 rounded-lg">
                            <Globe className="h-4 w-4 text-primary" />
                        </div>
                    </GlassCardHeader>
                    <GlassCardContent>
                        <div className="text-5xl font-bold tracking-tighter text-on-surface tabular-nums">{stats?.active_ip_policies ?? '--'}</div>
                        <p className="text-[11px] font-bold text-primary mt-4 tracking-tight italic">Security rules</p>
                    </GlassCardContent>
                </GlassCard>

                <GlassCard className="shadow-on-surface/5">
                    <GlassCardHeader className="flex flex-row items-center justify-between pb-4">
                        <GlassCardTitle className="text-sm font-bold tracking-tight text-on-surface-variant/40">Security Score</GlassCardTitle>
                        <div className="p-2 bg-primary/5 rounded-lg">
                            <ShieldCheck className="h-4 w-4 text-primary" />
                        </div>
                    </GlassCardHeader>
                    <GlassCardContent>
                        <div className="text-5xl font-bold tracking-tighter text-on-surface tabular-nums">{stats?.hygiene_score ?? '--'}<span className="text-2xl ml-1 opacity-20">%</span></div>
                        <p className="text-[11px] font-bold text-success mt-4 tracking-tight italic">Overall health</p>
                    </GlassCardContent>
                </GlassCard>
            </div>

            <div className="grid gap-6 md:grid-cols-7">
                <GlassCard className="col-span-4">
                    <GlassCardHeader>
                        <GlassCardTitle className="flex items-center gap-2">
                            <Database className="w-4 h-4 opacity-20" />
                            System Activity
                        </GlassCardTitle>
                    </GlassCardHeader>
                    <GlassCardContent className="p-8">
                        <div className="h-[260px] w-full">
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={[
                                    { name: 'Identities', value: stats?.active_users ?? 0 },
                                    { name: 'Groups', value: stats?.total_groups ?? 0 },
                                    { name: 'Workloads', value: stats?.active_workloads ?? 0 },
                                    { name: 'Policies', value: stats?.active_ip_policies ?? 0 },
                                ]}>
                                    <XAxis dataKey="name" fontSize={10} fontWeight="600" tickLine={false} axisLine={false} dy={10} />
                                    <YAxis fontSize={10} fontWeight="600" tickLine={false} axisLine={false} />
                                    <Bar dataKey="value" fill="currentColor" className="text-primary" radius={[4, 4, 0, 0]} barSize={40} />
                                </BarChart>
                            </ResponsiveContainer>
                        </div>
                    </GlassCardContent>
                </GlassCard>

                <GlassCard className="col-span-3">
                    <GlassCardHeader>
                        <GlassCardTitle className="flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4 opacity-20" />
                            Security Risks
                        </GlassCardTitle>
                    </GlassCardHeader>
                    <GlassCardContent className="p-8">
                        <div className="h-[260px] w-full">
                            <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                    <Pie
                                        data={riskData}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={70}
                                        outerRadius={90}
                                        paddingAngle={4}
                                        dataKey="value"
                                        stroke="none"
                                    >
                                        {riskData.map((entry, index) => (
                                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                        ))}
                                    </Pie>
                                    <Tooltip {...chartTooltipStyle} />
                                    <Legend iconType="circle" iconSize={8} verticalAlign="bottom" height={36} formatter={(value) => <span className="text-[11px] font-semibold text-on-surface-variant pl-2">{value}</span>} />
                                </PieChart>
                            </ResponsiveContainer>
                        </div>
                    </GlassCardContent>
                </GlassCard>
            </div>

            {/* Content Table */}
            <GlassCard className="shadow-on-surface/5">
                <GlassCardHeader className="py-8 px-10">
                    <div className="flex items-center gap-5">
                        <div className="p-3.5 bg-primary/5 rounded-2xl">
                            <Users className="w-6 h-6 text-primary" />
                        </div>
                        <div>
                            <GlassCardTitle className="text-2xl font-bold tracking-tight text-on-surface">Recent Users</GlassCardTitle>
                            <p className="text-on-surface-variant/40 font-semibold text-[12px] mt-1 tracking-tight">Latest identity updates</p>
                        </div>
                    </div>
                </GlassCardHeader>
                <GlassCardContent className="p-0">
                    <div className="overflow-x-auto">
                        <GlassTable>
                            <GlassTableHeader>
                                <GlassTableRow className="hover:bg-transparent border-b border-on-surface/5">
                                    <GlassTableHead className="py-6 pl-10">User</GlassTableHead>
                                    <GlassTableHead>Status</GlassTableHead>
                                    <GlassTableHead>Date Added</GlassTableHead>
                                    <GlassTableHead className="text-right pr-10">Actions</GlassTableHead>
                                </GlassTableRow>
                            </GlassTableHeader>
                            <TableBody>
                                {users.length === 0 ? (
                                    <GlassTableRow>
                                        <TableCell colSpan={4} className="py-32 text-center text-sm font-medium text-on-surface-variant/40">
                                            No users found.
                                        </TableCell>
                                    </GlassTableRow>
                                ) : (
                                    users.map((user) => (
                                        <GlassTableRow key={user.id} className="hover:bg-surface-container/20 transition-all border-b border-on-surface/5 last:border-0 group">
                                            <TableCell className="py-6 pl-10">
                                                <div className="flex items-center gap-5">
                                                    <Avatar className="h-10 w-10 border-none ring-1 ring-on-surface/5 rounded-2xl overflow-hidden group-hover:scale-105 transition-transform">
                                                        <AvatarImage src={`https://avatar.vercel.sh/${user.userName}`} />
                                                        <AvatarFallback className="bg-primary/5 text-xs font-bold text-primary">{user.userName?.substring(0, 2).toUpperCase() || '??'}</AvatarFallback>
                                                    </Avatar>
                                                    <div className="flex flex-col">
                                                        <span className="font-bold text-sm tracking-tight text-on-surface group-hover:text-primary transition-colors">{user.userName}</span>
                                                        <span className="text-[10px] text-on-surface-variant/40 font-mono tracking-tight">{user.id}</span>
                                                    </div>
                                                </div>
                                            </TableCell>
                                            <TableCell className="py-6">
                                                <Badge className={cn("rounded-lg font-bold text-[10px] tracking-tight px-3 py-1 shadow-none border-none", user.active ? "bg-success-subtle text-success" : "bg-destructive/10 text-destructive")}>
                                                    {user.active ? 'Active' : 'Inactive'}
                                                </Badge>
                                            </TableCell>
                                            <TableCell className="py-6 text-on-surface-variant text-xs font-medium">
                                                {user.meta?.created ? new Date(user.meta.created).toLocaleDateString() : 'Initial Link'}
                                            </TableCell>
                                            <TableCell className="py-6 text-right pr-10">
                                                <Button
                                                    variant="ghost"
                                                    size="sm"
                                                    onClick={() => navigator.clipboard.writeText(user.id)}
                                                    className="h-9 w-9 rounded-xl hover:bg-surface-container transition-all"
                                                >
                                                    <MoreHorizontal className="h-4 w-4 opacity-40" />
                                                </Button>
                                            </TableCell>
                                        </GlassTableRow>
                                    ))
                                )}
                            </TableBody>
                        </GlassTable>
                    </div>
                </GlassCardContent>
            </GlassCard>
        </div>
    );
};

export default Dashboard;
