import React, { useEffect, useState } from 'react';
import { getSCIMUsers } from '../api';
import { useNavigate } from 'react-router-dom';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '@/components/ui/card';
import { TableBody, TableCell } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import BoringAvatar from 'boring-avatars';
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
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassTable, GlassTableHeader, GlassTableRow, GlassTableHead, PageLayout
} from '@/components/layout';
import { cn } from '@/lib/utils';
import { colors, chartTooltipStyle } from '@/components/theme';

interface AdminMetricCardProps {
    title: string;
    value: string | number;
    statusLabel: string;
    statusColorClass?: string;
    icon: React.ReactNode;
    theme?: 'primary' | 'default';
}

const AdminMetricCard: React.FC<AdminMetricCardProps> = ({ title, value, statusLabel, statusColorClass = "text-success", icon, theme = 'default' }) => {
    if (theme === 'primary') {
        return (
            <GlassCard className="bg-primary text-primary-foreground shadow-lg shadow-primary/10 border-none hover:translate-y-[-2px] transition-all duration-300">
                <GlassCardHeader className="flex flex-row items-center justify-between pb-2 pt-card px-card">
                    <GlassCardTitle className="text-label text-primary-foreground/60 uppercase">{title}</GlassCardTitle>
                    <div className="p-2 bg-black/10 rounded-lg">
                        {icon}
                    </div>
                </GlassCardHeader>
                <GlassCardContent className="px-card pb-card pt-0">
                    <div className="text-title font-bold tracking-tight text-primary-foreground tabular-nums">{value}</div>
                    <p className="text-detail font-medium text-primary-foreground/60 mt-1">{statusLabel}</p>
                </GlassCardContent>
            </GlassCard>
        );
    }

    return (
        <PageLayout>
        <GlassCard className="shadow-on-surface/5 border-none bg-card hover:translate-y-[-2px] transition-all duration-300">
            <GlassCardHeader className="flex flex-row items-center justify-between pb-2 pt-card px-card">
                <GlassCardTitle className="text-label text-on-surface-variant/40 uppercase">{title}</GlassCardTitle>
                <div className="p-2 bg-primary/5 rounded-lg">
                    {icon}
                </div>
            </GlassCardHeader>
            <GlassCardContent className="px-card pb-card pt-0">
                <div className="text-title font-bold tracking-tight text-on-surface tabular-nums">{value}</div>
                <p className={cn("text-detail font-medium mt-1", statusColorClass)}>{statusLabel}</p>
            </GlassCardContent>
        </GlassCard>
        </PageLayout>
    );
};

interface UserTableRowProps {
    user: any;
    onCopyId: (id: string) => void;
}

const UserTableRow: React.FC<UserTableRowProps> = ({ user, onCopyId }) => {
    return (
        <GlassTableRow className="hover:bg-surface-container/20 transition-all border-b border-on-surface/5 last:border-0 group">
            <TableCell className="py-card pl-card">
                <div className="flex items-center gap-3">
                    <Avatar className="h-8 w-8 border-none ring-1 ring-on-surface/5 rounded-lg overflow-hidden group-hover:scale-105 transition-transform">
                        <BoringAvatar
                            size={32}
                            name={user.userName}
                            variant="marble"
                            colors={["#00FF9E", "#17171C", "#8B5CF6", "#06B6D4", "#10B981"]}
                        />
                    </Avatar>
                    <div className="flex flex-col">
                        <span className="font-bold text-body tracking-tight text-on-surface group-hover:text-primary transition-colors">{user.userName}</span>
                        <span className="text-detail text-on-surface-variant/40 font-mono tracking-tight">{user.id}</span>
                    </div>
                </div>
            </TableCell>
            <TableCell className="py-card">
                <Badge className={cn("rounded-lg font-bold text-detail tracking-tight px-2 py-0.5 shadow-none border-none", user.active ? "bg-success-subtle text-success" : "bg-destructive/10 text-destructive")}>
                    {user.active ? 'Active' : 'Inactive'}
                </Badge>
            </TableCell>
            <TableCell className="py-card text-on-surface-variant text-caption font-medium">
                {user.meta?.created ? new Date(user.meta.created).toLocaleDateString() : 'Initial Link'}
            </TableCell>
            <TableCell className="py-card text-right pr-card">
                <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => onCopyId(user.id)}
                    className="h-8 w-8 rounded-lg hover:bg-surface-container transition-all"
                >
                    <MoreHorizontal className="h-4 w-4 opacity-40" />
                </Button>
            </TableCell>
        </GlassTableRow>
    );
};

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

    const handleCopyId = (id: string) => {
        navigator.clipboard.writeText(id);
    };

    return (
        <div className="space-y-page animate-in fade-in duration-700">
            <PageHeader
                icon={<img src="/wardseal.svg" alt="WardSeal" className="w-6 h-6" />}
                title="Dashboard"
                description="Overview of your identity infrastructure — users, access requests, policies, and security posture."
                actions={
                    <Button
                        onClick={() => navigate('/users/new')}
                        className="h-9 rounded-lg bg-primary text-primary-foreground font-bold text-label tracking-tight px-4 shadow-xl shadow-primary/20 transition-all hover:scale-[1.02] active:scale-[0.98]"
                    >
                        <UserPlus className="mr-1.5 h-4 w-4" /> Add user
                    </Button>
                }
            />

            {error && (
                <div className="bg-destructive/5 text-destructive px-5 py-3 rounded-xl border border-destructive/10 text-caption font-semibold">
                    {error}
                </div>
            )}

            {/* Stats Cards */}
            <div className="grid gap-card md:grid-cols-2 lg:grid-cols-4">
                <AdminMetricCard 
                    title="Total Users" 
                    value={stats?.active_users ?? users.length} 
                    statusLabel="Active accounts" 
                    statusColorClass="text-success"
                    icon={<Users className="h-4 w-4 text-primary" />} 
                />

                <AdminMetricCard 
                    title="Pending Approvals" 
                    value={stats?.pending_requests ?? '--'} 
                    statusLabel="Needs attention" 
                    theme="primary"
                    icon={<Clock className="h-4 w-4 text-primary-foreground" />} 
                />

                <AdminMetricCard 
                    title="IP Policies" 
                    value={stats?.active_ip_policies ?? '--'} 
                    statusLabel="Security rules" 
                    statusColorClass="text-primary"
                    icon={<Globe className="h-4 w-4 text-primary" />} 
                />

                <AdminMetricCard 
                    title="Security Score" 
                    value={`${stats?.hygiene_score ?? '--'}%`} 
                    statusLabel="Overall health" 
                    statusColorClass="text-success"
                    icon={<ShieldCheck className="h-4 w-4 text-primary" />} 
                />
            </div>

            <div className="grid gap-card md:grid-cols-7">
                <GlassCard className="col-span-4 border-none bg-card">
                    <GlassCardHeader className="py-card px-card border-b border-on-surface/5">
                        <GlassCardTitle className="flex items-center gap-2 text-body font-bold tracking-tight">
                            <Database className="w-4 h-4 opacity-20 text-primary" />
                            System Activity
                        </GlassCardTitle>
                    </GlassCardHeader>
                    <GlassCardContent className="p-card">
                        <div className="h-[200px] w-full">
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={[
                                    { name: 'Identities', value: stats?.active_users ?? 0 },
                                    { name: 'Groups', value: stats?.total_groups ?? 0 },
                                    { name: 'Workloads', value: stats?.active_workloads ?? 0 },
                                    { name: 'Policies', value: stats?.active_ip_policies ?? 0 },
                                ]}>
                                    <XAxis dataKey="name" fontSize={10} fontWeight="600" tickLine={false} axisLine={false} dy={5} />
                                    <YAxis fontSize={10} fontWeight="600" tickLine={false} axisLine={false} />
                                    <Bar dataKey="value" fill="currentColor" className="text-primary" radius={[4, 4, 0, 0]} barSize={32} />
                                </BarChart>
                            </ResponsiveContainer>
                        </div>
                    </GlassCardContent>
                </GlassCard>

                <GlassCard className="col-span-3 border-none bg-card">
                    <GlassCardHeader className="py-card px-card border-b border-on-surface/5">
                        <GlassCardTitle className="flex items-center gap-2 text-body font-bold tracking-tight">
                            <AlertTriangle className="w-4 h-4 opacity-20 text-warning" />
                            Security Risks
                        </GlassCardTitle>
                    </GlassCardHeader>
                    <GlassCardContent className="p-card">
                        <div className="h-[200px] w-full">
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
                                    <Legend iconType="circle" iconSize={6} verticalAlign="bottom" height={32} formatter={(value) => <span className="text-detail font-semibold text-on-surface-variant pl-1.5">{value}</span>} />
                                </PieChart>
                            </ResponsiveContainer>
                        </div>
                    </GlassCardContent>
                </GlassCard>
            </div>

            {/* Content Table */}
            <GlassCard className="shadow-on-surface/5 border-none bg-card overflow-hidden">
                <GlassCardHeader className="py-card px-card border-b border-on-surface/5">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-primary/5 rounded-lg">
                            <Users className="w-4 h-4 text-primary" />
                        </div>
                        <div>
                            <GlassCardTitle className="text-body font-bold tracking-tight text-on-surface">Recent Users</GlassCardTitle>
                            <p className="text-on-surface-variant/40 font-semibold text-detail mt-0.5 tracking-tight uppercase">Latest identity updates</p>
                        </div>
                    </div>
                </GlassCardHeader>
                <GlassCardContent className="p-0">
                    <div className="overflow-x-auto">
                        <GlassTable>
                            <GlassTableHeader>
                                <GlassTableRow className="hover:bg-transparent border-b border-on-surface/5">
                                    <GlassTableHead className="py-3 pl-card font-bold text-label tracking-tight text-on-surface-variant/40 uppercase">User</GlassTableHead>
                                    <GlassTableHead className="font-bold text-label tracking-tight text-on-surface-variant/40 uppercase">Status</GlassTableHead>
                                    <GlassTableHead className="font-bold text-label tracking-tight text-on-surface-variant/40 uppercase">Date Added</GlassTableHead>
                                    <GlassTableHead className="text-right pr-card font-bold text-label tracking-tight text-on-surface-variant/40 uppercase">Actions</GlassTableHead>
                                </GlassTableRow>
                            </GlassTableHeader>
                            <TableBody>
                                {users.length === 0 ? (
                                    <GlassTableRow>
                                        <TableCell colSpan={4} className="py-20 text-center text-body font-medium text-on-surface-variant/40">
                                            No users found.
                                        </TableCell>
                                    </GlassTableRow>
                                ) : (
                                    users.map((user) => (
                                        <UserTableRow key={user.id} user={user} onCopyId={handleCopyId} />
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
