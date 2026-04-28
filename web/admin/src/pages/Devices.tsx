import React, { useEffect, useState } from 'react';
import { getEndpoints, updateEndpointStatus, Device } from '../api';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
    Loader2,
    MonitorSmartphone,
    ShieldCheck,
    ShieldAlert,
    ShieldIcon,
    User,
    Info,
    CheckCircle2,
    XCircle,
    Activity,
    Lock,
    Smartphone,
    Cpu,
    Zap,
    ExternalLink,
    MoreHorizontal,
    Terminal,
    Binary
} from 'lucide-react';
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassTable, GlassTableHeader, GlassTableHead, GlassTableRow, GlassCardDescription } from '@/components/layout';
import { TableBody, TableCell } from '@/components/ui/table';
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Alert, AlertDescription } from '@/components/ui/alert';

const Devices: React.FC = () => {
    const [devices, setDevices] = useState<Device[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    const fetchDevices = async () => {
        try {
            setLoading(true);
            const data = await getEndpoints();
            setDevices(data || []);
        } catch (err) {
            console.error(err);
            setError('Failed to load devices.');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchDevices();
    }, []);

    const handleUpdateStatus = async (id: string, status: string) => {
        try {
            await updateEndpointStatus(id, status);
            fetchDevices();
        } catch (err) {
            console.error(err);
            setError('Failed to update security status.');
        }
    };

    const getStatusBadge = (status: string) => {
        switch (status) {
             case 'trusted':
                return <Badge className="bg-success/10 text-success border-none gap-2 rounded-xl font-bold text-[10px] tracking-tight px-4 py-1.5"><ShieldCheck className="w-3.5 h-3.5" /> Verified</Badge>;
            case 'untrusted':
                return <Badge className="bg-destructive/100/10 text-destructive border-none gap-2 rounded-xl font-bold text-[10px] tracking-tight px-4 py-1.5"><ShieldAlert className="w-3.5 h-3.5" /> Blocked</Badge>;
            default:
                return <Badge className="bg-amber-500/10 text-amber-600 border-none gap-2 rounded-xl font-bold text-[10px] tracking-tight px-4 py-1.5"><Activity className="w-3.5 h-3.5" /> Pending</Badge>;
        }
    };

    if (loading && devices.length === 0) return <div className="h-[400px] flex items-center justify-center"><Loader2 className="h-10 w-10 animate-spin text-primary opacity-20" /></div>;

    return (
        <div className="space-y-12 animate-in fade-in slide-in-from-bottom-4 duration-700">
            <PageHeader
                icon={<MonitorSmartphone className="w-10 h-10 text-primary" />}
                title="Devices"
                description="Manage and verify the security status of all company devices."
                actions={
                    <div className="flex gap-6">
                        {[
                            { label: 'Verified Devices', value: devices.filter(d => d.trust_status === 'trusted').length, color: 'text-success', bg: 'bg-success-subtle' },
                            { label: 'Pending Review', value: devices.filter(d => d.trust_status === 'pending').length, color: 'text-amber-500', bg: 'bg-amber-50' },
                        ].map((stat, i) => (
                             <GlassCard key={i} className="min-w-[160px] border-none shadow-xl shadow-on-surface/5 bg-card rounded-2xl p-6">
                                <div className="flex flex-col items-center gap-3">
                                    <span className={`text-3xl font-black tracking-tighter ${stat.color}`}>{stat.value}</span>
                                    <span className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 italic mt-1">{stat.label}</span>
                                </div>
                            </GlassCard>
                        ))}
                    </div>
                }
            />

             {error && (
                <Alert variant="destructive" className="rounded-2xl border-none bg-destructive/10 text-destructive animate-in slide-in-from-top-2">
                    <AlertDescription className="font-bold text-xs tracking-tight flex items-center gap-3">
                        <ShieldAlert className="w-4 h-4" />
                        Device error: {error}
                    </AlertDescription>
                </Alert>
            )}

            <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-card overflow-hidden rounded-[40px]">
                <GlassCardHeader className="py-10 px-10 border-b border-on-surface/5 bg-surface-container/5">
                    <div className="flex items-center gap-6">
                        <div className="p-4 bg-primary/5 rounded-2xl text-primary">
                            <Lock className="w-7 h-7" />
                        </div>
                         <div>
                            <GlassCardTitle className="text-3xl font-bold tracking-tight text-on-surface">Device Directory</GlassCardTitle>
                            <p className="text-on-surface-variant/60 font-medium text-[11px] mt-2">List of devices allowed to access company resources.</p>
                        </div>
                    </div>
                </GlassCardHeader>
                <GlassCardContent className="p-0">
                    <div className="overflow-x-auto min-h-[500px]">
                        <GlassTable>
                            <GlassTableHeader>
                                 <GlassTableRow className="hover:bg-transparent border-b border-on-surface/5">
                                    <GlassTableHead className="py-6 pl-10">Serial Number</GlassTableHead>
                                    <GlassTableHead>User</GlassTableHead>
                                    <GlassTableHead>Platform</GlassTableHead>
                                    <GlassTableHead>Security Status</GlassTableHead>
                                    <GlassTableHead>Last Seen</GlassTableHead>
                                    <GlassTableHead className="text-right pr-10">Actions</GlassTableHead>
                                </GlassTableRow>
                            </GlassTableHeader>
                            <TableBody>
                                {devices.length === 0 ? (
                                    <GlassTableRow>
                                         <TableCell colSpan={6} className="py-40 text-center">
                                             <div className="flex flex-col items-center gap-6 opacity-20">
                                                 <Smartphone className="h-16 w-16" />
                                                 <span className="text-[13px] font-bold tracking-tight italic">No devices found.</span>
                                             </div>
                                        </TableCell>
                                    </GlassTableRow>
                                ) : (
                                    devices.map(device => (
                                        <GlassTableRow key={device.id} className="hover:bg-surface-container/10 transition-all border-b border-on-surface/5 last:border-0 group">
                                            <TableCell className="py-8 pl-10">
                                                <div className="flex items-center gap-4">
                                                     <div className="w-10 h-10 rounded-2xl bg-surface-container flex items-center justify-center group-hover:bg-primary/10 group-hover:text-primary transition-all">
                                                        <Binary className="h-5 w-5 opacity-40 group-hover:opacity-100" />
                                                    </div>
                                                    <code className="text-[11px] font-bold text-primary tracking-tight font-mono group-hover:underline cursor-pointer">
                                                        {device.serial}
                                                    </code>
                                                </div>
                                            </TableCell>
                                            <TableCell className="py-8">
                                                <div className="flex items-center gap-4">
                                                     <div className="w-9 h-9 rounded-xl bg-surface-container flex items-center justify-center group-hover:bg-primary/10 group-hover:text-primary transition-all">
                                                        <User className="w-4 h-4 opacity-40 group-hover:opacity-100" />
                                                    </div>
                                                    <span className="text-[11px] font-bold text-on-surface-variant/60 tracking-tight">{device.user_id.substring(0, 16)}...</span>
                                                </div>
                                            </TableCell>
                                            <TableCell className="py-8">
                                                 <div className="flex flex-col">
                                                    <span className="text-sm font-bold tracking-tight text-on-surface group-hover:text-primary transition-colors">{device.platform}</span>
                                                    <span className="text-[10px] font-bold text-on-surface-variant/30 tracking-tight mt-1 italic">{device.os_version}</span>
                                                </div>
                                            </TableCell>
                                            <TableCell className="py-8">
                                                {getStatusBadge(device.trust_status)}
                                            </TableCell>
                                             <TableCell className="py-8 text-[11px] font-medium text-on-surface-variant/40 italic tracking-tight">
                                                {new Date(device.last_scan_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}
                                            </TableCell>
                                            <TableCell className="py-8 text-right pr-10">
                                                <div className="flex justify-end gap-3">
                                                    <DropdownMenu>
                                                        <DropdownMenuTrigger asChild>
                                                            <Button variant="ghost" size="icon" className="h-10 w-10 rounded-xl hover:bg-surface-container transition-all">
                                                                <MoreHorizontal className="h-5 w-5 text-on-surface-variant/60" />
                                                            </Button>
                                                        </DropdownMenuTrigger>
                                                        <DropdownMenuContent align="end" className="w-[200px] rounded-[24px] border-none shadow-2xl shadow-on-surface/10 p-2 bg-card">
                                                             <DropdownMenuItem 
                                                                 className="font-bold text-xs gap-3 py-3.5 px-4 cursor-pointer rounded-2xl focus:bg-success-subtle focus:text-success transition-colors"
                                                                 onClick={() => handleUpdateStatus(device.id, 'trusted')}
                                                                 disabled={device.trust_status === 'trusted'}
                                                             >
                                                                 <ShieldCheck className="w-4 h-4 opacity-50" />
                                                                 Verify Device
                                                             </DropdownMenuItem>
                                                             <DropdownMenuItem 
                                                                 className="font-bold text-xs gap-3 py-3.5 px-4 cursor-pointer rounded-2xl focus:bg-destructive/10 focus:text-destructive transition-colors"
                                                                 onClick={() => handleUpdateStatus(device.id, 'untrusted')}
                                                                 disabled={device.trust_status === 'untrusted'}
                                                             >
                                                                 <ShieldAlert className="w-4 h-4" />
                                                                 Block Device
                                                             </DropdownMenuItem>
                                                             <DropdownMenuItem className="font-bold text-xs gap-3 py-3.5 px-4 cursor-pointer rounded-2xl focus:bg-primary/5 focus:text-primary transition-colors">
                                                                 <Terminal className="w-4 h-4 opacity-50" />
                                                                 Terminal
                                                             </DropdownMenuItem>
                                                        </DropdownMenuContent>
                                                    </DropdownMenu>
                                                </div>
                                            </TableCell>
                                        </GlassTableRow>
                                    ))
                                )}
                            </TableBody>
                        </GlassTable>
                    </div>
                </GlassCardContent>
            </GlassCard>

            <div className="bg-inverse text-on-inverse p-12 rounded-[48px] shadow-2xl shadow-on-surface/10 relative overflow-hidden group">
                <div className="absolute top-0 right-0 p-8 opacity-5 pointer-events-none group-hover:scale-110 transition-transform">
                    <Cpu className="w-32 h-32 -mr-8 -mt-8 text-primary" />
                </div>
                <div className="flex flex-col md:flex-row items-center gap-12 relative z-10">
                    <div className="p-6 bg-card/5 rounded-3xl backdrop-blur-xl border border-on-inverse/5">
                        <Activity className="w-12 h-12 text-primary animate-pulse" />
                    </div>
                      <div className="space-y-6 flex-1 text-center md:text-left">
                         <h3 className="text-3xl font-bold tracking-tight">Device Security Policy</h3>
                         <p className="text-sm font-medium opacity-60 max-w-2xl leading-relaxed italic">
                             All devices must be verified to access company data. Unrecognized devices will be blocked automatically according to global security policies.
                         </p>
                     </div>
                     <Button variant="outline" className="h-14 px-10 rounded-2xl border-on-inverse/10 bg-card/5 hover:bg-card/10 text-white font-bold tracking-tight text-[11px] hidden lg:flex">
                         View Policy
                     </Button>
                </div>
            </div>
        </div>
    );
};

export default Devices;
