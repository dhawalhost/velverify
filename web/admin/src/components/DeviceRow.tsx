import React from 'react';
import { User, ShieldCheck, ShieldAlert, Terminal, MoreHorizontal, Binary } from 'lucide-react';
import { TableCell } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { GlassTableRow } from '@/components/layout';
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

interface Device {
    id: string;
    serial: string;
    user_id: string;
    platform: string;
    os_version: string;
    trust_status: 'trusted' | 'untrusted' | 'pending';
    last_scan_at: string;
    created_at: string;
}

interface DeviceRowProps {
    device: Device;
    getStatusBadge: (status: string) => React.ReactNode;
    handleUpdateStatus: (id: string, status: string) => void;
}

export const DeviceRow: React.FC<DeviceRowProps> = ({
    device,
    getStatusBadge,
    handleUpdateStatus,
}) => {
    return (
        <GlassTableRow className="hover:bg-surface-container/10 transition-all border-b border-on-surface/5 last:border-0 group">
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
    );
};
