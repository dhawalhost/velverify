import React from 'react';
import { Fingerprint, Terminal, Clock } from 'lucide-react';
import { TableCell } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { GlassTableRow } from '@/components/layout';

export interface AccessRequest {
    id: string;
    requester_id: string;
    resource_type: string;
    resource_id: string;
    reason: string;
    duration: string | null;
    status: 'pending' | 'approved' | 'rejected';
}

interface PortalAccessRequestRowProps {
    req: AccessRequest;
    handleApprove: (id: string) => void;
    handleReject: (id: string) => void;
}

export const PortalAccessRequestRow: React.FC<PortalAccessRequestRowProps> = ({
    req,
    handleApprove,
    handleReject,
}) => {
    return (
        <GlassTableRow className="hover:bg-surface-container/10 transition-all border-b border-on-surface/5 last:border-0 group">
            <TableCell className="py-8 pl-10">
                <div className="flex items-center gap-5">
                    <div className="w-11 h-11 rounded-xl bg-surface-container flex items-center justify-center group-hover:bg-primary/10 group-hover:text-primary transition-all">
                        <Fingerprint className="h-5 w-5 opacity-40" />
                    </div>
                     <div className="flex flex-col">
                        <span className="text-lg font-bold tracking-tight text-on-surface group-hover:text-primary transition-colors">{req.requester_id}</span>
                        <span className="text-[9px] font-bold font-mono tracking-tight text-on-surface-variant/30 mt-1 italic">ID: {req.id.substring(0, 8).toLowerCase()}</span>
                    </div>
                </div>
            </TableCell>
            <TableCell className="py-8">
                <div className="flex flex-col gap-2">
                     <div className="flex items-center gap-2">
                        <Badge className="bg-surface-container text-on-surface-variant border-none rounded-lg font-bold text-[9px] px-2.5 py-1 tracking-tight">{req.resource_type}</Badge>
                        <span className="text-[11px] font-bold text-on-surface-variant/60 tracking-tight flex items-center gap-2 italic">
                            <Terminal className="w-3.5 h-3.5" />
                            {req.resource_id}
                        </span>
                    </div>
                    <span className="text-[10px] font-medium text-on-surface-variant/40 truncate max-w-[200px]" title={req.reason}>
                        {req.reason}
                    </span>
                </div>
            </TableCell>
            <TableCell className="py-8">
                 {req.duration ? (
                    <div className="flex items-center gap-2 text-[11px] font-bold text-primary tracking-tight">
                        <Clock className="w-3.5 h-3.5 opacity-40" />
                        {req.duration}
                    </div>
                ) : (
                    <span className="text-[10px] font-bold text-on-surface-variant/20 tracking-tight italic">Permanent</span>
                )}
            </TableCell>
            <TableCell className="py-8">
                 <Badge
                    className={`rounded-xl font-bold text-[9px] tracking-tight px-4 py-1.5 border-none shadow-sm transition-all ${req.status === 'pending' ? 'bg-amber-50 text-amber-600' :
                        req.status === 'approved' ? 'bg-success-subtle text-success' :
                            'bg-destructive/10 text-destructive'
                        }`}
                >
                    {req.status.charAt(0).toUpperCase() + req.status.slice(1)}
                </Badge>
            </TableCell>
            <TableCell className="py-8 text-right pr-10">
                {req.status === 'pending' && (
                     <div className="flex justify-end gap-3">
                        <Button
                            size="sm"
                            className="h-10 rounded-xl bg-success text-success-foreground hover:bg-emerald-600 font-bold text-[11px] px-5 shadow-lg shadow-emerald-500/10 transition-all border-none"
                            onClick={() => handleApprove(req.id)}
                        >
                            Approve
                        </Button>
                        <Button
                            size="sm"
                            variant="ghost"
                            className="h-10 rounded-xl text-destructive hover:bg-destructive/10 font-bold text-[11px] px-5 transition-all"
                            onClick={() => handleReject(req.id)}
                        >
                            Reject
                        </Button>
                    </div>
                )}
            </TableCell>
        </GlassTableRow>
    );
};
