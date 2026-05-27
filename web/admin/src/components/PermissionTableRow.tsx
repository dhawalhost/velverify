import React from 'react';
import { GlassTableRow } from '@/components/layout';
import { TableCell } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';

interface Permission {
    id: string;
    resource: string;
    action: string;
    description: string;
}

interface PermissionTableRowProps {
    permission: Permission;
}

export const PermissionTableRow: React.FC<PermissionTableRowProps> = ({ permission }) => {
    return (
        <GlassTableRow className="hover:bg-surface-container/20 transition-all border-b border-on-surface/5 last:border-0 group">
            <TableCell className="py-1.5 pl-4 font-mono text-[10px] font-bold text-on-surface/60">{permission.resource}</TableCell>
            <TableCell className="py-1.5">
                <Badge className="bg-primary/5 text-primary border-none rounded-md font-bold text-[8px] tracking-tight px-2 py-0.5 group-hover:bg-primary group-hover:text-primary-foreground transition-all shadow-none uppercase">
                    {permission.action}
                </Badge>
            </TableCell>
            <TableCell className="py-1.5 text-[9px] font-bold text-on-surface-variant/20 italic tracking-tight pr-4">{permission.description || 'No system definition metadata'}</TableCell>
        </GlassTableRow>
    );
};
