import React from 'react';
import { Trash2, ExternalLink } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { GlassTableRow, GlassTableHead } from '@/components/layout';
import { TableCell } from '@/components/ui/table';

interface Webhook {
    id: string;
    url: string;
    events: string[];
    active: boolean;
    created_at: string;
}

interface WebhookTableRowProps {
    webhook: Webhook;
    handleDelete: (id: string) => void;
}

export const WebhookTableRow: React.FC<WebhookTableRowProps> = ({
    webhook,
    handleDelete
}) => {
    return (
        <GlassTableRow className="hover:bg-surface-container/10 transition-all border-b border-on-surface/5 last:border-0 group">
            <TableCell className="py-2 pl-5">
                <div className="flex items-center gap-3">
                    <div className="w-7 h-7 rounded-lg bg-surface-container/50 text-on-surface-variant/40 flex items-center justify-center transition-all group-hover:bg-primary group-hover:text-primary-foreground">
                        <ExternalLink className="h-3.5 w-3.5" />
                    </div>
                    <div className="flex flex-col">
                        <span className="text-xs font-bold tracking-tight text-on-surface group-hover:text-primary transition-colors truncate max-w-[180px]">{webhook.url}</span>
                        <span className="text-[8px] font-bold font-mono tracking-tight text-on-surface-variant/20 uppercase">id // {webhook.id?.substring(0, 8)}</span>
                    </div>
                </div>
            </TableCell>
            <TableCell className="py-3">
                <div className="flex flex-wrap gap-1.5">
                    {webhook.events.map(ev => (
                        <Badge key={ev} className="bg-surface-container/50 text-on-surface-variant/60 border-none rounded-md font-bold text-[9px] tracking-tight px-2 py-0.5 group-hover:bg-primary/5 group-hover:text-primary transition-all uppercase">
                            {ev.split('.')[1]}
                        </Badge>
                    ))}
                </div>
            </TableCell>
            <TableCell className="py-3">
                <div className="flex items-center gap-2">
                    <div className={`h-1.5 w-1.5 rounded-full transition-all ${webhook.active ? 'bg-success' : 'bg-on-surface/20'}`} />
                    <span className={`text-[10px] font-bold tracking-tight uppercase transition-all ${webhook.active ? 'text-success' : 'text-on-surface-variant/40'}`}>
                        {webhook.active ? 'Active' : 'Dormant'}
                    </span>
                </div>
            </TableCell>
            <TableCell className="py-3 text-right pr-6">
                <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8 rounded-lg text-on-surface-variant/40 hover:text-destructive hover:bg-destructive/10 transition-all"
                    onClick={() => handleDelete(webhook.id)}
                >
                    <Trash2 className="w-4 h-4" />
                </Button>
            </TableCell>
        </GlassTableRow>
    );
};
