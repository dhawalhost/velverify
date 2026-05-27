import React from 'react';
import { Trash2, ExternalLink } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { GlassTableRow } from '@/components/layout';
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
            <TableCell className="py-8 pl-10">
                <div className="flex items-center gap-6">
                    <div className="w-12 h-12 rounded-xl bg-surface-container/50 text-on-surface-variant/40 flex items-center justify-center transition-all group-hover:bg-primary group-hover:text-primary-foreground">
                        <ExternalLink className="h-5 w-5" />
                    </div>
                    <div className="flex flex-col gap-1.5">
                        <span className="text-base font-bold tracking-tight text-on-surface group-hover:text-primary transition-colors truncate max-w-[280px]">{webhook.url}</span>
                        <span className="text-[10px] font-bold font-mono tracking-tight text-on-surface-variant/20 italic">id // {webhook.id?.substring(0, 8).toLowerCase() || 'external'}</span>
                    </div>
                </div>
            </TableCell>
            <TableCell className="py-8">
                <div className="flex flex-wrap gap-2">
                    {webhook.events.map(ev => (
                        <Badge key={ev} className="bg-surface-container/50 text-on-surface-variant/60 border-none rounded-lg font-bold text-[10px] tracking-tight px-3 py-1 group-hover:bg-primary/5 group-hover:text-primary transition-all">
                            {ev.split('.')[1]}
                        </Badge>
                    ))}
                </div>
            </TableCell>
            <TableCell className="py-8">
                <div className="flex items-center gap-3">
                    <div className={`h-2 w-2 rounded-full transition-all ${webhook.active ? 'bg-success' : 'bg-on-surface/20'}`} />
                    <span className={`text-[11px] font-bold tracking-tight transition-all ${webhook.active ? 'text-success' : 'text-on-surface-variant/40'}`}>
                        {webhook.active ? 'Active' : 'Dormant'}
                    </span>
                </div>
            </TableCell>
            <TableCell className="py-8 text-right pr-10">
                <Button 
                    variant="ghost" 
                    size="icon" 
                    className="h-11 w-11 rounded-xl text-on-surface-variant/40 hover:text-destructive hover:bg-destructive/10 transition-all"
                    onClick={() => handleDelete(webhook.id)}
                >
                    <Trash2 className="w-5 h-5" />
                </Button>
            </TableCell>
        </GlassTableRow>
    );
};
