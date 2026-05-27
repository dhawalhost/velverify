import React from 'react';
import { Fingerprint } from 'lucide-react';
import { Button } from '@/components/ui/button';

interface APIKey {
    id: string;
    name: string;
    key_prefix: string;
    status: string;
    created_at: string;
}

interface APIKeyRowProps {
    apiKey: APIKey;
    handleViewLogs: (id: string, name: string, type: 'app' | 'key') => void;
    handleRevokeKey: (id: string) => void;
}

export const APIKeyRow: React.FC<APIKeyRowProps> = ({
    apiKey,
    handleViewLogs,
    handleRevokeKey
}) => {
    return (
        <div className="flex items-center justify-between p-4 hover:bg-surface-container/20 transition-all group">
            <div className="flex items-center gap-4">
                <div className="p-2 rounded-lg bg-surface-container/50 ring-1 ring-on-surface/5 group-hover:bg-primary/10 group-hover:ring-primary/20 transition-all">
                    <Fingerprint className="h-4 w-4 text-on-surface-variant/40 group-hover:text-primary transition-colors" />
                </div>
                <div className="space-y-0.5">
                    <div className="text-[13px] font-bold tracking-tight text-on-surface group-hover:text-primary transition-colors leading-none uppercase">{apiKey.name}</div>
                    <div className="flex items-center gap-3 text-[10px] font-bold tracking-tight text-on-surface-variant/40 uppercase">
                        <span className="font-mono bg-surface-container px-1.5 py-0.5 rounded text-[9px]">{apiKey.key_prefix}...</span>
                        <span>• {new Date(apiKey.created_at).toLocaleDateString()}</span>
                    </div>
                </div>
            </div>
            <div className="flex gap-2">
                <Button variant="ghost" className="h-7 rounded-lg bg-surface-container/50 font-bold text-[9px] tracking-tight hover:bg-primary hover:text-primary-foreground px-3 transition-all uppercase" onClick={() => handleViewLogs(apiKey.id, apiKey.name, 'key')}>
                    Logs
                </Button>
                <Button variant="ghost" className="h-7 rounded-lg bg-surface-container/50 font-bold text-[9px] tracking-tight hover:bg-destructive/100 hover:text-white px-3 text-destructive transition-all uppercase" onClick={() => handleRevokeKey(apiKey.id)}>
                    Revoke
                </Button>
            </div>
        </div>
    );
};
