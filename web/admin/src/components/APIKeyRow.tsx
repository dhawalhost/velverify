import React from 'react';
import { Fingerprint, Activity } from 'lucide-react';
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
        <div className="flex items-center justify-between p-5 hover:bg-surface-container/20 transition-all group">
            <div className="flex items-center gap-5">
                <div className="p-2.5 rounded-xl bg-surface-container/50 ring-1 ring-on-surface/5 group-hover:bg-primary/10 group-hover:ring-primary/20 transition-all">
                    <Fingerprint className="h-5 w-5 text-on-surface-variant/40 group-hover:text-primary transition-colors" />
                </div>
                <div className="space-y-0.5">
                    <div className="text-lg font-bold tracking-tight text-on-surface group-hover:text-primary transition-colors leading-none">{apiKey.name}</div>
                    <div className="flex items-center gap-3 text-[10px] font-semibold tracking-tight text-on-surface-variant/40">
                        <span className="font-mono bg-surface-container px-1.5 py-0.5 rounded text-[9px]">{apiKey.key_prefix}...</span>
                        <span>• {new Date(apiKey.created_at).toLocaleDateString()}</span>
                    </div>
                </div>
            </div>
            <div className="flex gap-2">
                <Button variant="ghost" className="h-9 rounded-xl bg-surface-container/50 font-bold text-[10px] tracking-tight hover:bg-primary hover:text-primary-foreground px-4 transition-all" onClick={() => handleViewLogs(apiKey.id, apiKey.name, 'key')}>
                    <Activity className="mr-2 h-3.5 w-3.5 opacity-40" /> Logs
                </Button>
                <Button variant="ghost" className="h-9 rounded-xl bg-surface-container/50 font-bold text-[10px] tracking-tight hover:bg-destructive/100 hover:text-white px-4 text-destructive transition-all" onClick={() => handleRevokeKey(apiKey.id)}>
                    Revoke
                </Button>
            </div>
        </div>
    );
};
