import React from 'react';
import { Trash2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

interface SAMLServiceProvider {
    entity_id: string;
    acs_url?: string;
    sign_assertions: boolean;
    encrypt_assertions: boolean;
}

interface SAMLProviderRowProps {
    sp: SAMLServiceProvider;
    handleDeleteSAMLProvider: (entityId: string) => void;
}

export const SAMLProviderRow: React.FC<SAMLProviderRowProps> = ({
    sp,
    handleDeleteSAMLProvider
}) => {
    return (
        <div className="flex flex-col md:flex-row items-center justify-between p-4 hover:bg-surface-container/20 transition-all group">
            <div className="flex-1 min-w-0 pr-4 space-y-1">
                <div className="flex items-center gap-3">
                    <Badge className="bg-on-surface/5 text-on-surface-variant/60 rounded-lg font-bold text-[9px] tracking-tight px-2 border-none">Provider</Badge>
                    <div className="text-sm font-bold tracking-tight text-on-surface truncate group-hover:text-primary transition-colors">{sp.entity_id}</div>
                </div>
                <div className="font-mono text-[9px] text-on-surface-variant/40 truncate ml-1">{sp.acs_url}</div>
                <div className="flex gap-2 pt-1 ml-1">
                    <Badge className={`rounded-md font-bold text-[8px] tracking-tight px-1.5 py-0.5 border-none ${sp.sign_assertions ? 'bg-success-subtle text-success' : 'bg-surface-container text-on-surface-variant/20'}`}>Signed</Badge>
                    <Badge className={`rounded-md font-bold text-[8px] tracking-tight px-1.5 py-0.5 border-none ${sp.encrypt_assertions ? 'bg-success-subtle text-success' : 'bg-surface-container text-on-surface-variant/20'}`}>Encrypted</Badge>
                </div>
            </div>
            <Button variant="ghost" size="icon" className="h-9 w-9 rounded-xl hover:bg-destructive/10 hover:text-destructive transition-all" onClick={() => handleDeleteSAMLProvider(sp.entity_id)}>
                <Trash2 className="h-4 w-4" />
            </Button>
        </div>
    );
};
