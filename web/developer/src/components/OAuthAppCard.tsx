import React from 'react';
import { Box, Pencil, Trash2, RefreshCw, Users, Terminal, Activity } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent } from '@/components/layout';

interface DeveloperApp {
    id: string;
    tenant_id?: string;
    name: string;
    description?: string;
    client_id: string;
    app_type: string;
    redirect_uris: string[];
    grant_types?: string[];
    scopes?: string[];
    status: string;
    created_at: string;
}

interface OAuthAppCardProps {
    app: DeveloperApp;
    handleOpenEditApp: (app: DeveloperApp) => void;
    handleDeleteApp: (id: string) => void;
    handleRotateSecret: (id: string) => void;
    handleManageAssignments: (app: DeveloperApp) => void;
    setQuickstartApp: (app: DeveloperApp) => void;
    handleViewLogs: (id: string, name: string, type: 'app' | 'key') => void;
}

export const OAuthAppCard: React.FC<OAuthAppCardProps> = ({
    app,
    handleOpenEditApp,
    handleDeleteApp,
    handleRotateSecret,
    handleManageAssignments,
    setQuickstartApp,
    handleViewLogs
}) => {
    return (
        <GlassCard className="group border-none shadow-xl shadow-on-surface/5 hover:shadow-2xl hover:shadow-primary/5 transition-all overflow-hidden rounded-xl bg-card ring-1 ring-on-surface/5">
            <GlassCardHeader className="bg-surface-container/30 p-5 relative overflow-hidden border-b border-on-surface/5">
                <div className="absolute top-0 right-0 p-4 opacity-[0.03] transition-transform group-hover:scale-125">
                    <Box className="w-20 h-20" />
                </div>
                <div className="relative z-10 flex justify-between items-start">
                    <div className="space-y-3">
                        <div className="flex items-center gap-3">
                            <Badge className="rounded-lg bg-primary/10 text-primary font-bold text-[9px] tracking-tight px-2 border-none h-5 uppercase">{app.app_type}</Badge>
                            <span className="text-[9px] font-bold tracking-tight text-on-surface-variant/40 uppercase">ID: {app.client_id}</span>
                        </div>
                        <GlassCardTitle className="text-lg font-bold tracking-tight text-on-surface transition-colors uppercase leading-none">{app.name}</GlassCardTitle>
                        <p className="text-[10px] font-medium text-on-surface-variant/40 line-clamp-1">{app.description || "Default application configuration."}</p>
                    </div>
                    <div className="flex items-center gap-1.5">
                        <Button size="icon" variant="ghost" className="h-8 w-8 text-on-surface-variant/40 hover:bg-card hover:text-primary rounded-lg" onClick={() => handleOpenEditApp(app)}>
                            <Pencil className="h-4 w-4" />
                        </Button>
                        <Button size="icon" variant="ghost" className="h-8 w-8 text-on-surface-variant/40 hover:bg-destructive/10 hover:text-destructive rounded-lg" onClick={() => handleDeleteApp(app.id)}>
                            <Trash2 className="h-4 w-4" />
                        </Button>
                    </div>
                </div>
            </GlassCardHeader>
            <GlassCardContent className="p-4 space-y-4 bg-card">
                <div className="grid grid-cols-2 gap-4 pb-4 border-b border-on-surface/5">
                    <div>
                        <span className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 uppercase">Permissions</span>
                        <div className="flex flex-wrap gap-1.5 mt-2.5">
                            {(app.scopes && app.scopes.length > 0 ? app.scopes : ['openid', 'profile', 'email']).map(scope => (
                                <span key={scope} className="text-[9px] font-bold tracking-tight px-2 py-1 bg-surface-container/50 text-on-surface-variant/60 rounded-md ring-1 ring-on-surface/5 uppercase">{scope}</span>
                            ))}
                        </div>
                    </div>
                    <div>
                        <span className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 uppercase">Login Flows</span>
                        <div className="flex flex-wrap gap-1.5 mt-2.5">
                            {(app.grant_types && app.grant_types.length > 0 ? app.grant_types : ['authorization_code', 'refresh_token']).map(grantType => (
                                <span key={grantType} className="text-[9px] font-bold tracking-tight px-2 py-1 bg-primary/5 text-primary rounded-md ring-1 ring-primary/10 uppercase">{grantType.replace('_', ' ')}</span>
                            ))}
                        </div>
                    </div>
                </div>

                <div className="grid grid-cols-2 lg:grid-cols-4 gap-2">
                    <Button variant="ghost" className="h-9 rounded-lg bg-surface-container/30 hover:bg-primary hover:text-primary-foreground transition-all p-0 flex flex-col justify-center gap-0.5 group/btn" onClick={() => handleRotateSecret(app.id)}>
                        <RefreshCw className="h-2.5 w-2.5 text-on-surface-variant/40 group-hover/btn:text-white transition-colors" />
                        <span className="text-[8px] font-bold tracking-tight uppercase">Rotate</span>
                    </Button>
                    <Button variant="ghost" className="h-9 rounded-lg bg-surface-container/30 hover:bg-primary hover:text-primary-foreground transition-all p-0 flex flex-col justify-center gap-0.5 group/btn" onClick={() => handleManageAssignments(app)}>
                        <Users className="h-2.5 w-2.5 text-on-surface-variant/40 group-hover/btn:text-white transition-colors" />
                        <span className="text-[8px] font-bold tracking-tight uppercase">Access</span>
                    </Button>
                    <Button variant="ghost" className="h-9 rounded-lg bg-surface-container/30 hover:bg-primary hover:text-primary-foreground transition-all p-0 flex flex-col justify-center gap-0.5 group/btn" onClick={() => setQuickstartApp(app)}>
                        <Terminal className="h-2.5 w-2.5 text-on-surface-variant/40 group-hover/btn:text-white transition-colors" />
                        <span className="text-[8px] font-bold tracking-tight uppercase">Snippet</span>
                    </Button>
                    <Button variant="ghost" className="h-9 rounded-lg bg-surface-container/30 hover:bg-success hover:text-white transition-all p-0 flex flex-col justify-center gap-0.5 group/btn" onClick={() => handleViewLogs(app.id, app.name, 'app')}>
                        <Activity className="h-2.5 w-2.5 text-on-surface-variant/40 group-hover/btn:text-white transition-colors" />
                        <span className="text-[8px] font-bold tracking-tight uppercase">Audits</span>
                    </Button>
                </div>
            </GlassCardContent>
        </GlassCard>
    );
};
