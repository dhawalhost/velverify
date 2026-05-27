import React from 'react';
import { Button } from "@/components/ui/button";
import { ExternalLink, Sparkles } from "lucide-react";
import { GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent } from '@/components/layout';

export interface Application {
    id: string;
    name: string;
    description: string;
    icon_url?: string;
    launch_url: string;
}

interface RegistryAppCardProps {
    app: Application;
    onLaunch: (app: Application) => void;
}

export const RegistryAppCard: React.FC<RegistryAppCardProps> = ({ app, onLaunch }) => {
    return (
        <GlassCard className="group hover:ring-primary/20 hover:shadow-2xl hover:translate-y-[-2px] transition-all duration-300 overflow-hidden flex flex-col bg-card hover:bg-card rounded-xl">
            <GlassCardHeader className="p-card pb-2">
                <div className="flex items-start justify-between">
                    <div className="flex flex-col gap-3">
                        <div className="w-10 h-10 bg-surface-container rounded-lg flex items-center justify-center group-hover:scale-105 transition-transform ring-1 ring-on-surface/5">
                            {app.icon_url ? (
                                <img src={app.icon_url} alt={app.name} className="w-6 h-6 object-contain" />
                            ) : (
                                <Sparkles className="w-5 h-5 text-primary" />
                            )}
                        </div>
                        <div className="flex flex-col gap-1">
                            <div className="flex items-center gap-1.5">
                                <div className="w-1.5 h-1.5 bg-success rounded-full animate-pulse shadow-glow-success" />
                                <span className="font-bold text-detail tracking-widest text-success uppercase">Active</span>
                            </div>
                            <GlassCardTitle className="text-heading font-bold tracking-tight text-on-surface group-hover:text-primary transition-colors leading-none">{app.name}</GlassCardTitle>
                        </div>
                    </div>
                </div>
            </GlassCardHeader>
            <GlassCardContent className="p-card pt-0 space-y-3 flex-1 flex flex-col justify-between">
                <p className="text-caption font-medium text-on-surface-variant/60 leading-tight line-clamp-2">
                    {app.description || 'Enterprise secure resource with end-to-end identity verification.'}
                </p>

                <div className="space-y-2">
                    <div className="px-2 py-1.5 bg-surface-container rounded-md font-mono text-detail truncate text-on-surface-variant/30 ring-1 ring-on-surface/5">
                        <span className="opacity-40 mr-1">$</span>{app.launch_url}
                    </div>
                    <Button
                        onClick={() => onLaunch(app)}
                        className="w-full h-9 rounded-lg font-bold text-label tracking-wide shadow-lg shadow-primary/5 transition-all group-hover:bg-primary group-hover:text-primary-foreground"
                    >
                        Launch Application
                        <ExternalLink className="ml-1.5 h-3.5 w-3.5 opacity-50" />
                    </Button>
                </div>
            </GlassCardContent>
        </GlassCard>
    );
};
