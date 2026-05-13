import React from 'react';
import { cn } from '@/lib/utils';

export interface PageHeaderProps {
    title: string;
    description?: React.ReactNode;
    icon?: React.ReactNode;
    actions?: React.ReactNode;
    className?: string;
}

export const PageHeader: React.FC<PageHeaderProps> = ({ title, description, icon, actions, className = '' }) => {
    return (
        <div className={cn("flex justify-between items-center border-b pb-4 border-outline/10 mb-6", className)}>
            <div className="space-y-1">
                <div className="flex items-center gap-3">
                    {icon && <div className="p-2 bg-surface-container rounded-lg text-primary">{icon}</div>}
                    <h1 className="text-xl font-bold tracking-tight text-on-surface uppercase">
                        {title}
                    </h1>
                </div>
                {description && (
                    <p className="text-on-surface-variant/60 text-[11px] font-medium leading-relaxed max-w-2xl uppercase">
                        {description}
                    </p>
                )}
            </div>

            {actions && (
                <div className="flex items-center gap-3">
                    {actions}
                </div>
            )}
        </div>
    );
};
