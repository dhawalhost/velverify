import React from 'react';
import { GlassCard } from '@/components/layout';

interface MetricCardProps {
    label: string;
    value: string;
    detail?: React.ReactNode;
    children?: React.ReactNode;
}

export const MetricCard: React.FC<MetricCardProps> = ({ label, value, detail, children }) => {
    return (
        <GlassCard className="p-card flex flex-col justify-center bg-card hover:bg-card hover:translate-y-[-2px] transition-all duration-300 rounded-xl">
            <span className="text-detail font-bold tracking-[0.2em] text-primary uppercase opacity-40">{label}</span>
            {children ? children : (
                <div className="flex items-baseline gap-2 mt-0.5">
                    <p className="text-title font-bold text-on-surface tracking-tighter tabular-nums">{value}</p>
                    {detail}
                </div>
            )}
        </GlassCard>
    );
};
