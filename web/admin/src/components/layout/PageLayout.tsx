import React from 'react';
import { cn } from '@/lib/utils';

interface PageLayoutProps {
    children: React.ReactNode;
    className?: string;
}

/**
 * Standard padded, scrollable wrapper for regular (non-master-detail) pages.
 * Master-detail pages do NOT use this — they fill the viewport directly.
 */
export const PageLayout: React.FC<PageLayoutProps> = ({ children, className }) => {
    return (
        <div className={cn('flex-1 overflow-y-auto p-8 max-w-[1600px] mx-auto w-full custom-scrollbar', className)}>
            {children}
        </div>
    );
};
