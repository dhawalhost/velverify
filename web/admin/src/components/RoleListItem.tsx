import React from 'react';
import { Button } from '@/components/ui/button';
import { Fingerprint, ChevronRight, Trash2 } from 'lucide-react';

interface Role {
    id: string;
    name: string;
    description: string;
    created_at: string;
}

interface RoleListItemProps {
    role: Role;
    isSelected: boolean;
    onSelect: (role: Role) => void;
    onDelete: (id: string, e: React.MouseEvent) => void;
}

export const RoleListItem: React.FC<RoleListItemProps> = ({
    role,
    isSelected,
    onSelect,
    onDelete
}) => {
    return (
        <div
            onClick={() => onSelect(role)}
            className={`
                group flex items-center justify-between p-3.5 cursor-pointer transition-all rounded-xl
                ${isSelected
                    ? 'bg-primary/10 ring-1 ring-primary/30 shadow-lg shadow-primary/5'
                    : 'bg-card/50 hover:bg-surface-container/40 ring-1 ring-on-surface/5 hover:ring-on-surface/10'}
            `}
        >
            <div className="min-w-0 pr-4">
                <div className={`font-bold text-[12px] tracking-tight truncate flex items-center gap-2 transition-colors ${isSelected ? 'text-primary' : 'text-on-surface'}`}>
                    <Fingerprint className={`h-4.5 w-4.5 opacity-40 ${isSelected ? 'text-primary opacity-100' : ''}`} />
                    {role.name}
                </div>
                <div className="text-[10px] font-medium text-on-surface-variant/40 truncate mt-1.5 tracking-tight">
                    {role.description || 'No description provided'}
                </div>
            </div>
            <div className="flex items-center gap-2">
                {isSelected && <ChevronRight className="h-4.5 w-4.5 text-primary/60 animate-in fade-in slide-in-from-left-2" />}
                <Button
                    size="icon"
                    variant="ghost"
                    className={`h-7 w-7 rounded-md hover:bg-destructive/10 hover:text-destructive transition-all ${isSelected ? 'opacity-40' : 'opacity-0 group-hover:opacity-40'}`}
                    onClick={(e) => onDelete(role.id, e)}
                >
                    <Trash2 className="h-3.5 w-3.5" />
                </Button>
            </div>
        </div>
    );
};
