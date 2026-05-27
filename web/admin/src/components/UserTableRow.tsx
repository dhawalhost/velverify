import React from 'react';
import { Settings2, Key, Mail, ShieldAlert, MoreHorizontal } from 'lucide-react';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import BoringAvatar from 'boring-avatars';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { GlassTableRow } from '@/components/layout';
import { TableCell } from '@/components/ui/table';
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
    DropdownMenuSeparator
} from '@/components/ui/dropdown-menu';

interface Group {
    value: string;
    display: string;
}

interface User {
    id: string;
    userName: string;
    displayName?: string;
    active: boolean;
    emails?: Array<{ value: string }>;
    groups?: Group[];
}

interface UserTableRowProps {
    user: User;
    navigate: (path: string) => void;
    handleDeleteUser: (id: string) => void;
    handleSendResetLink: (id: string) => void;
    setSelectedUser: (user: User) => void;
    setIsPasswordDialogOpen: (open: boolean) => void;
}

export const UserTableRow: React.FC<UserTableRowProps> = ({
    user,
    navigate,
    handleDeleteUser,
    handleSendResetLink,
    setSelectedUser,
    setIsPasswordDialogOpen
}) => {
    return (
        <GlassTableRow className="hover:bg-surface-container/20 transition-all border-b border-on-surface/5 last:border-0 group">
            <TableCell className="py-1.5 pl-4">
                <div className="flex items-center gap-2.5">
                    <Avatar className="h-6 w-6 border-none ring-1 ring-on-surface/5 rounded-md overflow-hidden group-hover:scale-105 transition-transform">
                        <BoringAvatar
                            size={24}
                            name={user.emails?.[0]?.value || user.userName}
                            variant="marble"
                            colors={["#00FF9E", "#17171C", "#8B5CF6", "#06B6D4", "#10B981"]}
                        />
                    </Avatar>
                    <div className="flex flex-col">
                        <span className="font-bold text-[11px] tracking-tight text-on-surface group-hover:text-primary transition-colors">
                            {user.displayName || user.userName}
                        </span>
                        <span className="text-[8px] font-medium text-on-surface-variant/60 mt-0 flex items-center gap-2">
                            {user.emails?.[0]?.value || 'No verifiable email'}
                        </span>
                    </div>
                </div>
            </TableCell>
            <TableCell className="py-1.5">
                <Badge className={`rounded-md font-bold text-[7px] tracking-tight px-1 py-0 shadow-none border-none ${user.active
                    ? 'bg-success-subtle text-success'
                    : 'bg-destructive/10 text-destructive'
                    }`}>
                    {user.active ? 'Active' : 'Suspended'}
                </Badge>
            </TableCell>
            <TableCell className="py-1.5">
                <div className="flex flex-wrap gap-1">
                    {(user.groups || []).map((group: any) => (
                        <Badge key={group.value} variant="outline" className="rounded-md font-bold text-[7px] tracking-tight px-1 py-0 bg-on-surface/5 border-none text-on-surface-variant/60">
                            {group.display}
                        </Badge>
                    ))}
                    {(!user.groups || user.groups.length === 0) && (
                        <span className="text-[8px] font-medium text-on-surface-variant/20 italic">No groups</span>
                    )}
                </div>
            </TableCell>
            <TableCell className="py-1.5 text-right pr-4">
                <div className="flex items-center justify-end gap-2">
                    <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => navigate(`/users/edit/${user.id}`)}
                        className="h-7 px-3 rounded-lg bg-primary/5 text-primary border border-primary/10 hover:bg-primary hover:text-primary-foreground transition-all font-bold text-[9px] uppercase tracking-wider"
                    >
                        Edit
                    </Button>
                    <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                            <Button
                                variant="ghost"
                                className="h-7 w-7 rounded-lg bg-on-surface/[0.03] border border-on-surface/5 hover:bg-surface-container hover:text-on-surface transition-all active:scale-95 flex items-center justify-center p-0"
                                title="More Actions"
                            >
                                <MoreHorizontal className="h-3.5 w-3.5" />
                            </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end" className="w-[160px] rounded-lg border-none shadow-xl shadow-on-surface/10 p-1 bg-card">
                            <DropdownMenuItem
                                onClick={() => navigate('/groups')}
                                className="font-bold text-[9px] tracking-tight gap-2 py-1.5 px-2.5 rounded-md focus:bg-primary/5 focus:text-primary cursor-pointer transition-colors"
                            >
                                <Settings2 className="w-3 h-3 opacity-40" /> Manage Groups
                            </DropdownMenuItem>
                            <DropdownMenuItem
                                onClick={() => {
                                    setSelectedUser(user);
                                    setIsPasswordDialogOpen(true);
                                }}
                                className="font-bold text-[9px] tracking-tight gap-2 py-1.5 px-2.5 rounded-md focus:bg-primary/5 focus:text-primary cursor-pointer transition-colors"
                            >
                                <Key className="w-3 h-3 opacity-40" /> Set Password
                            </DropdownMenuItem>
                            <DropdownMenuItem
                                onClick={() => handleSendResetLink(user.id)}
                                className="font-bold text-[9px] tracking-tight gap-2 py-1.5 px-2.5 rounded-md focus:bg-primary/5 focus:text-primary cursor-pointer transition-colors"
                            >
                                <Mail className="w-3 h-3 opacity-40" /> Send Reset Link
                            </DropdownMenuItem>
                            <DropdownMenuSeparator className="bg-on-surface/5 my-1 mx-2" />
                            <DropdownMenuItem
                                onClick={() => handleDeleteUser(user.id)}
                                className="text-destructive font-bold text-[9px] tracking-tight gap-2 py-1.5 px-2.5 rounded-md focus:bg-destructive/10 focus:text-destructive cursor-pointer transition-colors"
                            >
                                <ShieldAlert className="w-3 h-3" /> Delete User
                            </DropdownMenuItem>
                        </DropdownMenuContent>
                    </DropdownMenu>
                </div>
            </TableCell>
        </GlassTableRow>
    );
};
