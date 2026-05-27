import React from 'react';
import { Group } from '../api';
import { GlassTableRow } from '@/components/layout';
import { TableCell } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
    Sheet,
    SheetContent,
    SheetDescription,
    SheetHeader,
    SheetTitle,
    SheetTrigger,
} from "@/components/ui/sheet";
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import BoringAvatar from 'boring-avatars';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
    Users,
    Trash2,
    Search,
    ShieldCheck,
    ShieldAlert,
    Loader2,
    ArrowRight,
} from 'lucide-react';

interface User {
    id: string;
    userName?: string;
    email?: string;
    emails?: { value: string }[];
    status?: string;
}

interface GroupTableRowProps {
    group: Group;
    members: User[];
    allUsers: User[];
    loadingMembers: boolean;
    searchUser: string;
    setSearchUser: (value: string) => void;
    handleManageMembers: (group: Group) => void;
    handleAddUser: (user: User) => void;
    handleRemoveUser: (userId: string) => void;
    handleDeleteGroup: (id: string) => void;
}

export const GroupTableRow: React.FC<GroupTableRowProps> = ({
    group,
    members,
    allUsers,
    loadingMembers,
    searchUser,
    setSearchUser,
    handleManageMembers,
    handleAddUser,
    handleRemoveUser,
    handleDeleteGroup,
}) => {
    // Filter available users inside the component
    const filteredAvailableUsers = allUsers.filter(u => {
        const primaryEmail = (u.email || (u.emails && u.emails.length > 0 ? u.emails[0].value : '')) || '';
        const searchSafeEmail = primaryEmail.toLowerCase();
        const searchSafeQuery = (searchUser || '').toLowerCase();
        return !members.find(m => m.id === u.id) && searchSafeEmail.includes(searchSafeQuery);
    });

    return (
        <GlassTableRow className="hover:bg-surface-container/20 transition-all border-b border-on-surface/5 last:border-0 group">
            <TableCell className="py-1.5 pl-4">
                <div className="flex items-center gap-2">
                    <span className="font-bold text-xs tracking-tight text-on-surface group-hover:text-primary transition-colors">
                        {group.name}
                    </span>
                </div>
            </TableCell>
            <TableCell className="py-1.5">
                <code className="bg-surface-container px-2 py-0.5 rounded text-primary font-mono text-[9px] tracking-tight">
                    {group.id}
                </code>
            </TableCell>
            <TableCell className="py-1.5">
                <span className="text-[10px] font-medium text-on-surface-variant/60 flex items-center gap-2">
                    {group.created_at ? new Date(group.created_at).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : 'Verified'}
                </span>
            </TableCell>
            <TableCell className="py-1.5 text-right pr-4 space-x-1">
                <Sheet onOpenChange={(open) => {
                    if (open) {
                        handleManageMembers(group);
                    }
                }}>
                    <SheetTrigger asChild>
                        <Button variant="ghost" className="h-7 rounded-md px-2.5 font-bold text-[10px] tracking-tight text-primary hover:bg-primary/5 transition-all">
                            <Users className="w-3.5 h-3.5 mr-1.5 opacity-60" /> Manage Members
                        </Button>
                    </SheetTrigger>
                    <SheetContent className="sm:max-w-xl p-0 border-none rounded-l-[24px] shadow-2xl shadow-on-surface/20 bg-card overflow-hidden">
                        <div className="bg-primary p-8 text-primary-foreground">
                            <SheetHeader>
                                <div className="flex items-center gap-6">
                                    <div className="w-14 h-14 bg-black/10 rounded-2xl flex items-center justify-center backdrop-blur-md">
                                        <Users className="w-7 h-7 text-primary-foreground" />
                                    </div>
                                    <div>
                                        <SheetTitle className="text-2xl font-bold tracking-tight text-primary-foreground">
                                            {group.name}
                                        </SheetTitle>
                                        <SheetDescription className="text-primary-foreground/50 font-bold text-[10px] mt-2 tracking-tight uppercase">
                                            Manage the members of this group.
                                        </SheetDescription>
                                    </div>
                                </div>
                            </SheetHeader>
                        </div>
                        <ScrollArea className="h-[calc(100vh-140px)]">
                            <div className="p-8 space-y-10">
                                {/* Current Members Section */}
                                <section>
                                    <div className="flex items-center justify-between mb-4">
                                        <h3 className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 flex items-center gap-2 uppercase">
                                            <ShieldCheck className="w-3.5 h-3.5 text-success" />
                                            Current Members
                                        </h3>
                                        <Badge className="bg-primary/5 text-primary border-none rounded-lg h-6 px-3 text-[10px] font-bold shadow-none">
                                            {members.length} Members
                                        </Badge>
                                    </div>

                                    <div className="space-y-2">
                                        {loadingMembers ? (
                                            <div className="py-12 flex items-center justify-center">
                                                <Loader2 className="w-8 h-8 animate-spin text-primary/30" />
                                            </div>
                                        ) : members.length === 0 ? (
                                            <div className="py-12 text-center border-2 border-dashed rounded-2xl bg-surface-container/10">
                                                <ShieldAlert className="w-8 h-8 mx-auto text-on-surface-variant/10 mb-2" />
                                                <p className="text-xs font-medium text-on-surface-variant/40">No users are in this group.</p>
                                            </div>
                                        ) : (
                                            <div className="grid gap-2">
                                                {members.map(member => (
                                                    <div key={member.id} className="flex items-center justify-between p-3 bg-card border border-on-surface/5 rounded-xl hover:border-primary/20 hover:shadow-lg hover:shadow-primary/5 transition-all group/member">
                                                        <div className="flex items-center gap-3">
                                                            {(() => {
                                                                const email = member.email || (member.emails && member.emails.length > 0 ? member.emails[0].value : '');
                                                                return (
                                                                    <>
                                                                        <Avatar className="h-8 w-8 rounded-lg ring-1 ring-on-surface/5 overflow-hidden">
                                                                            <BoringAvatar
                                                                                size={32}
                                                                                name={email || ''}
                                                                                variant="marble"
                                                                                colors={["#00FF9E", "#17171C", "#8B5CF6", "#06B6D4", "#10B981"]}
                                                                            />
                                                                        </Avatar>
                                                                        <div>
                                                                            <p className="text-xs font-bold text-on-surface">{email || 'Unknown User'}</p>
                                                                            <p className="text-[9px] font-bold text-on-surface-variant/20 mt-0.5 flex items-center gap-1 tracking-tight">
                                                                                <span className={`h-1.5 w-1.5 rounded-full ${member.status === 'active' ? 'bg-success' : 'bg-destructive/100'}`} />
                                                                                {member.status === 'active' ? 'Active' : 'Offline'}
                                                                            </p>
                                                                        </div>
                                                                    </>
                                                                );
                                                            })()}
                                                        </div>
                                                        <Button
                                                            variant="ghost"
                                                            size="icon"
                                                            className="h-8 w-8 rounded-lg hover:bg-destructive/10 hover:text-destructive transition-all opacity-0 group-hover/member:opacity-100"
                                                            onClick={() => handleRemoveUser(member.id)}
                                                        >
                                                            <Trash2 className="w-4 h-4" />
                                                        </Button>
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                </section>

                                {/* Assign New Members Section */}
                                <section className="space-y-6">
                                    <div className="flex flex-col gap-4">
                                        <h3 className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 flex items-center gap-2 uppercase">
                                            <Users className="w-3.5 h-3.5 text-primary" />
                                            Add More Members
                                        </h3>
                                        <div className="relative group">
                                            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-on-surface-variant/40 group-focus-within:text-primary transition-colors" />
                                            <Input
                                                placeholder="Search for users to add..."
                                                className="h-10 border-none rounded-xl font-medium text-xs pl-10 bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all"
                                                value={searchUser}
                                                onChange={(e) => setSearchUser(e.target.value)}
                                            />
                                        </div>
                                    </div>

                                    <div className="grid gap-2 max-h-[300px] overflow-y-auto pr-2 custom-scrollbar">
                                        {filteredAvailableUsers.length === 0 ? (
                                            <div className="py-8 text-center bg-surface-container/10 rounded-2xl border-2 border-dashed">
                                                <p className="text-[10px] font-bold text-on-surface-variant/20 tracking-tight uppercase">No users found.</p>
                                            </div>
                                        ) : (
                                            filteredAvailableUsers.map(user => (
                                                <div key={user.id} className="flex items-center justify-between p-2.5 bg-card border border-on-surface/5 rounded-xl hover:border-primary/20 hover:shadow-lg hover:shadow-primary/5 transition-all group/add">
                                                    <div className="flex items-center gap-3">
                                                        {(() => {
                                                            const email = user.email || (user.emails && user.emails.length > 0 ? user.emails[0].value : '');
                                                            return (
                                                                <>
                                                                    <Avatar className="h-7 w-7 rounded-lg ring-1 ring-on-surface/5 overflow-hidden">
                                                                        <BoringAvatar
                                                                            size={28}
                                                                            name={email || ''}
                                                                            variant="marble"
                                                                            colors={["#00FF9E", "#17171C", "#8B5CF6", "#06B6D4", "#10B981"]}
                                                                        />
                                                                    </Avatar>
                                                                    <p className="text-[11px] font-bold text-on-surface">{email || 'Anonymous'}</p>
                                                                </>
                                                            );
                                                        })()}
                                                    </div>
                                                    <Button
                                                        size="icon"
                                                        variant="ghost"
                                                        className="h-7 w-7 rounded-lg text-primary hover:bg-primary hover:text-primary-foreground transition-all"
                                                        onClick={() => handleAddUser(user)}
                                                    >
                                                        <ArrowRight className="w-3.5 h-3.5" />
                                                    </Button>
                                                </div>
                                            ))
                                        )}
                                    </div>
                                </section>
                            </div>
                        </ScrollArea>
                    </SheetContent>
                </Sheet>
                <Button
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7 rounded-md hover:bg-destructive/10 hover:text-destructive transition-all opacity-40 hover:opacity-100"
                    onClick={() => handleDeleteGroup(group.id)}
                >
                    <Trash2 className="w-3.5 h-3.5" />
                </Button>
            </TableCell>
        </GlassTableRow>
    );
};
