import React, { useState, useEffect } from 'react';
import {
    getGroups, createGroup, deleteGroup,
    getGroupMembers, addUserToGroup, removeUserFromGroup,
    getSCIMUsers, Group
} from '../api';

interface User {
    id: string;
    userName?: string;
    email?: string;
    emails?: { value: string }[];
    status?: string;
}

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import BoringAvatar from 'boring-avatars';
import {
    Users, UserPlus, Trash2, Search, Plus,
    Loader2, X, ChevronRight, Layers, UserMinus, ArrowRight
} from 'lucide-react';
import {
    Dialog, DialogContent, DialogDescription,
    DialogFooter, DialogHeader, DialogTitle, DialogTrigger,
} from "@/components/ui/dialog";
import { cn } from '@/lib/utils';

const Groups: React.FC = () => {
    const [groups, setGroups] = useState<Group[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [searchTerm, setSearchTerm] = useState('');

    const [showCreate, setShowCreate] = useState(false);
    const [newGroupName, setNewGroupName] = useState('');
    const [newGroupDesc, setNewGroupDesc] = useState('');
    const [creating, setCreating] = useState(false);

    const [selectedGroup, setSelectedGroup] = useState<Group | null>(null);
    const [members, setMembers] = useState<User[]>([]);
    const [allUsers, setAllUsers] = useState<User[]>([]);
    const [loadingMembers, setLoadingMembers] = useState(false);
    const [searchUser, setSearchUser] = useState('');

    const fetchGroupsData = async () => {
        setLoading(true);
        try {
            const data = await getGroups();
            setGroups(data.groups || []);
        } catch {
            setError('Failed to load groups.');
        } finally {
            setLoading(false);
        }
    };

    const fetchAllUsers = async () => {
        try {
            const data = await getSCIMUsers();
            setAllUsers(data.Resources || []);
        } catch { }
    };

    useEffect(() => {
        fetchGroupsData();
        fetchAllUsers();
    }, []);

    const handleSelectGroup = async (group: Group) => {
        if (selectedGroup?.id === group.id) { setSelectedGroup(null); return; }
        setSelectedGroup(group);
        setLoadingMembers(true);
        try {
            const list = await getGroupMembers(group.id);
            setMembers(list || []);
        } catch { } finally {
            setLoadingMembers(false);
        }
    };

    const handleCreateGroup = async (e: React.FormEvent) => {
        e.preventDefault();
        setCreating(true);
        try {
            await createGroup({ name: newGroupName, description: newGroupDesc });
            setShowCreate(false);
            setNewGroupName('');
            setNewGroupDesc('');
            fetchGroupsData();
        } catch {
            setError('Failed to create group.');
        } finally {
            setCreating(false);
        }
    };

    const handleDeleteGroup = async (id: string) => {
        if (!window.confirm('Delete this group?')) return;
        try {
            await deleteGroup(id);
            if (selectedGroup?.id === id) setSelectedGroup(null);
            fetchGroupsData();
        } catch {
            setError('Failed to delete group.');
        }
    };

    const handleAddUser = async (user: User) => {
        if (!selectedGroup) return;
        try {
            await addUserToGroup(selectedGroup.id, user.id);
            const list = await getGroupMembers(selectedGroup.id);
            setMembers(list || []);
        } catch {
            alert('Failed to add user.');
        }
    };

    const handleRemoveUser = async (userID: string) => {
        if (!selectedGroup) return;
        try {
            await removeUserFromGroup(selectedGroup.id, userID);
            const list = await getGroupMembers(selectedGroup.id);
            setMembers(list || []);
        } catch {
            alert('Failed to remove user.');
        }
    };

    const filteredGroups = groups.filter(g =>
        g.name?.toLowerCase().includes(searchTerm.toLowerCase())
    );

    const filteredAvailableUsers = allUsers.filter(u => {
        const email = (u.email || u.emails?.[0]?.value || '').toLowerCase();
        return !members.find(m => m.id === u.id) && email.includes(searchUser.toLowerCase());
    });

    return (
        <div className="flex h-full gap-0 animate-in fade-in duration-500">
            {/* ── Master: group list ─────────────────────────────────── */}
            <div className={cn(
                "flex flex-col transition-all duration-300",
                selectedGroup ? "w-[380px] min-w-[380px]" : "flex-1"
            )}>
                {/* Toolbar */}
                <div className="flex items-center justify-between px-6 py-4 border-b border-on-surface/5 bg-card/50">
                    <div>
                        <h1 className="text-sm font-bold tracking-tight text-on-surface">Groups</h1>
                        <p className="text-[10px] text-on-surface-variant/40 font-medium mt-0.5">
                            {groups.length} identity groups
                        </p>
                    </div>
                    <div className="flex items-center gap-2">
                        <div className="relative group">
                            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3 w-3 text-on-surface-variant/30 group-focus-within:text-primary transition-colors" />
                            <Input
                                placeholder="Filter groups..."
                                className="h-8 w-40 border-none rounded-lg text-[11px] pl-8 bg-surface-container/50 ring-1 ring-on-surface/5 focus-visible:ring-primary/20 font-medium"
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                            />
                        </div>
                        <Dialog open={showCreate} onOpenChange={setShowCreate}>
                            <DialogTrigger asChild>
                                <Button className="h-8 rounded-lg bg-primary text-primary-foreground font-bold text-[10px] px-3 shadow-md shadow-primary/20">
                                    <Plus className="w-3 h-3 mr-1.5" /> New Group
                                </Button>
                            </DialogTrigger>
                            <DialogContent className="sm:max-w-[420px] p-0 border-none rounded-2xl shadow-2xl bg-card overflow-hidden">
                                <div className="bg-primary p-6 text-primary-foreground">
                                    <DialogHeader>
                                        <DialogTitle className="text-lg font-bold flex items-center gap-3 text-primary-foreground">
                                            <div className="w-8 h-8 bg-black/10 rounded-lg flex items-center justify-center">
                                                <Plus className="w-4 h-4" />
                                            </div>
                                            Create Group
                                        </DialogTitle>
                                        <DialogDescription className="text-primary-foreground/60 text-xs mt-1">
                                            Group users together to manage shared access policies.
                                        </DialogDescription>
                                    </DialogHeader>
                                </div>
                                <form onSubmit={handleCreateGroup} className="p-6 space-y-4">
                                    <div className="space-y-1.5">
                                        <Label className="text-[9px] font-bold tracking-widest text-on-surface-variant/40 uppercase">Group Name</Label>
                                        <Input
                                            value={newGroupName}
                                            onChange={(e) => setNewGroupName(e.target.value)}
                                            className="h-9 rounded-lg bg-surface-container/30 border-none ring-1 ring-on-surface/5 focus-visible:ring-primary/20 text-xs font-medium"
                                            placeholder="e.g. INFRA_CORE"
                                            required
                                        />
                                    </div>
                                    <div className="space-y-1.5">
                                        <Label className="text-[9px] font-bold tracking-widest text-on-surface-variant/40 uppercase">Description</Label>
                                        <Input
                                            value={newGroupDesc}
                                            onChange={(e) => setNewGroupDesc(e.target.value)}
                                            className="h-9 rounded-lg bg-surface-container/30 border-none ring-1 ring-on-surface/5 focus-visible:ring-primary/20 text-xs font-medium"
                                            placeholder="Purpose of this group..."
                                        />
                                    </div>
                                    <DialogFooter>
                                        <Button type="submit" disabled={creating} className="w-full h-9 rounded-lg font-bold text-xs shadow-md shadow-primary/10">
                                            {creating ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Create Group'}
                                        </Button>
                                    </DialogFooter>
                                </form>
                            </DialogContent>
                        </Dialog>
                    </div>
                </div>

                {/* Group list */}
                <div className="flex-1 overflow-y-auto custom-scrollbar bg-card/20">
                    {loading ? (
                        <div className="h-48 flex items-center justify-center">
                            <Loader2 className="h-6 w-6 animate-spin text-primary/30" />
                        </div>
                    ) : filteredGroups.length === 0 ? (
                        <div className="py-20 text-center">
                            <p className="text-[11px] text-on-surface-variant/30 font-medium">No groups found</p>
                        </div>
                    ) : (
                        <div className="divide-y divide-on-surface/5">
                            {filteredGroups.map((group) => {
                                const isSelected = selectedGroup?.id === group.id;
                                return (
                                    <div
                                        key={group.id}
                                        onClick={() => handleSelectGroup(group)}
                                        className={cn(
                                            "flex items-center gap-3 px-5 py-3.5 cursor-pointer transition-all group",
                                            isSelected
                                                ? "bg-primary/5 border-l-2 border-primary"
                                                : "hover:bg-surface-container/40 border-l-2 border-transparent"
                                        )}
                                    >
                                        <div className={cn(
                                            "w-8 h-8 rounded-lg flex items-center justify-center shrink-0 transition-colors",
                                            isSelected ? "bg-primary/15" : "bg-surface-container/80 group-hover:bg-primary/8"
                                        )}>
                                            <Layers className={cn(
                                                "w-4 h-4 transition-colors",
                                                isSelected ? "text-primary" : "text-on-surface-variant/40 group-hover:text-primary"
                                            )} />
                                        </div>
                                        <div className="flex-1 min-w-0">
                                            <p className={cn(
                                                "text-[12px] font-semibold truncate transition-colors",
                                                isSelected ? "text-primary" : "text-on-surface group-hover:text-primary"
                                            )}>
                                                {group.name}
                                            </p>
                                            <p className="text-[10px] text-on-surface-variant/30 truncate font-medium mt-0.5">
                                                {group.description || 'No description'}
                                            </p>
                                        </div>
                                        <ChevronRight className={cn(
                                            "w-3 h-3 shrink-0 transition-all",
                                            isSelected ? "text-primary rotate-90" : "text-on-surface-variant/20"
                                        )} />
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
            </div>

            {/* ── Detail panel ──────────────────────────────────────── */}
            {selectedGroup && (
                <div className="flex-1 border-l border-on-surface/5 bg-card flex flex-col overflow-hidden animate-in slide-in-from-right-4 duration-300">
                    {/* Header */}
                    <div className="bg-primary px-6 py-5 text-primary-foreground shrink-0">
                        <div className="flex items-start justify-between">
                            <div className="flex items-center gap-4">
                                <div className="w-10 h-10 bg-black/10 rounded-xl flex items-center justify-center">
                                    <Users className="w-5 h-5 text-primary-foreground" />
                                </div>
                                <div>
                                    <h2 className="text-base font-bold text-primary-foreground">{selectedGroup.name}</h2>
                                    <p className="text-primary-foreground/60 text-[11px] font-medium mt-0.5">
                                        {members.length} member{members.length !== 1 ? 's' : ''}
                                    </p>
                                </div>
                            </div>
                            <div className="flex items-center gap-2">
                                <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => handleDeleteGroup(selectedGroup.id)}
                                    className="h-7 px-2 rounded-lg bg-black/10 hover:bg-black/20 text-primary-foreground text-[10px] font-bold"
                                >
                                    <Trash2 className="w-3 h-3 mr-1" /> Delete
                                </Button>
                                <Button
                                    variant="ghost"
                                    size="icon"
                                    className="h-7 w-7 rounded-lg bg-black/10 hover:bg-black/20 text-primary-foreground"
                                    onClick={() => setSelectedGroup(null)}
                                >
                                    <X className="w-3.5 h-3.5" />
                                </Button>
                            </div>
                        </div>
                    </div>

                    {/* Body */}
                    <div className="flex-1 overflow-y-auto custom-scrollbar p-5 space-y-5">
                        {/* Current members */}
                        <section>
                            <h3 className="text-[9px] font-bold tracking-widest text-on-surface-variant/30 uppercase mb-3">
                                Members ({members.length})
                            </h3>
                            {loadingMembers ? (
                                <div className="flex justify-center py-8">
                                    <Loader2 className="h-5 w-5 animate-spin text-primary/30" />
                                </div>
                            ) : members.length === 0 ? (
                                <div className="py-6 text-center bg-surface-container/20 rounded-xl border-2 border-dashed border-on-surface/5">
                                    <p className="text-[10px] font-medium text-on-surface-variant/30">No members yet</p>
                                </div>
                            ) : (
                                <div className="space-y-1">
                                    {members.map(member => {
                                        const email = member.email || member.emails?.[0]?.value || '';
                                        return (
                                            <div key={member.id} className="flex items-center gap-3 p-2 rounded-lg hover:bg-surface-container/40 group transition-all">
                                                <Avatar className="h-7 w-7 rounded-lg ring-1 ring-on-surface/5 shrink-0">
                                                    <BoringAvatar
                                                        size={28}
                                                        name={email}
                                                        variant="marble"
                                                        colors={["#00FF9E", "#17171C", "#8B5CF6", "#06B6D4", "#10B981"]}
                                                    />
                                                </Avatar>
                                                <div className="flex-1 min-w-0">
                                                    <p className="text-[11px] font-semibold text-on-surface truncate">{email || member.userName}</p>
                                                </div>
                                                <Button
                                                    variant="ghost"
                                                    size="icon"
                                                    onClick={() => handleRemoveUser(member.id)}
                                                    className="h-6 w-6 rounded-md opacity-0 group-hover:opacity-100 transition-all hover:bg-destructive/10 hover:text-destructive"
                                                >
                                                    <UserMinus className="w-3 h-3" />
                                                </Button>
                                            </div>
                                        );
                                    })}
                                </div>
                            )}
                        </section>

                        {/* Add members */}
                        <section className="border-t border-on-surface/5 pt-5">
                            <h3 className="text-[9px] font-bold tracking-widest text-on-surface-variant/30 uppercase mb-3">Add Members</h3>
                            <div className="relative group mb-3">
                                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3 w-3 text-on-surface-variant/30 group-focus-within:text-primary transition-colors" />
                                <Input
                                    placeholder="Search users to add..."
                                    className="h-8 pl-8 border-none rounded-lg text-[11px] bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-primary/20 font-medium"
                                    value={searchUser}
                                    onChange={(e) => setSearchUser(e.target.value)}
                                />
                            </div>
                            <div className="space-y-1 max-h-[240px] overflow-y-auto custom-scrollbar">
                                {filteredAvailableUsers.length === 0 ? (
                                    <p className="text-[10px] text-on-surface-variant/30 font-medium text-center py-4">No users available to add</p>
                                ) : filteredAvailableUsers.map(user => {
                                    const email = user.email || user.emails?.[0]?.value || '';
                                    return (
                                        <div key={user.id} className="flex items-center gap-3 p-2 rounded-lg hover:bg-surface-container/40 group transition-all">
                                            <Avatar className="h-7 w-7 rounded-lg ring-1 ring-on-surface/5 shrink-0">
                                                <BoringAvatar
                                                    size={28}
                                                    name={email}
                                                    variant="marble"
                                                    colors={["#00FF9E", "#17171C", "#8B5CF6", "#06B6D4", "#10B981"]}
                                                />
                                            </Avatar>
                                            <p className="flex-1 text-[11px] font-semibold text-on-surface truncate">{email || user.userName}</p>
                                            <Button
                                                variant="ghost"
                                                size="sm"
                                                onClick={() => handleAddUser(user)}
                                                className="h-6 px-2 rounded-md text-[9px] font-bold bg-primary/5 text-primary hover:bg-primary hover:text-primary-foreground transition-all opacity-0 group-hover:opacity-100"
                                            >
                                                <UserPlus className="w-3 h-3 mr-1" /> Add
                                            </Button>
                                        </div>
                                    );
                                })}
                            </div>
                        </section>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Groups;
