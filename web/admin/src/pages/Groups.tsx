import React, { useState, useEffect } from 'react';
import {
    getGroups,
    createGroup,
    deleteGroup,
    getGroupMembers,
    addUserToGroup,
    removeUserFromGroup,
    getSCIMUsers,
    Group
} from '../api';

interface User {
    id: string;
    userName?: string;
    email?: string;
    emails?: { value: string }[];
    status?: string;
}
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import {
    Users,
    UserPlus,
    Trash2,
    Search,
    Plus,
    ShieldCheck,
    ShieldAlert,
    Loader2,
    MoreHorizontal,
    ArrowRight,
    UsersIcon
} from 'lucide-react';
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from "@/components/ui/dialog";
import {
    Sheet,
    SheetContent,
    SheetDescription,
    SheetHeader,
    SheetTitle,
    SheetTrigger,
} from "@/components/ui/sheet";
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { ScrollArea } from '@/components/ui/scroll-area';
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassTable, GlassTableHeader, GlassTableHead, GlassTableRow, GlassCardDescription } from '@/components/layout';

const Groups: React.FC = () => {
    const [groups, setGroups] = useState<Group[]>([]);
    const [total, setTotal] = useState(0);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    // Group Creation
    const [showCreate, setShowCreate] = useState(false);
    const [newGroupName, setNewGroupName] = useState('');
    const [newGroupDesc, setNewGroupDesc] = useState('');
    const [creating, setCreating] = useState(false);

    // Member Management
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
            setTotal(data.total || 0);
        } catch (err) {
            setError('Failed to load identity groups.');
        } finally {
            setLoading(false);
        }
    };

    const fetchAllUsers = async () => {
        try {
            const data = await getSCIMUsers();
            setAllUsers(data.Resources || []);
        } catch (err) {
            console.error('Failed to load users for assignment', err);
        }
    };

    useEffect(() => {
        fetchGroupsData();
        fetchAllUsers();
    }, []);

    const handleCreateGroup = async (e: React.FormEvent) => {
        e.preventDefault();
        setCreating(true);
        try {
            await createGroup({ name: newGroupName, description: newGroupDesc });
            setShowCreate(false);
            setNewGroupName('');
            setNewGroupDesc('');
            fetchGroupsData();
        } catch (err) {
            setError('Failed to create group.');
        } finally {
            setCreating(false);
        }
    };

    const handleDeleteGroup = async (id: string) => {
        if (!window.confirm('Are you sure you want to delete this group?')) return;
        try {
            await deleteGroup(id);
            fetchGroupsData();
        } catch (err) {
            setError('Failed to delete group.');
        }
    };

    const handleManageMembers = async (group: Group) => {
        setSelectedGroup(group);
        setLoadingMembers(true);
        try {
            const memberList = await getGroupMembers(group.id);
            setMembers(memberList || []);
        } catch (err) {
            console.error('Failed to load members', err);
        } finally {
            setLoadingMembers(false);
        }
    };

    const handleAddUser = async (user: User) => {
        if (!selectedGroup) return;
        try {
            await addUserToGroup(selectedGroup.id, user.id);
            const newList = await getGroupMembers(selectedGroup.id);
            setMembers(newList || []);
        } catch (err) {
            alert('Failed to add user to group.');
        }
    };

    const handleRemoveUser = async (userID: string) => {
        if (!selectedGroup) return;
        try {
            await removeUserFromGroup(selectedGroup.id, userID);
            const newList = await getGroupMembers(selectedGroup.id);
            setMembers(newList || []);
        } catch (err) {
            alert('Failed to remove user from group.');
        }
    };

    const filteredAvailableUsers = allUsers.filter(u => {
        const primaryEmail = (u.email || (u.emails && u.emails.length > 0 ? u.emails[0].value : '')) || '';
        const searchSafeEmail = primaryEmail.toLowerCase();
        const searchSafeQuery = (searchUser || '').toLowerCase();
        return !members.find(m => m.id === u.id) && searchSafeEmail.includes(searchSafeQuery);
    });

    if (loading && groups.length === 0) return <div className="h-[400px] flex items-center justify-center"><Loader2 className="h-10 w-10 animate-spin text-primary opacity-20" /></div>;

    return (
        <div className="space-y-4 animate-in fade-in duration-700">
            <PageHeader
                icon={<Users className="w-8 h-8 text-primary" />}
                title="Groups"
                description="Manage how users access resources by grouping them together. Create groups to apply security rules to many users at once."
                actions={
                    <Dialog open={showCreate} onOpenChange={setShowCreate}>
                        <DialogTrigger asChild>
                            <Button className="h-9 rounded-lg bg-primary text-primary-foreground font-bold tracking-tight text-[10px] px-6 shadow-lg shadow-primary/20 transition-all hover:scale-[1.02] active:scale-[0.98]">
                                <Plus className="w-3.5 h-3.5 mr-2" /> Add New Group
                            </Button>
                        </DialogTrigger>
                        <DialogContent className="sm:max-w-[480px] p-0 border-none rounded-[32px] shadow-2xl shadow-on-surface/10 bg-card overflow-hidden">
                            <div className="bg-primary p-8 text-white">
                                <DialogHeader>
                                    <DialogTitle className="text-xl font-bold tracking-tight flex items-center gap-3">
                                        <div className="w-10 h-10 bg-card/20 rounded-xl flex items-center justify-center backdrop-blur-md">
                                            <Plus className="w-5 h-5 text-white" />
                                        </div>
                                        Create Group
                                    </DialogTitle>
                                    <DialogDescription className="text-on-inverse/70 font-medium text-xs mt-2 tracking-tight">
                                        Create a new group to manage user access.
                                    </DialogDescription>
                                </DialogHeader>
                            </div>
                            <form onSubmit={handleCreateGroup} className="p-8 space-y-6 bg-card">
                                <div className="space-y-4">
                                    <div className="space-y-2">
                                        <Label htmlFor="name" className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 ml-1 uppercase">Group Name</Label>
                                        <Input
                                            id="name"
                                            value={newGroupName}
                                            onChange={(e) => setNewGroupName(e.target.value)}
                                            className="h-10 rounded-lg bg-surface-container/30 border-none ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium transition-all text-xs"
                                            placeholder="e.g. INFRA_CORE"
                                            required
                                        />
                                    </div>
                                    <div className="space-y-2">
                                        <Label htmlFor="desc" className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 ml-1 uppercase">Description</Label>
                                        <Input
                                            id="desc"
                                            value={newGroupDesc}
                                            onChange={(e) => setNewGroupDesc(e.target.value)}
                                            className="h-10 rounded-lg bg-surface-container/30 border-none ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium transition-all text-xs"
                                            placeholder="Purpose of this group..."
                                        />
                                    </div>
                                </div>
                                <DialogFooter className="pt-2">
                                    <Button type="submit" disabled={creating} className="w-full h-10 rounded-lg font-bold text-xs shadow-md shadow-primary/10">
                                        {creating ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Create Group'}
                                    </Button>
                                </DialogFooter>
                            </form>
                        </DialogContent>
                    </Dialog>
                }
            />

            <GlassCard className="overflow-hidden border-none shadow-xl shadow-on-surface/5 bg-card">
                <GlassCardHeader className="py-2 px-4">
                    <div className="flex items-center gap-4">
                        <div className="p-2 bg-primary/5 rounded-lg">
                            <UsersIcon className="w-4 h-4 text-primary" />
                        </div>
                        <div>
                            <GlassCardTitle className="text-base font-bold tracking-tight text-on-surface">All Groups</GlassCardTitle>
                            <p className="text-on-surface-variant/40 font-bold text-[9px] mt-0.5 tracking-tight uppercase">
                                {total} Total Groups
                            </p>
                        </div>
                    </div>
                </GlassCardHeader>
                <GlassCardContent className="p-0">
                    <div className="overflow-x-auto">
                        <GlassTable>
                            <GlassTableHeader>
                                <GlassTableRow className="hover:bg-transparent border-b border-on-surface/5">
                                    <GlassTableHead className="py-2 pl-4 font-bold text-[8px] tracking-widest text-on-surface-variant/40 uppercase">Group Name</GlassTableHead>
                                    <GlassTableHead className="py-2 font-bold text-[8px] tracking-widest text-on-surface-variant/40 uppercase">Group ID</GlassTableHead>
                                    <GlassTableHead className="py-2 font-bold text-[8px] tracking-widest text-on-surface-variant/40 uppercase">Created On</GlassTableHead>
                                    <GlassTableHead className="py-2 text-right font-bold text-[8px] tracking-widest text-on-surface-variant/40 pr-4 uppercase">Actions</GlassTableHead>
                                </GlassTableRow>
                            </GlassTableHeader>
                            <TableBody>
                                {groups.length === 0 ? (
                                    <GlassTableRow>
                                        <TableCell colSpan={4} className="py-32 text-center text-sm font-medium text-on-surface-variant/40">
                                            No groups found.
                                        </TableCell>
                                    </GlassTableRow>
                                ) : (
                                    groups.map((group) => (
                                        <GlassTableRow key={group.id} className="hover:bg-surface-container/20 transition-all border-b border-on-surface/5 last:border-0 group">
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
                                                <Sheet onOpenChange={() => handleManageMembers(group)}>
                                                    <SheetTrigger asChild>
                                                        <Button variant="ghost" className="h-7 rounded-md px-2.5 font-bold text-[10px] tracking-tight text-primary hover:bg-primary/5 transition-all">
                                                            <Users className="w-3.5 h-3.5 mr-1.5 opacity-60" /> Manage Members
                                                        </Button>
                                                    </SheetTrigger>
                                                    <SheetContent className="sm:max-w-xl p-0 border-none rounded-l-[24px] shadow-2xl shadow-on-surface/20 bg-card overflow-hidden">
                                                        <div className="bg-primary p-8 text-white">
                                                            <SheetHeader>
                                                                <div className="flex items-center gap-6">
                                                                    <div className="w-14 h-14 bg-card/20 rounded-2xl flex items-center justify-center backdrop-blur-md">
                                                                        <Users className="w-7 h-7 text-white" />
                                                                    </div>
                                                                    <div>
                                                                        <SheetTitle className="text-2xl font-bold tracking-tight text-white">
                                                                            {group.name}
                                                                        </SheetTitle>
                                                                        <SheetDescription className="text-on-inverse/50 font-bold text-[10px] mt-2 tracking-tight uppercase">
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
                                                                                                            <AvatarImage src={`https://avatar.vercel.sh/${email}`} className="contrast-[1.1]" />
                                                                                                            <AvatarFallback className="text-[9px] font-bold uppercase bg-primary/5 text-primary">{email ? email.substring(0, 2) : '??'}</AvatarFallback>
                                                                                                        </Avatar>
                                                                                                        <div>
                                                                                                            <p className="text-xs font-bold text-on-surface">{email || 'Unknown User'}</p>
                                                                                                            <p className="text-[9px] font-bold text-on-surface-variant/20 mt-0.5 flex items-center gap-1 tracking-tight">
                                                                                                                <div className={`h-1 w-1 rounded-full ${member.status === 'active' ? 'bg-success' : 'bg-destructive/100'}`} />
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
                                                                            <UserPlus className="w-3.5 h-3.5 text-primary" />
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
                                                                                                        <AvatarImage src={`https://avatar.vercel.sh/${email}`} className="contrast-[1.1]" />
                                                                                                        <AvatarFallback className="text-[9px] font-bold uppercase bg-primary/5 text-primary">{email ? email.substring(0, 2) : '??'}</AvatarFallback>
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
                                    ))
                                )}
                            </TableBody>
                        </GlassTable>
                    </div>
                </GlassCardContent>
            </GlassCard>
        </div>
    );
};

export default Groups;
