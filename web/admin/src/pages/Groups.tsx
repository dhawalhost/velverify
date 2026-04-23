import React, { useState, useEffect } from 'react';
import {
    getGroups,
    createGroup,
    deleteGroup,
    getGroupMembers,
    addUserToGroup,
    removeUserFromGroup,
    getSCIMUsers,
    Group,
    User
} from '../api';
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
        <div className="space-y-10 animate-in fade-in duration-700">
            <PageHeader
                icon={<Users className="w-10 h-10 text-primary" />}
                title="Identity Groups"
                description="Manage organizational resource access by bundling subjects into logical architectural clusters. Orchestrate group-based policy application."
                actions={
                    <Dialog open={showCreate} onOpenChange={setShowCreate}>
                        <DialogTrigger asChild>
                            <Button className="h-11 rounded-xl bg-primary text-white font-bold tracking-tight text-[11px] px-8 shadow-xl shadow-primary/20 transition-all hover:scale-[1.02] active:scale-[0.98]">
                                <Plus className="w-4 h-4 mr-3" /> Initialize New Group
                            </Button>
                        </DialogTrigger>
                        <DialogContent className="sm:max-w-[480px] p-0 border-none rounded-[32px] shadow-2xl shadow-on-surface/10 bg-white overflow-hidden">
                            <div className="bg-primary p-12 text-white">
                                <DialogHeader>
                                    <DialogTitle className="text-3xl font-bold tracking-tight flex items-center gap-4">
                                        <div className="w-12 h-12 bg-white/20 rounded-2xl flex items-center justify-center backdrop-blur-md">
                                            <Plus className="w-6 h-6 text-white" />
                                        </div>
                                        Provision Group
                                    </DialogTitle>
                                    <DialogDescription className="text-white/70 font-medium text-sm mt-3 tracking-tight">
                                        Initialize a new architectural identity bundle for resource orchestration.
                                    </DialogDescription>
                                </DialogHeader>
                            </div>
                            <form onSubmit={handleCreateGroup} className="p-10 space-y-8 bg-white">
                                <div className="space-y-6">
                                    <div className="space-y-2.5">
                                        <Label htmlFor="name" className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Group Identifier</Label>
                                        <Input
                                            id="name"
                                            value={newGroupName}
                                            onChange={(e) => setNewGroupName(e.target.value)}
                                            className="h-12 rounded-xl bg-surface-container/30 border-none ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium transition-all"
                                            placeholder="e.g. INFRA_CORE"
                                            required
                                        />
                                    </div>
                                    <div className="space-y-2.5">
                                        <Label htmlFor="desc" className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Architectural Context</Label>
                                        <Input
                                            id="desc"
                                            value={newGroupDesc}
                                            onChange={(e) => setNewGroupDesc(e.target.value)}
                                            className="h-12 rounded-xl bg-surface-container/30 border-none ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium transition-all"
                                            placeholder="System-wide administrative privileges..."
                                        />
                                    </div>
                                </div>
                                <DialogFooter className="pt-4">
                                    <Button type="submit" disabled={creating} className="w-full h-12 rounded-xl font-bold text-sm shadow-md shadow-primary/10">
                                        {creating ? <Loader2 className="w-5 h-5 animate-spin" /> : 'Commit Group Matrix'}
                                    </Button>
                                </DialogFooter>
                            </form>
                        </DialogContent>
                    </Dialog>
                }
            />

            <GlassCard className="overflow-hidden border-none shadow-xl shadow-on-surface/5 bg-white">
                <GlassCardHeader className="py-8 px-10">
                    <div className="flex items-center gap-5">
                        <div className="p-3.5 bg-primary/5 rounded-2xl">
                            <UsersIcon className="w-6 h-6 text-primary" />
                        </div>
                        <div>
                            <GlassCardTitle className="text-2xl font-bold tracking-tight text-on-surface">Group Registry</GlassCardTitle>
                            <p className="text-on-surface-variant/40 font-bold text-[12px] mt-1 tracking-tight">
                                {total} Verified Cluster Hubs
                            </p>
                        </div>
                    </div>
                </GlassCardHeader>
                <GlassCardContent className="p-0">
                    <div className="overflow-x-auto">
                        <GlassTable>
                            <GlassTableHeader>
                                <GlassTableRow className="hover:bg-transparent border-b border-on-surface/5">
                                    <GlassTableHead className="py-6 pl-10 font-bold text-[12px] tracking-tight text-on-surface-variant/40">Cluster Identity</GlassTableHead>
                                    <GlassTableHead className="font-bold text-[12px] tracking-tight text-on-surface-variant/40">Core UID</GlassTableHead>
                                    <GlassTableHead className="font-bold text-[12px] tracking-tight text-on-surface-variant/40">Established</GlassTableHead>
                                    <GlassTableHead className="text-right font-bold text-[12px] tracking-tight text-on-surface-variant/40 pr-10">Orchestration</GlassTableHead>
                                </GlassTableRow>
                            </GlassTableHeader>
                            <TableBody>
                                {groups.length === 0 ? (
                                    <GlassTableRow>
                                        <TableCell colSpan={4} className="py-32 text-center text-sm font-medium text-on-surface-variant/40">
                                            No cluster groups have been initialized.
                                        </TableCell>
                                    </GlassTableRow>
                                ) : (
                                    groups.map((group) => (
                                        <GlassTableRow key={group.id} className="hover:bg-surface-container/20 transition-all border-b border-on-surface/5 last:border-0 group">
                                            <TableCell className="py-6 pl-10">
                                                <div className="flex items-center gap-4">
                                                    <span className="font-bold text-base tracking-tight text-on-surface group-hover:text-primary transition-colors">
                                                        {group.name}
                                                    </span>
                                                </div>
                                            </TableCell>
                                            <TableCell className="py-6">
                                                <code className="bg-surface-container px-3 py-1.5 rounded-lg text-primary font-mono text-[10px] tracking-tight">
                                                    {group.id}
                                                </code>
                                            </TableCell>
                                            <TableCell className="py-6">
                                                <span className="text-sm font-medium text-on-surface-variant/60 flex items-center gap-2">
                                                    {group.created_at ? new Date(group.created_at).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : 'Verified'}
                                                </span>
                                            </TableCell>
                                            <TableCell className="py-6 text-right pr-10 space-x-2">
                                                <Sheet onOpenChange={() => handleManageMembers(group)}>
                                                    <SheetTrigger asChild>
                                                        <Button variant="ghost" className="h-10 rounded-xl px-5 font-bold text-[11px] tracking-tight text-primary hover:bg-primary/5 transition-all">
                                                            <Users className="w-4 h-4 mr-2.5 opacity-60" /> Roster Management
                                                        </Button>
                                                    </SheetTrigger>
                                                    <SheetContent className="sm:max-w-2xl p-0 border-none rounded-l-[40px] shadow-2xl shadow-on-surface/20 bg-white overflow-hidden">
                                                        <div className="bg-primary p-12 text-white">
                                                            <SheetHeader>
                                                                <div className="flex items-center gap-8">
                                                                    <div className="w-20 h-20 bg-white/20 rounded-3xl flex items-center justify-center backdrop-blur-md">
                                                                        <Users className="w-9 h-9 text-white" />
                                                                    </div>
                                                                    <div>
                                                                        <SheetTitle className="text-4xl font-bold tracking-tight text-white">
                                                                            {group.name}
                                                                        </SheetTitle>
                                                                        <SheetDescription className="text-white/50 font-bold text-[12px] mt-4 tracking-tight">
                                                                            Roster management pool — {group.id?.substring(0, 8).toLowerCase() || 'arch-hub'}
                                                                        </SheetDescription>
                                                                    </div>
                                                                </div>
                                                            </SheetHeader>
                                                        </div>

                                                        <ScrollArea className="h-[calc(100vh-180px)]">
                                                            <div className="p-12 space-y-16">
                                                                {/* Current Members Section */}
                                                                <section>
                                                                    <div className="flex items-center justify-between mb-8">
                                                                        <h3 className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 flex items-center gap-3">
                                                                            <ShieldCheck className="w-4.5 h-4.5 text-emerald-500" />
                                                                            Current Identity Assignments
                                                                        </h3>
                                                                        <Badge className="bg-primary/5 text-primary border-none rounded-xl h-8 px-4 text-xs font-bold shadow-none">
                                                                            {members.length} Subjects
                                                                        </Badge>
                                                                    </div>

                                                                    <div className="space-y-4">
                                                                        {loadingMembers ? (
                                                                            <div className="py-20 flex items-center justify-center">
                                                                                <Loader2 className="w-10 h-10 animate-spin text-primary/30" />
                                                                            </div>
                                                                        ) : members.length === 0 ? (
                                                                            <div className="py-20 text-center border-2 border-dashed rounded-[32px] bg-surface-container/10">
                                                                                <ShieldAlert className="w-10 h-10 mx-auto text-on-surface-variant/10 mb-4" />
                                                                                <p className="text-sm font-medium text-on-surface-variant/40">No system subjects assigned to this cluster.</p>
                                                                            </div>
                                                                        ) : (
                                                                            <div className="grid gap-3">
                                                                                {members.map(member => (
                                                                                    <div key={member.id} className="flex items-center justify-between p-5 bg-white border border-on-surface/5 rounded-2xl hover:border-primary/20 hover:shadow-lg hover:shadow-primary/5 transition-all group/member">
                                                                                        <div className="flex items-center gap-5">
                                                                                            {(() => {
                                                                                                const email = member.email || (member.emails && member.emails.length > 0 ? member.emails[0].value : '');
                                                                                                return (
                                                                                                    <>
                                                                                                        <Avatar className="h-11 w-11 rounded-2xl ring-1 ring-on-surface/5 overflow-hidden">
                                                                                                            <AvatarImage src={`https://avatar.vercel.sh/${email}`} className="contrast-[1.1]" />
                                                                                                            <AvatarFallback className="text-[11px] font-bold uppercase bg-primary/5 text-primary">{email ? email.substring(0, 2) : '??'}</AvatarFallback>
                                                                                                        </Avatar>
                                                                                                        <div>
                                                                                                            <p className="text-sm font-bold text-on-surface">{email || 'Anonymous Subject'}</p>
                                                                                                            <p className="text-[10px] font-bold text-on-surface-variant/20 mt-1 flex items-center gap-1.5 tracking-tight">
                                                                                                                <div className={`h-1.5 w-1.5 rounded-full ${member.status === 'active' ? 'bg-emerald-500' : 'bg-red-500'}`} />
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
                                                                                            className="h-10 w-10 rounded-xl hover:bg-red-50 hover:text-red-500 transition-all opacity-0 group-hover/member:opacity-100"
                                                                                            onClick={() => handleRemoveUser(member.id)}
                                                                                        >
                                                                                            <Trash2 className="w-4.5 h-4.5" />
                                                                                        </Button>
                                                                                    </div>
                                                                                ))}
                                                                            </div>
                                                                        )}
                                                                    </div>
                                                                </section>

                                                                {/* Assign New Members Section */}
                                                                <section className="space-y-8">
                                                                    <div className="flex flex-col gap-6">
                                                                        <h3 className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 flex items-center gap-3">
                                                                            <UserPlus className="w-4.5 h-4.5 text-primary" />
                                                                            Enroll New Subjects
                                                                        </h3>
                                                                        <div className="relative group">
                                                                            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4.5 h-4.5 text-on-surface-variant/40 group-focus-within:text-primary transition-colors" />
                                                                            <Input
                                                                                placeholder="Lookup identity to enroll..."
                                                                                className="h-12 border-none rounded-2xl font-medium text-sm pl-11 bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all"
                                                                                value={searchUser}
                                                                                onChange={(e) => setSearchUser(e.target.value)}
                                                                            />
                                                                        </div>
                                                                    </div>

                                                                    <div className="grid gap-3 max-h-[400px] overflow-y-auto pr-2 custom-scrollbar">
                                                                        {filteredAvailableUsers.length === 0 ? (
                                                                            <div className="py-12 text-center bg-surface-container/10 rounded-[32px] border-2 border-dashed">
                                                                                <p className="text-[11px] font-bold text-on-surface-variant/20 tracking-tight">No available subjects matching query</p>
                                                                            </div>
                                                                        ) : (
                                                                            filteredAvailableUsers.map(user => (
                                                                                <div key={user.id} className="flex items-center justify-between p-4 bg-white border border-on-surface/5 rounded-2xl hover:border-primary/20 hover:shadow-lg hover:shadow-primary/5 transition-all group/add">
                                                                                    <div className="flex items-center gap-4">
                                                                                        {(() => {
                                                                                            const email = user.email || (user.emails && user.emails.length > 0 ? user.emails[0].value : '');
                                                                                            return (
                                                                                                <>
                                                                                                    <Avatar className="h-9 w-9 rounded-xl ring-1 ring-on-surface/5 overflow-hidden">
                                                                                                        <AvatarImage src={`https://avatar.vercel.sh/${email}`} className="contrast-[1.1]" />
                                                                                                        <AvatarFallback className="text-[10px] font-bold uppercase bg-primary/5 text-primary">{email ? email.substring(0, 2) : '??'}</AvatarFallback>
                                                                                                    </Avatar>
                                                                                                    <p className="text-xs font-bold text-on-surface">{email || 'Anonymous'}</p>
                                                                                                </>
                                                                                            );
                                                                                        })()}
                                                                                    </div>
                                                                                    <Button
                                                                                        size="icon"
                                                                                        variant="ghost"
                                                                                        className="h-9 w-9 rounded-xl text-primary hover:bg-primary hover:text-white transition-all"
                                                                                        onClick={() => handleAddUser(user)}
                                                                                    >
                                                                                        <ArrowRight className="w-4 h-4" />
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
                                                    className="h-9 w-9 rounded-xl hover:bg-red-50 hover:text-red-500 transition-all opacity-40 hover:opacity-100"
                                                    onClick={() => handleDeleteGroup(group.id)}
                                                >
                                                    <Trash2 className="w-4.5 h-4.5" />
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
