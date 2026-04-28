import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getSCIMUsers, deleteSCIMUser } from '../api';
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
    Plus,
    User as UserIcon,
    Mail,
    Search,
    MoreHorizontal,
    ShieldCheck,
    ShieldAlert,
    Loader2,
    Users as UsersIcon,
    ArrowUpRight,
    UserPlus,
    Fingerprint,
    Settings2,
    Eye
} from "lucide-react";
import { Input } from "@/components/ui/input";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
    DropdownMenuSeparator
} from "@/components/ui/dropdown-menu";
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassTable, GlassTableHeader, GlassTableHead, GlassTableRow, GlassCardDescription } from '@/components/layout';

const Users: React.FC = () => {
    const [users, setUsers] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState('');
    const navigate = useNavigate();

    const loadUsers = async () => {
        try {
            setLoading(true);
            const data = await getSCIMUsers();
            setUsers(data.Resources || []);
        } catch (error) {
            console.error("Failed to load users", error);
        } finally {
            setLoading(false);
        }
    };

    const handleDeleteUser = async (id: string) => {
        if (window.confirm("Are you sure you want to delete this user?")) {
            try {
                setLoading(true);
                await deleteSCIMUser(id);
                await loadUsers();
            } catch (error) {
                console.error("Failed to delete user", error);
            } finally {
                setLoading(false);
            }
        }
    };

    useEffect(() => {
        loadUsers();
    }, []);

    const filteredUsers = users.filter(user =>
        user.displayName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        user.userName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        user.emails?.[0]?.value?.toLowerCase().includes(searchTerm.toLowerCase())
    );

    if (loading && users.length === 0) return <div className="h-[400px] flex items-center justify-center"><Loader2 className="h-10 w-10 animate-spin text-primary opacity-20" /></div>;

    return (
        <div className="space-y-10 animate-in fade-in duration-700">
            <PageHeader
                icon={<UsersIcon className="w-10 h-10 text-primary" />}
                title="Users"
                description="Manage all user accounts in your organization. Assign users to groups and control their access to resources."
                actions={
                    <Button
                        onClick={() => navigate('/users/new')}
                        className="h-11 rounded-xl bg-primary text-primary-foreground font-bold tracking-tight text-[11px] px-8 shadow-xl shadow-primary/20 transition-all hover:scale-[1.02] active:scale-[0.98]"
                    >
                        <UserPlus className="w-4 h-4 mr-3" /> Add User
                    </Button>
                }
            />

            <GlassCard className="overflow-hidden border-none shadow-xl shadow-on-surface/5 bg-card">
                <GlassCardHeader className="py-8 px-10">
                    <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-8">
                        <div className="flex items-center gap-5">
                            <div className="p-3.5 bg-primary/5 rounded-2xl">
                                <Fingerprint className="w-6 h-6 text-primary" />
                            </div>
                            <div>
                                <GlassCardTitle className="text-2xl font-bold tracking-tight text-on-surface">User Registry</GlassCardTitle>
                                <p className="text-on-surface-variant/40 font-bold text-[12px] mt-1 tracking-tight">
                                    {users.length} Total Users
                                </p>
                            </div>
                        </div>
                        <div className="relative w-full md:w-96 group">
                            <Search className="absolute left-4 top-1/2 -translate-y-1/2 h-4.5 w-4.5 text-on-surface-variant/40 group-focus-within:text-primary transition-colors" />
                            <Input
                                placeholder="Search by UID or Alias..."
                                className="h-12 border-none rounded-2xl font-medium text-sm pl-11 bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all"
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                            />
                        </div>
                    </div>
                </GlassCardHeader>
                <GlassCardContent className="p-0">
                    <div className="overflow-x-auto">
                        <GlassTable>
                            <GlassTableHeader>
                                <GlassTableRow className="hover:bg-transparent border-b border-on-surface/5">
                                    <GlassTableHead className="py-6 pl-10 font-bold text-[12px] tracking-tight text-on-surface-variant/40">User</GlassTableHead>
                                    <GlassTableHead className="font-bold text-[12px] tracking-tight text-on-surface-variant/40">Status</GlassTableHead>
                                    <GlassTableHead className="font-bold text-[12px] tracking-tight text-on-surface-variant/40">Groups</GlassTableHead>
                                    <GlassTableHead className="text-right font-bold text-[12px] tracking-tight text-on-surface-variant/40 pr-10">Actions</GlassTableHead>
                                </GlassTableRow>
                            </GlassTableHeader>
                            <TableBody>
                                {filteredUsers.length === 0 ? (
                                    <GlassTableRow>
                                        <TableCell colSpan={4} className="py-32 text-center text-sm font-medium text-on-surface-variant/40">
                                            No users matching the current search criteria.
                                        </TableCell>
                                    </GlassTableRow>
                                ) : (
                                    filteredUsers.map((user) => (
                                        <GlassTableRow key={user.id} className="hover:bg-surface-container/20 transition-all border-b border-on-surface/5 last:border-0 group">
                                            <TableCell className="py-6 pl-10">
                                                <div className="flex items-center gap-5">
                                                    <Avatar className="h-12 w-12 border-none ring-1 ring-on-surface/5 rounded-2xl overflow-hidden group-hover:scale-105 transition-transform">
                                                        <AvatarImage src={`https://avatar.vercel.sh/${user.emails?.[0]?.value || user.userName}`} className="contrast-[1.1]" />
                                                        <AvatarFallback className="font-bold text-xs text-primary bg-primary/5 pb-0.5">
                                                            {(user.displayName || user.userName || '??').substring(0, 2)}
                                                        </AvatarFallback>
                                                    </Avatar>
                                                    <div className="flex flex-col">
                                                        <span className="font-bold text-base tracking-tight text-on-surface group-hover:text-primary transition-colors">
                                                            {user.displayName || user.userName}
                                                        </span>
                                                        <span className="text-[11px] font-medium text-on-surface-variant/60 mt-1 flex items-center gap-2">
                                                            {user.emails?.[0]?.value || 'No verifiable email'}
                                                        </span>
                                                    </div>
                                                </div>
                                            </TableCell>
                                            <TableCell className="py-6">
                                                <Badge className={`rounded-xl font-bold text-[11px] tracking-tight px-3 py-1 shadow-none border-none ${user.active
                                                    ? 'bg-success-subtle text-success'
                                                    : 'bg-destructive/10 text-destructive'
                                                    }`}>
                                                    {user.active ? 'Active' : 'Suspended'}
                                                </Badge>
                                            </TableCell>
                                            <TableCell className="py-6">
                                                <div className="flex flex-wrap gap-2 max-w-[300px]">
                                                    {user.groups && user.groups.length > 0 ? (
                                                        user.groups.slice(0, 3).map((group: any) => (
                                                            <Badge key={group.value} className="bg-surface-container text-on-surface-variant border-none rounded-xl text-[10px] font-bold tracking-tight py-1 px-2.5">
                                                                {group.display || 'Group'}
                                                            </Badge>
                                                        ))
                                                    ) : (
                                                        <span className="text-[11px] font-medium text-on-surface-variant/30 italic">No Groups</span>
                                                    )}
                                                    {user.groups && user.groups.length > 3 && (
                                                        <Badge className="bg-primary/5 text-primary border-none rounded-xl text-[10px] font-bold py-1 px-2">+{user.groups.length - 3}</Badge>
                                                    )}
                                                </div>
                                            </TableCell>
                                            <TableCell className="py-6 text-right pr-10">
                                                <DropdownMenu>
                                                    <DropdownMenuTrigger asChild>
                                                        <Button variant="ghost" className="h-9 w-9 rounded-xl hover:bg-surface-container transition-all">
                                                            <MoreHorizontal className="h-4.5 w-4.5 text-on-surface-variant/60" />
                                                        </Button>
                                                    </DropdownMenuTrigger>
                                                    <DropdownMenuContent align="end" className="w-[200px] rounded-2xl border-none shadow-xl shadow-on-surface/10 p-2 bg-card">
                                                        <DropdownMenuItem
                                                            onClick={() => navigate(`/users/edit/${user.id}`)}
                                                            className="font-bold text-[11px] tracking-tight gap-3 py-3 px-4 rounded-lg focus:bg-primary/5 focus:text-primary cursor-pointer transition-colors"
                                                        >
                                                            <Eye className="w-3.5 h-3.5 opacity-40" /> Edit Details
                                                        </DropdownMenuItem>
                                                        <DropdownMenuItem
                                                            onClick={() => navigate('/groups')}
                                                            className="font-bold text-[11px] tracking-tight gap-3 py-3 px-4 rounded-lg focus:bg-primary/5 focus:text-primary cursor-pointer transition-colors"
                                                        >
                                                            <Settings2 className="w-3.5 h-3.5 opacity-40" /> Manage Groups
                                                        </DropdownMenuItem>
                                                        <DropdownMenuSeparator className="bg-on-surface/5 my-1.5 mx-2" />
                                                        <DropdownMenuItem 
                                                            onClick={() => handleDeleteUser(user.id)}
                                                            className="text-destructive font-bold text-[11px] tracking-tight gap-3 py-3 px-4 rounded-lg focus:bg-destructive/10 focus:text-destructive cursor-pointer transition-colors"
                                                        >
                                                            <ShieldAlert className="w-3.5 h-3.5" /> Delete User
                                                        </DropdownMenuItem>
                                                    </DropdownMenuContent>
                                                </DropdownMenu>
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

export default Users;
