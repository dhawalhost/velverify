import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getSCIMUsers, deleteSCIMUser, requestPasswordSetupLink, updateSCIMUser } from '../api';
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
    Eye,
    Key,
    Lock
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
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";

const Users: React.FC = () => {
    const [users, setUsers] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState('');
    const [isPasswordDialogOpen, setIsPasswordDialogOpen] = useState(false);
    const [selectedUser, setSelectedUser] = useState<any>(null);
    const [newPassword, setNewPassword] = useState('');
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

    const handleSendResetLink = async (id: string) => {
        try {
            setLoading(true);
            await requestPasswordSetupLink(id, 'reset', 72, true);
            alert("Password reset link sent successfully.");
        } catch (error: any) {
            console.error("Failed to send reset link", error);
            alert(error.response?.data?.error || "Failed to send reset link");
        } finally {
            setLoading(false);
        }
    };
    const handleSetPassword = async () => {
        if (!selectedUser || !newPassword) return;
        if (newPassword.length < 8) {
            alert("Password must be at least 8 characters");
            return;
        }

        try {
            setLoading(true);
            await updateSCIMUser(selectedUser.id, { password: newPassword });
            alert(`Password for ${selectedUser.displayName || selectedUser.userName} updated successfully.`);
            setIsPasswordDialogOpen(false);
            setNewPassword('');
        } catch (error: any) {
            console.error("Failed to set password", error);
            alert(error.response?.data?.error || "Failed to set password");
        } finally {
            setLoading(false);
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
        <div className="space-y-4 animate-in fade-in duration-700">
            <PageHeader
                icon={<UsersIcon className="w-5 h-5 text-primary" />}
                title="Users"
                description="Manage all user accounts in your organization. Assign users to groups and control their access to resources."
                actions={
                    <Button
                        onClick={() => navigate('/users/new')}
                        className="h-8 rounded-lg bg-primary text-primary-foreground font-bold tracking-tight text-[10px] px-4 shadow-xl shadow-primary/20 transition-all hover:scale-[1.02] active:scale-[0.98]"
                    >
                        <UserPlus className="w-3.5 h-3.5 mr-1.5" /> Add User
                    </Button>
                }
            />

            <GlassCard className="overflow-hidden border-none shadow-xl shadow-on-surface/5 bg-card">
                <GlassCardHeader className="py-2.5 px-4">
                    <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-3">
                        <div className="flex items-center gap-3">
                            <div className="p-1.5 bg-primary/5 rounded-lg">
                                <Fingerprint className="w-4 h-4 text-primary" />
                            </div>
                            <div>
                                <GlassCardTitle className="text-sm font-bold tracking-tight text-on-surface">User Registry</GlassCardTitle>
                                <p className="text-on-surface-variant/40 font-bold text-[8px] mt-0.5 tracking-tight uppercase">
                                    {users.length} Total Users
                                </p>
                            </div>
                        </div>
                        <div className="relative w-full md:w-64 group">
                            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-on-surface-variant/40 group-focus-within:text-primary transition-colors" />
                            <Input
                                placeholder="Search by UID or Alias..."
                                className="h-8 border-none rounded-lg font-medium text-[11px] pl-9 bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all"
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
                                    <GlassTableHead className="py-2 pl-4 font-bold text-[9px] tracking-tight text-on-surface-variant/40 uppercase">User</GlassTableHead>
                                    <GlassTableHead className="font-bold text-[9px] tracking-tight text-on-surface-variant/40 uppercase">Status</GlassTableHead>
                                    <GlassTableHead className="font-bold text-[9px] tracking-tight text-on-surface-variant/40 uppercase">Groups</GlassTableHead>
                                    <GlassTableHead className="text-right font-bold text-[9px] tracking-tight text-on-surface-variant/40 pr-4 uppercase">Actions</GlassTableHead>
                                </GlassTableRow>
                            </GlassTableHeader>
                            <TableBody>
                                {filteredUsers.length === 0 ? (
                                    <GlassTableRow>
                                        <TableCell colSpan={4} className="py-20 text-center text-xs font-medium text-on-surface-variant/40">
                                            No users matching the current search criteria.
                                        </TableCell>
                                    </GlassTableRow>
                                ) : (
                                    filteredUsers.map((user) => (
                                        <GlassTableRow key={user.id} className="hover:bg-surface-container/20 transition-all border-b border-on-surface/5 last:border-0 group">
                                            <TableCell className="py-1.5 pl-4">
                                                <div className="flex items-center gap-2.5">
                                                    <Avatar className="h-6 w-6 border-none ring-1 ring-on-surface/5 rounded-md overflow-hidden group-hover:scale-105 transition-transform">
                                                        <AvatarImage src={`https://avatar.vercel.sh/${user.emails?.[0]?.value || user.userName}`} className="contrast-[1.1]" />
                                                        <AvatarFallback className="font-bold text-[8px] text-primary bg-primary/5 pb-0.5">
                                                            {(user.displayName || user.userName || '??').substring(0, 2)}
                                                        </AvatarFallback>
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
                                                        className="h-7 px-3 rounded-lg bg-primary/5 text-primary border border-primary/10 hover:bg-primary hover:text-white transition-all font-bold text-[9px] uppercase tracking-wider"
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
                                    ))
                                )}
                            </TableBody>
                        </GlassTable>
                    </div>
                </GlassCardContent>
            </GlassCard>
            <Dialog open={isPasswordDialogOpen} onOpenChange={setIsPasswordDialogOpen}>
                <DialogContent className="sm:max-w-[360px] rounded-xl border-none bg-card shadow-2xl p-5">
                    <DialogHeader>
                        <DialogTitle className="text-base font-bold tracking-tight text-on-surface flex items-center gap-2.5">
                            <div className="p-1.5 bg-primary/10 rounded-lg">
                                <Lock className="w-3.5 h-3.5 text-primary" />
                            </div>
                            Set Password
                        </DialogTitle>
                        <DialogDescription className="text-[11px] font-medium text-on-surface-variant/60 mt-1">
                            Set a new password for <span className="text-on-surface font-bold">{selectedUser?.displayName || selectedUser?.userName}</span>.
                        </DialogDescription>
                    </DialogHeader>
                    <div className="py-3 space-y-3">
                        <div className="space-y-1.5">
                            <Label className="text-[9px] font-bold tracking-tight text-on-surface-variant/40 ml-1 uppercase">New Password</Label>
                            <Input
                                type="password"
                                placeholder="Enter at least 8 characters"
                                value={newPassword}
                                onChange={(e) => setNewPassword(e.target.value)}
                                className="h-9 rounded-lg border-none bg-surface-container/50 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-bold text-xs px-3"
                            />
                        </div>
                    </div>
                    <DialogFooter className="gap-2">
                        <Button
                            variant="ghost"
                            onClick={() => setIsPasswordDialogOpen(false)}
                            className="rounded-lg font-bold text-[10px] tracking-tight px-3 h-8"
                        >
                            Cancel
                        </Button>
                        <Button
                            onClick={handleSetPassword}
                            disabled={!newPassword || newPassword.length < 8 || loading}
                            className="rounded-lg bg-primary text-primary-foreground font-bold text-[10px] tracking-tight px-4 h-8 shadow-lg shadow-primary/20"
                        >
                            {loading ? <Loader2 className="w-3 h-3 animate-spin" /> : "Update Password"}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>

    );
};

export default Users;
