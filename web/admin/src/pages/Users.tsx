import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getSCIMUsers, deleteSCIMUser, requestPasswordSetupLink, updateSCIMUser } from '../api';
import { Button } from "@/components/ui/button";
import { TableBody, TableCell } from "@/components/ui/table";
import {
    User as UserIcon,
    Search,
    ShieldCheck,
    ShieldAlert,
    Loader2,
    Users as UsersIcon,
    UserPlus,
    Fingerprint,
    Key,
    Mail,
    Lock,
    X,
    ChevronRight,
    Settings2,
    Trash2,
    Edit,
    Shield,
} from "lucide-react";
import { Input } from "@/components/ui/input";
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import BoringAvatar from 'boring-avatars';
import { Badge } from '@/components/ui/badge';
import { GlassCard, GlassCardContent, GlassCardHeader, GlassCardTitle, GlassTable, GlassTableHeader, GlassTableHead, GlassTableRow } from '@/components/layout';
import { Label } from "@/components/ui/label";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog";
import { cn } from '@/lib/utils';

const Users: React.FC = () => {
    const [users, setUsers] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState('');
    const [selectedUser, setSelectedUser] = useState<any>(null);
    const [isPasswordDialogOpen, setIsPasswordDialogOpen] = useState(false);
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
                await deleteSCIMUser(id);
                if (selectedUser?.id === id) setSelectedUser(null);
                await loadUsers();
            } catch (error) {
                console.error("Failed to delete user", error);
            }
        }
    };

    const handleSendResetLink = async (id: string) => {
        try {
            await requestPasswordSetupLink(id, 'reset', 72, true);
            alert("Password reset link sent successfully.");
        } catch (error: any) {
            alert(error.response?.data?.error || "Failed to send reset link");
        }
    };

    const handleSetPassword = async () => {
        if (!selectedUser || !newPassword || newPassword.length < 8) return;
        try {
            setLoading(true);
            await updateSCIMUser(selectedUser.id, { password: newPassword });
            alert(`Password updated successfully.`);
            setIsPasswordDialogOpen(false);
            setNewPassword('');
        } catch (error: any) {
            alert(error.response?.data?.error || "Failed to set password");
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { loadUsers(); }, []);

    const filteredUsers = users.filter(user =>
        user.displayName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        user.userName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        user.emails?.[0]?.value?.toLowerCase().includes(searchTerm.toLowerCase())
    );

    return (
        <div className="flex h-full gap-0 animate-in fade-in duration-500">
            {/* ── Master: user list ──────────────────────────────────── */}
            <div className={cn(
                "flex flex-col transition-all duration-300",
                selectedUser ? "w-[420px] min-w-[420px]" : "flex-1"
            )}>
                {/* Toolbar */}
                <div className="flex items-center justify-between px-6 py-4 border-b border-on-surface/5 bg-card/50">
                    <div>
                        <h1 className="text-sm font-bold tracking-tight text-on-surface">Users</h1>
                        <p className="text-[10px] text-on-surface-variant/40 font-medium mt-0.5">
                            {users.length} total accounts
                        </p>
                    </div>
                    <div className="flex items-center gap-2">
                        <div className="relative group">
                            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3 w-3 text-on-surface-variant/30 group-focus-within:text-primary transition-colors" />
                            <Input
                                placeholder="Search users..."
                                className="h-8 w-44 border-none rounded-lg text-[11px] pl-8 bg-surface-container/50 ring-1 ring-on-surface/5 focus-visible:ring-primary/20 font-medium"
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                            />
                        </div>
                        <Button
                            onClick={() => navigate('/users/new')}
                            className="h-8 rounded-lg bg-primary text-primary-foreground font-bold text-[10px] px-3 shadow-md shadow-primary/20"
                        >
                            <UserPlus className="w-3 h-3 mr-1.5" /> Add User
                        </Button>
                    </div>
                </div>

                {/* List */}
                <div className="flex-1 overflow-y-auto custom-scrollbar bg-card/20">
                    {loading && users.length === 0 ? (
                        <div className="h-48 flex items-center justify-center">
                            <Loader2 className="h-6 w-6 animate-spin text-primary/30" />
                        </div>
                    ) : filteredUsers.length === 0 ? (
                        <div className="py-20 text-center text-[11px] text-on-surface-variant/30 font-medium">
                            No users found
                        </div>
                    ) : (
                        <div className="divide-y divide-on-surface/5">
                            {filteredUsers.map((user) => {
                                const email = user.emails?.[0]?.value || user.userName || '';
                                const isSelected = selectedUser?.id === user.id;
                                return (
                                    <div
                                        key={user.id}
                                        onClick={() => setSelectedUser(isSelected ? null : user)}
                                        className={cn(
                                            "flex items-center gap-3 px-5 py-3 cursor-pointer transition-all group",
                                            isSelected
                                                ? "bg-primary/5 border-l-2 border-primary"
                                                : "hover:bg-surface-container/40 border-l-2 border-transparent"
                                        )}
                                    >
                                        <Avatar className="h-8 w-8 rounded-lg ring-1 ring-on-surface/5 shrink-0">
                                            <BoringAvatar
                                                size={32}
                                                name={email}
                                                variant="marble"
                                                colors={["#00FF9E", "#17171C", "#8B5CF6", "#06B6D4", "#10B981"]}
                                            />
                                        </Avatar>
                                        <div className="flex-1 min-w-0">
                                            <p className={cn(
                                                "text-[12px] font-semibold truncate transition-colors",
                                                isSelected ? "text-primary" : "text-on-surface group-hover:text-primary"
                                            )}>
                                                {user.displayName || user.userName}
                                            </p>
                                            <p className="text-[10px] text-on-surface-variant/40 truncate font-medium">
                                                {email}
                                            </p>
                                        </div>
                                        <div className="flex items-center gap-2 shrink-0">
                                            <Badge className={cn(
                                                "text-[8px] font-bold px-1.5 py-0 rounded border-none",
                                                user.active
                                                    ? "bg-success/10 text-success"
                                                    : "bg-destructive/10 text-destructive"
                                            )}>
                                                {user.active ? 'Active' : 'Inactive'}
                                            </Badge>
                                            <ChevronRight className={cn(
                                                "w-3 h-3 transition-all",
                                                isSelected ? "text-primary rotate-90" : "text-on-surface-variant/20"
                                            )} />
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
            </div>

            {/* ── Detail panel ──────────────────────────────────────── */}
            {selectedUser && (
                <div className="flex-1 border-l border-on-surface/5 bg-card flex flex-col overflow-hidden animate-in slide-in-from-right-4 duration-300">
                    {/* Panel header */}
                    <div className="bg-primary px-6 py-5 text-primary-foreground shrink-0">
                        <div className="flex items-start justify-between">
                            <div className="flex items-center gap-4">
                                <Avatar className="h-12 w-12 rounded-xl ring-2 ring-black/10">
                                    <BoringAvatar
                                        size={48}
                                        name={selectedUser.emails?.[0]?.value || selectedUser.userName}
                                        variant="marble"
                                        colors={["#00FF9E", "#17171C", "#8B5CF6", "#06B6D4", "#10B981"]}
                                    />
                                </Avatar>
                                <div>
                                    <h2 className="text-base font-bold tracking-tight text-primary-foreground">
                                        {selectedUser.displayName || selectedUser.userName}
                                    </h2>
                                    <p className="text-primary-foreground/60 text-[11px] font-medium mt-0.5">
                                        {selectedUser.emails?.[0]?.value || 'No email'}
                                    </p>
                                    <Badge className={cn(
                                        "mt-2 text-[8px] font-bold px-2 py-0.5 rounded border-none",
                                        selectedUser.active
                                            ? "bg-black/10 text-primary-foreground"
                                            : "bg-black/20 text-primary-foreground/60"
                                    )}>
                                        {selectedUser.active ? '● Active' : '○ Inactive'}
                                    </Badge>
                                </div>
                            </div>
                            <Button
                                variant="ghost"
                                size="icon"
                                className="h-7 w-7 rounded-lg bg-black/10 hover:bg-black/20 text-primary-foreground"
                                onClick={() => setSelectedUser(null)}
                            >
                                <X className="w-3.5 h-3.5" />
                            </Button>
                        </div>
                    </div>

                    {/* Panel body */}
                    <div className="flex-1 overflow-y-auto custom-scrollbar p-5 space-y-4">
                        {/* Identity */}
                        <section>
                            <h3 className="text-[9px] font-bold tracking-widest text-on-surface-variant/30 uppercase mb-2">Identity</h3>
                            <div className="bg-surface-container/30 rounded-xl divide-y divide-on-surface/5">
                                {[
                                    { label: 'Username', value: selectedUser.userName },
                                    { label: 'User ID', value: selectedUser.id },
                                    { label: 'Display Name', value: selectedUser.displayName || '—' },
                                    { label: 'External ID', value: selectedUser.externalId || '—' },
                                ].map(({ label, value }) => (
                                    <div key={label} className="flex items-center justify-between px-3 py-2">
                                        <span className="text-[10px] font-semibold text-on-surface-variant/40">{label}</span>
                                        <span className="text-[11px] font-semibold text-on-surface truncate max-w-[180px]">{value}</span>
                                    </div>
                                ))}
                            </div>
                        </section>

                        {/* Groups */}
                        <section>
                            <h3 className="text-[9px] font-bold tracking-widest text-on-surface-variant/30 uppercase mb-2">
                                Groups ({(selectedUser.groups || []).length})
                            </h3>
                            {(selectedUser.groups || []).length === 0 ? (
                                <p className="text-[10px] text-on-surface-variant/30 font-medium px-1">Not assigned to any groups</p>
                            ) : (
                                <div className="flex flex-wrap gap-1.5">
                                    {(selectedUser.groups || []).map((g: any) => (
                                        <Badge key={g.value} className="bg-primary/8 text-primary border border-primary/10 rounded-lg text-[9px] font-bold px-2 py-0.5">
                                            {g.display}
                                        </Badge>
                                    ))}
                                </div>
                            )}
                        </section>

                        {/* Actions */}
                        <section>
                            <h3 className="text-[9px] font-bold tracking-widest text-on-surface-variant/30 uppercase mb-2">Actions</h3>
                            <div className="grid grid-cols-2 gap-2">
                                <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={() => navigate(`/users/edit/${selectedUser.id}`)}
                                    className="h-8 rounded-lg text-[10px] font-bold border-on-surface/8 hover:border-primary/20 hover:text-primary hover:bg-primary/5 transition-all"
                                >
                                    <Edit className="w-3 h-3 mr-1.5" /> Edit Profile
                                </Button>
                                <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={() => { setIsPasswordDialogOpen(true); }}
                                    className="h-8 rounded-lg text-[10px] font-bold border-on-surface/8 hover:border-primary/20 hover:text-primary hover:bg-primary/5 transition-all"
                                >
                                    <Key className="w-3 h-3 mr-1.5" /> Set Password
                                </Button>
                                <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={() => handleSendResetLink(selectedUser.id)}
                                    className="h-8 rounded-lg text-[10px] font-bold border-on-surface/8 hover:border-primary/20 hover:text-primary hover:bg-primary/5 transition-all"
                                >
                                    <Mail className="w-3 h-3 mr-1.5" /> Reset Link
                                </Button>
                                <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={() => navigate('/groups')}
                                    className="h-8 rounded-lg text-[10px] font-bold border-on-surface/8 hover:border-primary/20 hover:text-primary hover:bg-primary/5 transition-all"
                                >
                                    <Shield className="w-3 h-3 mr-1.5" /> Manage Groups
                                </Button>
                            </div>
                        </section>

                        {/* Danger zone */}
                        <section className="pt-2 border-t border-on-surface/5">
                            <h3 className="text-[9px] font-bold tracking-widest text-destructive/40 uppercase mb-2">Danger Zone</h3>
                            <Button
                                variant="outline"
                                size="sm"
                                onClick={() => handleDeleteUser(selectedUser.id)}
                                className="w-full h-8 rounded-lg text-[10px] font-bold border-destructive/20 text-destructive hover:bg-destructive/5 transition-all"
                            >
                                <Trash2 className="w-3 h-3 mr-1.5" /> Delete User Account
                            </Button>
                        </section>
                    </div>
                </div>
            )}

            {/* Password dialog */}
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
                                placeholder="At least 8 characters"
                                value={newPassword}
                                onChange={(e) => setNewPassword(e.target.value)}
                                className="h-9 rounded-lg border-none bg-surface-container/50 ring-1 ring-on-surface/5 focus-visible:ring-primary/20 font-bold text-xs px-3"
                            />
                        </div>
                    </div>
                    <DialogFooter className="gap-2">
                        <Button variant="ghost" onClick={() => setIsPasswordDialogOpen(false)} className="rounded-lg font-bold text-[10px] h-8">Cancel</Button>
                        <Button
                            onClick={handleSetPassword}
                            disabled={!newPassword || newPassword.length < 8 || loading}
                            className="rounded-lg bg-primary text-primary-foreground font-bold text-[10px] px-4 h-8 shadow-lg shadow-primary/20"
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
