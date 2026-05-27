import React, { useState, useEffect } from 'react';
import { getRoles, createRole, deleteRole, getPermissions, createPermission, getRolePermissions, assignPermissionToRole } from '../api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { TableBody } from '@/components/ui/table';
import {
    Loader2, Plus, Trash2, Shield, Lock, ShieldCheck, Command, X,
    ChevronRight, Search, Key
} from 'lucide-react';
import {
    GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent,
    GlassTable, GlassTableHeader, GlassTableHead, GlassTableRow
} from '@/components/layout';
import { PermissionTableRow } from '../components/PermissionTableRow';
import { cn } from '@/lib/utils';

interface Role { id: string; name: string; description: string; created_at: string; }
interface Permission { id: string; resource: string; action: string; description: string; }

const Roles: React.FC = () => {
    const [roles, setRoles] = useState<Role[]>([]);
    const [permissions, setPermissions] = useState<Permission[]>([]);
    const [selectedRole, setSelectedRole] = useState<Role | null>(null);
    const [rolePermissions, setRolePermissions] = useState<Permission[]>([]);
    const [newRole, setNewRole] = useState({ name: '', description: '' });
    const [newPermission, setNewPermission] = useState({ resource: '', action: '', description: '' });
    const [loading, setLoading] = useState(true);
    const [activeTab, setActiveTab] = useState<'roles' | 'permissions'>('roles');
    const [searchTerm, setSearchTerm] = useState('');

    useEffect(() => { loadData(); }, []);
    useEffect(() => { if (selectedRole) loadRolePermissions(selectedRole.id); }, [selectedRole]);

    const loadData = async () => {
        try {
            const [rolesRes, permsRes] = await Promise.all([getRoles(), getPermissions()]);
            setRoles(rolesRes.roles || []);
            setPermissions(permsRes.permissions || []);
        } catch (error) {
            console.error('Failed to load data:', error);
        } finally {
            setLoading(false);
        }
    };

    const loadRolePermissions = async (roleId: string) => {
        try {
            const res = await getRolePermissions(roleId);
            setRolePermissions(res.permissions || []);
        } catch (error) {
            console.error('Failed to load role permissions:', error);
        }
    };

    const handleCreateRole = async (e: React.FormEvent) => {
        e.preventDefault();
        try {
            await createRole(newRole.name, newRole.description);
            setNewRole({ name: '', description: '' });
            loadData();
        } catch (error) {
            console.error('Failed to create role:', error);
        }
    };

    const handleDeleteRole = async (id: string, e: React.MouseEvent) => {
        e.stopPropagation();
        if (window.confirm('Delete this role?')) {
            try {
                await deleteRole(id);
                if (selectedRole?.id === id) setSelectedRole(null);
                loadData();
            } catch (error) {
                console.error('Failed to delete role:', error);
            }
        }
    };

    const handleCreatePermission = async (e: React.FormEvent) => {
        e.preventDefault();
        try {
            await createPermission(newPermission.resource, newPermission.action, newPermission.description);
            setNewPermission({ resource: '', action: '', description: '' });
            loadData();
        } catch (error) {
            console.error('Failed to create permission:', error);
        }
    };

    const handleAssignPermission = async (permissionId: string) => {
        if (!selectedRole) return;
        try {
            await assignPermissionToRole(selectedRole.id, permissionId);
            loadRolePermissions(selectedRole.id);
        } catch (error) {
            console.error('Failed to assign permission:', error);
        }
    };

    const filteredRoles = roles.filter(r =>
        r.name.toLowerCase().includes(searchTerm.toLowerCase())
    );

    if (loading) return (
        <div className="h-[400px] flex items-center justify-center">
            <Loader2 className="h-8 w-8 animate-spin text-primary/20" />
        </div>
    );

    return (
        <div className="flex flex-col h-full animate-in fade-in duration-500">
            {/* Tab bar */}
            <div className="flex items-center justify-between px-6 py-3 border-b border-on-surface/5 bg-card/50 shrink-0">
                <div className="flex items-center gap-1 bg-surface-container/50 p-0.5 rounded-lg">
                    <button
                        onClick={() => setActiveTab('roles')}
                        className={cn(
                            "px-4 py-1.5 rounded-md text-[11px] font-bold tracking-tight transition-all",
                            activeTab === 'roles'
                                ? "bg-card text-primary shadow-sm"
                                : "text-on-surface-variant/40 hover:text-on-surface"
                        )}
                    >
                        <Shield className="w-3 h-3 inline mr-1.5 mb-0.5" />
                        Roles
                    </button>
                    <button
                        onClick={() => setActiveTab('permissions')}
                        className={cn(
                            "px-4 py-1.5 rounded-md text-[11px] font-bold tracking-tight transition-all",
                            activeTab === 'permissions'
                                ? "bg-card text-primary shadow-sm"
                                : "text-on-surface-variant/40 hover:text-on-surface"
                        )}
                    >
                        <Key className="w-3 h-3 inline mr-1.5 mb-0.5" />
                        Permissions
                    </button>
                </div>
                <p className="text-[10px] text-on-surface-variant/30 font-medium">
                    {activeTab === 'roles' ? `${roles.length} roles` : `${permissions.length} permissions`}
                </p>
            </div>

            {activeTab === 'roles' ? (
                <div className="flex flex-1 overflow-hidden">
                    {/* ── Master: roles list ─────────────────────────────── */}
                    <div className={cn(
                        "flex flex-col border-r border-on-surface/5 transition-all duration-300",
                        selectedRole ? "w-[340px] min-w-[340px]" : "w-[340px] min-w-[340px]"
                    )}>
                        {/* Create role form */}
                        <div className="p-4 border-b border-on-surface/5 bg-card/30">
                            <p className="text-[9px] font-bold tracking-widest text-on-surface-variant/30 uppercase mb-3">Create New Role</p>
                            <form onSubmit={handleCreateRole} className="space-y-2">
                                <Input
                                    placeholder="Role name (e.g. CORE_OPERATOR)"
                                    value={newRole.name}
                                    onChange={(e) => setNewRole({ ...newRole, name: e.target.value })}
                                    className="h-8 border-none rounded-lg bg-surface-container/40 ring-1 ring-on-surface/5 focus-visible:ring-primary/20 text-[11px] font-medium"
                                    required
                                />
                                <Input
                                    placeholder="Description (optional)"
                                    value={newRole.description}
                                    onChange={(e) => setNewRole({ ...newRole, description: e.target.value })}
                                    className="h-8 border-none rounded-lg bg-surface-container/40 ring-1 ring-on-surface/5 focus-visible:ring-primary/20 text-[11px] font-medium"
                                />
                                <Button type="submit" className="w-full h-8 rounded-lg text-[10px] font-bold shadow-sm shadow-primary/10">
                                    <Plus className="w-3 h-3 mr-1.5" /> Create Role
                                </Button>
                            </form>
                        </div>

                        {/* Search */}
                        <div className="px-4 py-2 border-b border-on-surface/5">
                            <div className="relative group">
                                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3 w-3 text-on-surface-variant/30 group-focus-within:text-primary transition-colors" />
                                <Input
                                    placeholder="Filter roles..."
                                    value={searchTerm}
                                    onChange={(e) => setSearchTerm(e.target.value)}
                                    className="h-7 pl-7 border-none rounded-lg bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-primary/20 text-[11px] font-medium"
                                />
                            </div>
                        </div>

                        {/* Roles list */}
                        <div className="flex-1 overflow-y-auto custom-scrollbar divide-y divide-on-surface/5">
                            {filteredRoles.length === 0 ? (
                                <div className="py-12 text-center text-[11px] text-on-surface-variant/30 font-medium">No roles found</div>
                            ) : filteredRoles.map(role => {
                                const isSelected = selectedRole?.id === role.id;
                                return (
                                    <div
                                        key={role.id}
                                        onClick={() => setSelectedRole(isSelected ? null : role)}
                                        className={cn(
                                            "flex items-center gap-3 px-4 py-3 cursor-pointer transition-all group",
                                            isSelected
                                                ? "bg-primary/5 border-l-2 border-primary"
                                                : "hover:bg-surface-container/40 border-l-2 border-transparent"
                                        )}
                                    >
                                        <div className={cn(
                                            "w-7 h-7 rounded-lg flex items-center justify-center shrink-0 transition-colors",
                                            isSelected ? "bg-primary/15" : "bg-surface-container/80 group-hover:bg-primary/8"
                                        )}>
                                            <Shield className={cn("w-3.5 h-3.5 transition-colors", isSelected ? "text-primary" : "text-on-surface-variant/40")} />
                                        </div>
                                        <div className="flex-1 min-w-0">
                                            <p className={cn("text-[12px] font-semibold truncate", isSelected ? "text-primary" : "text-on-surface")}>{role.name}</p>
                                            <p className="text-[10px] text-on-surface-variant/30 truncate font-medium mt-0.5">{role.description || 'No description'}</p>
                                        </div>
                                        <button
                                            onClick={(e) => handleDeleteRole(role.id, e)}
                                            className="opacity-0 group-hover:opacity-100 h-6 w-6 rounded-md flex items-center justify-center hover:bg-destructive/10 hover:text-destructive transition-all text-on-surface-variant/30"
                                        >
                                            <Trash2 className="w-3 h-3" />
                                        </button>
                                    </div>
                                );
                            })}
                        </div>
                    </div>

                    {/* ── Detail: permissions ────────────────────────────── */}
                    <div className="flex-1 flex flex-col overflow-hidden bg-surface/50">
                        {selectedRole ? (
                            <>
                                {/* Detail header */}
                                <div className="bg-primary px-6 py-4 text-primary-foreground shrink-0 flex items-center justify-between">
                                    <div className="flex items-center gap-3">
                                        <div className="w-8 h-8 bg-black/10 rounded-lg flex items-center justify-center">
                                            <Shield className="w-4 h-4 text-primary-foreground" />
                                        </div>
                                        <div>
                                            <h2 className="text-sm font-bold text-primary-foreground">{selectedRole.name}</h2>
                                            <p className="text-primary-foreground/60 text-[10px] mt-0.5">
                                                {rolePermissions.length} permission{rolePermissions.length !== 1 ? 's' : ''} assigned
                                            </p>
                                        </div>
                                    </div>
                                    <Button variant="ghost" size="icon" className="h-7 w-7 rounded-lg bg-black/10 hover:bg-black/20 text-primary-foreground" onClick={() => setSelectedRole(null)}>
                                        <X className="w-3.5 h-3.5" />
                                    </Button>
                                </div>

                                <div className="flex-1 overflow-y-auto custom-scrollbar p-5 space-y-5">
                                    {/* Assigned permissions */}
                                    <section>
                                        <div className="flex items-center justify-between mb-3">
                                            <h3 className="text-[9px] font-bold tracking-widest text-on-surface-variant/30 uppercase flex items-center gap-2">
                                                <ShieldCheck className="w-3 h-3 text-success" /> Assigned Permissions
                                            </h3>
                                            <Badge className="bg-success/10 text-success border-none text-[8px] font-bold px-2 rounded-md">{rolePermissions.length}</Badge>
                                        </div>
                                        {rolePermissions.length === 0 ? (
                                            <div className="py-8 border-2 border-dashed border-on-surface/5 rounded-xl text-center">
                                                <Lock className="w-5 h-5 text-on-surface-variant/10 mx-auto mb-2" />
                                                <p className="text-[10px] text-on-surface-variant/30 font-medium">No permissions assigned</p>
                                            </div>
                                        ) : (
                                            <div className="grid grid-cols-2 gap-2">
                                                {rolePermissions.map(p => (
                                                    <div key={p.id} className="p-2.5 bg-card ring-1 ring-on-surface/5 rounded-lg flex items-center justify-between hover:ring-success/20 hover:bg-success/5 transition-all">
                                                        <div>
                                                            <p className="font-mono text-[10px] font-bold text-on-surface">{p.resource}</p>
                                                            <Badge className="mt-1 bg-primary/5 text-primary border-none rounded text-[8px] font-bold px-1.5">{p.action}</Badge>
                                                        </div>
                                                        <div className="w-6 h-6 bg-success/10 rounded flex items-center justify-center">
                                                            <ShieldCheck className="w-3 h-3 text-success" />
                                                        </div>
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                    </section>

                                    {/* Available to assign */}
                                    <section className="border-t border-on-surface/5 pt-5">
                                        <h3 className="text-[9px] font-bold tracking-widest text-on-surface-variant/30 uppercase mb-3 flex items-center gap-2">
                                            <Plus className="w-3 h-3" /> Available to Assign
                                        </h3>
                                        <div className="grid grid-cols-2 gap-2">
                                            {permissions
                                                .filter(p => !rolePermissions.find(rp => rp.id === p.id))
                                                .map(p => (
                                                    <div
                                                        key={p.id}
                                                        onClick={() => handleAssignPermission(p.id)}
                                                        className="p-2.5 bg-card ring-1 ring-on-surface/5 rounded-lg cursor-pointer group hover:ring-primary/20 hover:bg-primary/5 transition-all flex items-center justify-between"
                                                    >
                                                        <div className="min-w-0">
                                                            <p className="font-mono text-[10px] font-bold text-on-surface truncate">{p.resource}</p>
                                                            <p className="text-[9px] text-primary font-bold mt-0.5">{p.action}</p>
                                                        </div>
                                                        <div className="w-6 h-6 rounded bg-surface-container/80 group-hover:bg-primary group-hover:text-primary-foreground flex items-center justify-center transition-all shrink-0 ml-2">
                                                            <Plus className="w-3 h-3" />
                                                        </div>
                                                    </div>
                                                ))
                                            }
                                            {permissions.filter(p => !rolePermissions.find(rp => rp.id === p.id)).length === 0 && (
                                                <p className="col-span-2 text-[10px] text-on-surface-variant/30 font-medium text-center py-4">All permissions are assigned</p>
                                            )}
                                        </div>
                                    </section>
                                </div>
                            </>
                        ) : (
                            <div className="flex-1 flex flex-col items-center justify-center text-center p-8">
                                <div className="w-14 h-14 bg-primary/5 rounded-2xl flex items-center justify-center mb-4">
                                    <Shield className="h-6 w-6 text-primary/20" />
                                </div>
                                <h3 className="text-sm font-bold text-on-surface mb-1">Select a Role</h3>
                                <p className="text-[11px] text-on-surface-variant/30 font-medium max-w-xs">
                                    Click a role on the left to view and manage its assigned permissions.
                                </p>
                            </div>
                        )}
                    </div>
                </div>
            ) : (
                /* ── Permissions tab ──────────────────────────────────── */
                <div className="flex flex-1 overflow-hidden">
                    {/* Create permission form */}
                    <div className="w-[320px] min-w-[320px] border-r border-on-surface/5 p-4 space-y-4 bg-card/30">
                        <p className="text-[9px] font-bold tracking-widest text-on-surface-variant/30 uppercase">Add Permission</p>
                        <form onSubmit={handleCreatePermission} className="space-y-2.5">
                            <div>
                                <Label className="text-[9px] font-bold tracking-widest text-on-surface-variant/30 uppercase mb-1 block">Resource</Label>
                                <Input
                                    placeholder="e.g. applications"
                                    value={newPermission.resource}
                                    onChange={(e) => setNewPermission({ ...newPermission, resource: e.target.value })}
                                    className="h-8 border-none rounded-lg bg-surface-container/40 ring-1 ring-on-surface/5 focus-visible:ring-primary/20 text-[11px] font-medium"
                                    required
                                />
                            </div>
                            <div>
                                <Label className="text-[9px] font-bold tracking-widest text-on-surface-variant/30 uppercase mb-1 block">Action</Label>
                                <Input
                                    placeholder="e.g. READ, WRITE"
                                    value={newPermission.action}
                                    onChange={(e) => setNewPermission({ ...newPermission, action: e.target.value })}
                                    className="h-8 border-none rounded-lg bg-surface-container/40 ring-1 ring-on-surface/5 focus-visible:ring-primary/20 text-[11px] font-medium"
                                    required
                                />
                            </div>
                            <div>
                                <Label className="text-[9px] font-bold tracking-widest text-on-surface-variant/30 uppercase mb-1 block">Description</Label>
                                <Input
                                    placeholder="Brief description..."
                                    value={newPermission.description}
                                    onChange={(e) => setNewPermission({ ...newPermission, description: e.target.value })}
                                    className="h-8 border-none rounded-lg bg-surface-container/40 ring-1 ring-on-surface/5 focus-visible:ring-primary/20 text-[11px] font-medium"
                                />
                            </div>
                            <Button type="submit" className="w-full h-8 rounded-lg text-[10px] font-bold shadow-sm shadow-primary/10">
                                <Plus className="w-3 h-3 mr-1.5" /> Create Permission
                            </Button>
                        </form>
                    </div>

                    {/* Permissions table */}
                    <div className="flex-1 overflow-y-auto custom-scrollbar">
                        <GlassTable>
                            <GlassTableHeader>
                                <GlassTableRow className="hover:bg-transparent border-b border-on-surface/5">
                                    <GlassTableHead className="py-2 pl-5 font-bold text-[8px] tracking-widest text-on-surface-variant/40 uppercase">Resource</GlassTableHead>
                                    <GlassTableHead className="py-2 font-bold text-[8px] tracking-widest text-on-surface-variant/40 uppercase">Action</GlassTableHead>
                                    <GlassTableHead className="py-2 font-bold text-[8px] tracking-widest text-on-surface-variant/40 pr-5 uppercase">Description</GlassTableHead>
                                </GlassTableRow>
                            </GlassTableHeader>
                            <TableBody>
                                {permissions.map(p => (
                                    <PermissionTableRow key={p.id} permission={p} />
                                ))}
                                {permissions.length === 0 && (
                                    <tr>
                                        <td colSpan={3} className="py-20 text-center text-[11px] text-on-surface-variant/30 font-medium">No permissions defined</td>
                                    </tr>
                                )}
                            </TableBody>
                        </GlassTable>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Roles;
