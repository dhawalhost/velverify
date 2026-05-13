import React, { useState, useEffect } from 'react';
import { getRoles, createRole, deleteRole, getPermissions, createPermission, getRolePermissions, assignPermissionToRole } from '../api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { TableBody, TableCell } from '@/components/ui/table';
import { Loader2, Plus, Trash2, Shield, Lock, ChevronRight, ShieldCheck, Fingerprint, Command } from 'lucide-react';
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassTable, GlassTableHeader, GlassTableHead, GlassTableRow } from '@/components/layout';

interface Role {
    id: string;
    name: string;
    description: string;
    created_at: string;
}

interface Permission {
    id: string;
    resource: string;
    action: string;
    description: string;
}

const Roles: React.FC = () => {
    const [roles, setRoles] = useState<Role[]>([]);
    const [permissions, setPermissions] = useState<Permission[]>([]);
    const [selectedRole, setSelectedRole] = useState<Role | null>(null);
    const [rolePermissions, setRolePermissions] = useState<Permission[]>([]);
    const [newRole, setNewRole] = useState({ name: '', description: '' });
    const [newPermission, setNewPermission] = useState({ resource: '', action: '', description: '' });
    const [loading, setLoading] = useState(true);
    const [activeTab, setActiveTab] = useState<'roles' | 'permissions'>('roles');

    useEffect(() => { loadData(); }, []);

    useEffect(() => {
        if (selectedRole) {
            loadRolePermissions(selectedRole.id);
        }
    }, [selectedRole]);

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
        if (window.confirm('Are you sure you want to delete this role?')) {
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

    if (loading) return <div className="h-[400px] flex items-center justify-center"><Loader2 className="h-10 w-10 animate-spin text-primary opacity-20" /></div>;

    return (
        <div className="space-y-4 animate-in fade-in duration-700">
            <PageHeader
                icon={<Shield className="w-7 h-7 text-primary" />}
                title="Roles & Permissions"
                description="Manage system roles and the permissions assigned to them. Control who can access specific resources."
                actions={
                    <div className="flex bg-surface-container/50 p-0.5 rounded-xl ring-1 ring-on-surface/5">
                        <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setActiveTab('roles')}
                            className={`rounded-lg font-bold tracking-tight text-[10px] h-8 px-4 transition-all ${activeTab === 'roles' ? 'bg-card text-primary shadow-sm' : 'text-on-surface-variant/40 hover:text-on-surface'}`}
                        >
                            Roles List
                        </Button>
                        <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setActiveTab('permissions')}
                            className={`rounded-lg font-bold tracking-tight text-[10px] h-8 px-4 transition-all ${activeTab === 'permissions' ? 'bg-card text-primary shadow-sm' : 'text-on-surface-variant/40 hover:text-on-surface'}`}
                        >
                            System Permissions
                        </Button>
                    </div>
                }
            />

            {activeTab === 'roles' ? (
                <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-start">
                    {/* LEFT: ROLES MANAGEMENT */}
                    <div className="md:col-span-4 space-y-4">
                        <GlassCard className="border-none shadow-lg shadow-on-surface/5 bg-card overflow-hidden rounded-xl">
                            <GlassCardHeader className="bg-primary p-3 text-white">
                                <div className="flex items-center gap-2">
                                    <div className="p-1.5 bg-card/20 rounded-md backdrop-blur-md">
                                        <Plus className="w-3.5 h-3.5 text-white" />
                                    </div>
                                    <GlassCardTitle className="text-base font-bold tracking-tight">Create New Role</GlassCardTitle>
                                </div>
                            </GlassCardHeader>
                            <GlassCardContent className="p-4">
                                <form onSubmit={handleCreateRole} className="space-y-4">
                                    <div className="space-y-2">
                                        <Label className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 ml-1 uppercase">Role Name</Label>
                                        <Input
                                            placeholder="e.g. CORE_OPERATOR"
                                            value={newRole.name}
                                            onChange={(e) => setNewRole({ ...newRole, name: e.target.value })}
                                            className="h-10 border-none rounded-lg bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium transition-all text-xs"
                                            required
                                        />
                                    </div>
                                     <div className="space-y-2">
                                         <Label className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 ml-1 uppercase">Description</Label>
                                        <Input
                                            placeholder="What this role allows..."
                                            value={newRole.description}
                                            onChange={(e) => setNewRole({ ...newRole, description: e.target.value })}
                                            className="h-10 border-none rounded-lg bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium transition-all text-xs"
                                        />
                                    </div>
                                     <Button type="submit" className="w-full h-10 rounded-lg font-bold text-xs shadow-md shadow-primary/10">
                                         Create Role
                                     </Button>
                                </form>
                            </GlassCardContent>
                        </GlassCard>

                        <GlassCard className="border-none shadow-lg shadow-on-surface/5 bg-card overflow-hidden flex flex-col h-[400px] rounded-xl">
                            <GlassCardHeader className="py-2 px-4 border-b border-on-surface/5">
                                 <GlassCardTitle className="text-base font-bold tracking-tight text-on-surface">Active Roles</GlassCardTitle>
                                 <p className="text-[10px] font-bold text-on-surface-variant/40 mt-0.5 tracking-tight uppercase">{roles.length} Roles Found</p>
                            </GlassCardHeader>
                            <div className="flex-1 overflow-y-auto p-2 space-y-1.5 custom-scrollbar">
                                {roles.map(role => (
                                    <div
                                        key={role.id}
                                        onClick={() => setSelectedRole(role)}
                                        className={`
                                            group flex items-center justify-between p-2 cursor-pointer transition-all rounded-lg
                                            ${selectedRole?.id === role.id
                                                ? 'bg-primary/5 ring-1 ring-primary/20'
                                                : 'bg-card hover:bg-surface-container/30 ring-1 ring-on-surface/5 hover:ring-on-surface/10'}
                                        `}
                                    >
                                        <div className="min-w-0 pr-4">
                                            <div className={`font-bold text-[11px] tracking-tight truncate flex items-center gap-2 transition-colors ${selectedRole?.id === role.id ? 'text-primary' : 'text-on-surface'}`}>
                                                <Fingerprint className={`h-3 w-3 opacity-40 ${selectedRole?.id === role.id ? 'text-primary' : ''}`} />
                                                {role.name}
                                            </div>
                                            <div className="text-[9px] font-medium text-on-surface-variant/40 truncate mt-1 tracking-tight">
                                                {role.description || 'No description provided'}
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            {selectedRole?.id === role.id && <ChevronRight className="h-4 w-4 text-primary/40 animate-in fade-in slide-in-from-left-2" />}
                                            <Button
                                                size="icon"
                                                variant="ghost"
                                                className={`h-7 w-7 rounded-md hover:bg-destructive/10 hover:text-destructive transition-all ${selectedRole?.id === role.id ? 'opacity-20' : 'opacity-0 group-hover:opacity-40'}`}
                                                onClick={(e) => handleDeleteRole(role.id, e)}
                                            >
                                                <Trash2 className="h-3 w-3" />
                                            </Button>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </GlassCard>
                    </div>

                    {/* RIGHT: BINDING CONTROLS */}
                    <div className="md:col-span-8">
                        {selectedRole ? (
                            <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-card overflow-hidden min-h-[600px] flex flex-col rounded-xl">
                                <GlassCardHeader className="bg-surface-container p-4 ">
                                    <div className="flex items-center justify-between">
                                        <div className="space-y-3">
                                            <div className="flex items-center gap-3">
                                                <div className="p-2 bg-primary/10 rounded-lg">
                                                    <Shield className="w-5 h-5 text-primary" />
                                                </div>
                                                <h2 className="text-xl font-bold tracking-tight text-on-surface">{selectedRole.name}</h2>
                                            </div>
                                            <p className="font-medium text-xs text-on-surface-variant/60 max-w-xl">{selectedRole.description || 'Details for this role.'}</p>
                                        </div>
                                    </div>
                                </GlassCardHeader>
                                <GlassCardContent className="p-4 space-y-6 flex-1 overflow-y-auto bg-card">
                                    {/* BOUND POLICIES */}
                                    <div className="space-y-4">
                                        <div className="flex items-center justify-between border-b border-on-surface/5 pb-3">
                                             <h3 className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 flex items-center gap-2 uppercase">
                                                 <ShieldCheck className="w-3.5 h-3.5 text-success" />
                                                 Assigned Permissions
                                             </h3>
                                             <Badge className="bg-success-subtle text-success border-none rounded-lg h-5 px-2.5 text-[9px] font-bold tracking-tight uppercase">
                                                 {rolePermissions.length} Permissions
                                             </Badge>
                                        </div>
                                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                            {rolePermissions.length === 0 ? (
                                                <div className="col-span-full py-12 border-2 border-dashed rounded-2xl bg-surface-container/10 flex flex-col items-center justify-center">
                                                    <Lock className="w-8 h-8 mb-2 text-on-surface-variant/10" />
                                                    <span className="text-xs font-medium text-on-surface-variant/40">No permissions assigned to this role.</span>
                                                </div>
                                            ) : (
                                                rolePermissions.map(p => (
                                                    <div key={p.id} className="p-2.5 bg-card ring-1 ring-on-surface/5 rounded-lg flex items-center justify-between group hover:ring-emerald-500/20 hover:bg-success-subtle/10 transition-all shadow-sm">
                                                         <div className="flex flex-col">
                                                             <span className="text-[9px] font-bold tracking-tight text-on-surface-variant/40 mb-1 italic uppercase">Resource</span>
                                                            <div className="flex items-center gap-2">
                                                                <span className="font-mono text-[10px] font-bold text-on-surface">{p.resource}</span>
                                                                <span className="text-on-surface-variant/10">/</span>
                                                                <Badge className="bg-primary/5 text-primary border-none rounded-md font-bold text-[9px] tracking-tight px-2 py-0.5 uppercase">{p.action}</Badge>
                                                            </div>
                                                        </div>
                                                        <div className="w-7 h-7 bg-success-subtle rounded-md flex items-center justify-center">
                                                            <ShieldCheck className="w-3.5 h-3.5 text-success" />
                                                        </div>
                                                    </div>
                                                ))
                                            )}
                                        </div>
                                    </div>

                                    {/* AVAILABLE POLICIES */}
                                    <div className="space-y-4">
                                        <div className="flex items-center justify-between border-b border-on-surface/5 pb-3">
                                             <h3 className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 flex items-center gap-2 uppercase">
                                                 <Command className="w-3.5 h-3.5 text-primary/40" />
                                                 Available Permissions
                                             </h3>
                                        </div>
                                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 max-h-[400px] overflow-y-auto pr-3 custom-scrollbar">
                                            {permissions
                                                .filter(p => !rolePermissions.find(rp => rp.id === p.id))
                                                .map(p => (
                                                    <div key={p.id} className="p-4 bg-card ring-1 ring-on-surface/5 rounded-xl group hover:ring-primary/20 hover:bg-primary/5 transition-all cursor-pointer shadow-sm" onClick={() => handleAssignPermission(p.id)}>
                                                        <div className="flex items-center justify-between">
                                                            <div className="flex flex-col min-w-0 pr-3">
                                                                <div className="flex items-center gap-2 mb-1.5">
                                                                    <span className="font-mono text-[10px] font-bold text-on-surface">{p.resource}</span>
                                                                    <span className="text-on-surface-variant/10">:</span>
                                                                    <span className="font-bold text-[10px] text-primary">{p.action}</span>
                                                                </div>
                                                                <span className="text-[9px] font-medium text-on-surface-variant/40 tracking-tight truncate">{p.description || 'No verifiable description provided'}</span>
                                                            </div>
                                                            <div className="flex-shrink-0 w-7 h-7 rounded-md bg-surface-container/50 group-hover:bg-primary group-hover:text-primary-foreground flex items-center justify-center transition-all">
                                                                <Plus className="h-3 w-3" />
                                                            </div>
                                                        </div>
                                                    </div>
                                                ))
                                            }
                                            {permissions.length === 0 && <div className="col-span-full py-12 text-center text-sm font-medium text-on-surface-variant/20 italic">No permissions available to assign.</div>}
                                        </div>
                                    </div>
                                </GlassCardContent>
                            </GlassCard>
                        ) : (
                            <div className="h-full flex flex-col items-center justify-center border-2 border-dashed rounded-[24px] border-on-surface/5 bg-surface-container/10 min-h-[700px] animate-in fade-in duration-1000">
                                <div className="p-10 bg-card rounded-2xl shadow-xl shadow-on-surface/5 flex flex-col items-center text-center max-w-sm mx-auto">
                                    <div className="w-16 h-16 bg-primary/5 rounded-2xl flex items-center justify-center mb-6">
                                        <Shield className="h-8 w-8 text-primary/20 animate-pulse" />
                                    </div>
                                    <h3 className="text-xl font-bold tracking-tight text-on-surface mb-2">No Role Selected</h3>
                                    <p className="text-xs font-medium text-on-surface-variant/40 leading-relaxed max-w-xs">Choose a role from the list on the left to view and manage its permissions.</p>
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            ) : (
                /* PERMISSIONS REGISTRY */
                <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-start">
                    <div className="md:col-span-4">
                        <GlassCard className="border-none shadow-lg shadow-on-surface/5 bg-card overflow-hidden rounded-xl">
                            <GlassCardHeader className="bg-primary p-4 text-white">
                                <div className="flex items-center gap-3">
                                    <div className="p-2 bg-card/20 rounded-lg backdrop-blur-md">
                                        <Plus className="w-4 h-4 text-white" />
                                    </div>
                                     <GlassCardTitle className="text-lg font-bold tracking-tight">Add Permission</GlassCardTitle>
                                </div>
                            </GlassCardHeader>
                            <GlassCardContent className="p-4">
                                <form onSubmit={handleCreatePermission} className="space-y-5">
                                     <div className="space-y-2">
                                         <Label className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 ml-1 uppercase">Resource Name</Label>
                                        <Input
                                            placeholder="e.g. applications"
                                            value={newPermission.resource}
                                            onChange={(e) => setNewPermission({ ...newPermission, resource: e.target.value })}
                                            className="h-10 border-none rounded-lg bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium transition-all text-xs"
                                            required
                                        />
                                    </div>
                                     <div className="space-y-2">
                                         <Label className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 ml-1 uppercase">Action (e.g. READ, WRITE)</Label>
                                        <Input
                                            placeholder="e.g. WRITE"
                                            value={newPermission.action}
                                            onChange={(e) => setNewPermission({ ...newPermission, action: e.target.value })}
                                            className="h-10 border-none rounded-lg bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium transition-all text-xs"
                                            required
                                        />
                                    </div>
                                     <div className="space-y-2">
                                         <Label className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 ml-1 uppercase">Description</Label>
                                        <Input
                                            placeholder="Detailed access logic description..."
                                            value={newPermission.description}
                                            onChange={(e) => setNewPermission({ ...newPermission, description: e.target.value })}
                                            className="h-10 border-none rounded-lg bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium transition-all text-xs"
                                        />
                                    </div>
                                     <Button type="submit" className="w-full h-10 rounded-lg font-bold text-xs shadow-md shadow-primary/10">
                                         Create Permission
                                     </Button>
                                </form>
                            </GlassCardContent>
                        </GlassCard>
                    </div>
                    <div className="md:col-span-8">
                        <GlassCard className="border-none shadow-lg shadow-on-surface/5 bg-card overflow-hidden rounded-2xl">
                            <GlassCardHeader className="py-2 px-4 border-b border-on-surface/5">
                                <div className="flex items-center gap-3">
                                    <div className="p-2 bg-primary/5 rounded-lg">
                                        <Lock className="w-4 h-4 text-primary" />
                                    </div>
                                     <div>
                                         <GlassCardTitle className="text-base font-bold tracking-tight text-on-surface">All Permissions</GlassCardTitle>
                                         <p className="text-on-surface-variant/40 font-bold text-[9px] mt-0.5 tracking-tight uppercase">{permissions.length} Permissions Found</p>
                                     </div>
                                </div>
                            </GlassCardHeader>
                            <GlassCardContent className="p-0">
                                <div className="overflow-x-auto">
                                    <GlassTable>
                                        <GlassTableHeader>
                                            <GlassTableRow className="hover:bg-transparent border-b border-on-surface/5">
                                                 <GlassTableHead className="py-2 pl-4 font-bold text-[8px] tracking-widest text-on-surface-variant/40 uppercase">Resource</GlassTableHead>
                                                 <GlassTableHead className="py-2 font-bold text-[8px] tracking-widest text-on-surface-variant/40 uppercase">Action</GlassTableHead>
                                                 <GlassTableHead className="py-2 font-bold text-[8px] tracking-widest text-on-surface-variant/40 pr-4 uppercase">Description</GlassTableHead>
                                            </GlassTableRow>
                                        </GlassTableHeader>
                                        <TableBody>
                                            {permissions.map(p => (
                                                <GlassTableRow key={p.id} className="hover:bg-surface-container/20 transition-all border-b border-on-surface/5 last:border-0 group">
                                                    <TableCell className="py-1.5 pl-4 font-mono text-[10px] font-bold text-on-surface/60">{p.resource}</TableCell>
                                                     <TableCell className="py-1.5">
                                                         <Badge className="bg-primary/5 text-primary border-none rounded-md font-bold text-[8px] tracking-tight px-2 py-0.5 group-hover:bg-primary group-hover:text-primary-foreground transition-all shadow-none uppercase">
                                                             {p.action}
                                                         </Badge>
                                                     </TableCell>
                                                    <TableCell className="py-1.5 text-[9px] font-bold text-on-surface-variant/20 italic tracking-tight pr-4">{p.description || 'No system definition metadata'}</TableCell>
                                                </GlassTableRow>
                                            ))}
                                        </TableBody>
                                    </GlassTable>
                                </div>
                            </GlassCardContent>
                        </GlassCard>
                    </div>
                </div>
            )}
        </div>

    );
};

export default Roles;
