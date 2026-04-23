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
        <div className="space-y-10 animate-in fade-in duration-700">
            <PageHeader
                icon={<Shield className="w-8 h-8 text-primary" />}
                title="Sentry & Access"
                description="Orchestrate security roles and cryptographic permission protocols across the administrative matrix."
                actions={
                    <div className="flex bg-surface-container/50 p-1 rounded-2xl ring-1 ring-on-surface/5">
                        <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setActiveTab('roles')}
                            className={`rounded-xl font-bold tracking-tight text-[11px] h-10 px-6 transition-all ${activeTab === 'roles' ? 'bg-white text-primary shadow-sm' : 'text-on-surface-variant/40 hover:text-on-surface'}`}
                        >
                            Roles Registry
                        </Button>
                        <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setActiveTab('permissions')}
                            className={`rounded-xl font-bold tracking-tight text-[11px] h-10 px-6 transition-all ${activeTab === 'permissions' ? 'bg-white text-primary shadow-sm' : 'text-on-surface-variant/40 hover:text-on-surface'}`}
                        >
                            Permission Vectors
                        </Button>
                    </div>
                }
            />

            {activeTab === 'roles' ? (
                <div className="grid grid-cols-1 md:grid-cols-12 gap-10 items-start">
                    {/* LEFT: ROLES MANAGEMENT */}
                    <div className="md:col-span-4 space-y-10">
                        <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-white overflow-hidden rounded-[24px]">
                            <GlassCardHeader className="bg-primary p-8 text-white">
                                <div className="flex items-center gap-4">
                                    <div className="p-2.5 bg-white/20 rounded-xl backdrop-blur-md">
                                        <Plus className="w-5 h-5 text-white" />
                                    </div>
                                    <GlassCardTitle className="text-xl font-bold tracking-tight">Define Role</GlassCardTitle>
                                </div>
                            </GlassCardHeader>
                            <GlassCardContent className="p-8">
                                <form onSubmit={handleCreateRole} className="space-y-8">
                                    <div className="space-y-2.5">
                                        <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Role Identifier</Label>
                                        <Input
                                            placeholder="e.g. CORE_OPERATOR"
                                            value={newRole.name}
                                            onChange={(e) => setNewRole({ ...newRole, name: e.target.value })}
                                            className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium transition-all"
                                            required
                                        />
                                    </div>
                                     <div className="space-y-2.5">
                                         <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">System metadata</Label>
                                        <Input
                                            placeholder="Operational privilege set..."
                                            value={newRole.description}
                                            onChange={(e) => setNewRole({ ...newRole, description: e.target.value })}
                                            className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium transition-all"
                                        />
                                    </div>
                                     <Button type="submit" className="w-full h-12 rounded-xl font-bold text-sm shadow-md shadow-primary/10">
                                         Initialize role
                                     </Button>
                                </form>
                            </GlassCardContent>
                        </GlassCard>

                        <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-white overflow-hidden flex flex-col h-[600px] rounded-[24px]">
                            <GlassCardHeader className="py-8 px-8 border-b border-on-surface/5">
                                 <GlassCardTitle className="text-lg font-bold tracking-tight text-on-surface">Roles index</GlassCardTitle>
                                 <p className="text-[12px] font-bold text-on-surface-variant/40 mt-1 tracking-tight">{roles.length} Registered identifiers</p>
                            </GlassCardHeader>
                            <div className="flex-1 overflow-y-auto p-4 space-y-2 custom-scrollbar">
                                {roles.map(role => (
                                    <div
                                        key={role.id}
                                        onClick={() => setSelectedRole(role)}
                                        className={`
                                            group flex items-center justify-between p-5 cursor-pointer transition-all rounded-2xl
                                            ${selectedRole?.id === role.id
                                                ? 'bg-primary/5 ring-1 ring-primary/20'
                                                : 'bg-white hover:bg-surface-container/30 ring-1 ring-on-surface/5 hover:ring-on-surface/10'}
                                        `}
                                    >
                                        <div className="min-w-0 pr-4">
                                            <div className={`font-bold text-sm tracking-tight truncate flex items-center gap-3 transition-colors ${selectedRole?.id === role.id ? 'text-primary' : 'text-on-surface'}`}>
                                                <Fingerprint className={`h-4 w-4 opacity-40 ${selectedRole?.id === role.id ? 'text-primary' : ''}`} />
                                                {role.name}
                                            </div>
                                            <div className="text-[10px] font-medium text-on-surface-variant/40 truncate mt-1.5 tracking-tight">
                                                {role.description || 'No system metadata provided'}
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            {selectedRole?.id === role.id && <ChevronRight className="h-5 w-5 text-primary/40 animate-in fade-in slide-in-from-left-2" />}
                                            <Button
                                                size="icon"
                                                variant="ghost"
                                                className={`h-9 w-9 rounded-xl hover:bg-red-50 hover:text-red-500 transition-all ${selectedRole?.id === role.id ? 'opacity-20' : 'opacity-0 group-hover:opacity-40'}`}
                                                onClick={(e) => handleDeleteRole(role.id, e)}
                                            >
                                                <Trash2 className="h-4 w-4" />
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
                            <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-white overflow-hidden min-h-[850px] flex flex-col rounded-[32px]">
                                <GlassCardHeader className="bg-surface-container p-12 ">
                                    <div className="flex items-center justify-between">
                                        <div className="space-y-5">
                                            <div className="flex items-center gap-5">
                                                <div className="p-3.5 bg-primary/10 rounded-2xl">
                                                    <Shield className="w-8 h-8 text-primary" />
                                                </div>
                                                <h2 className="text-4xl font-bold tracking-tight text-on-surface">{selectedRole.name}</h2>
                                            </div>
                                            <p className="font-medium text-sm text-on-surface-variant/60 max-w-xl">{selectedRole.description || 'System-defined security object identified.'}</p>
                                        </div>
                                    </div>
                                </GlassCardHeader>
                                <GlassCardContent className="p-12 space-y-16 flex-1 overflow-y-auto bg-white">
                                    {/* BOUND POLICIES */}
                                    <div className="space-y-10">
                                        <div className="flex items-center justify-between border-b border-on-surface/5 pb-6">
                                             <h3 className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 flex items-center gap-3">
                                                 <ShieldCheck className="w-4.5 h-4.5 text-emerald-500" />
                                                 Synchronized permissions
                                             </h3>
                                             <Badge className="bg-emerald-50 text-emerald-600 border-none rounded-xl h-8 px-4 text-xs font-bold tracking-tight">
                                                 {rolePermissions.length} Active vectors
                                             </Badge>
                                        </div>
                                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                            {rolePermissions.length === 0 ? (
                                                <div className="col-span-full py-20 border-2 border-dashed rounded-[32px] bg-surface-container/10 flex flex-col items-center justify-center">
                                                    <Lock className="w-10 h-10 mb-4 text-on-surface-variant/10" />
                                                    <span className="text-sm font-medium text-on-surface-variant/40">No permissions associated with this matrix.</span>
                                                </div>
                                            ) : (
                                                rolePermissions.map(p => (
                                                    <div key={p.id} className="p-6 bg-white ring-1 ring-on-surface/5 rounded-2xl flex items-center justify-between group hover:ring-emerald-500/20 hover:bg-emerald-50/10 transition-all shadow-sm hover:shadow-lg hover:shadow-emerald-500/5">
                                                         <div className="flex flex-col">
                                                             <span className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 mb-2 italic">Resource vector</span>
                                                            <div className="flex items-center gap-3">
                                                                <span className="font-mono text-xs font-bold text-on-surface">{p.resource}</span>
                                                                <span className="text-on-surface-variant/10">/</span>
                                                                <Badge className="bg-primary/5 text-primary border-none rounded-lg font-bold text-[10px] tracking-tight px-2.5 py-1">{p.action}</Badge>
                                                            </div>
                                                        </div>
                                                        <div className="w-10 h-10 bg-emerald-50 rounded-xl flex items-center justify-center">
                                                            <ShieldCheck className="w-4.5 h-4.5 text-emerald-600" />
                                                        </div>
                                                    </div>
                                                ))
                                            )}
                                        </div>
                                    </div>

                                    {/* AVAILABLE POLICIES */}
                                    <div className="space-y-10">
                                        <div className="flex items-center justify-between border-b border-on-surface/5 pb-6">
                                             <h3 className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 flex items-center gap-3">
                                                 <Command className="w-4.5 h-4.5 text-primary/40" />
                                                 Available system vectors
                                             </h3>
                                        </div>
                                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 max-h-[500px] overflow-y-auto pr-4 custom-scrollbar">
                                            {permissions
                                                .filter(p => !rolePermissions.find(rp => rp.id === p.id))
                                                .map(p => (
                                                    <div key={p.id} className="p-6 bg-white ring-1 ring-on-surface/5 rounded-2xl group hover:ring-primary/20 hover:bg-primary/5 transition-all cursor-pointer shadow-sm hover:shadow-lg hover:shadow-primary/5" onClick={() => handleAssignPermission(p.id)}>
                                                        <div className="flex items-center justify-between">
                                                            <div className="flex flex-col min-w-0 pr-4">
                                                                <div className="flex items-center gap-3 mb-2">
                                                                    <span className="font-mono text-[11px] font-bold text-on-surface">{p.resource}</span>
                                                                    <span className="text-on-surface-variant/10">:</span>
                                                                    <span className="font-bold text-[11px] text-primary">{p.action}</span>
                                                                </div>
                                                                <span className="text-[10px] font-medium text-on-surface-variant/40 tracking-tight truncate">{p.description || 'No verifiable description provided'}</span>
                                                            </div>
                                                            <div className="flex-shrink-0 w-10 h-10 rounded-xl bg-surface-container/50 group-hover:bg-primary group-hover:text-white flex items-center justify-center transition-all">
                                                                <Plus className="h-4.5 w-4.5" />
                                                            </div>
                                                        </div>
                                                    </div>
                                                ))
                                            }
                                            {permissions.length === 0 && <div className="col-span-full py-12 text-center text-sm font-medium text-on-surface-variant/20 italic">No available system vectors established.</div>}
                                        </div>
                                    </div>
                                </GlassCardContent>
                            </GlassCard>
                        ) : (
                            <div className="h-full flex flex-col items-center justify-center border-2 border-dashed rounded-[40px] border-on-surface/5 bg-surface-container/10 min-h-[850px] animate-in fade-in duration-1000">
                                <div className="p-16 bg-white rounded-[32px] shadow-2xl shadow-on-surface/5 flex flex-col items-center text-center max-w-lg mx-auto">
                                    <div className="w-24 h-24 bg-primary/5 rounded-[32px] flex items-center justify-center mb-10">
                                        <Shield className="h-12 w-12 text-primary/20 animate-pulse" />
                                    </div>
                                    <h3 className="text-2xl font-bold tracking-tight text-on-surface mb-4">Core Shrouded</h3>
                                    <p className="text-sm font-medium text-on-surface-variant/40 leading-relaxed max-w-xs">Select a cryptographic role from the primary index to orchestrate the underlying permission matrix.</p>
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            ) : (
                /* PERMISSIONS REGISTRY */
                <div className="grid grid-cols-1 md:grid-cols-12 gap-10 items-start">
                    <div className="md:col-span-4">
                        <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-white overflow-hidden rounded-[24px]">
                            <GlassCardHeader className="bg-primary p-12 text-white">
                                <div className="flex items-center gap-5">
                                    <div className="p-3 bg-white/20 rounded-2xl backdrop-blur-md">
                                        <Plus className="w-6 h-6 text-white" />
                                    </div>
                                     <GlassCardTitle className="text-2xl font-bold tracking-tight">Register vector</GlassCardTitle>
                                </div>
                            </GlassCardHeader>
                            <GlassCardContent className="p-10">
                                <form onSubmit={handleCreatePermission} className="space-y-8">
                                     <div className="space-y-2.5">
                                         <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Vector resource</Label>
                                        <Input
                                            placeholder="e.g. applications"
                                            value={newPermission.resource}
                                            onChange={(e) => setNewPermission({ ...newPermission, resource: e.target.value })}
                                            className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium transition-all"
                                            required
                                        />
                                    </div>
                                     <div className="space-y-2.5">
                                         <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Vector action</Label>
                                        <Input
                                            placeholder="e.g. WRITE"
                                            value={newPermission.action}
                                            onChange={(e) => setNewPermission({ ...newPermission, action: e.target.value })}
                                            className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium transition-all"
                                            required
                                        />
                                    </div>
                                     <div className="space-y-2.5">
                                         <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Vector description</Label>
                                        <Input
                                            placeholder="Detailed access logic description..."
                                            value={newPermission.description}
                                            onChange={(e) => setNewPermission({ ...newPermission, description: e.target.value })}
                                            className="h-12 border-none rounded-xl bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 font-medium transition-all"
                                        />
                                    </div>
                                     <Button type="submit" className="w-full h-12 rounded-xl font-bold text-sm shadow-md shadow-primary/10">
                                         Commit permission
                                     </Button>
                                </form>
                            </GlassCardContent>
                        </GlassCard>
                    </div>
                    <div className="md:col-span-8">
                        <GlassCard className="border-none shadow-xl shadow-on-surface/5 bg-white overflow-hidden rounded-[32px]">
                            <GlassCardHeader className="py-10 px-10 border-b border-on-surface/5">
                                <div className="flex items-center gap-6">
                                    <div className="p-4 bg-primary/5 rounded-[20px]">
                                        <Lock className="w-8 h-8 text-primary" />
                                    </div>
                                     <div>
                                         <GlassCardTitle className="text-3xl font-bold tracking-tight text-on-surface">System vectors</GlassCardTitle>
                                         <p className="text-on-surface-variant/40 font-bold text-[12px] mt-1 tracking-tight">{permissions.length} Granular protocols established</p>
                                     </div>
                                </div>
                            </GlassCardHeader>
                            <GlassCardContent className="p-0">
                                <div className="overflow-x-auto">
                                    <GlassTable>
                                        <GlassTableHeader>
                                            <GlassTableRow className="hover:bg-transparent border-b border-on-surface/5">
                                                 <GlassTableHead className="py-6 pl-10 font-bold text-[12px] tracking-tight text-on-surface-variant/40">Resource context</GlassTableHead>
                                                 <GlassTableHead className="font-bold text-[12px] tracking-tight text-on-surface-variant/40">Action protocol</GlassTableHead>
                                                 <GlassTableHead className="font-bold text-[12px] tracking-tight text-on-surface-variant/40 pr-10">System description</GlassTableHead>
                                            </GlassTableRow>
                                        </GlassTableHeader>
                                        <TableBody>
                                            {permissions.map(p => (
                                                <GlassTableRow key={p.id} className="hover:bg-surface-container/20 transition-all border-b border-on-surface/5 last:border-0 group">
                                                    <TableCell className="py-8 pl-10 font-mono text-sm font-bold text-on-surface/60">{p.resource}</TableCell>
                                                     <TableCell className="py-8">
                                                         <Badge className="bg-primary/5 text-primary border-none rounded-lg font-bold text-[10px] tracking-tight px-4 py-1.5 group-hover:bg-primary group-hover:text-white transition-all shadow-none">
                                                             {p.action}
                                                         </Badge>
                                                     </TableCell>
                                                    <TableCell className="py-8 text-[11px] font-bold text-on-surface-variant/20 italic tracking-tight pr-10">{p.description || 'No system definition metadata'}</TableCell>
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
