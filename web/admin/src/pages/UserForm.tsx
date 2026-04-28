import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { 
    getSCIMUser, 
    createSCIMUser, 
    updateSCIMUser, 
    getGroups, 
    getOrganizations 
} from '../api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { 
    Loader2, 
    Save, 
    X, 
    User, 
    Users, 
    Building2, 
    Mail, 
    ShieldCheck, 
    Globe, 
    ArrowLeft,
    CheckCircle2,
    Info,
    Layout
} from 'lucide-react';
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassCardDescription } from '@/components/layout';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';

export default function UserForm() {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const isEdit = !!id;

    const [loading, setLoading] = useState(isEdit);
    const [submitting, setSubmitting] = useState(false);
    const [groups, setGroups] = useState<any[]>([]);
    const [orgs, setOrgs] = useState<any[]>([]);
    const [error, setError] = useState<string | null>(null);

    const [formData, setFormData] = useState({
        userName: '',
        displayName: '',
        active: true,
        primaryEmail: '',
        organizationId: '',
        groups: [] as string[]
    });

    useEffect(() => {
        const loadData = async () => {
            try {
                const [groupsData, orgsData] = await Promise.all([
                    getGroups(),
                    getOrganizations()
                ]);
                setGroups(groupsData.groups || groupsData.Resources || []);
                setOrgs(orgsData.organizations || []);

                if (isEdit) {
                    const user = await getSCIMUser(id);
                    setFormData({
                        userName: user.userName || '',
                        displayName: user.displayName || '',
                        active: user.active ?? true,
                        primaryEmail: user.emails?.[0]?.value || '',
                        organizationId: user['urn:ietf:params:scim:schemas:extension:wardseal:2.0:User']?.organizationId || '',
                        groups: user.groups?.map((g: any) => g.value) || []
                    });
                }
            } catch (err) {
                console.error(err);
                setError('Failed to load identity metadata.');
            } finally {
                setLoading(false);
            }
        };

        loadData();
    }, [id, isEdit]);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setSubmitting(true);
        setError(null);

        const payload = {
            schemas: ["urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:wardseal:2.0:User"],
            userName: formData.userName,
            displayName: formData.displayName,
            active: formData.active,
            emails: [{ value: formData.primaryEmail, primary: true }],
            groups: formData.groups.map(gid => ({ value: gid })),
            "urn:ietf:params:scim:schemas:extension:wardseal:2.0:User": {
                organizationId: formData.organizationId
            }
        };

        try {
            if (isEdit) {
                await updateSCIMUser(id, payload);
            } else {
                await createSCIMUser(payload);
            }
            navigate('/users');
        } catch (err: any) {
            console.error(err);
            setError(err.response?.data?.detail || 'Failed to persist identity state.');
        } finally {
            setSubmitting(false);
        }
    };

    const toggleGroup = (groupId: string) => {
        setFormData(prev => ({
            ...prev,
            groups: prev.groups.includes(groupId)
                ? prev.groups.filter(id => id !== groupId)
                : [...prev.groups, groupId]
        }));
    };

    if (loading) return <div className="h-[400px] flex items-center justify-center"><Loader2 className="h-10 w-10 animate-spin text-primary opacity-20" /></div>;

    return (
        <div className="max-w-5xl mx-auto space-y-12 animate-in fade-in slide-in-from-bottom-4 duration-700 py-12">
            <PageHeader
                icon={<User className="w-10 h-10 text-primary" />}
                title={isEdit ? "Edit User" : "Add User"}
                description={isEdit ? "Update user details and their group memberships." : "Add a new user to your organization."}
                actions={
                    <Button 
                        variant="outline" 
                        onClick={() => navigate('/users')}
                        className="h-11 rounded-xl bg-card ring-1 ring-on-surface/5 font-semibold text-sm px-8 shadow-sm transition-all hover:bg-surface-container"
                    >
                        <ArrowLeft className="mr-3 h-4 w-4" /> Cancel
                    </Button>
                }
            />

            <form onSubmit={handleSubmit} className="space-y-12">
                {error && (
                    <Alert variant="destructive" className="rounded-2xl border-none bg-destructive/10 text-destructive animate-in slide-in-from-top-2">
                        <AlertDescription className="font-semibold text-sm flex items-center gap-3">
                            <ShieldCheck className="w-4 h-4" />
                            Error: {error}
                        </AlertDescription>
                    </Alert>
                )}

                <div className="grid grid-cols-1 lg:grid-cols-12 gap-12">
                    <div className="lg:col-span-12 space-y-10">
                        <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-card overflow-hidden rounded-[32px]">
                            <GlassCardHeader className="py-10 px-10 border-b border-on-surface/5 bg-surface-container/10">
                                <div className="flex items-center gap-6">
                                    <div className="p-4 bg-primary/5 rounded-2xl text-primary">
                                        <Layout className="w-7 h-7" />
                                    </div>
                                    <div>
                                        <GlassCardTitle className="text-3xl font-bold tracking-tight text-on-surface">Core Information</GlassCardTitle>
                                        <p className="text-on-surface-variant/60 font-medium text-[12px] tracking-tight mt-2">Basic user details.</p>
                                    </div>
                                </div>
                            </GlassCardHeader>
                            <GlassCardContent className="p-10">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-10">
                                    <div className="space-y-4">
                                        <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1 flex items-center gap-2">
                                            <Mail className="w-3.5 h-3.5" />
                                            Username (Email)
                                        </Label>
                                        <Input
                                            value={formData.userName}
                                            onChange={e => setFormData({ ...formData, userName: e.target.value })}
                                            placeholder="e.g. j.doe@wardseal.io"
                                            className="h-14 rounded-2xl border-none bg-surface-container/50 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-bold text-sm px-6"
                                            required
                                        />
                                    </div>
                                    <div className="space-y-4">
                                        <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1 flex items-center gap-2">
                                            <User className="w-3.5 h-3.5" />
                                            Display Name
                                        </Label>
                                        <Input
                                            value={formData.displayName}
                                            onChange={e => setFormData({ ...formData, displayName: e.target.value })}
                                            placeholder="e.g. John Doe"
                                            className="h-14 rounded-2xl border-none bg-surface-container/50 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-bold text-sm px-6"
                                            required
                                        />
                                    </div>
                                    <div className="space-y-4">
                                        <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1 flex items-center gap-2">
                                            <Globe className="w-3.5 h-3.5" />
                                            Contact Email
                                        </Label>
                                        <Input
                                            type="email"
                                            value={formData.primaryEmail}
                                            onChange={e => setFormData({ ...formData, primaryEmail: e.target.value })}
                                            placeholder="e.g. john.doe@provider.com"
                                            className="h-14 rounded-2xl border-none bg-surface-container/50 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-bold text-sm px-6"
                                            required
                                        />
                                    </div>
                                    <div className="space-y-4">
                                        <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1 flex items-center gap-2">
                                            <ShieldCheck className="w-3.5 h-3.5" />
                                            Account Status
                                        </Label>
                                        <div className="h-14 rounded-2xl bg-surface-container/50 ring-1 ring-on-surface/5 px-6 flex items-center justify-between group cursor-pointer" onClick={() => setFormData({ ...formData, active: !formData.active })}>
                                            <span className="text-sm font-bold tracking-tight text-on-surface-variant/60">Active Account</span>
                                            <Switch
                                                checked={formData.active}
                                                onCheckedChange={checked => setFormData({ ...formData, active: checked })}
                                                className="data-[state=checked]:bg-success"
                                            />
                                        </div>
                                    </div>
                                </div>
                            </GlassCardContent>
                        </GlassCard>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-12">
                            <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-card overflow-hidden rounded-[32px]">
                                <GlassCardHeader className="py-8 px-10 border-b border-on-surface/5">
                                    <div className="flex items-center gap-5">
                                        <div className="p-3 bg-primary/5 rounded-xl text-primary">
                                            <Building2 className="w-6 h-6" />
                                        </div>
                                        <div>
                                            <GlassCardTitle className="text-xl font-bold tracking-tight text-on-surface">Organization</GlassCardTitle>
                                            <p className="text-on-surface-variant/60 font-medium text-[11px] tracking-tight mt-1">Assign user to an organization.</p>
                                        </div>
                                    </div>
                                </GlassCardHeader>
                                <GlassCardContent className="p-10 space-y-4">
                                    {orgs.map(org => (
                                        <div 
                                            key={org.id} 
                                            onClick={() => setFormData({ ...formData, organizationId: org.id })}
                                            className={`p-6 rounded-2xl cursor-pointer transition-all border flex items-center justify-between group ${formData.organizationId === org.id 
                                                ? 'bg-primary/5 border-primary/20 shadow-lg shadow-primary/5' 
                                                : 'bg-card border-on-surface/5 hover:border-primary/10'}`}
                                        >
                                            <div className="flex items-center gap-4">
                                                <div className={`w-3 h-3 rounded-full transition-all ${formData.organizationId === org.id ? 'bg-primary scale-110' : 'bg-on-surface/10'}`} />
                                                <div className="flex flex-col">
                                                    <span className={`text-sm font-bold tracking-tight transition-colors ${formData.organizationId === org.id ? 'text-primary' : 'text-on-surface'}`}>{org.name}</span>
                                                    <span className="text-[10px] font-mono text-on-surface-variant/40 tracking-tight">ID: {org.id.substring(0, 12)}</span>
                                                </div>
                                            </div>
                                            {formData.organizationId === org.id && <CheckCircle2 className="w-5 h-5 text-primary animate-in zoom-in-50" />}
                                        </div>
                                    ))}
                                    {orgs.length === 0 && (
                                        <div className="py-12 text-center text-on-surface-variant/20 italic text-sm font-medium">No organizations registered.</div>
                                    )}
                                </GlassCardContent>
                            </GlassCard>

                            <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-card overflow-hidden rounded-[32px]">
                                <GlassCardHeader className="py-8 px-10 border-b border-on-surface/5">
                                    <div className="flex items-center gap-5">
                                        <div className="p-3 bg-primary/5 rounded-xl text-primary">
                                            <Users className="w-6 h-6" />
                                        </div>
                                        <div>
                                            <GlassCardTitle className="text-xl font-bold tracking-tight text-on-surface">Group Memberships</GlassCardTitle>
                                            <p className="text-on-surface-variant/60 font-medium text-[11px] tracking-tight mt-1">Assign user to security groups.</p>
                                        </div>
                                    </div>
                                </GlassCardHeader>
                                <GlassCardContent className="p-10">
                                    <div className="grid grid-cols-1 gap-4 max-h-[360px] overflow-y-auto pr-2 custom-scrollbar">
                                        {groups.map(group => (
                                            <div 
                                                key={group.id} 
                                                onClick={() => toggleGroup(group.id)}
                                                className={`p-5 rounded-2xl cursor-pointer transition-all border flex items-center justify-between group ${formData.groups.includes(group.id) 
                                                    ? 'bg-primary/5 border-primary/20 shadow-lg shadow-primary/5' 
                                                    : 'bg-card border-on-surface/5 hover:border-primary/10'}`}
                                            >
                                                <div className="flex flex-col">
                                                    <span className={`text-sm font-bold tracking-tight transition-colors ${formData.groups.includes(group.id) ? 'text-primary' : 'text-on-surface'}`}>{group.displayName}</span>
                                                    <span className="text-[10px] font-medium text-on-surface-variant/40 tracking-tight mt-0.5">{group.members?.length || 0} members</span>
                                                </div>
                                                <div className={`w-6 h-6 rounded-lg border-2 flex items-center justify-center transition-all ${formData.groups.includes(group.id) 
                                                    ? 'bg-primary border-primary text-white' 
                                                    : 'bg-card border-on-surface/10 group-hover:border-primary/30'}`}>
                                                    {formData.groups.includes(group.id) && <CheckCircle2 className="w-4 h-4" />}
                                                </div>
                                            </div>
                                        ))}
                                        {groups.length === 0 && (
                                            <div className="py-12 text-center text-on-surface-variant/20 italic text-sm font-medium">No authorization groups defined.</div>
                                        )}
                                    </div>
                                </GlassCardContent>
                            </GlassCard>
                        </div>

                        <div className="pt-10 flex gap-6">
                            <Button 
                                type="submit" 
                                disabled={submitting} 
                                className="flex-1 h-16 rounded-[24px] font-bold text-sm shadow-2xl shadow-primary/30 hover:scale-[1.01] active:scale-[0.99] transition-all"
                            >
                                {submitting ? <Loader2 className="mr-3 h-5 w-5 animate-spin" /> : <ShieldCheck className="mr-3 h-4 w-4" />}
                                {isEdit ? "Save Changes" : "Create User"}
                            </Button>
                            <Button 
                                type="button" 
                                variant="outline" 
                                onClick={() => navigate('/users')}
                                className="h-16 w-16 p-0 rounded-[24px] ring-1 ring-on-surface/5 hover:bg-surface-container transition-all"
                            >
                                <X className="h-6 w-6 text-on-surface-variant/40" />
                            </Button>
                        </div>
                    </div>
                </div>
            </form>
        </div>
    );
}
