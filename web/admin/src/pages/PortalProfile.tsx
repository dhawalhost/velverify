import { useState } from 'react';
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { User, Mail, Shield, Key, Save, Loader2, Fingerprint, Lock, Activity } from "lucide-react";
import { useAuth } from '../hooks/useAuth';
import { api } from '../api';
import { GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassCardDescription } from '@/components/layout';

const PortalProfile = () => {
    const { user } = useAuth();
    const [isSaving, setIsSaving] = useState(false);
    const [newPassword, setNewPassword] = useState('');
    const [saveMessage, setSaveMessage] = useState('');

    const handleSaveProfile = async () => {
        setSaveMessage('');
        if (!newPassword) {
            setSaveMessage('Please enter a new password');
            return;
        }

        setIsSaving(true);
        try {
            await api.post('/api/v1/user/profile', { password: newPassword });
            setNewPassword('');
            setSaveMessage('Profile security updated successfully');
        } catch (error: any) {
            setSaveMessage(`Update failed: ${error?.response?.data?.error || 'Unknown error'}`);
        } finally {
            setIsSaving(false);
        }
    };

    return (
        <div className="space-y-12 max-w-4xl animate-in fade-in duration-700">
            {/* Header */}
            <div className="space-y-4">
                <div className="flex items-center gap-4 text-primary">
                    <div className="p-3 bg-primary/10 rounded-2xl">
                        <Fingerprint className="w-8 h-8" />
                    </div>
                    <span className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 uppercase">Identity Profile</span>
                </div>
                <h1 className="text-5xl font-bold tracking-tight text-on-surface">Subject Attributes</h1>
                <p className="text-on-surface-variant/40 font-medium tracking-tight text-sm max-w-xl">
                    Managed identity parameters and security credentials for your authorized persona.
                </p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 items-start">
                <div className="lg:col-span-12 space-y-10">
                    <GlassCard className="border-none shadow-2xl shadow-on-surface/5 overflow-hidden rounded-[32px] bg-white">
                        <GlassCardHeader className="bg-surface-container/50 border-b border-on-surface/5 py-10 px-10">
                            <div className="flex items-center gap-6">
                                <div className="p-4 bg-primary rounded-2xl text-white shadow-lg shadow-primary/20">
                                    <User className="w-8 h-8" />
                                </div>
                                <div>
                                    <GlassCardTitle className="text-3xl font-bold tracking-tight text-on-surface leading-none">Entity Lineage</GlassCardTitle>
                                    <p className="text-on-surface-variant/40 font-semibold tracking-tight text-[12px] mt-3">Static and dynamic user primitives.</p>
                                </div>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-10 space-y-12">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-10">
                                <div className="space-y-3">
                                    <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Given Name</Label>
                                    <Input 
                                        defaultValue={user?.firstName || ''} 
                                        className="h-14 border-none rounded-2xl font-semibold text-sm bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20"
                                        placeholder="Given Name"
                                    />
                                </div>
                                <div className="space-y-3">
                                    <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Family Name</Label>
                                    <Input 
                                        defaultValue={user?.lastName || ''} 
                                        className="h-14 border-none rounded-2xl font-semibold text-sm bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20"
                                        placeholder="Family Name"
                                    />
                                </div>
                            </div>

                            <div className="space-y-3">
                                <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Communication Vector Email</Label>
                                <div className="relative">
                                    <Mail className="absolute left-5 top-1/2 -translate-y-1/2 w-5 h-5 opacity-20" />
                                    <Input
                                        type="email"
                                        className="h-14 pl-14 border-none rounded-2xl font-semibold text-sm bg-surface-container/30 ring-1 ring-on-surface/5 text-on-surface opacity-50 cursor-not-allowed"
                                        defaultValue={user?.email || ''}
                                        disabled
                                    />
                                </div>
                                <p className="text-[11px] font-semibold tracking-tight opacity-40 italic ml-1">Vector locked by administrative policy infrastructure.</p>
                            </div>
                        </GlassCardContent>
                    </GlassCard>

                    <GlassCard className="border-none shadow-2xl shadow-on-surface/5 overflow-hidden rounded-[32px] bg-white">
                        <GlassCardHeader className="bg-on-surface text-white py-10 px-10 relative overflow-hidden">
                            <div className="absolute top-0 right-0 p-8 opacity-10 rotate-12">
                                <Shield className="w-32 h-32" />
                            </div>
                            <div className="relative z-10 flex items-center gap-6">
                                <div className="p-4 bg-primary text-white rounded-2xl shadow-lg shadow-white/10">
                                    <Lock className="w-8 h-8" />
                                </div>
                                <div>
                                    <GlassCardTitle className="text-3xl font-bold tracking-tight text-white leading-none">Security Stack</GlassCardTitle>
                                    <p className="text-primary font-bold tracking-tight text-[12px] mt-4 opacity-80 leading-none uppercase">Protection Protocol Management</p>
                                </div>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-10 space-y-10">
                            <div className="flex flex-col md:flex-row items-center gap-8 p-10 rounded-[32px] bg-surface-container/50 border-2 border-dashed border-on-surface/5">
                                <div className="flex-1 space-y-3">
                                    <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Credential Rotation</Label>
                                    <div className="relative">
                                        <Key className="absolute left-5 top-1/2 -translate-y-1/2 w-5 h-5 opacity-20" />
                                        <Input
                                            type="password"
                                            placeholder="Enter new entropy string..."
                                            value={newPassword}
                                            onChange={(e) => setNewPassword(e.target.value)}
                                            className="h-14 pl-14 border-none rounded-2xl font-mono text-sm bg-white ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20"
                                        />
                                    </div>
                                </div>
                                <Button 
                                    onClick={handleSaveProfile} 
                                    disabled={isSaving}
                                    className="h-14 bg-primary text-white hover:opacity-90 rounded-2xl px-12 font-bold text-[14px] tracking-tight shadow-xl shadow-primary/20 transition-all font-semibold"
                                >
                                    {isSaving ? <Loader2 className="h-5 w-5 animate-spin" /> : <Save className="h-5 w-5 mr-3" />}
                                    Commit Rotation
                                </Button>
                            </div>

                            {saveMessage && (
                                <div className={`p-6 rounded-2xl font-bold text-[11px] tracking-tight flex items-center gap-4 animate-in slide-in-from-bottom-4 duration-500 ${saveMessage.includes('successful') ? 'bg-emerald-50 text-emerald-600 ring-1 ring-emerald-100' : 'bg-red-50 text-red-600 ring-1 ring-red-100'}`}>
                                    <Activity className="h-4 w-4 animate-pulse" />
                                    {saveMessage.toUpperCase()}
                                </div>
                            )}

                            <Separator className="h-px bg-on-surface/5" />

                            <div className="flex flex-col md:flex-row items-center justify-between gap-10 p-10 rounded-[32px] border-2 border-dashed border-on-surface/5 opacity-60 hover:opacity-100 transition-opacity group">
                                <div className="flex items-center gap-8">
                                    <div className="h-16 w-16 flex items-center justify-center bg-surface-container rounded-2xl group-hover:bg-primary/20 transition-colors">
                                        <Shield className="h-8 w-8 opacity-40 group-hover:opacity-100 group-hover:text-primary transition-all" />
                                    </div>
                                    <div>
                                        <h4 className="text-xl font-bold tracking-tight text-on-surface">Multi Factor Authentication</h4>
                                        <p className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 mt-1 uppercase">Secondary Identity Proofing</p>
                                    </div>
                                </div>
                                <Button variant="outline" className="h-12 border-none ring-1 ring-on-surface/10 font-bold text-[11px] tracking-tight rounded-xl px-8 hover:bg-surface-container transition-all">
                                    Configure MFA
                                </Button>
                            </div>
                        </GlassCardContent>
                    </GlassCard>
                </div>
            </div>
        </div>
    );
};

export default PortalProfile;

