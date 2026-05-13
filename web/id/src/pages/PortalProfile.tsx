import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { User, Mail, Shield, Key, Save, Loader2, Fingerprint, Lock, Activity, Database, Download, AlertTriangle } from "lucide-react";
import { api } from '../api';
import { GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassCardDescription } from '@/components/layout';

const PortalProfile = () => {
    const navigate = useNavigate();
    const [isSaving, setIsSaving] = useState(false);
    const [newPassword, setNewPassword] = useState('');
    const [saveMessage, setSaveMessage] = useState('');
    const [userProfile, setUserProfile] = useState<any>(null);
    const [isExporting, setIsExporting] = useState(false);
    const [isDeleting, setIsDeleting] = useState(false);
    const [privacyMessage, setPrivacyMessage] = useState('');

    useEffect(() => {
        const fetchProfile = async () => {
            try {
                const res = await api.get('/api/v1/user/profile');
                const nameParts = (res.data.name || "").split(" ");
                const firstName = nameParts[0] || "";
                const lastName = nameParts.slice(1).join(" ") || "";
                setUserProfile({
                    email: res.data.email || "",
                    firstName,
                    lastName
                });
            } catch (error) {
                console.error("Failed to fetch profile", error);
            }
        };
        fetchProfile();
    }, []);

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

    const handleExportData = async () => {
        setIsExporting(true);
        setPrivacyMessage('');
        try {
            const res = await api.post('/api/v1/user/export', {}, { responseType: 'blob' });
            const url = window.URL.createObjectURL(new Blob([res.data]));
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', 'wardseal_privacy_export.json');
            document.body.appendChild(link);
            link.click();
            link.parentNode?.removeChild(link);
            setPrivacyMessage('Data export downloaded successfully.');
        } catch (error: any) {
            setPrivacyMessage('Failed to initiate data export.');
        } finally {
            setIsExporting(false);
        }
    };

    const handleDeleteAccount = async () => {
        if (!window.confirm("WARNING: This will permanently delete your account and all associated personal data. This action cannot be undone. Are you sure?")) {
            return;
        }
        setIsDeleting(true);
        setPrivacyMessage('');
        try {
            await api.delete('/api/v1/user/account');
            setPrivacyMessage('Account deletion requested. You will be logged out shortly.');
            setTimeout(() => {
                window.location.href = '/login';
            }, 2000);
        } catch (error: any) {
            setPrivacyMessage('Failed to submit account deletion request.');
        } finally {
            setIsDeleting(false);
        }
    };

    return (
        <div className="space-y-8 max-w-4xl animate-in fade-in duration-700">
            {/* Header */}
            <div className="space-y-2">
                <div className="flex items-center gap-2 text-primary">
                    <div className="p-2 bg-primary/10 rounded-lg">
                        <Fingerprint className="w-5 h-5" />
                    </div>
                    <span className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 uppercase">Identity Profile</span>
                </div>
                <h1 className="text-3xl font-bold tracking-tight text-on-surface">Subject Attributes</h1>
                <p className="text-on-surface-variant/40 font-medium tracking-tight text-xs max-w-xl">
                    Managed identity parameters and security credentials for your authorized persona.
                </p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 items-start">
                <div className="lg:col-span-12 space-y-6">
                    <GlassCard className="border-none shadow-sm shadow-on-surface/5 overflow-hidden rounded-lg bg-card">
                        <GlassCardHeader className="bg-surface-container/50 border-b border-on-surface/5 py-5 px-6">
                            <div className="flex items-center gap-4">
                                <div className="p-2 bg-primary rounded-lg text-white shadow-sm shadow-primary/20">
                                    <User className="w-5 h-5" />
                                </div>
                                <div>
                                    <GlassCardTitle className="text-lg font-bold tracking-tight text-on-surface leading-none">Entity Lineage</GlassCardTitle>
                                    <p className="text-on-surface-variant/40 font-semibold tracking-tight text-[10px] mt-2">Static and dynamic user primitives.</p>
                                </div>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent key={userProfile?.email || 'loading'} className="p-6 space-y-6">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                <div className="space-y-1.5">
                                    <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Given Name</Label>
                                    <Input
                                        defaultValue={userProfile?.firstName || ''}
                                        className="h-10 border-none rounded-lg font-semibold text-sm bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20"
                                        placeholder="Given Name"
                                    />
                                </div>
                                <div className="space-y-1.5">
                                    <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Family Name</Label>
                                    <Input
                                        defaultValue={userProfile?.lastName || ''}
                                        className="h-10 border-none rounded-lg font-semibold text-sm bg-surface-container/30 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20"
                                        placeholder="Family Name"
                                    />
                                </div>
                            </div>

                            <div className="space-y-1.5">
                                <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Communication Vector Email</Label>
                                <div className="relative">
                                    <Mail className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 opacity-20" />
                                    <Input
                                        type="email"
                                        className="h-10 pl-12 border-none rounded-lg font-semibold text-sm bg-surface-container/30 ring-1 ring-on-surface/5 text-on-surface opacity-50 cursor-not-allowed"
                                        defaultValue={userProfile?.email || ''}
                                        disabled
                                    />
                                </div>
                                <p className="text-[10px] font-semibold tracking-tight opacity-40 italic ml-1">Vector locked by administrative policy infrastructure.</p>
                            </div>
                        </GlassCardContent>
                    </GlassCard>

                    <GlassCard className="border-none shadow-sm shadow-on-surface/5 overflow-hidden rounded-lg bg-card">
                        <GlassCardHeader className="bg-inverse text-on-inverse py-5 px-6 relative overflow-hidden">
                            <div className="absolute top-0 right-0 p-4 opacity-10 rotate-12">
                                <Shield className="w-16 h-16" />
                            </div>
                            <div className="relative z-10 flex items-center gap-4">
                                <div className="p-2 bg-primary text-primary-foreground rounded-lg shadow-sm shadow-on-inverse/10">
                                    <Lock className="w-5 h-5" />
                                </div>
                                <div>
                                    <GlassCardTitle className="text-lg font-bold tracking-tight text-white leading-none">Security Stack</GlassCardTitle>
                                    <p className="text-primary font-bold tracking-tight text-[10px] mt-2 opacity-80 leading-none uppercase">Protection Protocol Management</p>
                                </div>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-6 space-y-6">
                            <div className="flex flex-col md:flex-row items-center gap-6 p-6 rounded-lg bg-surface-container/50 border border-dashed border-on-surface/5">
                                <div className="flex-1 space-y-1.5">
                                    <Label className="text-[11px] font-bold tracking-tight text-on-surface-variant/40 ml-1">Credential Rotation</Label>
                                    <div className="relative">
                                        <Key className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 opacity-20" />
                                        <Input
                                            type="password"
                                            placeholder="Enter new entropy string..."
                                            value={newPassword}
                                            onChange={(e) => setNewPassword(e.target.value)}
                                            className="h-10 pl-12 border-none rounded-lg font-mono text-xs bg-card ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20"
                                        />
                                    </div>
                                </div>
                                <Button
                                    onClick={handleSaveProfile}
                                    disabled={isSaving}
                                    className="h-10 bg-primary text-primary-foreground hover:opacity-90 rounded-lg px-8 font-bold text-xs tracking-tight shadow-md shadow-primary/20 transition-all"
                                >
                                    {isSaving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4 mr-2" />}
                                    Commit Rotation
                                </Button>
                            </div>

                            {saveMessage && (
                                <div className={`p-6 rounded-2xl font-bold text-[11px] tracking-tight flex items-center gap-4 animate-in slide-in-from-bottom-4 duration-500 ${saveMessage.includes('successful') ? 'bg-success-subtle text-success ring-1 ring-emerald-100' : 'bg-destructive/10 text-destructive ring-1 ring-red-100'}`}>
                                    <Activity className="h-4 w-4 animate-pulse" />
                                    {saveMessage.toUpperCase()}
                                </div>
                            )}

                            <Separator className="h-px bg-on-surface/5" />

                            <div className="flex flex-col md:flex-row items-center justify-between gap-6 p-6 rounded-lg border border-dashed border-on-surface/5 opacity-80 hover:opacity-100 transition-opacity group">
                                <div className="flex items-center gap-4">
                                    <div className="h-10 w-10 flex items-center justify-center bg-surface-container rounded-lg group-hover:bg-primary/20 transition-colors">
                                        <Shield className="h-5 w-5 opacity-40 group-hover:opacity-100 group-hover:text-primary transition-all" />
                                    </div>
                                    <div>
                                        <h4 className="text-sm font-bold tracking-tight text-on-surface">Multi Factor Authentication</h4>
                                        <p className="text-[10px] font-bold tracking-tight text-on-surface-variant/40 mt-0.5 uppercase">Secondary Identity Proofing</p>
                                    </div>
                                </div>
                                <Button 
                                    variant="outline" 
                                    className="h-9 border-none ring-1 ring-on-surface/10 font-bold text-[10px] tracking-tight rounded-lg px-6 hover:bg-surface-container transition-all"
                                    onClick={() => navigate('/mfa')}
                                >
                                    Configure MFA
                                </Button>
                            </div>
                        </GlassCardContent>
                    </GlassCard>

                    {/* DPDP Compliance Card */}
                    <GlassCard className="border-none shadow-sm shadow-on-surface/5 overflow-hidden rounded-lg bg-card mt-6">
                        <GlassCardHeader className="bg-destructive/5 border-b border-destructive/10 py-5 px-6">
                            <div className="flex items-center gap-4">
                                <div className="p-2 bg-destructive text-destructive-foreground rounded-lg shadow-sm shadow-destructive/20">
                                    <Database className="w-5 h-5" />
                                </div>
                                <div>
                                    <GlassCardTitle className="text-lg font-bold tracking-tight text-destructive leading-none">Data Privacy & Rights</GlassCardTitle>
                                    <p className="text-destructive/70 font-semibold tracking-tight text-[10px] mt-2 uppercase">DPDP / GDPR Compliance Controls</p>
                                </div>
                            </div>
                        </GlassCardHeader>
                        <GlassCardContent className="p-6 space-y-6">
                            {privacyMessage && (
                                <div className={`p-6 rounded-2xl font-bold text-[11px] tracking-tight flex items-center gap-4 animate-in slide-in-from-bottom-4 duration-500 bg-surface-container text-on-surface ring-1 ring-on-surface/10`}>
                                    <Activity className="h-4 w-4 animate-pulse text-primary" />
                                    {privacyMessage.toUpperCase()}
                                </div>
                            )}

                            <div className="flex flex-col md:flex-row items-center justify-between gap-6 p-6 rounded-lg border border-dashed border-on-surface/5 opacity-80 hover:opacity-100 transition-opacity group">
                                <div className="flex items-center gap-4">
                                    <div className="h-10 w-10 flex items-center justify-center bg-surface-container rounded-lg group-hover:bg-primary/20 transition-colors">
                                        <Download className="h-5 w-5 opacity-60 group-hover:opacity-100 group-hover:text-primary transition-all" />
                                    </div>
                                    <div>
                                        <h4 className="text-sm font-bold tracking-tight text-on-surface">Data Export (Portability)</h4>
                                        <p className="text-[11px] font-medium tracking-tight text-on-surface-variant/60 mt-0.5 max-w-md">
                                            Request an archive of all personal data tied to your account.
                                        </p>
                                    </div>
                                </div>
                                <Button 
                                    variant="outline" 
                                    className="h-9 border-none ring-1 ring-on-surface/10 font-bold text-[10px] tracking-tight rounded-lg px-6 hover:bg-surface-container transition-all"
                                    onClick={handleExportData}
                                    disabled={isExporting}
                                >
                                    {isExporting ? <Loader2 className="h-3 w-3 animate-spin mr-2" /> : null}
                                    Export Data
                                </Button>
                            </div>

                            <div className="flex flex-col md:flex-row items-center justify-between gap-6 p-6 rounded-lg border border-dashed border-destructive/20 bg-destructive/5 opacity-90 hover:opacity-100 transition-opacity group">
                                <div className="flex items-center gap-4">
                                    <div className="h-10 w-10 flex items-center justify-center bg-destructive/10 rounded-lg group-hover:bg-destructive/20 transition-colors">
                                        <AlertTriangle className="h-5 w-5 text-destructive opacity-80 group-hover:opacity-100 transition-all" />
                                    </div>
                                    <div>
                                        <h4 className="text-sm font-bold tracking-tight text-destructive">Account Erasure (Right to be Forgotten)</h4>
                                        <p className="text-[11px] font-medium tracking-tight text-destructive/70 mt-0.5 max-w-md">
                                            Permanently delete your account and all associated personal data.
                                        </p>
                                    </div>
                                </div>
                                <Button 
                                    variant="destructive" 
                                    className="h-9 font-bold text-[10px] tracking-tight rounded-lg px-6 transition-all shadow-md shadow-destructive/20"
                                    onClick={handleDeleteAccount}
                                    disabled={isDeleting}
                                >
                                    {isDeleting ? <Loader2 className="h-3 w-3 animate-spin mr-2" /> : null}
                                    Erase Account
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

