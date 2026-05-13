import React, { useState } from 'react';
import { createAccessRequest } from '../api';
import { useNavigate } from 'react-router-dom';
import { CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { Loader2, Send, GitPullRequest, ShieldCheck, Clock, MessageSquare, Info } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { PageHeader, GlassCard, GlassCardHeader, GlassCardTitle, GlassCardContent, GlassCardDescription } from '@/components/layout';

const RequestAccess: React.FC = () => {
    const [resourceType, setResourceType] = useState('group');
    const [resourceID, setResourceID] = useState('');
    const [reason, setReason] = useState('');
    const [duration, setDuration] = useState('4h');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setLoading(true);
        try {
            await createAccessRequest(resourceType, resourceID, reason, duration === 'indefinite' ? undefined : duration);
            navigate('/requests');
        } catch (err: any) {
            console.error(err);
            setError('Failed to submit request. Please verify the resource identifier and try again.');
            setLoading(false);
        }
    };

    return (
        <div className="max-w-3xl mx-auto space-y-12 animate-in fade-in slide-in-from-bottom-4 duration-700 py-12">
            <PageHeader
                icon={<GitPullRequest className="w-10 h-10 text-primary" />}
                title="Request Access"
                description="Submit an elevated privilege request for just-in-time access to organizational resources."
            />

            <div className="grid grid-cols-1 lg:grid-cols-1 gap-12">
                <GlassCard className="border-none shadow-2xl shadow-on-surface/5 bg-card overflow-hidden rounded-[32px]">
                    <GlassCardHeader className="py-10 px-10 border-b border-on-surface/5 bg-surface-container/10">
                        <div className="flex items-center gap-6">
                            <div className="p-4 bg-primary/5 rounded-2xl text-primary">
                                <ShieldCheck className="w-7 h-7" />
                            </div>
                             <div>
                                <GlassCardTitle className="text-3xl font-bold tracking-tight text-on-surface">New access request</GlassCardTitle>
                                <GlassCardDescription className="text-on-surface-variant/40 font-bold text-[12px] mt-1 tracking-tight">
                                    Identity verification & permission handshake
                                </GlassCardDescription>
                            </div>
                        </div>
                    </GlassCardHeader>
                    
                    <GlassCardContent className="p-10">
                        <form onSubmit={handleSubmit} className="space-y-10">
                             {error && (
                                <Alert variant="destructive" className="rounded-2xl border-none bg-destructive/10 text-destructive animate-in slide-in-from-top-2">
                                    <AlertDescription className="font-bold text-xs tracking-tight">{error}</AlertDescription>
                                </Alert>
                            )}

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                                 <div className="space-y-4">
                                    <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1 flex items-center gap-2">
                                        <Info className="w-3.5 h-3.5" />
                                        Resource type
                                    </Label>
                                    <Select value={resourceType} onValueChange={setResourceType}>
                                        <SelectTrigger className="h-14 rounded-2xl border-none bg-surface-container/50 ring-1 ring-on-surface/5 focus:ring-2 focus:ring-primary/20 transition-all font-bold text-sm px-6">
                                            <SelectValue placeholder="Select type" />
                                        </SelectTrigger>
                                        <SelectContent className="rounded-2xl border-none shadow-xl font-bold text-xs">
                                            <SelectItem value="group">Group</SelectItem>
                                            <SelectItem value="role">Role (RBAC)</SelectItem>
                                            <SelectItem value="app">Application</SelectItem>
                                        </SelectContent>
                                    </Select>
                                </div>

                                 <div className="space-y-4">
                                    <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1">UID / Identifier</Label>
                                    <Input
                                        value={resourceID}
                                        onChange={(e) => setResourceID(e.target.value)}
                                        placeholder={resourceType === 'group' ? "e.g. engineering" : "e.g. salesforce"}
                                        className="h-14 rounded-2xl border-none bg-surface-container/50 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-bold text-sm px-6 placeholder:opacity-30"
                                        required
                                    />
                                    <p className="text-[10px] text-on-surface-variant/40 font-medium italic ml-1 leading-relaxed">
                                        Enter the exact system identifier for authentication.
                                    </p>
                                </div>
                            </div>

                             <div className="space-y-4">
                                <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1 flex items-center gap-2">
                                    <Clock className="w-3.5 h-3.5" />
                                    Just-in-time window
                                </Label>
                                <Select value={duration} onValueChange={setDuration}>
                                    <SelectTrigger className="h-14 rounded-2xl border-none bg-surface-container/50 ring-1 ring-on-surface/5 focus:ring-2 focus:ring-primary/20 transition-all font-bold text-sm px-6">
                                        <SelectValue placeholder="Select duration" />
                                    </SelectTrigger>
                                    <SelectContent className="rounded-2xl border-none shadow-xl font-bold text-xs">
                                        <SelectItem value="1h">1 Hour (Quick Tasks)</SelectItem>
                                        <SelectItem value="4h">4 Hours (Standard Session)</SelectItem>
                                        <SelectItem value="24h">24 Hours (Daily Access)</SelectItem>
                                        <SelectItem value="indefinite">Indefinite (Static RBAC)</SelectItem>
                                    </SelectContent>
                                </Select>
                            </div>

                             <div className="space-y-4">
                                <Label className="text-[12px] font-bold tracking-tight text-on-surface-variant/40 ml-1 flex items-center gap-2">
                                    <MessageSquare className="w-3.5 h-3.5" />
                                    Business justification
                                </Label>
                                <Textarea
                                    value={reason}
                                    onChange={(e) => setReason(e.target.value)}
                                    placeholder="Provide detailed context for this privilege escalation..."
                                    required
                                    rows={4}
                                    className="rounded-2xl border-none bg-surface-container/50 ring-1 ring-on-surface/5 focus-visible:ring-2 focus-visible:ring-primary/20 transition-all font-medium text-sm p-6 resize-none placeholder:opacity-30"
                                />
                            </div>

                            <div className="pt-6 flex flex-col gap-4">
                                 <Button type="submit" className="w-full h-16 rounded-[20px] font-bold text-[13px] tracking-tight shadow-xl shadow-primary/20 hover:scale-[1.01] active:scale-[0.99] transition-all" disabled={loading}>
                                    {loading ? (
                                        <>
                                            <Loader2 className="mr-3 h-5 w-5 animate-spin" /> Finalizing request...
                                        </>
                                    ) : (
                                        <>
                                            <Send className="mr-3 h-4 w-4" /> Commit request
                                        </>
                                    )}
                                </Button>

                                 <Button 
                                    variant="ghost" 
                                    type="button" 
                                    className="w-full h-12 font-bold text-[11px] tracking-tight text-on-surface-variant/40 hover:text-on-surface hover:bg-surface-container/20 rounded-xl transition-all" 
                                    onClick={() => navigate('/requests')}
                                >
                                    Cancel and return to dashboard
                                </Button>
                            </div>
                        </form>
                    </GlassCardContent>
                </GlassCard>
            </div>
        </div>
    );
};

export default RequestAccess;
