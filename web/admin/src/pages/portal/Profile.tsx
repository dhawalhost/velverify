import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from '@/api';
import { Loader2, ShieldCheck, User } from 'lucide-react';
import { useToast } from "@/components/ui/use-toast";

const PortalProfile = () => {
    const { toast } = useToast();
    const [loading, setLoading] = useState(true);
    const [userId, setUserId] = useState("");
    const [password, setPassword] = useState("");
    const [saving, setSaving] = useState(false);

    useEffect(() => {
        const fetchProfile = async () => {
            try {
                const res = await api.get('/user/profile');
                setUserId(res.data.id);
            } catch (err) {
                console.error("Failed to fetch profile", err);
            } finally {
                setLoading(false);
            }
        };
        fetchProfile();
    }, []);

    const handleUpdatePassword = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!password) return;

        setSaving(true);
        try {
            await api.post('/user/profile', { password });
            toast({
                title: "Password Updated",
                description: "Your password has been changed successfully.",
            });
            setPassword("");
        } catch (err) {
            toast({
                title: "Update Failed",
                description: "Failed to update password. Please try again.",
                variant: "destructive",
            });
        } finally {
            setSaving(false);
        }
    };

    if (loading) {
        return <div className="flex justify-center p-12"><Loader2 className="w-8 h-8 animate-spin text-primary" /></div>;
    }

    return (
        <div className="max-w-2xl mx-auto space-y-6">
            <h1 className="text-2xl font-bold tracking-tight">Profile & Security</h1>

            {/* Profile Info */}
            <Card>
                <CardHeader>
                    <div className="flex items-center gap-4">
                        <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center">
                            <User className="w-8 h-8 text-primary" />
                        </div>
                        <div>
                            <CardTitle>My Account</CardTitle>
                            <CardDescription>Manage your account settings</CardDescription>
                        </div>
                    </div>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div className="grid gap-1">
                        <Label>User ID</Label>
                        <div className="font-mono text-sm bg-muted p-2 rounded border">{userId}</div>
                    </div>
                </CardContent>
            </Card>

            {/* Security Settings */}
            <Card>
                <CardHeader>
                    <div className="flex items-center gap-4">
                        <div className="p-2 rounded-lg bg-orange-500/10">
                            <ShieldCheck className="w-6 h-6 text-orange-500" />
                        </div>
                        <div>
                            <CardTitle>Security</CardTitle>
                            <CardDescription>Update your password and security credentials</CardDescription>
                        </div>
                    </div>
                </CardHeader>
                <CardContent>
                    <form onSubmit={handleUpdatePassword} className="space-y-4">
                        <div className="space-y-2">
                            <Label htmlFor="password">New Password</Label>
                            <Input
                                id="password"
                                type="password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                placeholder="Enter new password"
                                minLength={8}
                            />
                        </div>
                        <Button type="submit" disabled={!password || saving}>
                            {saving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                            Update Password
                        </Button>
                    </form>
                </CardContent>
            </Card>
        </div>
    );
};

export default PortalProfile;
