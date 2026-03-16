import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { User, Mail, Shield, Key } from "lucide-react";
import { useAuth } from '../hooks/useAuth';
import { api } from '../api';

const PortalProfile = () => {
    const { user } = useAuth();
    const [isSaving, setIsSaving] = useState(false);
    const [newPassword, setNewPassword] = useState('');
    const [saveMessage, setSaveMessage] = useState('');

    const handleSaveProfile = async () => {
        setSaveMessage('');
        if (!newPassword) {
            setSaveMessage('Enter a new password to save changes.');
            return;
        }

        setIsSaving(true);
        try {
            await api.post('/api/v1/user/profile', { password: newPassword });
            setNewPassword('');
            setSaveMessage('Profile updated successfully.');
        } catch (error: any) {
            setSaveMessage(error?.response?.data?.error || 'Failed to update profile.');
        } finally {
            setIsSaving(false);
        }
    };

    return (
        <div className="space-y-8 max-w-2xl">
            {/* Header */}
            <div>
                <h1 className="text-3xl font-bold tracking-tight">Profile Settings</h1>
                <p className="text-muted-foreground mt-2">
                    Manage your account settings and preferences
                </p>
            </div>

            {/* Profile Information */}
            <Card>
                <CardHeader>
                    <div className="flex items-center gap-3">
                        <User className="h-5 w-5 text-primary" />
                        <div>
                            <CardTitle>Personal Information</CardTitle>
                            <CardDescription>Update your personal details</CardDescription>
                        </div>
                    </div>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div className="grid gap-4 md:grid-cols-2">
                        <div className="space-y-2">
                            <Label htmlFor="firstName">First Name</Label>
                            <Input id="firstName" placeholder="John" defaultValue={user?.firstName || ''} />
                        </div>
                        <div className="space-y-2">
                            <Label htmlFor="lastName">Last Name</Label>
                            <Input id="lastName" placeholder="Doe" defaultValue={user?.lastName || ''} />
                        </div>
                    </div>
                    <div className="space-y-2">
                        <Label htmlFor="email">Email Address</Label>
                        <div className="relative">
                            <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                            <Input
                                id="email"
                                type="email"
                                className="pl-10"
                                defaultValue={user?.email || ''}
                                disabled
                            />
                        </div>
                        <p className="text-xs text-muted-foreground">Contact an administrator to change your email</p>
                    </div>
                    <Button onClick={handleSaveProfile} disabled={isSaving}>
                        {isSaving ? 'Saving...' : 'Save Changes'}
                    </Button>
                    {saveMessage && (
                        <p className="text-xs text-muted-foreground">{saveMessage}</p>
                    )}
                </CardContent>
            </Card>

            <Separator />

            {/* Security Section */}
            <Card>
                <CardHeader>
                    <div className="flex items-center gap-3">
                        <Shield className="h-5 w-5 text-primary" />
                        <div>
                            <CardTitle>Security</CardTitle>
                            <CardDescription>Manage your security settings</CardDescription>
                        </div>
                    </div>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div className="flex items-center justify-between p-4 border rounded-lg">
                        <div className="flex items-center gap-3">
                            <Key className="h-5 w-5 text-muted-foreground" />
                            <div>
                                <p className="font-medium">Password</p>
                                <p className="text-sm text-muted-foreground">Change your account password</p>
                            </div>
                        </div>
                        <div className="w-full max-w-xs ml-4 flex gap-2">
                            <Input
                                type="password"
                                placeholder="New password"
                                value={newPassword}
                                onChange={(e) => setNewPassword(e.target.value)}
                            />
                        </div>
                    </div>
                    <div className="flex items-center justify-between p-4 border rounded-lg">
                        <div className="flex items-center gap-3">
                            <Shield className="h-5 w-5 text-muted-foreground" />
                            <div>
                                <p className="font-medium">Two-Factor Authentication</p>
                                <p className="text-sm text-muted-foreground">Add an extra layer of security</p>
                            </div>
                        </div>
                        <Button variant="outline" size="sm">
                            Configure
                        </Button>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
};

export default PortalProfile;
