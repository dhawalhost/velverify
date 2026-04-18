import React, { useState } from 'react';
import { createAccessRequest } from '../api';
import { useNavigate } from 'react-router-dom';
import { Card, CardHeader, CardTitle, CardContent, CardDescription, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { Loader2, Send } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';

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
            setError('Failed to submit request. Please try again.');
            setLoading(false);
        }
    };

    return (
        <div className="flex flex-col items-center justify-center min-h-[80vh] py-12 px-4 sm:px-6 lg:px-8">
            <div className="w-full max-w-md space-y-8">
                <div className="text-center">
                    <h1 className="text-3xl font-bold tracking-tight">Request Access</h1>
                    <p className="mt-2 text-sm text-muted-foreground">Submit a request to access an application or group.</p>
                </div>

                <Card>
                    <CardHeader>
                        <CardTitle>New Request</CardTitle>
                        <CardDescription>
                            Admins will review your request shortly.
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <form onSubmit={handleSubmit} className="space-y-6">
                            {error && (
                                <Alert variant="destructive">
                                    <AlertDescription>{error}</AlertDescription>
                                </Alert>
                            )}

                            <div className="space-y-2">
                                <Label>Resource Type</Label>
                                <Select value={resourceType} onValueChange={setResourceType}>
                                    <SelectTrigger>
                                        <SelectValue placeholder="Select type" />
                                    </SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="group">Group</SelectItem>
                                        <SelectItem value="role">Role (RBAC)</SelectItem>
                                        <SelectItem value="app">Application</SelectItem>
                                    </SelectContent>
                                </Select>
                            </div>

                            <div className="space-y-2">
                                <Label>Resource ID</Label>
                                <Input
                                    value={resourceID}
                                    onChange={(e) => setResourceID(e.target.value)}
                                    placeholder={resourceType === 'group' ? "e.g. engineering" : "e.g. salesforce"}
                                    required
                                />
                                <p className="text-[0.8rem] text-muted-foreground">
                                    Enter the exact identifier (e.g. 'admin', 'eng-lead').
                                </p>
                            </div>

                            <div className="space-y-2">
                                <Label>Duration (Just-In-Time)</Label>
                                <Select value={duration} onValueChange={setDuration}>
                                    <SelectTrigger>
                                        <SelectValue placeholder="Select duration" />
                                    </SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="1h">1 Hour (Quick Tasks)</SelectItem>
                                        <SelectItem value="4h">4 Hours (Standard Session)</SelectItem>
                                        <SelectItem value="24h">24 Hours (Daily Access)</SelectItem>
                                        <SelectItem value="indefinite">Indefinite (Static RBAC)</SelectItem>
                                    </SelectContent>
                                </Select>
                                <p className="text-[0.8rem] text-muted-foreground">
                                    Zero Trust recommendation: Choose the shortest duration needed.
                                </p>
                            </div>

                            <div className="space-y-2">
                                <Label>Reason</Label>
                                <Textarea
                                    value={reason}
                                    onChange={(e) => setReason(e.target.value)}
                                    placeholder="I need access for..."
                                    required
                                    rows={4}
                                />
                            </div>

                            <Button type="submit" className="w-full" disabled={loading}>
                                {loading ? (
                                    <>
                                        <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Submitting...
                                    </>
                                ) : (
                                    <>
                                        <Send className="mr-2 h-4 w-4" /> Submit Request
                                    </>
                                )}
                            </Button>
                        </form>
                    </CardContent>
                    <CardFooter className="flex justify-center border-t p-4">
                        <Button variant="link" size="sm" onClick={() => navigate('/requests')}>
                            Cancel and go back to list
                        </Button>
                    </CardFooter>
                </Card>
            </div>
        </div>
    );
};

export default RequestAccess;
