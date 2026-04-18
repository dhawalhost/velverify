import React, { useEffect, useState } from 'react';
import { getSafetyActions, confirmSafetyAction, rejectSafetyAction } from '../api';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '@/components/ui/card';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Check, X, ShieldAlert, History } from 'lucide-react';

const SafetyInbox: React.FC = () => {
    const [actions, setActions] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    const fetchActions = async () => {
        try {
            setLoading(true);
            const data = await getSafetyActions('pending');
            setActions(data.actions || []);
        } catch (err: any) {
            console.error(err);
            setError('Failed to fetch safety actions');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchActions();
    }, []);

    const handleConfirm = async (id: string) => {
        try {
            await confirmSafetyAction(id, 'Confirmed via Dashboard');
            fetchActions(); // Refresh list
        } catch (err) {
            alert('Failed to confirm safety action');
        }
    };

    const handleReject = async (id: string) => {
        try {
            await rejectSafetyAction(id, 'Cancelled via Dashboard');
            fetchActions();
        } catch (err) {
            alert('Failed to reject safety action');
        }
    };

    if (loading) return <div className="p-8 text-center text-muted-foreground">Monitoring directory safe state...</div>;

    return (
        <div className="space-y-6">
            <div className="flex justify-between items-center">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Safety Inbox</h1>
                    <p className="text-muted-foreground">Confirm or intercept automated security revocations.</p>
                </div>
                <Button variant="outline" size="sm" onClick={() => fetchActions()}>
                    <History className="mr-2 h-4 w-4" /> Refresh
                </Button>
            </div>

            {error && (
                <div className="bg-destructive/15 text-destructive px-4 py-2 rounded-md flex items-center gap-2 text-sm">
                    <ShieldAlert className="h-4 w-4" />
                    {error}
                </div>
            )}

            <Card className="border-red-500/20 shadow-lg shadow-red-500/5">
                <CardHeader className="bg-red-500/5 border-b border-red-500/10 rounded-t-lg">
                    <CardTitle className="text-lg flex items-center gap-2 text-red-600">
                        <ShieldAlert className="h-5 w-5" />
                        Pending Critical Actions
                    </CardTitle>
                    <CardDescription>
                        These actions require human confirmation to proceed. Unconfirmed actions will remain in the safety store.
                    </CardDescription>
                </CardHeader>
                <CardContent className="pt-6">
                    <Table>
                        <TableHeader>
                            <TableRow>
                                <TableHead>Action Type</TableHead>
                                <TableHead>Target User</TableHead>
                                <TableHead>Reason</TableHead>
                                <TableHead>Metadata</TableHead>
                                <TableHead>Proposed At</TableHead>
                                <TableHead className="text-right">Safety Control</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {actions.length === 0 ? (
                                <TableRow>
                                    <TableCell colSpan={6} className="text-center text-muted-foreground h-32">
                                        No pending safety actions. System is in safe state.
                                    </TableCell>
                                </TableRow>
                            ) : (
                                actions.map((action) => (
                                    <TableRow key={action.id}>
                                        <TableCell>
                                            <Badge variant="destructive" className="font-mono bg-red-600">
                                                {action.action_type.replaceAll('_', ' ')}
                                            </Badge>
                                        </TableCell>
                                        <TableCell className="font-medium">{action.target_id}</TableCell>
                                        <TableCell className="max-w-xs">{action.reason}</TableCell>
                                        <TableCell>
                                            <div className="flex gap-1 flex-wrap">
                                                {action.metadata && action.metadata.org_ids && action.metadata.org_ids.map((org: string) => (
                                                    <Badge key={org} variant="secondary" className="text-[10px] px-1 h-4">
                                                        {org}
                                                    </Badge>
                                                ))}
                                            </div>
                                        </TableCell>
                                        <TableCell className="text-muted-foreground text-sm">
                                            {new Date(action.created_at).toLocaleString()}
                                        </TableCell>
                                        <TableCell className="text-right">
                                            <div className="flex justify-end gap-2">
                                                <Button 
                                                    size="sm" 
                                                    className="bg-red-600 hover:bg-red-700 text-white"
                                                    onClick={() => handleConfirm(action.id)}
                                                >
                                                    <Check className="h-4 w-4 mr-1" /> Execute
                                                </Button>
                                                <Button 
                                                    size="sm" 
                                                    variant="outline" 
                                                    className="text-muted-foreground hover:bg-secondary"
                                                    onClick={() => handleReject(action.id)}
                                                >
                                                    <X className="h-4 w-4 mr-1" /> Intercept
                                                </Button>
                                            </div>
                                        </TableCell>
                                    </TableRow>
                                ))
                            )}
                        </TableBody>
                    </Table>
                </CardContent>
            </Card>
        </div>
    );
};

export default SafetyInbox;
