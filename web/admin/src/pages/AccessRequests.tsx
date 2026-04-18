import React, { useEffect, useState } from 'react';
import { getAccessRequests, approveAccessRequest, rejectAccessRequest } from '../api';
import { Link } from 'react-router-dom';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Check, X, ShieldAlert, Plus } from 'lucide-react';

const AccessRequests: React.FC = () => {
    const [requests, setRequests] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    const fetchRequests = async () => {
        try {
            setLoading(true);
            const data = await getAccessRequests();
            setRequests(data.requests || []);
        } catch (err: any) {
            console.error(err);
            setError('Failed to fetch requests');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchRequests();
    }, []);

    const handleApprove = async (id: string) => {
        try {
            await approveAccessRequest(id, 'Approved by admin');
            fetchRequests(); // Refresh list
        } catch (err) {
            alert('Failed to approve request');
        }
    };

    const handleReject = async (id: string) => {
        try {
            await rejectAccessRequest(id, 'Rejected by admin');
            fetchRequests();
        } catch (err) {
            alert('Failed to reject request');
        }
    };

    if (loading) return <div className="p-8 text-center text-muted-foreground">Loading specific requests...</div>;

    return (
        <div className="space-y-6">
            <div className="flex justify-between items-center">
                <h1 className="text-3xl font-bold tracking-tight">Access Requests</h1>
                <Link to="/request-access">
                    <Button>
                        <Plus className="mr-2 h-4 w-4" /> New Request
                    </Button>
                </Link>
            </div>

            {error && (
                <div className="bg-destructive/15 text-destructive px-4 py-2 rounded-md flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4" />
                    {error}
                </div>
            )}

            <Card>
                <CardHeader>
                    <CardTitle>Pending Requests</CardTitle>
                </CardHeader>
                <CardContent>
                    <Table>
                        <TableHeader>
                            <TableRow>
                                <TableHead>ID</TableHead>
                                <TableHead>Requester</TableHead>
                                <TableHead>Resource</TableHead>
                                <TableHead>Duration</TableHead>
                                <TableHead>Reason</TableHead>
                                <TableHead>Status</TableHead>
                                <TableHead>Created At</TableHead>
                                <TableHead className="text-right">Actions</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {requests.length === 0 ? (
                                <TableRow>
                                    <TableCell colSpan={7} className="text-center text-muted-foreground h-24">
                                        No access requests found.
                                    </TableCell>
                                </TableRow>
                            ) : (
                                requests.map((req) => (
                                    <TableRow key={req.id}>
                                        <TableCell className="font-mono text-xs text-muted-foreground">
                                            {req.id.substring(0, 8)}...
                                        </TableCell>
                                        <TableCell className="font-medium">{req.requester_id}</TableCell>
                                        <TableCell>
                                            <Badge variant="outline" className="font-mono">
                                                {req.resource_type}:{req.resource_id}
                                            </Badge>
                                        </TableCell>
                                        <TableCell>
                                            {req.duration ? (
                                                <Badge variant="secondary" className="font-mono text-xs">
                                                    {req.duration}
                                                </Badge>
                                            ) : (
                                                <span className="text-muted-foreground text-xs italic">Indefinite</span>
                                            )}
                                        </TableCell>
                                        <TableCell className="max-w-xs truncate" title={req.reason}>
                                            {req.reason}
                                        </TableCell>
                                        <TableCell>
                                            <Badge variant={req.status === 'pending' ? 'secondary' : req.status === 'approved' ? 'default' : 'destructive'}>
                                                {req.status.toUpperCase()}
                                            </Badge>
                                        </TableCell>
                                        <TableCell className="text-muted-foreground text-sm">
                                            {new Date(req.created_at).toLocaleDateString()}
                                        </TableCell>
                                        <TableCell className="text-right">
                                            {req.status === 'pending' && (
                                                <div className="flex justify-end gap-2">
                                                    <Button size="sm" variant="outline" className="text-green-600 hover:text-green-700 hover:bg-green-50" onClick={() => handleApprove(req.id)}>
                                                        <Check className="h-4 w-4 mr-1" /> Approve
                                                    </Button>
                                                    <Button size="sm" variant="outline" className="text-destructive hover:bg-destructive/10" onClick={() => handleReject(req.id)}>
                                                        <X className="h-4 w-4 mr-1" /> Reject
                                                    </Button>
                                                </div>
                                            )}
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

export default AccessRequests;
