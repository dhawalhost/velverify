import React, { useEffect, useState } from 'react';
import { getEndpoints, updateEndpointStatus, Device } from '../api';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '@/components/ui/card';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { 
    Loader2, 
    MonitorSmartphone, 
    ShieldCheck, 
    ShieldAlert, 
    ShieldIcon, 
    User, 
    Info,
    CheckCircle2,
    XCircle
} from 'lucide-react';

const Devices: React.FC = () => {
    const [devices, setDevices] = useState<Device[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    const fetchDevices = async () => {
        try {
            setLoading(true);
            const data = await getEndpoints();
            setDevices(data || []);
        } catch (err) {
            console.error(err);
            setError('Failed to load organizational endpoints');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchDevices();
    }, []);

    const handleUpdateStatus = async (id: string, status: string) => {
        try {
            await updateEndpointStatus(id, status);
            fetchDevices();
        } catch (err) {
            console.error(err);
            alert("Failed to update trust status");
        }
    };

    const getStatusBadge = (status: string) => {
        switch (status) {
            case 'trusted':
                return <Badge className="bg-green-600 hover:bg-green-700 gap-1"><ShieldCheck className="w-3 h-3" /> Trusted</Badge>;
            case 'untrusted':
                return <Badge variant="destructive" className="gap-1"><ShieldAlert className="w-3 h-3" /> Untrusted</Badge>;
            default:
                return <Badge variant="outline" className="gap-1 text-amber-600 border-amber-600"><ShieldIcon className="w-3 h-3" /> Pending</Badge>;
        }
    };

    if (loading && devices.length === 0) {
        return (
            <div className="h-[400px] flex items-center justify-center">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
        );
    }

    return (
        <div className="space-y-6">
            <div className="flex justify-between items-end">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Endpoint Identity Registry</h1>
                    <p className="text-muted-foreground mt-1">Manage and verify the trust status of all corporate devices.</p>
                </div>
                <div className="flex gap-4">
                    <Card className="min-w-[120px] shadow-sm">
                        <CardContent className="p-4 py-2 flex flex-col items-center">
                            <span className="text-2xl font-bold text-green-600">{devices.filter(d => d.trust_status === 'trusted').length}</span>
                            <span className="text-[10px] uppercase text-muted-foreground font-semibold">Verified</span>
                        </CardContent>
                    </Card>
                    <Card className="min-w-[120px] shadow-sm">
                        <CardContent className="p-4 py-2 flex flex-col items-center">
                            <span className="text-2xl font-bold text-amber-500">{devices.filter(d => d.trust_status === 'pending').length}</span>
                            <span className="text-[10px] uppercase text-muted-foreground font-semibold">Pending</span>
                        </CardContent>
                    </Card>
                </div>
            </div>

            <Card className="border-none shadow-md overflow-hidden">
                <CardHeader className="bg-muted/50 border-b">
                    <CardTitle className="text-lg flex items-center gap-2">
                        <MonitorSmartphone className="w-5 h-5" /> Registered Corporate Endpoints
                    </CardTitle>
                    <CardDescription>Review device health and authenticate hardware for sensitive role assumption.</CardDescription>
                </CardHeader>
                <CardContent className="p-0">
                    {error && <div className="p-4 bg-destructive/10 text-destructive flex items-center gap-2"><Info className="w-4 h-4" /> {error}</div>}

                    {devices.length === 0 ? (
                        <div className="p-20 text-center text-muted-foreground flex flex-col items-center gap-4">
                            <div className="w-16 h-16 rounded-full bg-muted flex items-center justify-center">
                                <ShieldIcon className="h-8 w-8 opacity-40" />
                            </div>
                            <div className="max-w-[200px]">No endpoints have been registered for this tenant yet.</div>
                        </div>
                    ) : (
                        <Table>
                            <TableHeader className="bg-muted/30">
                                <TableRow>
                                    <TableHead>Serial Number</TableHead>
                                    <TableHead>Primary User</TableHead>
                                    <TableHead>Platform / OS</TableHead>
                                    <TableHead>Trust Level</TableHead>
                                    <TableHead>Last Validation</TableHead>
                                    <TableHead className="text-right">Access Control</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {devices.map(device => (
                                    <TableRow key={device.id} className="hover:bg-muted/10 transition-colors">
                                        <TableCell className="font-mono text-xs font-semibold uppercase">
                                            {device.serial}
                                        </TableCell>
                                        <TableCell>
                                            <div className="flex items-center gap-2">
                                                <div className="w-6 h-6 rounded-full bg-primary/10 flex items-center justify-center">
                                                    <User className="w-3 h-3 text-primary" />
                                                </div>
                                                <span className="text-sm font-medium">{device.user_id.substring(0, 8)}...</span>
                                            </div>
                                        </TableCell>
                                        <TableCell>
                                            <div className="flex flex-col">
                                                <span className="text-sm font-medium">{device.platform}</span>
                                                <span className="text-[10px] text-muted-foreground font-mono">{device.os_version}</span>
                                            </div>
                                        </TableCell>
                                        <TableCell>
                                            {getStatusBadge(device.trust_status)}
                                        </TableCell>
                                        <TableCell className="text-muted-foreground text-sm">
                                            {new Date(device.last_scan_at).toLocaleDateString()}
                                        </TableCell>
                                        <TableCell className="text-right">
                                            <div className="flex justify-end gap-1">
                                                {device.trust_status !== 'trusted' && (
                                                    <Button 
                                                        size="sm" 
                                                        variant="outline" 
                                                        className="h-8 border-green-600 text-green-600 hover:bg-green-600 hover:text-white"
                                                        onClick={() => handleUpdateStatus(device.id, 'trusted')}
                                                    >
                                                        <CheckCircle2 className="w-3 h-3 mr-1" /> Trust
                                                    </Button>
                                                )}
                                                {device.trust_status !== 'untrusted' && (
                                                    <Button 
                                                        size="sm" 
                                                        variant="ghost" 
                                                        className="h-8 text-destructive hover:bg-destructive/10"
                                                        onClick={() => handleUpdateStatus(device.id, 'untrusted')}
                                                    >
                                                        <XCircle className="w-3 h-3 mr-1" /> Block
                                                    </Button>
                                                )}
                                            </div>
                                        </TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    )}
                </CardContent>
            </Card>
        </div>
    );
};

export default Devices;
