import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  MenuItem,
  Typography,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Chip,
  Tooltip,
  Alert,
  CircularProgress,
} from '@mui/material';
import {
  Delete as DeleteIcon,
  Add as AddIcon,
  PlayArrow as PlayArrowIcon,
  Stop as StopIcon,
  Replay as ReplayIcon,
} from '@mui/icons-material';
import axios from 'axios';

interface Server {
  id: number;
  name: string;
  publicKey: string;
  listenPort: number;
  address: string;
  peers: any[];
  status: string; // 'active' or 'inactive'
  deploymentMode?: string;
  targetNodes?: string[];
  activeNodes?: string[];
}

const Servers: React.FC = () => {
  const [servers, setServers] = useState<Server[]>([]);
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [newServer, setNewServer] = useState({
    name: 'wg0',
    listenPort: 51820,
    address: '10.0.0.1/24',
    dns: '8.8.8.8',
    mtu: 1420,
    initialPeers: 1,
    deploymentMode: 'local',
  });
  const [createLoading, setCreateLoading] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const fetchServers = useCallback(async () => {
    setLoading(true);
    try {
      const response = await axios.get(`${process.env.REACT_APP_API_URL}/api/servers`);
      setServers(response.data || []);
      setError(null);
    } catch (err) {
      console.error('Failed to fetch servers:', err);
      setError('Could not fetch servers.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchServers();
  }, [fetchServers]);

  const handleCreateServer = async () => {
    setCreateLoading(true);
    setCreateError(null);
    try {
      // The backend now handles key generation automatically
      const serverData = {
        ...newServer,
        initialPeers: newServer.initialPeers,
      };

      await axios.post(`${process.env.REACT_APP_API_URL}/api/servers`, serverData);
      setOpen(false);
      // Reset form
      setNewServer({
        name: 'wg0',
        listenPort: 51820,
        address: '10.0.0.1/24',
        dns: '8.8.8.8',
        mtu: 1420,
        initialPeers: 1,
        deploymentMode: 'local',
      });
      fetchServers();
    } catch (error: any) {
      setCreateError(error.response?.data?.error || error.message);
    } finally {
      setCreateLoading(false);
    }
  };
  
  const handleServerAction = useCallback(async (id: number, action: 'start' | 'stop' | 'restart') => {
    try {
        await axios.post(`${process.env.REACT_APP_API_URL}/api/servers/${id}/${action}`);
        // Refresh server list to show new status
        setTimeout(fetchServers, 1000); // Give more time for container operations
    } catch (error: any) {
        alert(`Error performing action ${action}: ` + (error.response?.data?.error || error.message));
    }
  }, [fetchServers]);

  const handleDeleteServer = async (id: number) => {
    if (window.confirm('Are you sure you want to delete this server? This will also delete the associated Docker container and all peers.')) {
      try {
        await axios.delete(`${process.env.REACT_APP_API_URL}/api/servers/${id}`);
        fetchServers();
      } catch (error) {
        console.error('Failed to delete server:', error);
      }
    }
  };
  
  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4">WireGuard Servers ({servers.length})</Typography>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => setOpen(true)}>
          Add Server
        </Button>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Status</TableCell>
              <TableCell>Name</TableCell>
              <TableCell>Listen Port</TableCell>
              <TableCell>Address</TableCell>
              <TableCell>Peers</TableCell>
              <TableCell>Active Nodes</TableCell>
              <TableCell sx={{ width: '40%' }}>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {servers.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} align="center">
                  No servers found. Create your first WireGuard server to get started.
                </TableCell>
              </TableRow>
            ) : (
              servers.map((server) => (
                <TableRow key={server.id}>
                  <TableCell>
                    <Chip
                      label={server.status}
                      color={server.status === 'active' ? 'success' : 'default'}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>{server.name}</TableCell>
                  <TableCell>{server.listenPort}</TableCell>
                  <TableCell>{server.address}</TableCell>
                  <TableCell>{server.peers ? server.peers.length : 0}</TableCell>
                  <TableCell>
                    {server.activeNodes && server.activeNodes.length > 0
                      ? server.activeNodes.join(', ')
                      : '—'}
                  </TableCell>
                  <TableCell>
                    <Tooltip title="Start">
                      <span>
                        <IconButton onClick={() => handleServerAction(server.id, 'start')} disabled={server.status === 'active'}>
                          <PlayArrowIcon />
                        </IconButton>
                      </span>
                    </Tooltip>
                    <Tooltip title="Stop">
                       <span>
                        <IconButton onClick={() => handleServerAction(server.id, 'stop')} disabled={server.status !== 'active'}>
                          <StopIcon />
                        </IconButton>
                      </span>
                    </Tooltip>
                    <Tooltip title="Restart">
                       <span>
                        <IconButton onClick={() => handleServerAction(server.id, 'restart')} disabled={server.status !== 'active'}>
                          <ReplayIcon />
                        </IconButton>
                      </span>
                    </Tooltip>
                    <Tooltip title="Delete">
                      <IconButton color="error" onClick={() => handleDeleteServer(server.id)}>
                        <DeleteIcon />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>
      
      <Dialog open={open} onClose={() => { setOpen(false); setCreateError(null); }} maxWidth="sm" fullWidth>
        <DialogTitle>Add New WireGuard Server</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Create a new WireGuard server. The system will automatically generate keys and create a Docker container.
          </Typography>
          <TextField
            autoFocus
            margin="dense"
            label="Server Name"
            fullWidth
            value={newServer.name}
            onChange={(e) => setNewServer({ ...newServer, name: e.target.value })}
            helperText="Unique name for this server"
          />
          <TextField
            margin="dense"
            label="Listen Port"
            type="number"
            fullWidth
            value={newServer.listenPort}
            onChange={(e) =>
              setNewServer({ ...newServer, listenPort: parseInt(e.target.value) })
            }
            helperText="UDP port for WireGuard (default: 51820)"
          />
          <TextField
            margin="dense"
            label="Server Address"
            fullWidth
            value={newServer.address}
            onChange={(e) => setNewServer({ ...newServer, address: e.target.value })}
            helperText="Server IP in CIDR notation (e.g., 10.0.0.1/24)"
          />
          <TextField
            margin="dense"
            label="DNS Server"
            fullWidth
            value={newServer.dns}
            onChange={(e) => setNewServer({ ...newServer, dns: e.target.value })}
            helperText="DNS server for clients (e.g., 8.8.8.8)"
          />
          <TextField
            margin="dense"
            label="MTU"
            type="number"
            fullWidth
            value={newServer.mtu}
            onChange={(e) =>
              setNewServer({ ...newServer, mtu: parseInt(e.target.value) })
            }
            helperText="Maximum Transmission Unit (default: 1420)"
          />
          <TextField
            margin="dense"
            label="Initial Peers"
            type="number"
            fullWidth
            value={newServer.initialPeers}
            onChange={(e) =>
              setNewServer({ ...newServer, initialPeers: parseInt(e.target.value) })
            }
            helperText="Number of peers to create automatically (0-10)"
          />
          <TextField
            select
            margin="dense"
            label="Deployment Mode"
            fullWidth
            value={newServer.deploymentMode}
            onChange={(e) => setNewServer({ ...newServer, deploymentMode: e.target.value })}
            helperText="Choose where the WireGuard container should run"
          >
            <MenuItem value="local">Local node</MenuItem>
            <MenuItem value="all">All SSH nodes</MenuItem>
          </TextField>
          {createError && (
            <Alert severity="error" sx={{ mt: 2 }}>
              {createError}
            </Alert>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => { setOpen(false); setCreateError(null); }} disabled={createLoading}>
            Cancel
          </Button>
          <Button onClick={handleCreateServer} variant="contained" disabled={createLoading}>
            {createLoading ? 'Creating...' : 'Create Server'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default Servers; 