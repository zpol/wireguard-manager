import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
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
  });

  const fetchServers = useCallback(async () => {
    setLoading(true);
    try {
      const response = await axios.get(`${process.env.REACT_APP_API_URL}/api/servers`);
      setServers(response.data || []);
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
    try {
      const keysResponse = await axios.post(`${process.env.REACT_APP_API_URL}/api/wg/genkeys`);
      const { privateKey, publicKey } = keysResponse.data;

      const serverData = {
        ...newServer,
        publicKey,
        privateKey,
        initialPeers: newServer.initialPeers,
      };

      await axios.post(`${process.env.REACT_APP_API_URL}/api/servers`, serverData);
      setOpen(false);
      fetchServers();
    } catch (error: any) {
      alert('Error creating server: ' + (error.response?.data?.error || error.message));
    }
  };
  
  const handleServerAction = useCallback(async (id: number, action: 'start' | 'stop' | 'restart') => {
    try {
        await axios.post(`${process.env.REACT_APP_API_URL}/api/servers/${id}/${action}`);
        // Refresh server list to show new status
        setTimeout(fetchServers, 500); // Give a bit of time for the interface to update
    } catch (error: any) {
        alert(`Error performing action ${action}: ` + (error.response?.data?.error || error.message));
    }
  }, [fetchServers]);


  const handleDeleteServer = async (id: number) => {
    if (window.confirm('Are you sure you want to delete this server?')) {
      try {
        await axios.delete(`${process.env.REACT_APP_API_URL}/api/servers/${id}`);
        fetchServers();
      } catch (error) {
        console.error('Failed to delete server:', error);
      }
    }
  };
  
  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4">WireGuard Servers ({servers.length})</Typography>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => setOpen(true)}>
          Add Server
        </Button>
      </Box>

        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Status</TableCell>
                <TableCell>Name</TableCell>
                <TableCell>Listen Port</TableCell>
                <TableCell>Address</TableCell>
                <TableCell>Peers</TableCell>
                <TableCell sx={{ width: '40%' }}>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {servers.map((server) => (
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
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      
      <Dialog open={open} onClose={() => setOpen(false)}>
        <DialogTitle>Add New Server</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            margin="dense"
            label="Name"
            fullWidth
            value={newServer.name}
            onChange={(e) => setNewServer({ ...newServer, name: e.target.value })}
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
          />
          <TextField
            margin="dense"
            label="Address"
            fullWidth
            value={newServer.address}
            onChange={(e) => setNewServer({ ...newServer, address: e.target.value })}
          />
          <TextField
            margin="dense"
            label="DNS"
            fullWidth
            value={newServer.dns}
            onChange={(e) => setNewServer({ ...newServer, dns: e.target.value })}
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
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>Cancel</Button>
          <Button onClick={handleCreateServer} variant="contained">
            Create
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default Servers; 