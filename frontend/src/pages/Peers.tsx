import React, { useState, useEffect } from 'react';
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
  MenuItem,
  DialogContentText,
  Alert,
  CircularProgress,
  Chip,
  Stack,
} from '@mui/material';
import {
  Delete as DeleteIcon,
  Add as AddIcon,
  QrCode as QrCodeIcon,
  Download as DownloadIcon,
  Edit as EditIcon,
  LabelOutlined as LabelIcon,
} from '@mui/icons-material';
import axios from 'axios';

interface Peer {
  id: number;
  name: string;
  publicKey: string;
  address: string;
  dns: string;
  allowedIPs: string;
  serverID: number;
  status: string;
  tags?: string;
}

interface Server {
  id: number;
  name: string;
  address: string;
}

const Peers: React.FC = () => {
  const [peers, setPeers] = useState<Peer[]>([]);
  const [servers, setServers] = useState<Server[]>([]);
  const [open, setOpen] = useState(false);
  const [qrCodeOpen, setQrCodeOpen] = useState(false);
  const [selectedPeer, setSelectedPeer] = useState<Peer | null>(null);
  const [qrCode, setQrCode] = useState('');
  const [newPeer, setNewPeer] = useState<Partial<Peer>>({
    name: '',
    serverID: 0,
    tags: '',
  });
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [createLoading, setCreateLoading] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [editPeer, setEditPeer] = useState<Peer | null>(null);
  const [editTags, setEditTags] = useState('');
  const [editLoading, setEditLoading] = useState(false);
  const [editError, setEditError] = useState<string | null>(null);

  const fetchPeers = async () => {
    try {
      const res = await axios.get(`${process.env.REACT_APP_API_URL}/api/peers`);
      setPeers(Array.isArray(res.data) ? res.data : []);
      setError(null);
    } catch (err) {
      setPeers([]);
      setError('Error al obtener los peers.');
    }
  };

  const fetchServers = async () => {
    try {
      const response = await axios.get(`${process.env.REACT_APP_API_URL}/api/servers`);
      setServers(Array.isArray(response.data) ? response.data : []);
    } catch (error) {
      setServers([]);
      console.error('Failed to fetch servers:', error);
    }
  };

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      await Promise.all([fetchPeers(), fetchServers()]);
      setLoading(false);
    };
    loadData();
  }, []);

  const handleCreatePeer = async () => {
    if (!newPeer.name || !newPeer.serverID) {
      setCreateError('Name and server are required');
      return;
    }

    setCreateLoading(true);
    setCreateError(null);
    try {
      // The backend now handles key generation and IP allocation automatically
      const peerData = {
        name: newPeer.name,
        serverID: newPeer.serverID,
        tags: newPeer.tags,
      };

      await axios.post(`${process.env.REACT_APP_API_URL}/api/peers`, peerData);
      setOpen(false);
      // Reset form
      setNewPeer({
        name: '',
        serverID: 0,
        tags: '',
      });
      fetchPeers();
    } catch (error: any) {
      setCreateError(error.response?.data?.error || error.message);
    } finally {
      setCreateLoading(false);
    }
  };

  const handleDeletePeer = async (id: number) => {
    if (window.confirm('Are you sure you want to delete this peer?')) {
      try {
        await axios.delete(`${process.env.REACT_APP_API_URL}/api/peers/${id}`);
        fetchPeers();
      } catch (error) {
        console.error('Failed to delete peer:', error);
      }
    }
  };

  const handleShowQRCode = async (peer: Peer) => {
    try {
      const response = await axios.get(
        `${process.env.REACT_APP_API_URL}/api/peers/${peer.id}/qrcode`
      );
      setQrCode(response.data.qrcode);
      setSelectedPeer(peer);
      setQrCodeOpen(true);
    } catch (error) {
      console.error('Failed to fetch QR code:', error);
    }
  };

  const handleDownloadConfig = async (peer: Peer) => {
    try {
      const response = await axios.get(
        `${process.env.REACT_APP_API_URL}/api/peers/${peer.id}/config`,
        { responseType: 'blob' }
      );
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `wg-${peer.name}.conf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (error) {
      console.error('Failed to download config:', error);
    }
  };

  const handleOpenEdit = (peer: Peer) => {
    setEditPeer(peer);
    setEditTags(peer.tags || '');
    setEditError(null);
  };

  const handleCloseEdit = () => {
    setEditPeer(null);
    setEditTags('');
    setEditError(null);
  };

  const handleUpdateTags = async () => {
    if (!editPeer) return;
    setEditLoading(true);
    setEditError(null);
    try {
      await axios.put(`${process.env.REACT_APP_API_URL}/api/peers/${editPeer.id}`, { tags: editTags });
      handleCloseEdit();
      fetchPeers();
    } catch (error: any) {
      setEditError(error.response?.data?.error || error.message);
    } finally {
      setEditLoading(false);
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
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3 }}>
        <Typography variant="h4">WireGuard Peers ({peers.length})</Typography>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => setOpen(true)}
          disabled={servers.length === 0}
        >
          Add Peer
        </Button>
      </Box>

      {servers.length === 0 && (
        <Alert severity="info" sx={{ mb: 2 }}>
          No servers available. Please create a WireGuard server first before adding peers.
        </Alert>
      )}

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Public Key</TableCell>
              <TableCell>Address</TableCell>
              <TableCell>DNS</TableCell>
              <TableCell>Allowed IPs</TableCell>
              <TableCell>Tags</TableCell>
              <TableCell>Server</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {peers.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} align="center">
                  No peers found. Create your first peer to get started.
                </TableCell>
              </TableRow>
            ) : (
              peers.map((peer) => {
                const server = servers.find(s => s.id === peer.serverID);
                return (
                  <TableRow key={peer.id}>
                    <TableCell>{peer.name}</TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                        {peer.publicKey ? `${peer.publicKey.substring(0, 20)}...` : 'Not generated'}
                      </Typography>
                    </TableCell>
                    <TableCell>{peer.address}</TableCell>
                    <TableCell>{peer.dns}</TableCell>
                    <TableCell>{peer.allowedIPs}</TableCell>
                    <TableCell>
                      {peer.tags && peer.tags.trim() !== '' ? (
                        <Stack direction="row" spacing={0.5}>
                          {peer.tags.split(',').map((tag, idx) => (
                            <Chip
                              key={idx}
                              icon={<LabelIcon sx={{ color: '#b388ff' }} />}
                              label={tag.trim()}
                              size="small"
                              sx={{
                                backgroundColor: '#ede7f6',
                                color: '#6a1b9a',
                                fontWeight: 500,
                                borderRadius: '6px',
                                border: 'none',
                                px: 0.5,
                                fontSize: '0.85em',
                              }}
                            />
                          ))}
                        </Stack>
                      ) : (
                        '-'
                      )}
                    </TableCell>
                    <TableCell>{server ? server.name : 'Unknown'}</TableCell>
                    <TableCell>
                      <Typography variant="body2" color={peer.status === 'active' ? 'success.main' : 'text.secondary'}>
                        {peer.status || 'unknown'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <IconButton onClick={() => handleShowQRCode(peer)}>
                        <QrCodeIcon />
                      </IconButton>
                      <IconButton onClick={() => handleDownloadConfig(peer)}>
                        <DownloadIcon />
                      </IconButton>
                      <IconButton color="error" onClick={() => handleDeletePeer(peer.id)}>
                        <DeleteIcon />
                      </IconButton>
                      <IconButton color="primary" onClick={() => handleOpenEdit(peer)}>
                        <EditIcon />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog open={open} onClose={() => { setOpen(false); setCreateError(null); }} maxWidth="sm" fullWidth>
        <DialogTitle>Add New Peer</DialogTitle>
        <DialogContent>
          <DialogContentText sx={{ mb: 2 }}>
            Create a new WireGuard peer. The system will automatically generate keys and assign an IP address.
          </DialogContentText>
          <TextField
            autoFocus
            margin="dense"
            label="Peer Name"
            fullWidth
            value={newPeer.name}
            onChange={(e) => setNewPeer({ ...newPeer, name: e.target.value })}
            helperText="Unique name for this peer"
          />
          <TextField
            select
            margin="dense"
            label="Server"
            fullWidth
            value={newPeer.serverID}
            onChange={(e) => setNewPeer({ ...newPeer, serverID: parseInt(e.target.value) })}
            helperText="Select the WireGuard server for this peer"
          >
            {servers.map((server) => (
              <MenuItem key={server.id} value={server.id}>
                {server.name} ({server.address})
              </MenuItem>
            ))}
          </TextField>
          <TextField
            margin="dense"
            label="Tags"
            fullWidth
            value={newPeer.tags}
            onChange={(e) => setNewPeer({ ...newPeer, tags: e.target.value })}
            helperText="Comma-separated tags (e.g., soporte,cliente,VPN)"
          />
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
          <Button onClick={handleCreatePeer} variant="contained" disabled={createLoading}>
            {createLoading ? 'Creating...' : 'Create Peer'}
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={qrCodeOpen} onClose={() => setQrCodeOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>QR Code for {selectedPeer?.name}</DialogTitle>
        <DialogContent>
          {qrCode && (
            <Box sx={{ textAlign: 'center' }}>
              <img src={qrCode} alt="QR Code" style={{ maxWidth: '100%', height: 'auto' }} />
              <Typography variant="body2" sx={{ mt: 2 }}>
                Scan this QR code with your WireGuard mobile app to quickly configure the peer.
              </Typography>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setQrCodeOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      <Dialog open={!!editPeer} onClose={handleCloseEdit} maxWidth="xs" fullWidth>
        <DialogTitle>Edit Tags</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            margin="dense"
            label="Tags"
            fullWidth
            value={editTags}
            onChange={(e) => setEditTags(e.target.value)}
            helperText="Comma-separated tags (e.g., soporte,cliente,VPN)"
          />
          {editError && (
            <Alert severity="error" sx={{ mt: 2 }}>
              {editError}
            </Alert>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseEdit} disabled={editLoading}>Cancel</Button>
          <Button onClick={handleUpdateTags} variant="contained" disabled={editLoading}>
            {editLoading ? 'Saving...' : 'Save'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default Peers; 