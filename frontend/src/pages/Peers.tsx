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
} from '@mui/material';
import {
  Delete as DeleteIcon,
  Add as AddIcon,
  QrCode as QrCodeIcon,
  Download as DownloadIcon,
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
}

interface Server {
  id: number;
  name: string;
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
    address: '10.0.0.2/24',
    dns: '8.8.8.8',
    allowedIPs: '0.0.0.0/0',
  });
  const [error, setError] = useState<string | null>(null);

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
    fetchPeers();
    fetchServers();
  }, []);

  const handleCreatePeer = async () => {
    try {
      // Generate keys first
      const keysResponse = await axios.post(`${process.env.REACT_APP_API_URL}/api/wg/genkeys`);
      const { privateKey, publicKey } = keysResponse.data;

      // Create peer with generated keys
      const peerData = {
        ...newPeer,
        publicKey,
        privateKey,
      };

      await axios.post(`${process.env.REACT_APP_API_URL}/api/peers`, peerData);
      setOpen(false);
      fetchPeers();
      setNewPeer({
        name: '',
        address: '10.0.0.2/24',
        dns: '8.8.8.8',
        allowedIPs: '0.0.0.0/0',
      });
    } catch (error: any) {
      console.error('Failed to create peer:', error.response?.data || error.message);
      alert('Error al crear peer: ' + (error.response?.data?.error || error.message));
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

  console.log('Valor de peers en render:', peers);

  if (!Array.isArray(peers)) {
    return <Typography color="error">Error crítico: peers no es un array. Valor: {JSON.stringify(peers)}</Typography>;
  }

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3 }}>
        <Typography variant="h4">WireGuard Peers</Typography>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => setOpen(true)}
        >
          Add Peer
        </Button>
      </Box>

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Public Key</TableCell>
              <TableCell>Address</TableCell>
              <TableCell>DNS</TableCell>
              <TableCell>Allowed IPs</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {error ? (
              <TableRow>
                <TableCell colSpan={7} align="center">
                  {error}
                </TableCell>
              </TableRow>
            ) : Array.isArray(peers) ? (
              peers.length > 0 ? (
                peers.map((peer) => (
                  <TableRow key={peer.id}>
                    <TableCell>{peer.name}</TableCell>
                    <TableCell>{peer.publicKey}</TableCell>
                    <TableCell>{peer.address}</TableCell>
                    <TableCell>{peer.dns}</TableCell>
                    <TableCell>{peer.allowedIPs}</TableCell>
                    <TableCell>{peer.status}</TableCell>
                    <TableCell>
                      <IconButton
                        color="primary"
                        onClick={() => handleShowQRCode(peer)}
                      >
                        <QrCodeIcon />
                      </IconButton>
                      <IconButton
                        color="primary"
                        onClick={() => handleDownloadConfig(peer)}
                      >
                        <DownloadIcon />
                      </IconButton>
                      <IconButton
                        color="error"
                        onClick={() => handleDeletePeer(peer.id)}
                      >
                        <DeleteIcon />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell colSpan={7} align="center">
                    No hay peers configurados.
                  </TableCell>
                </TableRow>
              )
            ) : (
              <TableRow>
                <TableCell colSpan={7} align="center">
                  Error: Peers data is invalid.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog open={open} onClose={() => setOpen(false)}>
        <DialogTitle>Add New Peer</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            margin="dense"
            name="name"
            label="Name"
            fullWidth
            onChange={e => setNewPeer({ ...newPeer, name: e.target.value })}
          />
          <TextField
            select
            margin="dense"
            name="serverID"
            label="Server"
            fullWidth
            onChange={e =>
              setNewPeer({ ...newPeer, serverID: parseInt(e.target.value) })
            }
            value={newPeer.serverID || ''}
          >
            {servers.map(server => (
              <MenuItem key={server.id} value={server.id}>
                {server.name}
              </MenuItem>
            ))}
          </TextField>
          <TextField
            margin="dense"
            name="address"
            label="Address"
            fullWidth
            value={newPeer.address}
            onChange={(e) => setNewPeer({ ...newPeer, address: e.target.value })}
          />
          <TextField
            margin="dense"
            label="DNS"
            fullWidth
            value={newPeer.dns}
            onChange={(e) => setNewPeer({ ...newPeer, dns: e.target.value })}
          />
          <TextField
            margin="dense"
            label="Allowed IPs"
            fullWidth
            value={newPeer.allowedIPs}
            onChange={(e) =>
              setNewPeer({ ...newPeer, allowedIPs: e.target.value })
            }
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>Cancel</Button>
          <Button onClick={handleCreatePeer} variant="contained">
            Create
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={qrCodeOpen} onClose={() => setQrCodeOpen(false)}>
        <DialogTitle>QR Code for {selectedPeer?.name}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Scan this QR code with your WireGuard client to add this peer
            configuration.
          </DialogContentText>
          {qrCode ? (
            <Box
              sx={{
                display: 'flex',
                justifyContent: 'center',
                mt: 2,
              }}
            >
              <img src={qrCode} alt={`QR Code for ${selectedPeer?.name}`} />
            </Box>
          ) : (
            <Typography>Generating QR Code...</Typography>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setQrCodeOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default Peers; 