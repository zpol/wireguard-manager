import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Paper,
  Typography,
  CircularProgress,
} from '@mui/material';
import {
  Storage as ServerIcon,
  People as PeerIcon,
  Speed as SpeedIcon,
} from '@mui/icons-material';
import axios from 'axios';

interface Stats {
  totalServers: number;
  totalPeers: number;
  activePeers: number;
  traffic: {
    rx: number;
    tx: number;
  };
}

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<Stats>({
    totalServers: 0,
    totalPeers: 0,
    activePeers: 0,
    traffic: { rx: 0, tx: 0 }
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchStats();
  }, []);

  const fetchStats = async () => {
    try {
      const response = await axios.get(`${process.env.REACT_APP_API_URL}/api/stats`);
      setStats({
        totalServers: response.data.totalServers ?? 0,
        totalPeers: response.data.totalPeers ?? 0,
        activePeers: response.data.activePeers ?? 0,
        traffic: {
          rx: response.data.traffic?.rx ?? 0,
          tx: response.data.traffic?.tx ?? 0,
        },
      });
    } catch (error) {
      console.error('Failed to fetch stats:', error);
    } finally {
      setLoading(false);
    }
  };

  const formatBytes = (bytes: number) => {
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    if (bytes === 0) return '0 Byte';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${Math.round(bytes / Math.pow(1024, i))} ${sizes[i]}`;
  };

  if (loading) {
    return (
      <Box
        sx={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          height: '100vh',
        }}
      >
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 4 }}>
        Dashboard
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12} sm={6} md={3}>
          <Paper
            sx={{
              p: 3,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
            }}
          >
            <ServerIcon sx={{ fontSize: 40, color: 'primary.main', mb: 1 }} />
            <Typography variant="h6">Total Servers</Typography>
            <Typography variant="h4">{stats?.totalServers || 0}</Typography>
          </Paper>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Paper
            sx={{
              p: 3,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
            }}
          >
            <PeerIcon sx={{ fontSize: 40, color: 'primary.main', mb: 1 }} />
            <Typography variant="h6">Total Peers</Typography>
            <Typography variant="h4">{stats?.totalPeers || 0}</Typography>
          </Paper>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Paper
            sx={{
              p: 3,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
            }}
          >
            <PeerIcon sx={{ fontSize: 40, color: 'success.main', mb: 1 }} />
            <Typography variant="h6">Active Peers</Typography>
            <Typography variant="h4">{stats?.activePeers || 0}</Typography>
          </Paper>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Paper
            sx={{
              p: 3,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
            }}
          >
            <SpeedIcon sx={{ fontSize: 40, color: 'primary.main', mb: 1 }} />
            <Typography variant="h6">Total Traffic</Typography>
            <Typography variant="body1">
              ↑ {formatBytes(stats?.traffic.tx ?? 0)}
            </Typography>
            <Typography variant="body1">
              ↓ {formatBytes(stats?.traffic.rx ?? 0)}
            </Typography>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Dashboard; 