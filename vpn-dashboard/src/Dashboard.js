// src/Dashboard.js
import React, { useState, useEffect } from 'react';
import { Line } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend } from 'chart.js';
import { Box, Card, CardContent, Typography, Grid } from '@mui/material';
import io from 'socket.io-client';


const socket = io('http://localhost:5000');

// Register the necessary components
ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend);

const generateRandomData = (length, max) => {
    return Array.from({ length }, () => Math.floor(Math.random() * max));
};

const Dashboard = () => {
    const [data, setData] = useState({
        packetLoss: 1,
        activeSessions: 138,
        trafficIn: generateRandomData(24, 300),
        trafficOut: generateRandomData(24, 250),
        cpuUsage: generateRandomData(24, 100),
        memoryUsage: generateRandomData(24, 100),
    });

    useEffect(() => {
        socket.on('update_data', (newData) =>{
            setData(newData);
        });

        return () => {
            socket.off('update_data');
            socket.disconnect();
          };
    }, []);

    const trafficData = {
        labels: Array.from({ length: 24 }, (_, i) => `${i}:00`),
        datasets: [
            {
                label: 'In Traffic',
                data: data.trafficIn,
                borderColor: 'rgba(75,192,192,1)',
                fill: false,
            },
            {
                label: 'Out Traffic',
                data: data.trafficOut,
                borderColor: 'rgba(255,99,132,1)',
                fill: false,
            },
        ],
    };

    const cpuMemoryData = {
        labels: Array.from({ length: 24 }, (_, i) => `${i}:00`),
        datasets: [
            {
                label: 'CPU Usage',
                data: data.cpuUsage,
                borderColor: 'rgba(153,102,255,1)',
                fill: false,
            },
            {
                label: 'Memory Usage',
                data: data.memoryUsage,
                borderColor: 'rgba(255,159,64,1)',
                fill: false,
            },
        ],
    };

    return (
        <Box sx={{ flexGrow: 1, padding: 3 }}>
            <Typography variant="h4" gutterBottom>
                Digital-Shield-VPN Server Dashboard
            </Typography>
            <Grid container spacing={3}>
                <Grid item xs={12} md={6} lg={3}>
                    <Card>
                        <CardContent>
                            <Typography variant="h5">Packet Loss</Typography>
                            <Typography variant="h6">{data.packetLoss}%</Typography>
                        </CardContent>
                    </Card>
                </Grid>
                <Grid item xs={12} md={6} lg={3}>
                    <Card>
                        <CardContent>
                            <Typography variant="h5">Active Sessions</Typography>
                            <Typography variant="h6">{data.activeSessions}</Typography>
                        </CardContent>
                    </Card>
                </Grid>
                <Grid item xs={12} md={6} lg={6}>
                    <Card>
                        <CardContent>
                            <Typography variant="h5">Traffic</Typography>
                            <Line data={trafficData} />
                        </CardContent>
                    </Card>
                </Grid>
                <Grid item xs={12} md={6} lg={6}>
                    <Card>
                        <CardContent>
                            <Typography variant="h5">CPU & Memory Usage</Typography>
                            <Line data={cpuMemoryData} />
                        </CardContent>
                    </Card>
                </Grid>
            </Grid>
        </Box>
    );
};

export default Dashboard;
