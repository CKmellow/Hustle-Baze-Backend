require('dotenv').config();
const axios = require('axios');

const baseUrl = process.env.RENDER_BACKEND_URL || 'https://hustle-baze-backend.onrender.com';
const cronSecret = process.env.CRON_SECRET;

async function pingDatabase() {
  const endpoint = `${baseUrl.replace(/\/$/, '')}/api/cron/ping-db`;

  try {
    const response = await axios.get(endpoint, {
      headers: cronSecret ? { 'x-cron-secret': cronSecret } : {},
      timeout: 15000,
    });

    console.log('Daily DB ping succeeded:', response.data);
    process.exit(0);
  } catch (error) {
    if (error.response) {
      console.error('Daily DB ping failed with response:', error.response.status, error.response.data);
    } else {
      console.error('Daily DB ping failed:', error.message);
    }

    process.exit(1);
  }
}

pingDatabase();
