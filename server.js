require('dotenv').config();
require('@aikidosec/firewall');
const express = require('express');
const helmet = require('helmet');
const axios = require('axios');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
app.use(helmet());

// Middleware
app.use(bodyParser.json());
app.use(cors()); // Ajustar según seguridad necesaria

// Configuración Auth0

const CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;

app.get('/check', (req, res) => {
  res.status(200).send('TODO OK!');
});

// ---------------------------------------------------------
// ENDPOINT 1: INICIAR ENROLAMIENTO (Steps 1, 2, 3)
// Recibe: El Access Token del usuario logueado (desde el front)
// Retorna: El Secret (para que generes el TOTP) y el mfa_token (oob_code)
// ---------------------------------------------------------
app.post('/initiate-enrollment', async (req, res) => {
  try {
    // Esperamos que el front envíe su Access Token actual en el header
    // Authorization: Bearer eyJ...
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({ error: 'Falta el Access Token del usuario' });
    }

    // LLAMADA A AUTH0: /mfa/associate
    // Usamos el token del usuario para decirle a Auth0 "este usuario quiere MFA"
    const associateUrl = `https://micoope-poc-demo.cic-demo-platform.auth0app.com/mfa/associate`;
    console.log(associateUrl);
        console.log(authHeader);
    const response = await axios.post(
      associateUrl,
      {
        authenticator_types: ["otp"]
      },
      {
        headers: {
          'Authorization': authHeader, // Pasamos el token del usuario
          'Content-Type': 'application/json'
        }
      }
    );

    // Auth0 devuelve: secret, barcode_uri, recovery_codes, y oob_code
    const data = response.data;

    // Aquí extraemos lo que tu App Swift necesita
    // IMPORTANTE: El 'oob_code' que devuelve esta llamada actúa como el 'mfa_token'
    // que necesitas para el paso final de confirmación.

    res.json({
      secret: data.secret,         // Para que tu Swift genere los códigos
      mfa_token: data.oob_code,    // GUÁRDALO en Swift, se necesita para el paso final
      recovery_codes: data.recovery_codes
    });

  } catch (error) {
    console.error('Error en /mfa/associate:', error.response?.data || error.message);
    res.status(500).json({ error: 'Error iniciando enrolamiento', details: error.response?.data });
  }
});

// ---------------------------------------------------------
// ENDPOINT 2: CONFIRMAR ENROLAMIENTO (Steps 4, 5)
// URL expuesta: /enroll-totp-Auth0
// Recibe: El código TOTP generado por Swift y el mfa_token (oob_code)
// ---------------------------------------------------------
app.post('/enroll-totp-Auth0', async (req, res) => {
  try {
    const { otp, mfa_token } = req.body;

    if (!otp || !mfa_token) {
      return res.status(400).json({ error: 'Faltan parámetros: otp o mfa_token' });
    }

    // LLAMADA A AUTH0: /oauth/token
    // Confirmamos la asociación probando que el usuario tiene el código correcto
    const tokenUrl = `https://${AUTH0_DOMAIN}/oauth/token`;

    const payload = new URLSearchParams();
    payload.append('grant_type', 'http://auth0.com/oauth/grant-type/mfa-otp');
    payload.append('client_id', CLIENT_ID);
    payload.append('client_secret', CLIENT_SECRET);
    payload.append('mfa_token', mfa_token); // Este es el oob_code del paso anterior
    payload.append('otp', otp);

    const response = await axios.post(tokenUrl, payload, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    // Si todo sale bien, Auth0 devuelve tokens nuevos (ID Token, Access Token)
    // Esto confirma que el MFA quedó asociado y validado.
    res.json({
      success: true,
      message: 'MFA Enrolado correctamente',
      tokens: response.data
    });

  } catch (error) {
    console.error('Error en /oauth/token:', error.response?.data || error.message);

    // Manejo de errores comunes (código inválido)
    if (error.response?.data?.error === 'invalid_grant') {
      return res.status(400).json({ error: 'El código TOTP es inválido o expiró' });
    }

    res.status(500).json({ error: 'Error confirmando enrolamiento', details: error.response?.data });
  }
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT,'0.0.0.0',() => {
  console.log(`Servidor de Enrolamiento MFA corriendo en puerto ${PORT}`);
});
