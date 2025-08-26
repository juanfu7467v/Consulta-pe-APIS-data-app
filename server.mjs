// server.mjs
import express from "express";
import admin from "firebase-admin";
import dotenv from "dotenv";
import axios from "axios";

dotenv.config();

const app = express();
app.use(express.json());

// Construir objeto de credenciales desde variables de entorno
const serviceAccount = {
    type: process.env.FIREBASE_TYPE,
    project_id: process.env.FIREBASE_PROJECT_ID,
    private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
    private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n"),
    client_email: process.env.FIREBASE_CLIENT_EMAIL,
    client_id: process.env.FIREBASE_CLIENT_ID,
    auth_uri: process.env.FIREBASE_AUTH_URI,
    token_uri: process.env.FIREBASE_TOKEN_URI,
    auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
    client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL,
    universe_domain: process.env.FIREBASE_UNIVERSE_DOMAIN,
};

// Inicializar Firebase Admin
if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
    });
}

const db = admin.firestore();

// Middleware de Autenticación y Autorización
const authMiddleware = async (req, res, next) => {
    const token = req.headers['x-api-key']; // El token se envía en el header 'x-api-key'

    if (!token) {
        return res.status(401).json({ error: "No se proporcionó un token de API." });
    }

    try {
        const usersRef = db.collection("usuarios");
        const snapshot = await usersRef.where("apiKey", "==", token).get();

        if (snapshot.empty) {
            return res.status(403).json({ error: "Token de API inválido." });
        }

        const userDoc = snapshot.docs[0];
        const userData = userDoc.data();
        const userId = userDoc.id;

        // Verificar el plan y los créditos
        if (userData.tipoPlan === "creditos" && userData.creditos <= 0) {
            return res.status(402).json({ error: "No te quedan créditos. Por favor, recarga tu plan." });
        }

        // Adjuntar datos del usuario a la solicitud para usarlos en el endpoint
        req.user = { id: userId, ...userData };
        next();
    } catch (error) {
        console.error("Error en el middleware de autenticación:", error);
        res.status(500).json({ error: "Error interno del servidor al validar el token." });
    }
};

// Middleware para decrementar créditos
const creditosMiddleware = async (req, res, next) => {
    if (req.user.tipoPlan === "creditos") {
        const userRef = db.collection("usuarios").doc(req.user.id);
        await userRef.update({
            creditos: admin.firestore.FieldValue.increment(-1),
            ultimaConsulta: new Date()
        });
    }
    next();
};

// Endpoint de prueba (protegido)
app.get("/api/test", authMiddleware, creditosMiddleware, (req, res) => {
    res.json({ message: `¡Hola, ${req.user.name}! Tu token es válido. Te quedan ${req.user.creditos - 1} créditos.`, data: "Datos de prueba." });
});

// Endpoint de proxy para las APIs
const BASE_API_URL = "https://poxy-production.up.railway.app";
app.get("/api/:endpoint", authMiddleware, creditosMiddleware, async (req, res) => {
    const { endpoint } = req.params;
    const { placa, dni, data, nombres, apepaterno, apematerno } = req.query;

    let apiUrl = `${BASE_API_URL}/${endpoint}`;
    
    // Construir la URL completa con los parámetros correctos
    if (placa) apiUrl += `?placa=${placa}`;
    else if (dni) apiUrl += `?dni=${dni}`;
    else if (data) apiUrl += `?data=${data}`;
    else if (nombres && apepaterno && apematerno) apiUrl += `?nombres=${nombres}&apepaterno=${apepaterno}&apematerno=${apematerno}`;
    // Añade más casos para otros endpoints si es necesario

    try {
        // Enviar la solicitud a la API original
        const response = await axios.get(apiUrl);
        res.status(response.status).json(response.data);
    } catch (error) {
        console.error("Error al hacer proxy de la API:", error.response ? error.response.data : error.message);
        res.status(error.response ? error.response.status : 500).json({
            error: "Error al consumir la API externa.",
            details: error.response ? error.response.data : error.message
        });
    }
});

// Resto de tus endpoints (perfil, etc.)
app.get("/", (req, res) => {
    res.send("🚀 API Consulta PE funcionando en Railway con Firebase!");
});

app.post("/perfil", async (req, res) => {
    // ... tu código actual ...
});

app.get("/perfiles", async (req, res) => {
    // ... tu código actual ...
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
