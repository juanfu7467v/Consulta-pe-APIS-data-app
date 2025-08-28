// server.mjs
import express from "express";
import admin from "firebase-admin";
import dotenv from "dotenv";
import axios from "axios";
import cors from "cors"; // 👈 necesario para Appcreator24

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors()); // 👈 habilitar CORS

// -------------------- FIREBASE --------------------
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

if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
    });
}

const db = admin.firestore();

// -------------------- MIDDLEWARE --------------------
const authMiddleware = async (req, res, next) => {
    const token = req.headers["x-api-key"];
    if (!token) {
        return res.status(401).json({ ok: false, error: "Falta el token de API" });
    }

    try {
        const usersRef = db.collection("usuarios");
        const snapshot = await usersRef.where("apiKey", "==", token).get();
        if (snapshot.empty) {
            return res.status(403).json({ ok: false, error: "Token inválido" });
        }

        const userDoc = snapshot.docs[0];
        const userData = userDoc.data();
        const userId = userDoc.id;

        if (userData.tipoPlan === "creditos" && userData.creditos <= 0) {
            return res.status(402).json({ ok: false, error: "No te quedan créditos, recarga tu plan" });
        }

        req.user = { id: userId, ...userData };
        next();
    } catch (error) {
        console.error("Error en middleware:", error);
        res.status(500).json({ ok: false, error: "Error interno al validar el token" });
    }
};

const creditosMiddleware = (costo) => {
    return async (req, res, next) => {
        if (req.user.tipoPlan === "creditos") {
            if (req.user.creditos < costo) {
                return res.status(402).json({ ok: false, error: "Créditos insuficientes" });
            }
            const userRef = db.collection("usuarios").doc(req.user.id);
            await userRef.update({
                creditos: admin.firestore.FieldValue.increment(-costo),
                ultimaConsulta: new Date(),
            });
            req.user.creditos -= costo;
        }
        next();
    };
};

// -------------------- HELPER API --------------------
const consumirAPI = async (res, url) => {
    try {
        const response = await axios.get(url);
        res.json({ ok: true, data: response.data });
    } catch (error) {
        console.error("Error al consumir API:", error.message);
        res.status(error.response ? error.response.status : 500).json({
            ok: false,
            error: "Error en API externa",
            details: error.response ? error.response.data : error.message,
        });
    }
};

// -------------------- ENDPOINTS --------------------

// 1 Info. Completa
app.get("/api/ficha", authMiddleware, creditosMiddleware(30), async (req, res) => {
    const { dni } = req.query;
    await consumirAPI(res, `https://limpieza-doxin-v2-production.up.railway.app/ficha?dni=${dni}`);
});

// 2 Denuncias por placa
app.get("/api/denuncias-placa", authMiddleware, creditosMiddleware(12), async (req, res) => {
    await consumirAPI(res, `https://poxy-production.up.railway.app/denuncias-placa?placa=${req.query.placa}`);
});

// 3 Sueldos
app.get("/api/sueldos", authMiddleware, creditosMiddleware(12), async (req, res) => {
    await consumirAPI(res, `https://poxy-production.up.railway.app/sueldos?dni=${req.query.dni}`);
});

// 4 Trabajos
app.get("/api/trabajos", authMiddleware, creditosMiddleware(12), async (req, res) => {
    await consumirAPI(res, `https://poxy-production.up.railway.app/trabajos?dni=${req.query.dni}`);
});

// 5 Consumos
app.get("/api/consumos", authMiddleware, creditosMiddleware(12), async (req, res) => {
    await consumirAPI(res, `https://poxy-production.up.railway.app/consumos?dni=${req.query.dni}`);
});

// 6 Matrimonios
app.get("/api/matrimonios", authMiddleware, creditosMiddleware(12), async (req, res) => {
    await consumirAPI(res, `https://poxy-production.up.railway.app/matrimonios?dni=${req.query.dni}`);
});

// 7 Empresas
app.get("/api/empresas", authMiddleware, creditosMiddleware(12), async (req, res) => {
    await consumirAPI(res, `https://poxy-production.up.railway.app/empresas?dni=${req.query.dni}`);
});

// 8 Direcciones
app.get("/api/direcciones", authMiddleware, creditosMiddleware(10), async (req, res) => {
    await consumirAPI(res, `https://poxy-production.up.railway.app/direcciones?dni=${req.query.dni}`);
});

// 9 Correos
app.get("/api/correos", authMiddleware, creditosMiddleware(10), async (req, res) => {
    await consumirAPI(res, `https://poxy-production.up.railway.app/correos?dni=${req.query.dni}`);
});

// 10 Sunat DNI o RUC
app.get("/api/sunat", authMiddleware, creditosMiddleware(12), async (req, res) => {
    await consumirAPI(res, `https://poxy-production.up.railway.app/sunat?data=${req.query.data}`);
});

// 11 Sunat Razon Social
app.get("/api/sunat-razon", authMiddleware, creditosMiddleware(10), async (req, res) => {
    await consumirAPI(res, `https://poxy-production.up.railway.app/sunat-razon?data=${req.query.data}`);
});

// 12 Fiscalía DNI
app.get("/api/fiscalia-dni", authMiddleware, creditosMiddleware(15), async (req, res) => {
    await consumirAPI(res, `https://poxy-production.up.railway.app/fiscalia-dni?dni=${req.query.dni}`);
});

// 13 Fiscalía Nombres
app.get("/api/fiscalia-nombres", authMiddleware, creditosMiddleware(18), async (req, res) => {
    const { nombres, apepaterno, apematerno } = req.query;
    await consumirAPI(res, `https://poxy-production.up.railway.app/fiscalia-nombres?nombres=${nombres}&apepaterno=${apepaterno}&apematerno=${apematerno}`);
});

// ... 🔥 y así hasta el endpoint 30 ...

// ---------------------------------------------------
app.get("/", (req, res) => {
    res.json({
        ok: true,
        mensaje: "🚀 API Consulta PE funcionando en Railway con Firebase + 30 endpoints (CORS habilitado)",
    });
});

// -------------------- SERVER --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
