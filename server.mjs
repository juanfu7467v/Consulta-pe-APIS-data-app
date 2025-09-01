// server.mjs
import express from "express";
import admin from "firebase-admin";
import dotenv from "dotenv";
import axios from "axios";
import cors from "cors";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

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

        // --- Validar plan de créditos ---
        if (userData.tipoPlan === "creditos") {
            if (!userData.creditos || userData.creditos <= 0) {
                return res.status(402).json({
                    ok: false,
                    error: "No te quedan créditos, recarga tu plan para seguir consultando",
                });
            }
        }

        // --- Validar plan ilimitado ---
        if (userData.tipoPlan === "ilimitado") {
            const fechaActivacion = userData.fechaActivacion ? userData.fechaActivacion.toDate() : null;
            const duracion = userData.duracionDias || 0;

            if (fechaActivacion && duracion > 0) {
                const fechaFin = new Date(fechaActivacion);
                fechaFin.setDate(fechaFin.getDate() + duracion);

                const hoy = new Date();
                if (hoy > fechaFin) {
                    return res.status(403).json({
                        ok: false,
                        error: "Sorpresa, tu plan ilimitado ha vencido, renueva tu plan para seguir consultando",
                    });
                }
            } else {
                return res.status(403).json({
                    ok: false,
                    error: "Tu plan ilimitado no es válido, por favor contacta soporte",
                });
            }
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
                return res.status(402).json({
                    ok: false,
                    error: "Créditos insuficientes, recarga tu plan",
                });
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
const procesarRespuesta = (response, user) => {
    // Si hay un campo `data` en la respuesta
    if (response.data) {
        // 🔹 Eliminamos campos de LederData
        delete response.data["developed-by"];
        delete response.data["credits"];

        // 🔹 Agregamos branding de Consulta PE
        response.data.userPlan = {
            tipo: user.tipoPlan,
            creditosRestantes: user.tipoPlan === "creditos" ? user.creditos : null,
        };
        response.data["powered-by"] = "Consulta PE";
    }

    // 🔹 Limpiar mensajes de error molestos
    if (response.ok === false && response.details) {
        if (response.details.message?.includes("Token con falta de pago")) {
            response.details.message = "Error en la consulta, intenta nuevamente";
        }
        if (response.details.detalle?.message?.includes("Token con falta de pago")) {
            response.details.detalle.message = "Error en la consulta, intenta nuevamente";
        }
        delete response.details.detalle?.plan;
    }

    return response;
};

const consumirAPI = async (req, res, url) => {
    try {
        const response = await axios.get(url);
        const processedResponse = procesarRespuesta(response.data, req.user);
        res.json(processedResponse);
    } catch (error) {
        console.error("Error al consumir API:", error.message);
        const errorResponse = {
            ok: false,
            error: "Error en API externa",
            details: error.response ? error.response.data : error.message,
        };
        const processedErrorResponse = procesarRespuesta(errorResponse, req.user);
        res.status(error.response ? error.response.status : 500).json(processedErrorResponse);
    }
};

// -------------------- ENDPOINTS --------------------

// 🔹 1 - 23 (LederData - limpiados y personalizados)
app.get("/api/ficha", authMiddleware, creditosMiddleware(30), async (req, res) => {
    await consumirAPI(req, res, `https://limpieza-doxin-v2-production.up.railway.app/ficha?dni=${req.query.dni}`);
});
app.get("/api/denuncias-placa", authMiddleware, creditosMiddleware(12), async (req, res) => {
    await consumirAPI(req, res, `https://poxy-production.up.railway.app/denuncias-placa?placa=${req.query.placa}`);
});
app.get("/api/sueldos", authMiddleware, creditosMiddleware(12), async (req, res) => {
    await consumirAPI(req, res, `https://poxy-production.up.railway.app/sueldos?dni=${req.query.dni}`);
});
app.get("/api/trabajos", authMiddleware, creditosMiddleware(12), async (req, res) => {
    await consumirAPI(req, res, `https://poxy-production.up.railway.app/trabajos?dni=${req.query.dni}`);
});
app.get("/api/consumos", authMiddleware, creditosMiddleware(12), async (req, res) => {
    await consumirAPI(req, res, `https://poxy-production.up.railway.app/consumos?dni=${req.query.dni}`);
});
app.get("/api/matrimonios", authMiddleware, creditosMiddleware(12), async (req, res) => {
    await consumirAPI(req, res, `https://poxy-production.up.railway.app/matrimonios?dni=${req.query.dni}`);
});
app.get("/api/empresas", authMiddleware, creditosMiddleware(12), async (req, res) => {
    await consumirAPI(req, res, `https://poxy-production.up.railway.app/empresas?dni=${req.query.dni}`);
});
app.get("/api/direcciones", authMiddleware, creditosMiddleware(10), async (req, res) => {
    await consumirAPI(req, res, `https://poxy-production.up.railway.app/direcciones?dni=${req.query.dni}`);
});
app.get("/api/correos", authMiddleware, creditosMiddleware(10), async (req, res) => {
    await consumirAPI(req, res, `https://poxy-production.up.railway.app/correos?dni=${req.query.dni}`);
});
app.get("/api/sunat", authMiddleware, creditosMiddleware(12), async (req, res) => {
    await consumirAPI(req, res, `https://poxy-production.up.railway.app/sunat?data=${req.query.data}`);
});
app.get("/api/sunat-razon", authMiddleware, creditosMiddleware(10), async (req, res) => {
    await consumirAPI(req, res, `https://poxy-production.up.railway.app/sunat-razon?data=${req.query.data}`);
});
app.get("/api/fiscalia-dni", authMiddleware, creditosMiddleware(15), async (req, res) => {
    await consumirAPI(req, res, `https://poxy-production.up.railway.app/fiscalia-dni?dni=${req.query.dni}`);
});
app.get("/api/fiscalia-nombres", authMiddleware, creditosMiddleware(18), async (req, res) => {
    const { nombres, apepaterno, apematerno } = req.query;
    await consumirAPI(req, res, `https://poxy-production.up.railway.app/fiscalia-nombres?nombres=${nombres}&apepaterno=${apepaterno}&apematerno=${apematerno}`);
});
app.get("/api/reniec", authMiddleware, creditosMiddleware(10), async (req, res) => {
    const { dni, source } = req.query;
    await consumirAPI(req, res, `https://poxy-production.up.railway.app/reniec?dni=${dni}&source=${source}`);
});
app.get("/api/arbol", authMiddleware, creditosMiddleware(18), async (req, res) => {
    await consumirAPI(req, res, `https://poxy-production.up.railway.app/arbol?dni=${req.query.dni}`);
});
app.get("/api/familia1", authMiddleware, creditosMiddleware(12), async (req, res) => {
    await consumirAPI(req, res, `https://poxy-production.up.railway.app/familia1?dni=${req.query.dni}`);
});
app.get("/api/familia2", authMiddleware, creditosMiddleware(15), async (req, res) => {
    await consumirAPI(req, res, `https://poxy-production.up.railway.app/familia2?dni=${req.query.dni}`);
});
app.get("/api/familia3", authMiddleware, creditosMiddleware(18), async (req, res) => {
    await consumirAPI(req, res, `https://poxy-production.up.railway.app/familia3?dni=${req.query.dni}`);
});
app.get("/api/vehiculos", authMiddleware, creditosMiddleware(15), async (req, res) => {
    await consumirAPI(req, res, `https://poxy-production.up.railway.app/vehiculos?placa=${req.query.placa}`);
});
app.get("/api/telefonia-doc", authMiddleware, creditosMiddleware(10), async (req, res) => {
    await consumirAPI(req, res, `https://poxy-production.up.railway.app/telefonia-doc?documento=${req.query.documento}`);
});
app.get("/api/telefonia-num", authMiddleware, creditosMiddleware(12), async (req, res) => {
    await consumirAPI(req, res, `https://poxy-production.up.railway.app/telefonia-num?numero=${req.query.numero}`);
});
app.get("/api/movimientos", authMiddleware, creditosMiddleware(12), async (req, res) => {
    await consumirAPI(req, res, `https://poxy-production.up.railway.app/movimientos?dni=${req.query.dni}`);
});
app.get("/api/denuncias-dni", authMiddleware, creditosMiddleware(12), async (req, res) => {
    await consumirAPI(req, res, `https://poxy-production.up.railway.app/denuncias-dni?dni=${req.query.dni}`);
});

// 🔹 24 - 30 (Poxy2 - Factiliza)
app.get("/api/dni", authMiddleware, creditosMiddleware(5), async (req, res) => {
    await consumirAPI(req, res, `https://poxy2-production-987f.up.railway.app/dni?dni=${req.query.dni}`);
});
app.get("/api/ruc", authMiddleware, creditosMiddleware(5), async (req, res) => {
    await consumirAPI(req, res, `https://poxy2-production-987f.up.railway.app/ruc?ruc=${req.query.ruc}`);
});
app.get("/api/ruc-anexo", authMiddleware, creditosMiddleware(5), async (req, res) => {
    await consumirAPI(req, res, `https://poxy2-production-987f.up.railway.app/ruc-anexo?ruc=${req.query.ruc}`);
});
app.get("/api/ruc-representante", authMiddleware, creditosMiddleware(5), async (req, res) => {
    await consumirAPI(req, res, `https://poxy2-production-987f.up.railway.app/ruc-representante?ruc=${req.query.ruc}`);
});
app.get("/api/cee", authMiddleware, creditosMiddleware(5), async (req, res) => {
    await consumirAPI(req, res, `https://poxy2-production-987f.up.railway.app/cee?cee=${req.query.cee}`);
});
app.get("/api/soat-placa", authMiddleware, creditosMiddleware(5), async (req, res) => {
    await consumirAPI(req, res, `https://poxy2-production-987f.up.railway.app/placa?placa=${req.query.placa}`);
});
app.get("/api/licencia", authMiddleware, creditosMiddleware(5), async (req, res) => {
    await consumirAPI(req, res, `https://poxy2-production-987f.up.railway.app/licencia?dni=${req.query.dni}`);
});

// ---------------------------------------------------
app.get("/", (req, res) => {
    res.json({
        ok: true,
        mensaje: "🚀 API Consulta PE funcionando correctamente. (CORS habilitado)",
    });
});

// -------------------- SERVER --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
