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
  // 🔹 Eliminar campos molestos de Lederdata
  delete response["developed-by"];
  delete response["credits"];

  // 🔹 Info del plan del usuario
  const userPlan = {
    tipo: user.tipoPlan,
    creditosRestantes: user.tipoPlan === "creditos" ? user.creditos : null,
  };

  // 🔹 Si hay un campo `data`, limpiamos y agregamos branding
  if (response.data) {
    delete response.data["developed-by"];
    delete response.data["credits"];

    response.data.userPlan = userPlan;
    response.data["powered-by"] = "Consulta PE";
  }

  // 🔹 Branding raíz SIEMPRE
  response["consulta-pe"] = {
    poweredBy: "Consulta PE",
    userPlan,
  };

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

// -------------------- ENDPOINTS (Actualizados con las nuevas URLs) --------------------

const NEW_API_V1_BASE_URL = "https://banckend-poxyv1-cosultape-masitaprex.fly.dev";
const NEW_IMAGEN_V2_BASE_URL = "https://imagen-v2.fly.dev";
const NEW_PDF_V3_BASE_URL = "https://generar-pdf-v3.fly.dev";


app.get("/api/dni", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/dni?dni=${req.query.dni}`);
});
app.get("/api/ruc", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/ruc?ruc=${req.query.ruc}`);
});
app.get("/api/ruc-anexo", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/ruc-anexo?ruc=${req.query.ruc}`);
});
app.get("/api/ruc-representante", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/ruc-representante?ruc=${req.query.ruc}`);
});
app.get("/api/cee", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/cee?cee=${req.query.cee}`);
});
app.get("/api/soat-placa", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/placa?placa=${req.query.placa}`);
});
app.get("/api/licencia", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/licencia?dni=${req.query.dni}`);
});


app.get("/api/ficha", authMiddleware, creditosMiddleware(30), async (req, res) => {
  await consumirAPI(req, res, `${NEW_IMAGEN_V2_BASE_URL}/generar-ficha?dni=${req.query.dni}`);
});
app.get("/api/reniec", authMiddleware, creditosMiddleware(10), async (req, res) => {
  const { dni } = req.query;
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/reniec?dni=${dni}`);
});
app.get("/api/denuncias-dni", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/denuncias-dni?dni=${req.query.dni}`);
});
app.get("/api/denuncias-placa", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/denuncias-placa?placa=${req.query.placa}`);
});
app.get("/api/sueldos", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/sueldos?dni=${req.query.dni}`);
});
app.get("/api/trabajos", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/trabajos?dni=${req.query.dni}`);
});
app.get("/api/sunat", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/sunat?data=${req.query.data}`);
});
app.get("/api/sunat-razon", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/sunat-razon?data=${req.query.data}`);
});
app.get("/api/consumos", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/consumos?dni=${req.query.dni}`);
});
app.get("/api/arbol", authMiddleware, creditosMiddleware(18), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/arbol?dni=${req.query.dni}`);
});
app.get("/api/familia1", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/familia1?dni=${req.query.dni}`);
});
app.get("/api/familia2", authMiddleware, creditosMiddleware(15), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/familia2?dni=${req.query.dni}`);
});
app.get("/api/familia3", authMiddleware, creditosMiddleware(18), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/familia3?dni=${req.query.dni}`);
});
app.get("/api/movimientos", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/movimientos?dni=${req.query.dni}`);
});
app.get("/api/matrimonios", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/matrimonios?dni=${req.query.dni}`);
});
app.get("/api/empresas", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/empresas?dni=${req.query.dni}`);
});
app.get("/api/direcciones", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/direcciones?dni=${req.query.dni}`);
});
app.get("/api/correos", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/correos?dni=${req.query.dni}`);
});
app.get("/api/telefonia-doc", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/telefonia-doc?documento=${req.query.documento}`);
});
app.get("/api/telefonia-num", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/telefonia-num?numero=${req.query.numero}`);
});
app.get("/api/vehiculos", authMiddleware, creditosMiddleware(15), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/vehiculos?placa=${req.query.placa}`);
});
app.get("/api/fiscalia-dni", authMiddleware, creditosMiddleware(15), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/fiscalia-dni?dni=${req.query.dni}`);
});
app.get("/api/fiscalia-nombres", authMiddleware, creditosMiddleware(18), async (req, res) => {
  const { nombres, apepaterno, apematerno } = req.query;
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/fiscalia-nombres?nombres=${nombres}&apepaterno=${apepaterno}&apematerno=${apematerno}`);
});
app.get("/api/info-total", authMiddleware, creditosMiddleware(50), async (req, res) => {
    await consumirAPI(req, res, `${NEW_PDF_V3_BASE_URL}/generar-ficha-pdf?dni=${req.query.dni}`);
});


// ---------------------------------------------------
app.get("/", (req, res) => {
  res.json({
    ok: true,
    mensaje: "🚀 API Consulta PE funcionando correctamente. (CORS habilitado)",
    "consulta-pe": {
      poweredBy: "Consulta PE",
      info: "API oficial con 30 endpoints v2 activos",
    },
  });
});

// -------------------- SERVER --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
