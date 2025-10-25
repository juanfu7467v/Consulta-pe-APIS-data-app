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
// Función para limpiar la marca de la respuesta de forma recursiva.
const cleanResponseRecursively = (data) => {
    const MARCA_A_INTERCEPTAR = "@LEDERDATA_OFC_BOT";
    if (data === null || typeof data !== 'object') {
        if (typeof data === 'string' && data.includes(MARCA_A_INTERCEPTAR)) {
            return data.replace(new RegExp(MARCA_A_INTERCEPTAR, 'g'), "");
        }
        return data;
    }

    if (Array.isArray(data)) {
        return data.map(item => cleanResponseRecursively(item));
    }

    const cleanedData = {};
    for (const key in data) {
        if (Object.prototype.hasOwnProperty.call(data, key)) {
            if (key === "bot_used" && data[key] === MARCA_A_INTERCEPTAR) {
                // Interceptamos el campo bot_used si contiene la marca
                cleanedData[key] = "";
            } else {
                cleanedData[key] = cleanResponseRecursively(data[key]);
            }
        }
    }
    return cleanedData;
};


const procesarRespuesta = (response, user) => {
  // Limpieza profunda de la marca
  let cleanedResponse = cleanResponseRecursively(response);
  
  // 🔹 Eliminar campos molestos de Factiliza/Lederdata
  delete cleanedResponse["developed-by"];
  delete cleanedResponse["credits"];
  // El campo "bot_used" ya fue limpiado por cleanResponseRecursively si tenía la marca.

  // 🔹 Info del plan del usuario
  const userPlan = {
    tipo: user.tipoPlan,
    creditosRestantes: user.tipoPlan === "creditos" ? user.creditos : null,
  };

  // 🔹 Si hay un campo `data`, limpiamos y agregamos branding
  if (cleanedResponse.data) {
    delete cleanedResponse.data["developed-by"];
    delete cleanedResponse.data["credits"];

    cleanedResponse.data.userPlan = userPlan;
    cleanedResponse.data["powered-by"] = "Consulta PE";
  }

  // 🔹 Branding raíz SIEMPRE
  cleanedResponse["consulta-pe"] = {
    poweredBy: "Consulta PE",
    userPlan,
  };

  // 🔹 Limpiar mensajes de error molestos
  if (cleanedResponse.ok === false && cleanedResponse.details) {
    if (cleanedResponse.details.message?.includes("Token con falta de pago")) {
      cleanedResponse.details.message = "Error en la consulta, intenta nuevamente";
    }
    if (cleanedResponse.details.detalle?.message?.includes("Token con falta de pago")) {
      cleanedResponse.details.detalle.message = "Error en la consulta, intenta nuevamente";
    }
    delete cleanedResponse.details.detalle?.plan;
  }

  return cleanedResponse;
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

// -------------------- ENDPOINTS (Nuevas APIs RailWay) --------------------

const NEW_BASE_URL = "https://web-production-75681.up.railway.app";


// 🔹 1. Búsqueda por DNI (8 dígitos)
app.get("/dni", authMiddleware, creditosMiddleware(4), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/dni?dni=${req.query.dni}`);
});
app.get("/c4", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/c4?dni=${req.query.dni}`);
});
app.get("/dnivaz", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/dnivaz?dni=${req.query.dni}`);
});
app.get("/dnivam", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/dnivam?dni=${req.query.dni}`);
});
app.get("/dnivel", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/dnivel?dni=${req.query.dni}`);
});
app.get("/dniveln", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/dniveln?dni=${req.query.dni}`);
});
app.get("/fa", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/fa?dni=${req.query.dni}`);
});
app.get("/fb", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/fb?dni=${req.query.dni}`);
});
app.get("/cnv", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/cnv?dni=${req.query.dni}`);
});
app.get("/cdef", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/cdef?dni=${req.query.dni}`);
});
app.get("/actancc", authMiddleware, creditosMiddleware(65), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/actancc?dni=${req.query.dni}`);
});
app.get("/actamcc", authMiddleware, creditosMiddleware(65), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/actamcc?dni=${req.query.dni}`);
});
app.get("/actadcc", authMiddleware, creditosMiddleware(65), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/actadcc?dni=${req.query.dni}`);
});
app.get("/tra", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/tra?dni=${req.query.dni}`);
});
app.get("/sue", authMiddleware, creditosMiddleware(8), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/sue?dni=${req.query.dni}`);
});
app.get("/cla", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/cla?dni=${req.query.dni}`);
});
app.get("/sune", authMiddleware, creditosMiddleware(4), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/sune?dni=${req.query.dni}`);
});
app.get("/cun", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/cun?dni=${req.query.dni}`);
});
app.get("/colp", authMiddleware, creditosMiddleware(6), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/colp?dni=${req.query.dni}`);
});
app.get("/mine", authMiddleware, creditosMiddleware(4), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/mine?dni=${req.query.dni}`);
});
app.get("/afp", authMiddleware, creditosMiddleware(6), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/afp?dni=${req.query.dni}`);
});
app.get("/antpen", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/antpen?dni=${req.query.dni}`);
});
app.get("/antpol", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/antpol?dni=${req.query.dni}`);
});
app.get("/antjud", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/antjud?dni=${req.query.dni}`);
});
app.get("/antpenv", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/antpenv?dni=${req.query.dni}`);
});
app.get("/dend", authMiddleware, creditosMiddleware(26), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/dend?dni=${req.query.dni}`);
});
app.get("/fis", authMiddleware, creditosMiddleware(32), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/fis?dni=${req.query.dni}`);
});
app.get("/fisdet", authMiddleware, creditosMiddleware(36), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/fisdet?dni=${req.query.dni}`);
});
app.get("/det", authMiddleware, creditosMiddleware(26), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/det?dni=${req.query.dni}`);
});
app.get("/rqh", authMiddleware, creditosMiddleware(8), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/rqh?dni=${req.query.dni}`);
});
app.get("/meta", authMiddleware, creditosMiddleware(26), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/meta?dni=${req.query.dni}`);
});

// 🔹 2. Consultas Generales (Query genérico)
app.get("/osiptel", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/osiptel?query=${req.query.query}`);
});
app.get("/claro", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/claro?query=${req.query.query}`);
});
app.get("/entel", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/entel?query=${req.query.query}`);
});
// Propiedades SUNARP y SBS no tienen costo de crédito especificado, se usa 5 por defecto (ejemplo)
app.get("/pro", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/pro?query=${req.query.query}`);
});
app.get("/sen", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/sen?query=${req.query.query}`);
});
app.get("/sbs", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/sbs?query=${req.query.query}`);
});
app.get("/pasaporte", authMiddleware, creditosMiddleware(20), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/pasaporte?query=${req.query.query}`);
});
app.get("/seeker", authMiddleware, creditosMiddleware(28), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/seeker?query=${req.query.query}`);
});
app.get("/bdir", authMiddleware, creditosMiddleware(28), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/bdir?query=${req.query.query}`);
});


// 🔹 3. Denuncias Policiales por otros Documentos
app.get("/dence", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/dence?carnet_extranjeria=${req.query.carnet_extranjeria}`);
});
app.get("/denpas", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/denpas?pasaporte=${req.query.pasaporte}`);
});
app.get("/denci", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/denci?cedula_identidad=${req.query.cedula_identidad}`);
});
app.get("/denp", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/denp?placa=${req.query.placa}`);
});
app.get("/denar", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/denar?serie_armamento=${req.query.serie_armamento}`);
});
app.get("/dencl", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/dencl?clave_denuncia=${req.query.clave_denuncia}`);
});


// 🔹 4. Consultas Venezolanas
app.get("/cedula", authMiddleware, creditosMiddleware(4), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/cedula?cedula=${req.query.cedula}`);
});
app.get("/venezolanos_nombres", authMiddleware, creditosMiddleware(4), async (req, res) => {
  await consumirAPI(req, res, `${NEW_BASE_URL}/venezolanos_nombres?query=${req.query.query}`);
});

// 🔹 5. Consultas por Nombres (Peruanos)
app.get("/dni_nombres", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { nombres, apepaterno, apematerno } = req.query;
  await consumirAPI(req, res, `${NEW_BASE_URL}/dni_nombres?nombres=${nombres}&apepaterno=${apepaterno}&apematerno=${apematerno}`);
});

// -------------------- ENDPOINTS (APIs Antiguas de Ejemplo - No Tocar) --------------------
// Nota: Se han eliminado los endpoints antiguos que se habían creado previamente
// con las URL's NEW_API_V1_BASE_URL, NEW_IMAGEN_V2_BASE_URL, y NEW_PDF_V3_BASE_URL
// para dar prioridad a los 44 endpoints de RailWay solicitados.

app.get("/api/dni", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto, use /dni" }));
app.get("/api/ruc", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/ruc-anexo", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/ruc-representante", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/cee", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/soat-placa", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/licencia", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/ficha", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/reniec", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/denuncias-dni", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/denuncias-placa", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/sueldos", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/trabajos", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/sunat", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/sunat-razon", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/consumos", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/arbol", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/familia1", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/familia2", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/familia3", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/movimientos", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/matrimonios", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/empresas", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/direcciones", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/correos", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/telefonia-doc", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/telefonia-num", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/vehiculos", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/fiscalia-dni", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/fiscalia-nombres", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));
app.get("/api/info-total", (req, res) => res.status(404).json({ ok: false, error: "Endpoint obsoleto" }));


// ---------------------------------------------------
app.get("/", (req, res) => {
  res.json({
    ok: true,
    mensaje: "🚀 API Consulta PE funcionando correctamente. (CORS habilitado)",
    "consulta-pe": {
      poweredBy: "Consulta PE",
      info: "API oficial con 44 endpoints activos",
    },
  });
});

// -------------------- SERVER --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
