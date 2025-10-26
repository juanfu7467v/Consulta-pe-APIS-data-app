import express from "express";
import admin from "firebase-admin";
import dotenv from "dotenv";
import axios from "axios";
import cors from "cors";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

// --- CONSTANTES PARA LAS BASES DE DATOS ANTIGUAS/EXISTENTES ---
const NEW_API_V1_BASE_URL = "https://banckend-poxyv1-cosultape-masitaprex.fly.dev";
const NEW_IMAGEN_V2_BASE_URL = "https://imagen-v2.fly.dev";
const NEW_PDF_V3_BASE_URL = "https://generar-pdf-v3.fly.dev";

// --- BASE URL PARA LAS NUEVAS APIS (Factiliza reemplazadas) ---
const NEW_FACTILIZA_BASE_URL = "https://web-production-75681.up.railway.app";
const NEW_BRANDING = "developer consulta pe"; // Marca a reemplazar

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

const replaceBranding = (data) => {
  if (typeof data === 'string') {
    // Reemplaza la marca en cadenas de texto
    return data.replace(/@LEDERDATA_OFC_BOT|@otra|\[FACTILIZA]/g, NEW_BRANDING);
  }
  if (Array.isArray(data)) {
    // Procesa cada elemento si es un array
    return data.map(item => replaceBranding(item));
  }
  if (typeof data === 'object' && data !== null) {
    // Procesa cada propiedad si es un objeto
    const newObject = {};
    for (const key in data) {
      if (Object.prototype.hasOwnProperty.call(data, key)) {
        // Intercepta y reemplaza el valor de "bot_used"
        if (key === "bot_used") {
          newObject[key] = NEW_BRANDING;
        } else {
          newObject[key] = replaceBranding(data[key]);
        }
      }
    }
    return newObject;
  }
  return data;
};


const procesarRespuesta = (response, user) => {
  // 🔹 Intercepta y reemplaza la marca en toda la respuesta
  let processedResponse = replaceBranding(response);

  // 🔹 Eliminar campos molestos
  delete processedResponse["developed-by"];
  delete processedResponse["credits"];

  // 🔹 Info del plan del usuario
  const userPlan = {
    tipo: user.tipoPlan,
    creditosRestantes: user.tipoPlan === "creditos" ? user.creditos : null,
  };

  // 🔹 Si hay un campo `data`, limpiamos y agregamos branding
  if (processedResponse.data) {
    delete processedResponse.data["developed-by"];
    delete processedResponse.data["credits"];

    processedResponse.data.userPlan = userPlan;
    processedResponse.data["powered-by"] = "Consulta PE";
  }

  // 🔹 Branding raíz SIEMPRE
  processedResponse["consulta-pe"] = {
    poweredBy: "Consulta PE",
    userPlan,
  };

  // 🔹 Limpiar mensajes de error molestos
  if (processedResponse.ok === false && processedResponse.details) {
    if (processedResponse.details.message?.includes("Token con falta de pago")) {
      processedResponse.details.message = "Error en la consulta, intenta nuevamente";
    }
    if (processedResponse.details.detalle?.message?.includes("Token con falta de pago")) {
      processedResponse.details.detalle.message = "Error en la consulta, intenta nuevamente";
    }
    delete processedResponse.details.detalle?.plan;
  }

  return processedResponse;
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


// -------------------- ENDPOINTS (Existentes) --------------------

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

// -------------------- ENDPOINTS (NUEVAS APIS - Reemplazo de Factiliza) --------------------

// 🔹 1. Búsqueda por DNI (8 dígitos)
app.get("/api/dni-full", authMiddleware, creditosMiddleware(4), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dni?dni=${req.query.dni}`);
});
app.get("/api/c4", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/c4?dni=${req.query.dni}`);
});
app.get("/api/dnivaz", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dnivaz?dni=${req.query.dni}`);
});
app.get("/api/dnivam", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dnivam?dni=${req.query.dni}`);
});
app.get("/api/dnivel", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dnivel?dni=${req.query.dni}`);
});
app.get("/api/dniveln", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dniveln?dni=${req.query.dni}`);
});
app.get("/api/fa", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/fa?dni=${req.query.dni}`);
});
app.get("/api/fb", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/fb?dni=${req.query.dni}`);
});
app.get("/api/cnv", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/cnv?dni=${req.query.dni}`);
});
app.get("/api/cdef", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/cdef?dni=${req.query.dni}`);
});
app.get("/api/actancc", authMiddleware, creditosMiddleware(65), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/actancc?dni=${req.query.dni}`);
});
app.get("/api/actamcc", authMiddleware, creditosMiddleware(65), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/actamcc?dni=${req.query.dni}`);
});
app.get("/api/actadcc", authMiddleware, creditosMiddleware(65), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/actadcc?dni=${req.query.dni}`);
});
app.get("/api/tra", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/tra?dni=${req.query.dni}`);
});
app.get("/api/sue", authMiddleware, creditosMiddleware(8), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/sue?dni=${req.query.dni}`);
});
app.get("/api/cla", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/cla?dni=${req.query.dni}`);
});
app.get("/api/sune", authMiddleware, creditosMiddleware(4), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/sune?dni=${req.query.dni}`);
});
app.get("/api/cun", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/cun?dni=${req.query.dni}`);
});
app.get("/api/colp", authMiddleware, creditosMiddleware(6), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/colp?dni=${req.query.dni}`);
});
app.get("/api/mine", authMiddleware, creditosMiddleware(4), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/mine?dni=${req.query.dni}`);
});
app.get("/api/afp", authMiddleware, creditosMiddleware(6), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/afp?dni=${req.query.dni}`);
});
app.get("/api/antpen", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/antpen?dni=${req.query.dni}`);
});
app.get("/api/antpol", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/antpol?dni=${req.query.dni}`);
});
app.get("/api/antjud", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/antjud?dni=${req.query.dni}`);
});
app.get("/api/antpenv", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/antpenv?dni=${req.query.dni}`);
});
app.get("/api/dend", authMiddleware, creditosMiddleware(26), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dend?dni=${req.query.dni}`);
});
app.get("/api/fis", authMiddleware, creditosMiddleware(32), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/fis?dni=${req.query.dni}`);
});
app.get("/api/fisdet", authMiddleware, creditosMiddleware(36), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/fisdet?dni=${req.query.dni}`);
});
app.get("/api/det", authMiddleware, creditosMiddleware(26), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/det?dni=${req.query.dni}`);
});
app.get("/api/rqh", authMiddleware, creditosMiddleware(8), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/rqh?dni=${req.query.dni}`);
});
app.get("/api/meta", authMiddleware, creditosMiddleware(26), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/meta?dni=${req.query.dni}`);
});

// 🔹 2. Consultas Generales (Query genérico)
app.get("/api/osiptel", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/osiptel?query=${req.query.query}`);
});
app.get("/api/claro", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/claro?query=${req.query.query}`);
});
app.get("/api/entel", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/entel?query=${req.query.query}`);
});
app.get("/api/pro", authMiddleware, creditosMiddleware(12), async (req, res) => {
  // Nota: No se especificó el costo para esta, se asume 12 créditos. Si no aplica se debe ajustar.
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/pro?query=${req.query.query}`);
});
app.get("/api/sen", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/sen?query=${req.query.query}`);
});
app.get("/api/sbs", authMiddleware, creditosMiddleware(12), async (req, res) => {
  // Nota: No se especificó el costo para esta, se asume 12 créditos. Si no aplica se debe ajustar.
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/sbs?query=${req.query.query}`);
});
app.get("/api/pasaporte", authMiddleware, creditosMiddleware(20), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/pasaporte?query=${req.query.query}`);
});
app.get("/api/seeker", authMiddleware, creditosMiddleware(28), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/seeker?query=${req.query.query}`);
});
app.get("/api/bdir", authMiddleware, creditosMiddleware(28), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/bdir?query=${req.query.query}`);
});

// 🔹 3. Denuncias Policiales por otros Documentos
app.get("/api/dence", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dence?carnet_extranjeria=${req.query.carnet_extranjeria}`);
});
app.get("/api/denpas", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/denpas?pasaporte=${req.query.pasaporte}`);
});
app.get("/api/denci", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/denci?cedula_identidad=${req.query.cedula_identidad}`);
});
app.get("/api/denp", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/denp?placa=${req.query.placa}`);
});
app.get("/api/denar", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/denar?serie_armamento=${req.query.serie_armamento}`);
});
app.get("/api/dencl", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dencl?clave_denuncia=${req.query.clave_denuncia}`);
});

// 🔹 4. Consultas Venezolanas
app.get("/api/cedula", authMiddleware, creditosMiddleware(4), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/cedula?cedula=${req.query.cedula}`);
});
app.get("/api/venezolanos_nombres", authMiddleware, creditosMiddleware(4), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/venezolanos_nombres?query=${req.query.query}`);
});

// 🔹 5. Consultas por Nombres (Peruanos)
app.get("/api/dni_nombres", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { nombres, apepaterno, apematerno } = req.query;
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dni_nombres?nombres=${nombres}&apepaterno=${apepaterno}&apematerno=${apematerno}`);
});


// ---------------------------------------------------
app.get("/", (req, res) => {
  res.json({
    ok: true,
    mensaje: "🚀 API Consulta PE funcionando correctamente. (CORS habilitado)",
    "consulta-pe": {
      poweredBy: "Consulta PE",
      info: "API oficial con endpoints actualizados",
    },
  });
});

// -------------------- SERVER --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
