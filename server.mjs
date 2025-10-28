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

// --- CLAVE SECRETA DE ADMINISTRADOR (SOLO DESDE VARIABLES DE ENTORNO) ---
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;

// 🛑 VERIFICACIÓN CRÍTICA: Si la clave ADMIN no está definida, salimos.
if (!ADMIN_API_KEY) {
  console.error("FATAL ERROR: ADMIN_API_KEY no está definida en el entorno. Acceso al panel deshabilitado.");
  // En un entorno real como Fly.io, puedes elegir lanzar un error o terminar el proceso.
  // process.exit(1);
}


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

// -------------------- MIDDLEWARE (Existentes y Nuevos) --------------------

/**
 * Middleware para validar el token de API del usuario.
 * @param {object} req - Objeto de solicitud de Express.
 * @param {object} res - Objeto de respuesta de Express.
 * @param {function} next - Función para pasar al siguiente middleware.
 */
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

/**
 * NUEVA FUNCIÓN: Extrae el dominio de origen de la petición.
 * @param {object} req - Objeto de solicitud de Express.
 * @returns {string} El host del dominio o "Unknown/Direct Access".
 */
const getOriginDomain = (req) => {
  const origin = req.headers.origin || req.headers.referer;
  if (!origin) return "Unknown/Direct Access";

  try {
    // Si se puede parsear como URL (ej. "https://example.com/page"), extrae el host.
    const url = new URL(origin);
    return url.host; 
  } catch (e) {
    // Si es un valor crudo o inválido, devuelve el valor original.
    return origin; 
  }
};


/**
 * Middleware para gestionar créditos, actualizar la última consulta,
 * el dominio de origen y crear un registro de log detallado.
 * @param {number} costo - Costo en créditos de la consulta.
 */
const creditosMiddleware = (costo) => {
  return async (req, res, next) => {
    const domain = getOriginDomain(req);
    const userRef = db.collection("usuarios").doc(req.user.id);
    const currentTime = new Date();

    // 1. Lógica de deducción de créditos y actualización de usuario
    if (req.user.tipoPlan === "creditos") {
      if (req.user.creditos < costo) {
        return res.status(402).json({
          ok: false,
          error: "Créditos insuficientes, recarga tu plan",
        });
      }
      // Deduce créditos y actualiza la última consulta y el dominio de uso
      await userRef.update({
        creditos: admin.firestore.FieldValue.increment(-costo),
        ultimaConsulta: currentTime, 
        ultimoDominio: domain,        
      });
      req.user.creditos -= costo;
    } else if (req.user.tipoPlan === "ilimitado") {
        // Solo actualiza la última consulta y el dominio para planes ilimitados
        await userRef.update({
            ultimaConsulta: currentTime,
            ultimoDominio: domain,
        });
    }

    // 2. NUEVO: Crea una entrada de log detallada en la colección 'api_logs'
    const logData = {
        userId: req.user.id,
        endpoint: req.path,
        timestamp: currentTime,
        domain: domain,
        success: false, // Por defecto es false, se actualiza a true al finalizar la consulta exitosamente
        cost: costo,
        queryParams: req.query,
    };
    
    // Almacena el log y guarda la referencia en el objeto de solicitud para actualizarlo más tarde
    try {
        const logRef = await db.collection("api_logs").add(logData);
        req.logRef = logRef; // La referencia al documento de log
    } catch (e) {
        console.error("Error al crear el log inicial en Firestore:", e.message);
        // Continuar de todos modos, el error de log no debe detener la API
    }
    
    next();
  };
};

/**
 * NUEVO MIDDLEWARE: Protege los endpoints de administración con la clave secreta.
 * Usará la clave de ADMIN_API_KEY que viene del entorno.
 * @param {object} req - Objeto de solicitud de Express.
 * @param {object} res - Objeto de respuesta de Express.
 * @param {function} next - Función para pasar al siguiente middleware.
 */
const adminAuthMiddleware = (req, res, next) => {
    // Si ADMIN_API_KEY no se cargó (por el chequeo al inicio), deshabilitamos el acceso
    if (!ADMIN_API_KEY) {
         return res.status(503).json({ ok: false, error: "Servicio de administración no disponible: Clave de entorno no cargada." });
    }
    
    const adminKey = req.headers["x-admin-key"];
    if (adminKey === ADMIN_API_KEY) {
        next();
    } else {
        // Este es el mensaje de error que recibías
        res.status(401).json({ ok: false, error: "Clave de administrador Inválida. Acceso no autorizado." });
    }
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
        // Intercepta y elimina la propiedad "bot_used"
        if (key === "bot_used") {
          continue; // Eliminar la clave "bot_used"
        } else {
          newObject[key] = replaceBranding(data[key]);
        }
      }
    }
    return newObject;
  }
  return data;
};

/**
 * Transforma la respuesta de búsquedas por nombre/texto a un formato tipo "result" en la raiz.
 * Aplica para endpoints como /api/dni_nombres
 * @param {object} response - La respuesta original de la API externa.
 * @param {object} user - Los datos del usuario actual (para el plan).
 * @returns {object} - La respuesta transformada.
 */
const transformarRespuestaBusqueda = (response, user) => {
  let processedResponse = procesarRespuesta(response, user);

  // Reestructuración específica para el formato solicitado (lista de resultados)
  if (processedResponse.message && typeof processedResponse.message === 'string') {
    // 1. Eliminar el texto molesto de la foto
    processedResponse.message = processedResponse.message.replace(/\s*↞ Puedes visualizar la foto de una coincidencia antes de usar \/dni ↠\s*/, '').trim();

    // 2. Si el mensaje es una lista de resultados, se podría considerar mover
    // todo el contenido de la respuesta (excepto "consulta-pe" y "message")
    // al campo "result", o simplemente dejar la estructura plana pero limpia.

    // Para este caso, solo se limpia el mensaje y se deja la estructura plana
    // ya que no hay una forma obvia de parsear el "message" a un array "result"
    // sin un parser robusto, y la solicitud pide mantener el funcionamiento actual
    // excepto por las eliminaciones/cambios.
  }

  // Si la respuesta es exitosa y tiene "dni" o "fields" vacíos, se asume que es una lista.
  if (processedResponse.status === "ok" && processedResponse.dni && Object.keys(processedResponse.fields || {}).length === 0) {
      // Dejamos la estructura plana (message, dni, fields, status, urls, consulta-pe)
      // pero con el "bot_used" eliminado y el "message" limpio.
      // Si el formato final de la solicitud { "message": "found data", "result": {...} }
      // fuera necesario para la búsqueda por nombres, se requeriría un parser robusto.
      // Asumiendo que para búsquedas que devuelven el 'message' largo, se permite el formato original (limpio).
      return processedResponse;
  }

  // Si es una respuesta de RUC/DNI único con info en 'result', aplicará la lógica original
  // y solo se requiere que 'message' sea "found data" y el contenido esté en 'result'.
  // Dado que el ejemplo de salida es para RUC, asumimos que este cambio es **opcional**
  // para la búsqueda por nombres, y sólo se requiere el **limpieza** para ese endpoint.
  // Mantendremos la estructura original de la API de lista, solo limpiando.

  return processedResponse;
};


/**
 * Procesa la respuesta de la API externa para aplicar branding y limpiar campos.
 * @param {object} response - La respuesta de la API externa.
 * @param {object} user - Los datos del usuario.
 * @returns {object} - La respuesta procesada.
 */
const procesarRespuesta = (response, user) => {
  // 🔹 Intercepta y reemplaza la marca en toda la respuesta, y ELIMINA "bot_used"
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


/**
 * Función genérica para consumir API, procesar la respuesta y actualizar el log.
 * @param {object} req - Objeto de solicitud de Express.
 * @param {object} res - Objeto de respuesta de Express.
 * @param {string} url - URL de la API a consumir.
 * @param {function} [transformer] - Función opcional para aplicar una transformación adicional a la respuesta exitosa.
 */
const consumirAPI = async (req, res, url, transformer = procesarRespuesta) => {
  try {
    const response = await axios.get(url);
    const processedResponse = transformer(response.data, req.user);

    // NUEVO: Marcar log como exitoso
    if (req.logRef) {
        await req.logRef.update({ 
            success: true, 
            responseStatus: response.status || 200 
        });
    }
    
    res.json(processedResponse);
  } catch (error) {
    console.error("Error al consumir API:", error.message);
    const errorResponse = {
      ok: false,
      error: "Error en API externa",
      details: error.response ? error.response.data : error.message,
    };
    
    // NUEVO: Marcar log como fallido (si existe la referencia)
    if (req.logRef) {
        await req.logRef.update({ 
            success: false, 
            responseStatus: error.response ? error.response.status : 500,
            errorMessage: error.message 
        });
    }

    // Procesar y enviar respuesta de error
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
  // Se aplica el transformer de búsqueda por lista.
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/fiscalia-nombres?nombres=${nombres}&apepaterno=${apepaterno}&apematerno=${apematerno}`, transformarRespuestaBusqueda);
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
// Endpoint que devuelve la lista y necesita la transformación.
app.get("/api/venezolanos_nombres", authMiddleware, creditosMiddleware(4), async (req, res) => {
  // Aplicar la función de transformación específica para respuestas de búsqueda por lista
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/venezolanos_nombres?query=${req.query.query}`, transformarRespuestaBusqueda);
});

// 🔹 5. Consultas por Nombres (Peruanos)
// Endpoint que devuelve la lista y necesita la transformación.
app.get("/api/dni_nombres", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { nombres, apepaterno, apematerno } = req.query;
  // Aplicar la función de transformación específica para respuestas de búsqueda por lista
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dni_nombres?nombres=${nombres}&apepaterno=${apepaterno}&apematerno=${apematerno}`, transformarRespuestaBusqueda);
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


/* ============================
   NUEVOS ADMIN ENDPOINTS (Panel de Gestión de API)
============================ */

/**
 * Endpoint para obtener el listado de todos los usuarios
 * con información clave para el panel (plan, créditos, última conexión, dominio).
 * Requiere la clave de administrador en el header 'x-admin-key'.
 */
app.get("/admin/users", adminAuthMiddleware, async (req, res) => {
    try {
        const usersRef = db.collection("usuarios");
        const snapshot = await usersRef.get();
        const users = snapshot.docs.map(doc => {
            const data = doc.data();
            return {
                userId: doc.id,
                email: data.email || 'N/A',
                tipoPlan: data.tipoPlan,
                creditos: data.creditos || 0,
                ultimaConsulta: data.ultimaConsulta ? data.ultimaConsulta.toDate().toISOString() : 'Nunca',
                ultimoDominio: data.ultimoDominio || 'Desconocido',
                fechaCreacion: data.fechaCreacion ? data.fechaCreacion.toDate().toISOString() : 'N/A',
            };
        });
        // Ordenar por última consulta (más reciente primero)
        users.sort((a, b) => new Date(b.ultimaConsulta) - new Date(a.ultimaConsulta));

        res.json({ ok: true, users });
    } catch (error) {
        console.error("Error al obtener usuarios:", error);
        res.status(500).json({ ok: false, error: "Error interno al obtener usuarios" });
    }
});

/**
 * Endpoint para obtener el historial de uso detallado (logs) de un usuario específico.
 * Muestra el endpoint, el dominio, el costo y el estado de éxito.
 * Requiere la clave de administrador.
 */
app.get("/admin/user/:userId/usage", adminAuthMiddleware, async (req, res) => {
    try {
        const { userId } = req.params;
        const limit = parseInt(req.query.limit) || 50; // Limita a las últimas 50 consultas por defecto

        const logsRef = db.collection("api_logs")
            .where("userId", "==", userId)
            .orderBy("timestamp", "desc")
            .limit(limit);

        const snapshot = await logsRef.get();
        const usage = snapshot.docs.map(doc => {
            const data = doc.data();
            return {
                logId: doc.id,
                endpoint: data.endpoint,
                timestamp: data.timestamp.toDate().toISOString(),
                domain: data.domain,
                cost: data.cost,
                success: data.success,
                status: data.responseStatus || 'N/A',
                query: data.queryParams,
            };
        });

        res.json({ ok: true, userId, usage });
    } catch (error) {
        console.error(`Error al obtener uso para usuario ${req.params.userId}:`, error);
        res.status(500).json({ ok: false, error: "Error interno al obtener el uso" });
    }
});

/**
 * Endpoint para obtener un listado de dominios únicos desde donde ha consultado
 * un usuario específico (para auditoría de origen).
 * Requiere la clave de administrador.
 */
app.get("/admin/user/:userId/domains", adminAuthMiddleware, async (req, res) => {
    try {
        const { userId } = req.params;

        // Recuperar un número considerable de logs para determinar los dominios recientes
        const logsRef = db.collection("api_logs")
            .where("userId", "==", userId)
            .orderBy("timestamp", "desc")
            .limit(500); // Se limita a las últimas 500 peticiones para eficiencia

        const snapshot = await logsRef.get();
        const domainsMap = new Map();

        snapshot.docs.forEach(doc => {
            const data = doc.data();
            if (data.domain) {
                const domain = data.domain;
                if (!domainsMap.has(domain)) {
                    domainsMap.set(domain, { 
                        domain: domain, 
                        // El firstSeen real sería la última aparición en esta consulta descendente
                        lastSeen: data.timestamp.toDate().toISOString(),
                        count: 1
                    });
                } else {
                    const existing = domainsMap.get(domain);
                    existing.count++;
                }
            }
        });
        
        // Convertir el mapa a array y ordenar por la última vez que se vio
        const uniqueDomains = Array.from(domainsMap.values()).sort((a, b) => {
             return new Date(b.lastSeen) - new Date(a.lastSeen);
        });

        res.json({ ok: true, userId, uniqueDomains });
    } catch (error) {
        console.error(`Error al obtener dominios para usuario ${req.params.userId}:`, error);
        res.status(500).json({ ok: false, error: "Error interno al obtener dominios" });
    }
});


// -------------------- SERVER --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
