import express from "express";
import admin from "firebase-admin";
import dotenv from "dotenv";
import axios from "axios";
import cors from "cors";
import url from "url"; // Importamos el módulo 'url'

dotenv.config();

const app = express();
app.use(express.json());

// 🟢 SOLUCIÓN AL ERROR DE CORS: Configuración de CORS más permisiva
const corsOptions = {
  // Permitir todos los orígenes
  origin: "*", 
  // Permitir los métodos comunes (incluyendo OPTIONS para preflight)
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE", 
  // Permitir encabezados necesarios para la autenticación
  allowedHeaders: ["Content-Type", "x-api-key", "x-admin-key"], 
  // Exponer los encabezados para que el frontend pueda leerlos
  exposedHeaders: ["x-api-key", "x-admin-key"],
  // Permitir credenciales (si fueran necesarias, aunque con origin: '*' no lo son estrictamente)
  credentials: true, 
};

app.use(cors(corsOptions)); // Aplicar la configuración de CORS
// ----------------------------------------------------


// --- CONSTANTES PARA LAS BASES DE DATOS ANTIGUAS/EXISTENTES ---
const NEW_API_V1_BASE_URL = "https://banckend-poxyv1-cosultape-masitaprex.fly.dev";
// ⭐ CLAVE: URL de la API de Generación de Ficha (IMAGEN) reemplazada por la nueva URL
const NEW_IMAGEN_V2_BASE_URL = "https://gdni-imagen-v2.fly.dev"; 
const NEW_PDF_V3_BASE_URL = "https://generar-pdf-v3.fly.dev";

// --- BASE URL PARA LAS NUEVAS APIS (Factiliza reemplazadas) ---
const NEW_FACTILIZA_BASE_URL = "https://web-production-75681.up.railway.app";
const NEW_BRANDING = "developer consulta pe"; // Marca a reemplazar

// --- URL PARA EL GUARDADO AUTOMÁTICO DEL LOG ---
const LOG_GUARDADO_BASE_URL = "https://base-datos-consulta-pe.fly.dev/guardar";

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
    // Usamos el módulo 'url' (o 'new URL' que está disponible en Node > 10)
    const parsedUrl = new url.URL(origin);
    return parsedUrl.host; 
  } catch (e) {
    // Si es un valor crudo o inválido, devuelve el valor original.
    return origin; 
  }
};


/**
 * Middleware para gestionar créditos y actualizar la última consulta y el dominio de origen.
 * ELIMINADA la lógica de guardado de logs en Firestore.
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

    // Almacena el dominio y el costo en el objeto req para usarlo en 'consumirAPI'
    req.logData = {
        domain: domain,
        cost: costo,
        endpoint: req.path,
    };
    
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

/**
 * NUEVA FUNCIÓN: Guarda el log en la API externa.
 * El 'tipo' de archivo de guardado será 'log_consulta'.
 * @param {object} logData - Datos del log (domain, endpoint, cost, userId, timestamp).
 */
const guardarLogExterno = async (logData) => {
    // Genera un timestamp legible para el guardado
    const horaConsulta = new Date(logData.timestamp).toISOString();
    
    // El 'tipo' se fija a 'log_consulta' para un archivo general de logs
    const url = `${LOG_GUARDADO_BASE_URL}/log_consulta?host=${encodeURIComponent(logData.domain)}&hora=${encodeURIComponent(horaConsulta)}&endpoint=${encodeURIComponent(logData.endpoint)}&userId=${encodeURIComponent(logData.userId)}&costo=${logData.cost}`;
    
    try {
        // Realiza la petición GET. No se necesita esperar el resultado para no bloquear la respuesta al usuario.
        // Se puede usar 'axios.get(url)' sin await para hacerlo en "fire and forget" o con await para registrar el error.
        await axios.get(url);
        // console.log("Log guardado exitosamente en API externa:", url);
    } catch (e) {
        console.error("Error al guardar log en API externa:", e.message);
        // El error de guardado de log no debe afectar la respuesta al usuario.
    }
};

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
        // Intercepta y elimina las propiedades "bot", "chat_id" y "bot_used"
        if (key === "bot_used" || key === "bot" || key === "chat_id") {
          continue; // Eliminar la clave
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

    // Si la respuesta es exitosa y tiene "dni" o "fields" vacíos, se asume que es una lista.
    if (processedResponse.status === "ok" && processedResponse.dni && Object.keys(processedResponse.fields || {}).length === 0) {
        // Dejamos la estructura plana (message, dni, fields, status, urls, consulta-pe)
        // con los campos solicitados eliminados y el "message" limpio.
    }
  }

  return processedResponse;
};


/**
 * Procesa la respuesta de la API externa para aplicar branding y limpiar campos.
 * @param {object} response - La respuesta de la API externa.
 * @param {object} user - Los datos del usuario.
 * @returns {object} - La respuesta procesada.
 */
const procesarRespuesta = (response, user) => {
  // 🔹 Intercepta y reemplaza la marca en toda la respuesta, y ELIMINA "bot", "chat_id" y "bot_used"
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
    
    // **NOTA**: Aquí mantenemos "Consulta PE" si el branding original iba dentro de 'data'
    processedResponse.data.userPlan = userPlan;
    processedResponse.data["powered-by"] = "Consulta PE"; 
  }

  // 🔹 Branding raíz SIEMPRE (Aquí aplicamos el cambio de nombre)
  processedResponse["consulta-pe"] = {
    // ⭐ CAMBIO SOLICITADO AQUÍ: Reemplazar por "Intermediario Consulta Pe v2"
    poweredBy: "Intermediario Consulta Pe v2",
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
 * Función genérica para consumir API, procesar la respuesta y AHORA GUARDAR EL LOG EXTERNO.
 * @param {object} req - Objeto de solicitud de Express.
 * @param {object} res - Objeto de respuesta de Express.
 * @param {string} url - URL de la API a consumir.
 * @param {function} [transformer] - Función opcional para aplicar una transformación adicional a la respuesta exitosa.
 */
const consumirAPI = async (req, res, url, transformer = procesarRespuesta) => {
  try {
    const response = await axios.get(url);
    const processedResponse = transformer(response.data, req.user);

    // 🟢 NUEVO: Llamar a la función de guardado de log externo solo si la consulta fue exitosa.
    if (response.status >= 200 && response.status < 300) {
        const logData = {
            userId: req.user.id,
            timestamp: new Date(),
            ...req.logData, // Incluye domain, endpoint, cost del creditosMiddleware
        };
        // Se ejecuta sin 'await' para que no bloquee la respuesta al usuario (fire and forget).
        guardarLogExterno(logData);
    }
    
    res.json(processedResponse);
  } catch (error) {
    console.error("Error al consumir API:", error.message);
    const errorResponse = {
      ok: false,
      error: "Error en API externa",
      details: error.response ? error.response.data : error.message,
    };
    
    // Procesar y enviar respuesta de error
    const processedErrorResponse = procesarRespuesta(errorResponse, req.user);
    res.status(error.response ? error.response.status : 500).json(processedErrorResponse);
  }
};

/**
 * Función específica para consumir APIs que devuelven ARCHIVOS (Imágenes/PDFs)
 * y que requieren la cabecera 'Content-Disposition' para forzar la descarga.
 * @param {object} req - Objeto de solicitud de Express.
 * @param {object} res - Objeto de respuesta de Express.
 * @param {string} url - URL de la API a consumir.
 * @param {string} defaultFileName - Nombre de archivo por defecto (ej. 'ficha.png').
 */
const consumirApiConDescarga = async (req, res, url, defaultFileName) => {
    try {
        // La consulta a la API de generación de imagen devuelve un JSON con la URL de descarga (FILE)
        const apiResponse = await axios.get(url);
        const processedResponse = procesarRespuesta(apiResponse.data, req.user);

        // 1. Verificar si la respuesta fue exitosa
        if (apiResponse.status >= 200 && apiResponse.status < 300) {
            
            // 2. Extraer la URL de la imagen/archivo
            const fileUrl = processedResponse.urls?.FILE;
            if (!fileUrl) {
                console.error("Error: URL de archivo no encontrada en la respuesta de la API externa.");
                throw new Error("Formato de respuesta de la API de archivo inválido.");
            }
            
            // 3. Obtener el nombre de archivo de la URL
            const urlParts = new URL(fileUrl);
            // El último segmento del path será el nombre del archivo (ej. d8d4105f076148.png)
            const fileName = urlParts.pathname.split('/').pop() || defaultFileName;
            
            // 4. Aplicar la cabecera de descarga al response final
            res.set({
                'Content-Disposition': `attachment; filename="${fileName}"`,
            });

            // 5. Llamar a la función de guardado de log externo (antes de enviar la respuesta)
            const logData = {
                userId: req.user.id,
                timestamp: new Date(),
                ...req.logData, 
            };
            guardarLogExterno(logData);

            // 6. Enviar la respuesta JSON con la URL para la descarga (el cliente se encargará)
            // Ya que la API externa devuelve un JSON con la URL, no reenviamos el buffer binario aquí.
            res.json(processedResponse);
            
        } else {
            // Si la API externa devolvió un error (ej. 404), procesar y enviar.
            const processedErrorResponse = procesarRespuesta(apiResponse.data, req.user);
            res.status(apiResponse.status).json(processedErrorResponse);
        }

    } catch (error) {
        console.error("Error al consumir API de descarga:", error.message);
        const errorResponse = {
            ok: false,
            error: "Error en API externa de descarga",
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

// ⭐ CLAVE: Endpoint /api/ficha con la nueva URL y el nuevo manejador de descarga
app.get("/api/ficha", authMiddleware, creditosMiddleware(30), async (req, res) => {
  // Nueva API: https://gdni-imagen-v2.fly.dev/generar-ficha?dni=${dni}
  await consumirApiConDescarga(req, res, `${NEW_IMAGEN_V2_BASE_URL}/generar-ficha?dni=${req.query.dni}`, 'ficha.png');
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
    // API de PDF, requiere descarga
    await consumirApiConDescarga(req, res, `${NEW_PDF_V3_BASE_URL}/generar-ficha-pdf?dni=${req.query.dni}`, 'ficha.pdf');
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
      // ⭐ CAMBIO SOLICITADO AQUÍ: Reemplazar por "Intermediario Consulta Pe v2"
      poweredBy: "Intermediario Consulta Pe v2",
      info: "API oficial con endpoints actualizados",
    },
  });
});


/* ============================
   ADMIN ENDPOINTS (Panel de Gestión de API) - SOLO USUARIOS
   *** LOS ENDPOINTS DE LOGS FUERON ELIMINADOS ***
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


// -------------------- SERVER --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
