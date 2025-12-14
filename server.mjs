import express from "express";
import admin from "firebase-admin";
import dotenv from "dotenv";
import axios from "axios";
import cors from "cors";
import url from "url";

dotenv.config();

const app = express();
// Habilitar el parsing de JSON en el cuerpo de las peticiones POST/PUT/PATCH
app.use(express.json());
// Habilitar el parsing de datos de formulario (URL-encoded) para POST,
// asegurando que los parámetros de formulario también sean accesibles.
app.use(express.urlencoded({ extended: true }));


// --- CONSTANTE PARA EL CICLO DE CRÉDITOS ---
const CREDIT_CYCLE = [5, 6, 7, 8]; // Los valores de descuento deseados

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

// -------------------- HELPER DE PARÁMETROS --------------------

/**
 * 💡 NUEVA FUNCIÓN: Unifica la obtención de parámetros para GET y POST.
 * Para GET, usa req.query. Para POST, usa req.body.
 * @param {object} req - Objeto de solicitud de Express.
 * @returns {object} Un objeto con los parámetros de la consulta (query o body).
 */
const getQueryParams = (req) => {
    // Si la petición es GET, se usan los parámetros de la URL (query).
    // Si la petición es POST, se usa el cuerpo (body) que debe ser JSON.
    return req.method === 'GET' ? req.query : req.body;
};

// -------------------- MIDDLEWARE (Existentes y Nuevos) --------------------

/**
 * Middleware para validar el token de API del usuario.
 * @param {object} req - Objeto de solicitud de Express.
 * @param {object} res - Objeto de respuesta de Express.
 * @param {function} next - Función para pasar al siguiente middleware.
 */
const authMiddleware = async (req, res, next) => {
  // Manejar el preflight de CORS (OPTIONS), permitiendo que pase sin autenticación.
  if (req.method === 'OPTIONS') {
    return next();
  }
  
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
    
    // --- Validar plan ---
    const validPlans = ["creditos", "ilimitado"];
    
    // ⭐ CORRECCIÓN CLAVE: Bloquear si el tipo de plan es "gratis" o inválido.
    // Esto asegura que solo los planes que deberían consumir créditos/tiempo pasen.
    if (!validPlans.includes(userData.tipoPlan)) {
         return res.status(403).json({ 
            ok: false, 
            error: "Tu plan no es válido o está deshabilitado. Recarga o contacta a soporte.",
        });
    }

    // --- Validar plan de créditos ---
    if (userData.tipoPlan === "creditos") {
      // Nota: La validación de crédito insuficiente se hace en creditosMiddleware o creditosFichaMiddleware
      // Usamos el operador nullish coalescing para tratar 'null' o 'undefined' como 0.
      if ((userData.creditos ?? 0) <= 0) {
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
    // Usamos el módulo 'url'
    const parsedUrl = new url.URL(origin);
    return parsedUrl.host;
  } catch (e) {
    // Si es un valor crudo o inválido, devuelve el valor original.
    return origin;
  }
};


/**
 * ⭐ CAMBIO CLAVE: Middleware para validar créditos. Ya NO DEDUCE CRÉDITOS, solo valida.
 * @param {number} costo - Costo en créditos de la consulta.
 */
const creditosMiddleware = (costo) => {
  return async (req, res, next) => {
    // Manejar el preflight de CORS (OPTIONS)
    if (req.method === 'OPTIONS') {
      return next();
    }
    
    const domain = getOriginDomain(req);
    
    // 1. Lógica de validación de créditos
    if (req.user.tipoPlan === "creditos") {
      
      // Obtener el saldo actual
      // Se utiliza el saldo de req.user, el cual fue validado en authMiddleware para ser > 0.
      const currentCredits = req.user.creditos ?? 0;
      
      if (currentCredits < costo) {
        return res.status(402).json({
          ok: false,
          error: `Créditos insuficientes (Se requerían ${costo} créditos). Saldo actual: ${currentCredits}`,
        });
      }
    }

    // Almacena el dominio y el costo en el objeto req para usarlo en 'consumirAPI'
    req.logData = {
        domain: domain,
        cost: req.user.tipoPlan === "creditos" ? costo : 0, // Costo real o 0 para ilimitado
        endpoint: req.path,
    };
    
    // Pasa al siguiente middleware o endpoint
    next();
  };
};

/**
 * ⭐ CAMBIO CLAVE: Middleware para validar créditos de Ficha. Ya NO DEDUCE CRÉDITOS, solo valida.
 */
const creditosFichaMiddleware = async (req, res, next) => {
    // Manejar el preflight de CORS (OPTIONS)
    if (req.method === 'OPTIONS') {
      return next();
    }
  
    const domain = getOriginDomain(req);
    const cycleRef = db.collection("metadata").doc("creditCycle");
    
    if (req.user.tipoPlan === "creditos") {
        let cost = 0; // Inicializar costo

        try {
            // Utilizamos una transacción para asegurar la consistencia al leer el contador
            await db.runTransaction(async (t) => {
                const cycleDoc = await t.get(cycleRef);
                
                // Leemos el saldo actual que ya sabemos que es > 0 por authMiddleware
                const currentCredits = req.user.creditos ?? 0;
                
                let currentIndex = cycleDoc.exists ? cycleDoc.data().currentIndex || 0 : 0;
                
                // 1. Determinar el costo actual 
                cost = CREDIT_CYCLE[currentIndex % CREDIT_CYCLE.length];
                
                // 2. Validar créditos con el saldo fresco
                if (currentCredits < cost) {
                    // Lanzamos un error específico para manejarlo fuera del runTransaction
                    throw new Error("Créditos insuficientes"); 
                }

                // ⭐ IMPORTANTE: El ciclo Index y la deducción se MUEVEN a `deducirCreditosFichaFirebase`

            });
            
            // Si la transacción fue exitosa:
            // Almacena el dominio y el costo en el objeto req para usarlo en 'consumirAPI'
            req.logData = {
                domain: domain,
                cost: cost,
                endpoint: req.path,
            };

        } catch (e) {
            if (e.message === "Créditos insuficientes") {
                // El costo debe reflejar el que se intentó usar para el mensaje de error.
                return res.status(402).json({
                    ok: false,
                    error: `Créditos insuficientes (Se requerían ${cost} créditos)`,
                });
            }
            // Otros errores de transacción (e.g., commit failed)
            console.error("Error en validación de Ficha:", e);
            return res.status(500).json({ ok: false, error: "Error interno al validar créditos para ficha" });
        }

    } else if (req.user.tipoPlan === "ilimitado") {
        // Para fines de log, establece un costo de 0
        req.logData = {
            domain: domain,
            cost: 0,
            endpoint: req.path,
        };
    }

    // Pasa al siguiente middleware o endpoint
    next();
};


// -------------------- HELPER API --------------------

/**
 * 🟢 NUEVO: Función para deducir créditos en Firebase después de una consulta exitosa.
 * Se encarga de la lógica atómica de deducción y la actualización del usuario.
 * @param {object} req - Objeto de solicitud de Express.
 * @param {number} costo - Costo a deducir.
 */
const deducirCreditosFirebase = async (req, costo) => {
    const userRef = db.collection("usuarios").doc(req.user.id);
    const currentTime = new Date();
    const domain = req.logData.domain;

    if (req.user.tipoPlan === "creditos" && costo > 0) {
        
        // ⭐ CAMBIO CLAVE: Usar una transacción para el descuento atómico.
        // Esto es CRÍTICO para evitar que dos consultas paralelas gasten el mismo crédito.
        try {
            await db.runTransaction(async (t) => {
                const freshUserDoc = await t.get(userRef);
                const currentCredits = freshUserDoc.data().creditos ?? 0;
                
                // Re-validación: Aunque se validó en el middleware, es una buena práctica.
                if (currentCredits < costo) {
                    // Esto no debería pasar si el middleware funciona bien, pero es seguro.
                    throw new Error("Saldo insuficiente durante la deducción atómica");
                }
                
                // Deduce créditos atómicamente y actualiza la última consulta y el dominio de uso
                t.update(userRef, {
                    creditos: currentCredits - costo, // Deducción segura
                    ultimaConsulta: currentTime, 
                    ultimoDominio: domain,        
                });
                
                // Actualiza el objeto de usuario local para la respuesta
                req.user.creditos = currentCredits - costo;
            });
        } catch (e) {
             console.error("Error crítico al deducir créditos (Transacción fallida):", e.message);
             // NO se propaga el error, la respuesta ya fue enviada. Simplemente el crédito no se descuenta.
        }

    } else if (req.user.tipoPlan === "ilimitado") {
        // Solo actualiza la última consulta y el dominio para planes ilimitados
        await userRef.update({
            ultimaConsulta: currentTime,
            ultimoDominio: domain,
        });
    }
    // Si la deducción es para `/api/ficha` (costo aleatorio), usamos `deducirCreditosFichaFirebase`.
    // Pero si usamos `creditosMiddleware` normal, se usa esta función.
    // La función que llama debe asegurarse de usar el helper correcto.
};


/**
 * 🟢 NUEVO: Función para deducir créditos en Firebase DESPUÉS DE UNA FICHA EXITOSA.
 * @param {object} req - Objeto de solicitud de Express.
 */
const deducirCreditosFichaFirebase = async (req) => {
    const userRef = db.collection("usuarios").doc(req.user.id);
    const cycleRef = db.collection("metadata").doc("creditCycle");
    const currentTime = new Date();
    const domain = req.logData.domain;
    const costo = req.logData.cost; // El costo ya fue calculado en el middleware

    if (req.user.tipoPlan === "creditos" && costo > 0) {

        // ⭐ CAMBIO CLAVE: Transacción para la deducción atómica y la actualización del ciclo.
        try {
            await db.runTransaction(async (t) => {
                const cycleDoc = await t.get(cycleRef);
                const freshUserDoc = await t.get(userRef);

                let currentIndex = cycleDoc.exists ? cycleDoc.data().currentIndex || 0 : 0;
                let currentCredits = freshUserDoc.data().creditos ?? 0;

                const nextIndex = (currentIndex + 1) % CREDIT_CYCLE.length;

                if (currentCredits < costo) {
                    // Esto no debería ocurrir, pero es una protección.
                    throw new Error("Saldo insuficiente durante la deducción atómica de ficha");
                }

                // 1. DEDUCIR CRÉDITOS
                t.update(userRef, {
                    creditos: currentCredits - costo, 
                    ultimaConsulta: currentTime, 
                    ultimoDominio: domain,        
                });

                // 2. ACTUALIZAR EL CONTADOR DE CICLO
                t.set(cycleRef, { currentIndex: nextIndex }, { merge: true }); 

                // 3. Actualizar el objeto req.user localmente 
                req.user.creditos = currentCredits - costo;
            });
        } catch (e) {
             console.error("Error crítico al deducir créditos de Ficha (Transacción fallida):", e.message);
             // NO se propaga el error.
        }
        
    } else if (req.user.tipoPlan === "ilimitado") {
         // Solo actualiza la última consulta y el dominio para planes ilimitados
        await userRef.update({
            ultimaConsulta: currentTime,
            ultimoDominio: domain,
        });
    }
};


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
    // ⭐ CORRECCIÓN CLAVE: Mostrar creditosRestantes solo si el tipoPlan es "creditos".
    // Usamos (user.creditos ?? 0) para asegurar que el valor sea 0 y no null si es que el saldo está agotado.
    creditosRestantes: user.tipoPlan === "creditos" ? (user.creditos ?? 0) : null,
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
 * Función genérica para consumir API, procesar la respuesta y DEDUCIR EL CRÉDITO SOLO SI ES EXITOSA.
 * @param {object} req - Objeto de solicitud de Express.
 * @param {object} res - Objeto de respuesta de Express.
 * @param {string} url - URL de la API a consumir.
 * @param {function} [transformer] - Función opcional para aplicar una transformación adicional a la respuesta exitosa.
 * @param {function} [creditDeductor] - Función para deducir créditos (deducirCreditosFirebase o deducirCreditosFichaFirebase).
 */
const consumirAPI = async (req, res, url, transformer = procesarRespuesta, creditDeductor = deducirCreditosFirebase) => {
  try {
    const response = await axios.get(url);
    
    // ⭐ CAMBIO CLAVE: Deducir crédito y guardar log SOLO si la respuesta es exitosa (2xx).
    if (response.status >= 200 && response.status < 300) {
        
        // 1. Procesar la respuesta ANTES de la deducción
        // Esto es clave para actualizar el objeto req.user.creditos con el saldo correcto en el paso 2.
        const processedResponse = transformer(response.data, req.user);
        
        // 2. Deducir créditos y actualizar el plan del usuario en req.user
        // Se pasa el costo que está en req.logData.cost.
        await creditDeductor(req, req.logData.cost);

        // 3. Guardar log externo (incluye el saldo actualizado en req.user.creditos)
        const logData = {
            userId: req.user.id,
            timestamp: new Date(),
            ...req.logData, // Incluye domain, endpoint, cost
        };
        // Se ejecuta sin 'await' para que no bloquee la respuesta al usuario (fire and forget).
        guardarLogExterno(logData);
        
        // 4. Enviar respuesta con el saldo de créditos actualizado.
        // Se re-procesa la respuesta para que tome el nuevo saldo de req.user
        res.json(procesarRespuesta(processedResponse, req.user));

    } else {
        // Si la API externa devolvió un error (ej. 404), procesar y enviar.
        const processedErrorResponse = procesarRespuesta(response.data, req.user);
        res.status(response.status).json(processedErrorResponse);
    }

  } catch (error) {
    console.error("Error al consumir API:", error.message);
    const errorResponse = {
      ok: false,
      error: "Error en API externa",
      // Si hay una respuesta de la API externa (ej. 404 con data), la mostramos.
      details: error.response ? error.response.data : error.message,
    };
    
    // Procesar y enviar respuesta de error
    const processedErrorResponse = procesarRespuesta(errorResponse, req.user);
    res.status(error.response ? error.response.status : 500).json(processedErrorResponse);
    // ⭐ NO DEDUCIR CRÉDITOS: La consulta falló.
  }
};

/**
 * Función específica para consumir APIs que devuelven ARCHIVOS (Imágenes/PDFs)
 * y que requieren la cabecera 'Content-Disposition' para forzar la descarga.
 * @param {object} req - Objeto de solicitud de Express.
 * @param {object} res - Objeto de respuesta de Express.
 * @param {string} url - URL de la API a consumir.
 * @param {string} defaultFileName - Nombre de archivo por defecto (ej. 'ficha.png').
 * @param {function} [creditDeductor] - Función para deducir créditos (deducirCreditosFirebase o deducirCreditosFichaFirebase).
 */
const consumirApiConDescarga = async (req, res, url, defaultFileName, creditDeductor = deducirCreditosFirebase) => {
    try {
        // La consulta a la API de generación de imagen devuelve un JSON con la URL de descarga (FILE)
        const apiResponse = await axios.get(url);
        
        // 1. Verificar si la respuesta fue exitosa
        if (apiResponse.status >= 200 && apiResponse.status < 300) {
            
            // Procesar respuesta ANTES de la deducción
            let processedResponse = procesarRespuesta(apiResponse.data, req.user);

            // ⭐ CAMBIO CLAVE: Deducir crédito y guardar log SOLO si la respuesta es exitosa.
            // Para ficha (/api/ficha) se usa deducirCreditosFichaFirebase.
            await creditDeductor(req, req.logData.cost); 
            
            // 2. Guardar log externo
            const logData = {
                userId: req.user.id,
                timestamp: new Date(),
                ...req.logData, 
            };
            guardarLogExterno(logData);

            // 3. Extraer la URL de la imagen/archivo
            const fileUrl = processedResponse.urls?.FILE;
            if (!fileUrl) {
                console.error("Error: URL de archivo no encontrada en la respuesta de la API externa.");
                throw new Error("Formato de respuesta de la API de archivo inválido.");
            }
            
            // 4. Obtener el nombre de archivo de la URL
            const urlParts = new URL(fileUrl);
            // El último segmento del path será el nombre del archivo (ej. d8d4105f076148.png)
            const fileName = urlParts.pathname.split('/').pop() || defaultFileName;
            
            // 5. Aplicar la cabecera de descarga al response final
            res.set({
                'Content-Disposition': `attachment; filename="${fileName}"`,
            });

            // 6. Enviar la respuesta JSON con la URL para la descarga (el cliente se encargará)
            // Se re-procesa la respuesta para que tome el nuevo saldo de req.user
            res.json(procesarRespuesta(processedResponse, req.user));
            
        } else {
            // Si la API externa devolvió un error (ej. 404), procesar y enviar.
            const processedErrorResponse = procesarRespuesta(apiResponse.data, req.user);
            res.status(apiResponse.status).json(processedErrorResponse);
            // ⭐ NO DEDUCIR CRÉDITOS: La consulta falló.
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
        // ⭐ NO DEDUCIR CRÉDITOS: La consulta falló.
    }
};


// -------------------- ENDPOINTS (Actualizados para GET/POST con app.use) --------------------

// 💡 Se reemplazó `app.get` por `app.use` en todos los endpoints de API.

// -------------------- ENDPOINTS (Existentes) --------------------

app.use("/api/dni", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/dni?dni=${dni}`);
});
app.use("/api/ruc", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { ruc } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/ruc?ruc=${ruc}`);
});
app.use("/api/ruc-anexo", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { ruc } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/ruc-anexo?ruc=${ruc}`);
});
app.use("/api/ruc-representante", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { ruc } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/ruc-representante?ruc=${ruc}`);
});
app.use("/api/cee", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { cee } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/cee?cee=${cee}`);
});
app.use("/api/soat-placa", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { placa } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/placa?placa=${placa}`);
});
app.use("/api/licencia", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/licencia?dni=${dni}`);
});

// ⭐ CLAVE: Endpoint /api/ficha USANDO EL MIDDLEWARE Y DEDUCTOR CORREGIDOS
app.use("/api/ficha", authMiddleware, creditosFichaMiddleware, async (req, res) => {
  const { dni } = getQueryParams(req);
  // Se pasa el deductor específico para la ficha
  await consumirApiConDescarga(req, res, `${NEW_IMAGEN_V2_BASE_URL}/generar-ficha?dni=${dni}`, 'ficha.png', deducirCreditosFichaFirebase);
});

app.use("/api/reniec", authMiddleware, creditosMiddleware(10), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/reniec?dni=${dni}`);
});
app.use("/api/denuncias-dni", authMiddleware, creditosMiddleware(12), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/denuncias-dni?dni=${dni}`);
});
app.use("/api/denuncias-placa", authMiddleware, creditosMiddleware(12), async (req, res) => {
  const { placa } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/denuncias-placa?placa=${placa}`);
});
app.use("/api/sueldos", authMiddleware, creditosMiddleware(12), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/sueldos?dni=${dni}`);
});
app.use("/api/trabajos", authMiddleware, creditosMiddleware(12), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/trabajos?dni=${dni}`);
});
app.use("/api/sunat", authMiddleware, creditosMiddleware(12), async (req, res) => {
  const { data } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/sunat?data=${data}`);
});
app.use("/api/sunat-razon", authMiddleware, creditosMiddleware(10), async (req, res) => {
  const { data } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/sunat-razon?data=${data}`);
});
app.use("/api/consumos", authMiddleware, creditosMiddleware(12), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/consumos?dni=${dni}`);
});
app.use("/api/arbol", authMiddleware, creditosMiddleware(18), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/arbol?dni=${dni}`);
});
app.use("/api/familia1", authMiddleware, creditosMiddleware(12), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/familia1?dni=${dni}`);
});
app.use("/api/familia2", authMiddleware, creditosMiddleware(15), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/familia2?dni=${dni}`);
});
app.use("/api/familia3", authMiddleware, creditosMiddleware(18), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/familia3?dni=${dni}`);
});
app.use("/api/movimientos", authMiddleware, creditosMiddleware(12), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/movimientos?dni=${dni}`);
});
app.use("/api/matrimonios", authMiddleware, creditosMiddleware(12), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/matrimonios?dni=${dni}`);
});
app.use("/api/empresas", authMiddleware, creditosMiddleware(12), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/empresas?dni=${dni}`);
});
app.use("/api/direcciones", authMiddleware, creditosMiddleware(10), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/direcciones?dni=${dni}`);
});
app.use("/api/correos", authMiddleware, creditosMiddleware(10), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/correos?dni=${dni}`);
});
app.use("/api/telefonia-doc", authMiddleware, creditosMiddleware(10), async (req, res) => {
  const { documento } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/telefonia-doc?documento=${documento}`);
});
app.use("/api/telefonia-num", authMiddleware, creditosMiddleware(12), async (req, res) => {
  const { numero } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/telefonia-num?numero=${numero}`);
});
app.use("/api/vehiculos", authMiddleware, creditosMiddleware(15), async (req, res) => {
  const { placa } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/vehiculos?placa=${placa}`);
});
app.use("/api/fiscalia-dni", authMiddleware, creditosMiddleware(15), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/fiscalia-dni?dni=${dni}`);
});
app.use("/api/fiscalia-nombres", authMiddleware, creditosMiddleware(18), async (req, res) => {
  const { nombres, apepaterno, apematerno } = getQueryParams(req);
  // Se aplica el transformer de búsqueda por lista.
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/fiscalia-nombres?nombres=${nombres}&apepaterno=${apepaterno}&apematerno=${apematerno}`, transformarRespuestaBusqueda);
});
app.use("/api/info-total", authMiddleware, creditosMiddleware(50), async (req, res) => {
    const { dni } = getQueryParams(req);
    // API de PDF, requiere descarga
    await consumirApiConDescarga(req, res, `${NEW_PDF_V3_BASE_URL}/generar-ficha-pdf?dni=${dni}`, 'ficha.pdf');
});

// -------------------- ENDPOINTS (NUEVAS APIS - Reemplazo de Factiliza) --------------------

// 🔹 1. Búsqueda por DNI (8 dígitos)
app.use("/api/dni-full", authMiddleware, creditosMiddleware(4), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dni?dni=${dni}`);
});
app.use("/api/c4", authMiddleware, creditosMiddleware(10), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/c4?dni=${dni}`);
});
app.use("/api/dnivaz", authMiddleware, creditosMiddleware(10), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dnivaz?dni=${dni}`);
});
app.use("/api/dnivam", authMiddleware, creditosMiddleware(10), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dnivam?dni=${dni}`);
});
app.use("/api/dnivel", authMiddleware, creditosMiddleware(10), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dnivel?dni=${dni}`);
});
app.use("/api/dniveln", authMiddleware, creditosMiddleware(10), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dniveln?dni=${dni}`);
});
app.use("/api/fa", authMiddleware, creditosMiddleware(10), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/fa?dni=${dni}`);
});
app.use("/api/fb", authMiddleware, creditosMiddleware(10), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/fb?dni=${dni}`);
});
app.use("/api/cnv", authMiddleware, creditosMiddleware(25), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/cnv?dni=${dni}`);
});
app.use("/api/cdef", authMiddleware, creditosMiddleware(25), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/cdef?dni=${dni}`);
});
app.use("/api/actancc", authMiddleware, creditosMiddleware(65), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/actancc?dni=${dni}`);
});
app.use("/api/actamcc", authMiddleware, creditosMiddleware(65), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/actamcc?dni=${dni}`);
});
app.use("/api/actadcc", authMiddleware, creditosMiddleware(65), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/actadcc?dni=${dni}`);
});
app.use("/api/tra", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/tra?dni=${dni}`);
});
app.use("/api/sue", authMiddleware, creditosMiddleware(8), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/sue?dni=${dni}`);
});
app.use("/api/cla", authMiddleware, creditosMiddleware(25), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/cla?dni=${dni}`);
});
app.use("/api/sune", authMiddleware, creditosMiddleware(4), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/sune?dni=${dni}`);
});
app.use("/api/cun", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/cun?dni=${dni}`);
});
app.use("/api/colp", authMiddleware, creditosMiddleware(6), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/colp?dni=${dni}`);
});
app.use("/api/mine", authMiddleware, creditosMiddleware(4), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/mine?dni=${dni}`);
});
app.use("/api/afp", authMiddleware, creditosMiddleware(6), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/afp?dni=${dni}`);
});
app.use("/api/antpen", authMiddleware, creditosMiddleware(10), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/antpen?dni=${dni}`);
});
app.use("/api/antpol", authMiddleware, creditosMiddleware(10), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/antpol?dni=${dni}`);
});
app.use("/api/antjud", authMiddleware, creditosMiddleware(10), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/antjud?dni=${dni}`);
});
app.use("/api/antpenv", authMiddleware, creditosMiddleware(10), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/antpenv?dni=${dni}`);
});
app.use("/api/dend", authMiddleware, creditosMiddleware(26), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dend?dni=${dni}`);
});
app.use("/api/fis", authMiddleware, creditosMiddleware(32), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/fis?dni=${dni}`);
});
app.use("/api/fisdet", authMiddleware, creditosMiddleware(36), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/fisdet?dni=${dni}`);
});
app.use("/api/det", authMiddleware, creditosMiddleware(26), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/det?dni=${dni}`);
});
app.use("/api/rqh", authMiddleware, creditosMiddleware(8), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/rqh?dni=${dni}`);
});
app.use("/api/meta", authMiddleware, creditosMiddleware(26), async (req, res) => {
  const { dni } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/meta?dni=${dni}`);
});

// 🔹 2. Consultas Generales (Query genérico)
app.use("/api/osiptel", authMiddleware, creditosMiddleware(10), async (req, res) => {
  const { query } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/osiptel?query=${query}`);
});
app.use("/api/claro", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { query } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/claro?query=${query}`);
});
app.use("/api/entel", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { query } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/entel?query=${query}`);
});
app.use("/api/pro", authMiddleware, creditosMiddleware(12), async (req, res) => {
  const { query } = getQueryParams(req);
  // Nota: No se especificó el costo para esta, se asume 12 créditos. Si no aplica se debe ajustar.
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/pro?query=${query}`);
});
app.use("/api/sen", authMiddleware, creditosMiddleware(12), async (req, res) => {
  const { query } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/sen?query=${query}`);
});
app.use("/api/sbs", authMiddleware, creditosMiddleware(12), async (req, res) => {
  const { query } = getQueryParams(req);
  // Nota: No se especificó el costo para esta, se asume 12 créditos. Si no aplica se debe ajustar.
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/sbs?query=${query}`);
});
app.use("/api/pasaporte", authMiddleware, creditosMiddleware(20), async (req, res) => {
  const { query } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/pasaporte?query=${query}`);
});
app.use("/api/seeker", authMiddleware, creditosMiddleware(28), async (req, res) => {
  const { query } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/seeker?query=${query}`);
});
app.use("/api/bdir", authMiddleware, creditosMiddleware(28), async (req, res) => {
  const { query } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/bdir?query=${query}`);
});

// 🔹 3. Denuncias Policiales por otros Documentos
app.use("/api/dence", authMiddleware, creditosMiddleware(25), async (req, res) => {
  const { carnet_extranjeria } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dence?carnet_extranjeria=${carnet_extranjeria}`);
});
app.use("/api/denpas", authMiddleware, creditosMiddleware(25), async (req, res) => {
  const { pasaporte } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/denpas?pasaporte=${pasaporte}`);
});
app.use("/api/denci", authMiddleware, creditosMiddleware(25), async (req, res) => {
  const { cedula_identidad } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/denci?cedula_identidad=${cedula_identidad}`);
});
app.use("/api/denp", authMiddleware, creditosMiddleware(25), async (req, res) => {
  const { placa } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/denp?placa=${placa}`);
});
app.use("/api/denar", authMiddleware, creditosMiddleware(25), async (req, res) => {
  const { serie_armamento } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/denar?serie_armamento=${serie_armamento}`);
});
app.use("/api/dencl", authMiddleware, creditosMiddleware(25), async (req, res) => {
  const { clave_denuncia } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dencl?clave_denuncia=${clave_denuncia}`);
});

// 🔹 4. Consultas Venezolanas
app.use("/api/cedula", authMiddleware, creditosMiddleware(4), async (req, res) => {
  const { cedula } = getQueryParams(req);
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/cedula?cedula=${cedula}`);
});
// Endpoint que devuelve la lista y necesita la transformación.
app.use("/api/venezolanos_nombres", authMiddleware, creditosMiddleware(4), async (req, res) => {
  const { query } = getQueryParams(req);
  // Aplicar la función de transformación específica para respuestas de búsqueda por lista
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/venezolanos_nombres?query=${query}`, transformarRespuestaBusqueda);
});

// 🔹 5. Consultas por Nombres (Peruanos)
// Endpoint que devuelve la lista y necesita la transformación.
app.use("/api/dni_nombres", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { nombres, apepaterno, apematerno } = getQueryParams(req);
  // Aplicar la función de transformación específica para respuestas de búsqueda por lista
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dni_nombres?nombres=${nombres}&apepaterno=${apepaterno}&apematerno=${apematerno}`, transformarRespuestaBusqueda);
});

// ---------------------------------------------------
app.use("/", (req, res) => {
  // Manejar el preflight de CORS (OPTIONS)
  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }
  
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

// -------------------- SERVER --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
