// server.mjs
import express from "express";
import admin from "firebase-admin";
import dotenv from "dotenv";

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

// Ruta de prueba
app.get("/", (req, res) => {
  res.send("🚀 API Consulta PE funcionando en Railway con Firebase!");
});

// Guardar perfil
app.post("/perfil", async (req, res) => {
  try {
    const data = req.body;
    const docRef = await db.collection("perfiles").add(data);
    res.json({ id: docRef.id, ...data });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error al guardar el perfil" });
  }
});

// Listar perfiles
app.get("/perfiles", async (req, res) => {
  try {
    const snapshot = await db.collection("perfiles").get();
    const perfiles = snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
    res.json(perfiles);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error al obtener perfiles" });
  }
});

// Puerto Railway
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
