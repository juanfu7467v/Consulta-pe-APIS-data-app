// server.mjs
import express from "express";
import admin from "firebase-admin";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());

// Construir objeto de credenciales desde variables de entorno
const serviceAccount = {
  type: process.env.type,
  project_id: process.env.project_id,
  private_key_id: process.env.private_key_id,
  private_key: process.env.private_key?.replace(/\\n/g, "\n"), // Importante para que funcione en Railway
  client_email: process.env.client_email,
  client_id: process.env.client_id,
  auth_uri: process.env.auth_uri,
  token_uri: process.env.token_uri,
  auth_provider_x509_cert_url: process.env.auth_provider_x509_cert_url,
  client_x509_cert_url: process.env.client_x509_cert_url,
  universe_domain: process.env.universe_domain,
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

// Ejemplo: guardar un perfil
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

// Ejemplo: listar perfiles
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

// Configurar puerto para Railway
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
