import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import admin from "firebase-admin";
import { readFileSync } from "fs";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// Inicializar Firebase Admin con la key
const serviceAccount = JSON.parse(
  readFileSync("./firebase-service-account.json", "utf8")
);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL
});

const db = admin.firestore();

// Ruta de prueba
app.get("/", (req, res) => {
  res.json({ message: "🚀 API Consulta PE funcionando en Railway!" });
});

// Ejemplo: obtener un perfil por ID
app.get("/perfil/:id", async (req, res) => {
  try {
    const doc = await db.collection("perfiles").doc(req.params.id).get();
    if (!doc.exists) {
      return res.status(404).json({ error: "Perfil no encontrado" });
    }
    res.json(doc.data());
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

// Puerto para Railway
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Servidor corriendo en http://localhost:${PORT}`);
});
