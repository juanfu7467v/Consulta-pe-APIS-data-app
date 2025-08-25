const express = require("express");
const jwt = require("jsonwebtoken");
const fetch = require("node-fetch");
const admin = require("firebase-admin");
require("dotenv").config();

const app = express();
app.use(express.json());

// Inicializar Firebase
admin.initializeApp({
  credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_CREDENTIALS))
});
const db = admin.firestore();

// Middleware para validar token de API
function verificarToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ error: "Token requerido" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Token inválido o expirado" });
    req.user = user;
    next();
  });
}

// Función para descontar créditos en Firebase
async function descontarCreditos(uid, costo) {
  const userRef = db.collection("users").doc(uid);
  const userSnap = await userRef.get();
  if (!userSnap.exists) throw new Error("Usuario no encontrado");

  const userData = userSnap.data();
  if (userData.credits < costo) throw new Error("Créditos insuficientes");

  await userRef.update({ credits: userData.credits - costo });
}

// Ruta para generar un token de API
app.post("/generar-token", async (req, res) => {
  const { uid } = req.body;
  if (!uid) return res.status(400).json({ error: "Falta UID del usuario" });

  const token = jwt.sign({ uid }, process.env.JWT_SECRET, { expiresIn: "7d" });
  res.json({ token });
});

// Proxy seguro para endpoints
async function proxySeguro(req, res, endpoint, costo) {
  try {
    await descontarCreditos(req.user.uid, costo);

    const query = new URLSearchParams(req.query).toString();
    const url = `${process.env.ORIGINAL_API_BASE}${endpoint}?${query}`;

    const response = await fetch(url);
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(403).json({ error: err.message });
  }
}

// === ENDPOINTS PROTEGIDOS ===
app.get("/reniec", verificarToken, (req, res) => proxySeguro(req, res, "reniec", 10));
app.get("/denuncias-dni", verificarToken, (req, res) => proxySeguro(req, res, "denuncias-dni", 15));
app.get("/denuncias-placa", verificarToken, (req, res) => proxySeguro(req, res, "denuncias-placa", 20));
app.get("/sueldos", verificarToken, (req, res) => proxySeguro(req, res, "sueldos", 20));
app.get("/trabajos", verificarToken, (req, res) => proxySeguro(req, res, "trabajos", 15));
app.get("/consumos", verificarToken, (req, res) => proxySeguro(req, res, "consumos", 20));
app.get("/matrimonios", verificarToken, (req, res) => proxySeguro(req, res, "matrimonios", 15));
app.get("/empresas", verificarToken, (req, res) => proxySeguro(req, res, "empresas", 20));
app.get("/direcciones", verificarToken, (req, res) => proxySeguro(req, res, "direcciones", 10));
app.get("/correos", verificarToken, (req, res) => proxySeguro(req, res, "correos", 10));
app.get("/sunat", verificarToken, (req, res) => proxySeguro(req, res, "sunat", 20));
app.get("/sunat-razon", verificarToken, (req, res) => proxySeguro(req, res, "sunat-razon", 20));
app.get("/fiscalia-dni", verificarToken, (req, res) => proxySeguro(req, res, "fiscalia-dni", 15));
app.get("/fiscalia-nombres", verificarToken, (req, res) => proxySeguro(req, res, "fiscalia-nombres", 15));
app.get("/familia1", verificarToken, (req, res) => proxySeguro(req, res, "familia1", 10));
app.get("/familia2", verificarToken, (req, res) => proxySeguro(req, res, "familia2", 10));
app.get("/familia3", verificarToken, (req, res) => proxySeguro(req, res, "familia3", 10));
app.get("/vehiculos", verificarToken, (req, res) => proxySeguro(req, res, "vehiculos", 20));
app.get("/telefonia-doc", verificarToken, (req, res) => proxySeguro(req, res, "telefonia-doc", 15));
app.get("/telefonia-num", verificarToken, (req, res) => proxySeguro(req, res, "telefonia-num", 15));
app.get("/movimientos", verificarToken, (req, res) => proxySeguro(req, res, "movimientos", 20));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ API corriendo en puerto ${PORT}`));
