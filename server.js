require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const jwt = require('jsonwebtoken'); 
const helmet = require('helmet'); 
const rateLimit = require('express-rate-limit'); 

const app = express();
const PORT = 3000;

const SECRET_KEY = process.env.SECRET_KEY;
const REMOVE_BG_API_KEY = process.env.VITE_REMOVE_BG_API_KEY;

// --- CONFIGURAÇÃO DO LIMITE DE FOTOS ---
const LIMITE_FOTOS = 25; // Altere este número para 50 quando quiser aumentar

if (!SECRET_KEY) {
  console.error("⚠️ ALERTA: SECRET_KEY não encontrada no arquivo .env!");
  process.exit(1);
}

app.use(helmet()); 
app.use(helmet.crossOriginResourcePolicy({ policy: "cross-origin" }));
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 5, 
  message: { error: 'Muitas tentativas de login falhas. Tente novamente em 15 minutos.' }
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = './uploads';
    if (!fs.existsSync(dir)) fs.mkdirSync(dir);
    cb(null, dir);
  },
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});

const fileFilter = (req, file, cb) => {
  const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/jpg'];
  if (allowedMimeTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Tentativa de invasão detectada: Formato de arquivo não permitido.'), false);
  }
};

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, 
  fileFilter: fileFilter
});

// Configuração do PostgreSQL
const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'apjoias',
  password: process.env.DB_PASSWORD || 'suasenha',
  port: process.env.DB_PORT || 5432,
});

// Criar tabelas se não existirem
const initDB = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        nome TEXT NOT NULL,
        categoria TEXT NOT NULL,
        imagem TEXT NOT NULL,
        quantidade INTEGER NOT NULL,
        status TEXT NOT NULL
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS api_usage (
        id INTEGER PRIMARY KEY,
        remove_bg_count INTEGER DEFAULT 0
      )
    `);

    // Insere o contador inicial se não existir (Sintaxe do Postgres)
    await pool.query(`
      INSERT INTO api_usage (id, remove_bg_count) 
      VALUES (1, 0) 
      ON CONFLICT (id) DO NOTHING
    `);
    console.log("Banco de dados PostgreSQL conectado e inicializado.");
  } catch (err) {
    console.error("Erro ao inicializar banco:", err);
  }
};
initDB();

// Funções auxiliares para ler e atualizar o contador no banco
const getUsageCount = () => new Promise((resolve, reject) => {
  db.get('SELECT remove_bg_count FROM api_usage WHERE id = 1', (err, row) => {
    if (err) reject(err);
    else resolve(row ? row.remove_bg_count : 0);
  });
});

const incrementUsageCount = () => new Promise((resolve, reject) => {
  db.run('UPDATE api_usage SET remove_bg_count = remove_bg_count + 1 WHERE id = 1', (err) => {
    if (err) reject(err);
    else resolve();
  });
});

// --- ROTAS DE SEGURANÇA ---

app.post('/api/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;
  
  if (username === 'admin' && password === SECRET_KEY) {
    const token = jwt.sign({ user: username }, SECRET_KEY, { expiresIn: '24h' });
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Credenciais inválidas' });
  }
});

const verificarToken = (req, res, next) => {
  const tokenHeader = req.headers['authorization'];
  if (!tokenHeader) return res.status(403).json({ error: 'Token não fornecido' });

  const token = tokenHeader.split(' ')[1];

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Token inválido ou expirado' });
    req.user = decoded.user;
    next(); 
  });
};

// --- ROTA DE PROCESSAMENTO DE IMAGEM (COM CONTADOR) ---
app.post('/api/remove-bg', verificarToken, upload.single('image_file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Nenhuma imagem enviada.' });
    if (!REMOVE_BG_API_KEY) return res.status(500).json({ error: 'Chave API não configurada.' });

    // 1. Verifica o contador antes de fazer a requisição
    const currentCount = await getUsageCount();
    
    if (currentCount >= LIMITE_FOTOS) {
      if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      return res.status(403).json({ 
        error: `Limite de ${LIMITE_FOTOS} remoções de fundo atingido. Atualize seu plano ou modifique o limite no servidor.` 
      });
    }

    // 2. Faz a requisição se estiver dentro do limite
    const fileBuffer = fs.readFileSync(req.file.path);
    const blob = new Blob([fileBuffer], { type: req.file.mimetype });

    const formData = new FormData();
    formData.append('size', 'auto');
    formData.append('crop', 'true');
    formData.append('image_file', blob, req.file.originalname);

    const removeBgResponse = await fetch('https://api.remove.bg/v1.0/removebg', {
      method: 'POST',
      headers: { 'X-Api-Key': REMOVE_BG_API_KEY },
      body: formData,
    });

    if (!removeBgResponse.ok) {
      const errorText = await removeBgResponse.text();
      throw new Error(`Erro API: ${errorText}`);
    }

    // 3. Imagem processada com sucesso! Atualiza o contador no banco
    await incrementUsageCount();

    const imageArrayBuffer = await removeBgResponse.arrayBuffer();
    fs.unlinkSync(req.file.path);

    // Envia no cabeçalho quantas imagens ainda restam, caso você queira usar no frontend no futuro
    res.set('X-Remaining-Credits', String(LIMITE_FOTOS - (currentCount + 1)));
    res.set('Content-Type', 'image/png');
    res.send(Buffer.from(imageArrayBuffer));

  } catch (error) {
    console.error('Erro:', error);
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    res.status(500).json({ error: 'Falha ao processar a imagem.' });
  }
});

// Rota para o frontend consultar o limite atual da API
app.get('/api/remove-bg/usage', verificarToken, async (req, res) => {
  try {
    const currentCount = await getUsageCount();
    res.json({ used: currentCount, limit: LIMITE_FOTOS });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao consultar uso' });
  }
});


// --- ROTAS DO PRODUTO (Blindadas) ---

app.get('/api/products', (req, res) => {
  db.all('SELECT * FROM products ORDER BY id DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Erro no servidor' }); 
    res.json(rows);
  });
});

app.post('/api/products', verificarToken, upload.single('imagemFile'), (req, res) => {
  const { nome, categoria, quantidade, imagemUrl } = req.body;
  
  const qtdSanitizada = parseInt(quantidade) || 0; 
  const status = qtdSanitizada > 0 ? 'Disponível' : 'Esgotado';
  
  let imagem = imagemUrl || '';
  if (req.file) imagem = `http://localhost:3000/uploads/${req.file.filename}`;
  
  db.run(`INSERT INTO products (nome, categoria, imagem, quantidade, status) VALUES (?, ?, ?, ?, ?)`, 
    [nome, categoria, imagem, qtdSanitizada, status], function(err) {
    if (err) return res.status(500).json({ error: 'Erro ao inserir no banco de dados' });
    res.status(201).json({ id: this.lastID });
  });
});

app.put('/api/products/:id', verificarToken, upload.single('imagemFile'), (req, res) => {
  const { nome, categoria, quantidade, imagemUrl } = req.body;
  
  const idSanitizado = parseInt(req.params.id);
  if (isNaN(idSanitizado)) return res.status(400).json({ error: 'ID inválido' });

  const qtdSanitizada = parseInt(quantidade) || 0;
  const status = qtdSanitizada > 0 ? 'Disponível' : 'Esgotado';
  let sql, params;

  if (req.file || imagemUrl) {
    let imagem = imagemUrl || '';
    if (req.file) imagem = `http://localhost:3000/uploads/${req.file.filename}`;
    sql = `UPDATE products SET nome = ?, categoria = ?, quantidade = ?, status = ?, imagem = ? WHERE id = ?`;
    params = [nome, categoria, qtdSanitizada, status, imagem, idSanitizado];
  } else {
    sql = `UPDATE products SET nome = ?, categoria = ?, quantidade = ?, status = ? WHERE id = ?`;
    params = [nome, categoria, qtdSanitizada, status, idSanitizado];
  }

  db.run(sql, params, function(err) {
    if (err) return res.status(500).json({ error: 'Erro ao atualizar o banco de dados' });
    res.json({ message: "Atualizado" });
  });
});

app.delete('/api/products/:id', verificarToken, (req, res) => {
  const idSanitizado = parseInt(req.params.id);
  if (isNaN(idSanitizado)) return res.status(400).json({ error: 'ID inválido' });

  db.run('DELETE FROM products WHERE id = ?', idSanitizado, function(err) {
    if (err) return res.status(500).json({ error: 'Erro ao deletar no banco de dados' });
    res.json({ message: "Removido" });
  });
});

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError || err) {
    return res.status(400).json({ error: err.message });
  }
  next();
});

app.listen(PORT, () => console.log(`Backend ultra-seguro rodando na porta ${PORT}`));