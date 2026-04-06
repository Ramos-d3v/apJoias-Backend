require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg'); // Usando PostgreSQL
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const jwt = require('jsonwebtoken'); 
const helmet = require('helmet'); 
const rateLimit = require('express-rate-limit'); 
const cloudinary = require('cloudinary').v2;

const app = express();
const PORT = process.env.PORT || 3005;

const SECRET_KEY = process.env.SECRET_KEY;
const REMOVE_BG_API_KEY = process.env.VITE_REMOVE_BG_API_KEY;

// --- CONFIGURAÇÃO DO LIMITE DE FOTOS ---
const LIMITE_FOTOS = 25; 

if (!SECRET_KEY) {
  console.error("⚠️ ALERTA: SECRET_KEY não encontrada no arquivo .env!");
  process.exit(1);
}

// 🛡️ Segurança de Headers e CORS
// 🛡️ Segurança de Headers e CORS (Ajustado para HTTP/IP)
app.use(helmet({
  crossOriginOpenerPolicy: false,
  originAgentCluster: false,
})); 
app.use(helmet.crossOriginResourcePolicy({ policy: "cross-origin" }));
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// 🛡️ Bloqueio de Força Bruta no Login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 5, 
  message: { error: 'Muitas tentativas de login falhas. Tente novamente em 15 minutos.' }
});

// 🛡️ Segurança e Configuração de Upload de Imagens
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname,'./uploads');
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
  limits: { fileSize: 15 * 1024 * 1024 }, 
  fileFilter: fileFilter
});

// --- CONFIGURAÇÃO DO BANCO DE DADOS (POSTGRESQL) ---
const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'apjoias',
  password: process.env.DB_PASSWORD || 'suasenha',
  port: process.env.DB_PORT || 5432,
});

// Testa a conexão ao iniciar o servidor
pool.connect((err) => {
  if (err) {
    console.error('❌ Erro ao conectar no PostgreSQL:', err.stack);
  } else {
    console.log('✅ Conectado ao banco de dados PostgreSQL com sucesso.');
  }
});

// Funções para controle de uso da API
const getUsageCount = async () => {
  const result = await pool.query('SELECT remove_bg_count FROM api_usage WHERE id = 1');
  return result.rows.length > 0 ? result.rows[0].remove_bg_count : 0;
};

const incrementUsageCount = async () => {
  await pool.query('UPDATE api_usage SET remove_bg_count = remove_bg_count + 1 WHERE id = 1');
};

// --- ROTAS DE AUTENTICAÇÃO ---

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

// --- ROTAS DO REMOVE.BG ---

app.get('/api/remove-bg/usage', verificarToken, async (req, res) => {
  try {
    const currentCount = await getUsageCount();
    res.json({ used: currentCount, limit: LIMITE_FOTOS });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao consultar uso' });
  }
});

app.post('/api/remove-bg', verificarToken, upload.single('image_file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Nenhuma imagem enviada.' });
    if (!REMOVE_BG_API_KEY) return res.status(500).json({ error: 'Chave API não configurada.' });

    const currentCount = await getUsageCount();
    
    if (currentCount >= LIMITE_FOTOS) {
      if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      return res.status(403).json({ 
        error: `Limite de ${LIMITE_FOTOS} remoções de fundo atingido.` 
      });
    }

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

    await incrementUsageCount();

    const imageArrayBuffer = await removeBgResponse.arrayBuffer();
    fs.unlinkSync(req.file.path);

    res.set('X-Remaining-Credits', String(LIMITE_FOTOS - (currentCount + 1)));
    res.set('Content-Type', 'image/png');
    res.send(Buffer.from(imageArrayBuffer));

  } catch (error) {
    console.error('Erro:', error);
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    res.status(500).json({ error: 'Falha ao processar a imagem.' });
  }
});

// --- ROTAS DE PRODUTOS ---

app.get('/api/products', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products ORDER BY id DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Erro no servidor' }); 
  }
});

app.post('/api/products', verificarToken, upload.single('imagemFile'), async (req, res) => {
  const { nome, categoria, quantidade, imagemUrl } = req.body;
  
  const qtdSanitizada = parseInt(quantidade) || 0; 
  const status = qtdSanitizada > 0 ? 'Disponível' : 'Esgotado';
  
  let imagem = imagemUrl || '';

  // Se o usuário fez upload de um arquivo, envia para o Cloudinary
  if (req.file) {
    try {
      const result = await cloudinary.uploader.upload(req.file.path, {
        folder: 'apjoias' // Cria uma pasta lá no Cloudinary para organizar
      });
      imagem = result.secure_url; // Pega a URL definitiva gerada pelo Cloudinary
      fs.unlinkSync(req.file.path); // Apaga a imagem da pasta /uploads local
    } catch (error) {
      console.error("Erro no Cloudinary:", error);
      return res.status(500).json({ error: 'Erro ao enviar imagem para a nuvem.' });
    }
  }
  
  try {
    const result = await pool.query(
      `INSERT INTO products (nome, categoria, imagem, quantidade, status) VALUES ($1, $2, $3, $4, $5) RETURNING id`, 
      [nome, categoria, imagem, qtdSanitizada, status]
    );
    res.status(201).json({ id: result.rows[0].id });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao inserir no banco de dados' });
  }
});

app.put('/api/products/:id', verificarToken, upload.single('imagemFile'), async (req, res) => {
  const { nome, categoria, quantidade, imagemUrl } = req.body;
  const idSanitizado = parseInt(req.params.id);
  
  if (isNaN(idSanitizado)) return res.status(400).json({ error: 'ID inválido' });

  const qtdSanitizada = parseInt(quantidade) || 0;
  const status = qtdSanitizada > 0 ? 'Disponível' : 'Esgotado';

  let imagem = imagemUrl || ''; // Mantém a imagem anterior graças ao ajuste no Frontend

  try {
    // Se enviou uma foto nova durante a edição, envia para o Cloudinary
    if (req.file) {
      const result = await cloudinary.uploader.upload(req.file.path, { folder: 'apjoias' });
      imagem = result.secure_url;
      fs.unlinkSync(req.file.path);
    }
    
    // Agora podemos usar apenas uma query de atualização simples
    await pool.query(
      `UPDATE products SET nome = $1, categoria = $2, quantidade = $3, status = $4, imagem = $5 WHERE id = $6`,
      [nome, categoria, qtdSanitizada, status, imagem, idSanitizado]
    );
    
    res.json({ message: "Atualizado com sucesso" });
  } catch (err) {
    console.error("Erro ao atualizar:", err);
    res.status(500).json({ error: 'Erro ao atualizar o banco de dados' });
  }
});

app.delete('/api/products/:id', verificarToken, async (req, res) => {
  const idSanitizado = parseInt(req.params.id);
  if (isNaN(idSanitizado)) return res.status(400).json({ error: 'ID inválido' });

  try {
    await pool.query('DELETE FROM products WHERE id = $1', [idSanitizado]);
    res.json({ message: "Removido" });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao deletar no banco de dados' });
  }
});

// Erros do multer (Tamanho de arquivo excedido, formato inválido, etc)
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError || err) {
    return res.status(400).json({ error: err.message });
  }
  next();
});

app.get('/api', (req, res) => {
  res.json({ mensagem: "API do ApJoias está rodando perfeitamente!" });
});

app.listen(PORT, () => console.log(`Backend PostgreSQL rodando na porta ${PORT}`));