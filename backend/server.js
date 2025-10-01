require('dotenv').config();
const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const { OpenAI } = require('openai');
const multer = require('multer');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const upload = multer({ dest: 'uploads/' });
const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET || 'verysecuresecretkey';
const MONGO_URI = process.env.MONGO_URI;

if (!MONGO_URI) {
  console.error('ERROR: MONGOURI environment variable not set. Please fix your .env file.');
  process.exit(1);
}

const client = new MongoClient(MONGO_URI);
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

let users;
let requirements;
let testcases;

async function connectDB() {
  if (!client.isConnected?.()) {
    await client.connect();
  }
  const db = client.db(''); // Replace with your MongoDB database name or leave empty if default
  users = db.collection('users');
  requirements = db.collection('requirements');
  testcases = db.collection('testcases');
}

// AUTH ROUTES

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  await connectDB();
  if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });
  const existing = await users.findOne({ username });
  if (existing) return res.status(400).json({ error: 'User already exists' });
  const hashed = await bcrypt.hash(password, 12);
  await users.insertOne({ username, password: hashed });
  res.json({ success: true });
  console.log('Storing password hash:', hashed);
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  await connectDB();
  console.log('Raw req.body:', req.body);
  console.log('Username:', JSON.stringify(username));
  console.log('Password:', JSON.stringify(password));
  const user = await users.findOne({ username });
  if (!user) return res.status(400).json({ error: 'Invalid login' });
  console.log('Database password hash:', user.password);
  const valid = await bcrypt.compare(password, user.password);
  console.log('Bcrypt compare result:', valid);
  if (!valid) return res.status(400).json({ error: 'Invalid login' });
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '2h' });
  res.json({ token });
});

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Missing token' });
  const token = auth.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// TEST CASE ROUTES

app.get('/api/testcases', authMiddleware, async (req, res) => {
  await connectDB();
  const filter = {};
  if (req.query.userStoryId) {
    filter.userStoryId = req.query.userStoryId;
  }
  const docs = await testcases.find(filter).toArray();
  res.json(docs);
});

app.post('/api/testcases', authMiddleware, async (req, res) => {
  await connectDB();
  const testCaseDoc = {
    feature: req.body.feature,
    description: req.body.description,
    steps: req.body.steps,
    expected: req.body.expected,
    priority: req.body.priority,
    dateCreated: req.body.dateCreated,
    requirementId: req.body.requirementId || null,
    status: req.body.status || 'Draft',
    userStoryId: req.body.userStoryId || null,
    userStoryTitle: req.body.userStoryTitle || null,
    createdAt: new Date()
  };
  const result = await testcases.insertOne(testCaseDoc);
  res.json(result);
});

app.put('/api/testcases/:id', authMiddleware, async (req, res) => {
  await connectDB();
  await testcases.updateOne({ _id: new ObjectId(req.params.id) }, { $set: req.body });
  res.json({ success: true });
});

app.delete('/api/testcases/:id', authMiddleware, async (req, res) => {
  try {
    await connectDB();
    await testcases.deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: 'Failed to delete test case' });
  }
});

// REQUIREMENTS ROUTES

app.post('/api/requirements', authMiddleware, async (req, res) => {
  await connectDB();
  const { title, description, date } = req.body;
  if (!title || !description || !date) return res.status(400).json({ error: 'Missing title, description or date' });
  const count = await requirements.countDocuments();
  const userStoryId = `US${String(count + 1).padStart(2, '0')}`;
  const docToInsert = { title, description, date, userStoryId, createdAt: new Date() };
  const result = await requirements.insertOne(docToInsert);
  if (!result.insertedId) return res.status(500).json({ error: "Failed to insert requirement" });
  docToInsert._id = result.insertedId;
  res.json(docToInsert);
});

app.get('/api/requirements', authMiddleware, async (req, res) => {
  await connectDB();
  const docs = await requirements.find({}).toArray();
  res.json(docs);
});

app.put('/api/requirements/:id', authMiddleware, async (req, res) => {
  await connectDB();
  const id = req.params.id;
  const updateData = req.body;
  delete updateData._id;
  await requirements.updateOne({ _id: new ObjectId(id) }, { $set: updateData });
  res.json({ success: true });
});

app.delete('/api/requirements/:id', authMiddleware, async (req, res) => {
  await connectDB();
  const id = req.params.id;
  await requirements.deleteOne({ _id: new ObjectId(id) });
  res.json({ success: true });
});

app.get('/api/requirements/:id', authMiddleware, async (req, res) => {
  await connectDB();
  try {
    const doc = await requirements.findOne({ _id: new ObjectId(req.params.id) });
    if (!doc) return res.status(404).json({ error: "Requirement not found" });
    res.json(doc);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Traceability matrix routes

app.get('/api/traceability', authMiddleware, async (req, res) => {
  await connectDB();
  const { userStoryId } = req.query;
  if (!userStoryId) return res.status(400).json({ error: 'Missing userStoryId query parameter' });
  try {
    const reqDoc = await requirements.findOne({ userStoryId: userStoryId.toUpperCase() });
    if (!reqDoc) return res.status(404).json({ error: `Requirement not found for ${userStoryId}` });
    const testCases = await testcases.find({ userStoryId: userStoryId.toUpperCase() }).toArray();
    res.json({ requirement: reqDoc, testCases });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/traceability-matrix', authMiddleware, async (req, res) => {
  await connectDB();
  const userStoryId = req.query.userStoryId?.toUpperCase();
  const reqFilter = userStoryId ? { userStoryId } : {};
  const testCaseFilter = userStoryId ? { userStoryId } : {};
  const allRequirements = await requirements.find(reqFilter).toArray();
  const allTestCases = await testcases.find(testCaseFilter).toArray();
  res.json({ requirements: allRequirements, testcases: allTestCases });
});

// AI generation route

app.post('/api/generate-testcases', upload.single('image'), async (req, res) => {
  try {
    const { textRequirement } = req.body;
    if (!textRequirement && !req.file) return res.status(400).json({ error: 'No requirement provided.' });

    const prompt = `
Given the following requirement, generate ONLY core functional software test cases for high and medium priority.
For each test case, specify:
- feature: module/feature name (string)
- sno: serial number (integer)
- name: test case name (string)
- steps: array of step strings
- expected: expected result (string)
- priority: High or Medium
- dateCreated: ISO 8601 date string or readable date when the test case was created
Output your result as a JSON array with these fields for each item.
Requirement:
${textRequirement}
`;
    await connectDB();
    console.log('Prompt to OpenAI:', prompt);

    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [
        { role: "system", content: "You are a senior QA engineer. Generate exhaustive test cases for given requirements only as valid JSON." },
        { role: "user", content: prompt }
      ],
      max_tokens: 800
    });

    let cases;
    try {
      const jsonMatch = completion.choices[0].message.content.match(/\[.*\]/s);
      cases = JSON.parse(jsonMatch ? jsonMatch[0] : completion.choices[0].message.content);
      res.json({ cases });
    } catch (err) {
      console.error('Error parsing AI response as JSON:', err, completion.choices[0].message.content);
      return res.status(500).json({ error: 'Failed to parse test cases', details: err.message });
    }
  } catch (err) {
    console.error('Error generating test cases:', err);
    res.status(500).json({ error: 'Failed to generate test cases', details: err.message });
  }
});

// Cosine similarity function

function cosineSimilarity(a, b) {
  let dot = 0,
    normA = 0,
    normB = 0;
  for (let i = 0; i < a.length; ++i) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  return dot / (Math.sqrt(normA) * Math.sqrt(normB));
}

// Requirement-Test Case Mapping

app.post('/api/map-requirement', authMiddleware, async (req, res) => {
  try {
    const { requirementText } = req.body;
    await connectDB();
    const cases = await testcases.find({}).toArray();

    const embeddingResponse = await openai.embeddings.create({
      model: "text-embedding-3-small",
      input: [requirementText]
    });

    const requirementEmbed = embeddingResponse.data[0].embedding;
    const caseTexts = cases.map(c => c.description);

    const testEmbeddingsResp = await openai.embeddings.create({
      model: "text-embedding-3-small",
      input: caseTexts
    });

    const testEmbeds = testEmbeddingsResp.data.map(d => d.embedding);

    const suggestions = cases
      .map((c, i) => ({ testCase: c, similarity: cosineSimilarity(requirementEmbed, testEmbeds[i]) }))
      .filter(c => c.similarity > 0.8);

    res.json({ suggestions });
  } catch (error) {
    console.error('Error mapping requirements:', error);
    res.status(500).json({ error: 'Failed to map requirement to test cases' });
  }
});

// Automation Script Generate Endpoint

app.post('/api/automation-script-generate', async (req, res) => {
  try {
    await connectDB();
    const { testCaseId, prompt } = req.body;
    if (!testCaseId || !prompt) return res.status(400).json({ error: 'Missing testCaseId or prompt' });
    const aiResponse = await openai.chat.completions.create({
      model: 'gpt-4',
      messages: [
        { role: 'system', content: 'You are an expert Playwright automation script generator.' },
        { role: 'user', content: prompt },
      ],
      temperature: 0,
    });
    const automationScript = aiResponse.choices[0].message.content;
    await testcases.updateOne(
      { _id: new ObjectId(testCaseId) },
      { $set: { automationScript, automationStatus: 'created' } }
    );
    res.json({ automationScript });
  } catch (error) {
    console.error('Error generating automation script:', error);
    res.status(500).json({ error: 'Failed to generate automation script' });
  }
});

// Automation Execute Endpoint

app.post('/api/automation-execute', async (req, res) => {
  try {
    await connectDB();
    const { testCaseId } = req.body;
    if (!testCaseId) return res.status(400).json({ error: 'Missing testCaseId' });
    const testCase = await testcases.findOne({ _id: new ObjectId(testCaseId) });
    if (!testCase || !testCase.automationScript) return res.status(400).json({ error: 'Test case or automation script not found' });
    const execPrompt = `Execute this Playwright script and reply PASS or FAIL:\n${testCase.automationScript}`;
    const execResponse = await openai.chat.completions.create({
      model: 'gpt-4',
      messages: [
        { role: 'system', content: 'Test automation executor simulation.' },
        { role: 'user', content: execPrompt },
      ],
      temperature: 0,
    });
    const replyText = execResponse.choices[0].message.content.toLowerCase();
    let status = 'not_executed';
    if (replyText.includes('pass')) status = 'passed';
    else if (replyText.includes('fail')) status = 'failed';
    await testcases.updateOne(
      { _id: new ObjectId(testCaseId) },
      { $set: { executionStatus: status } }
    );
    res.json({ status });
  } catch (error) {
    console.error('Error executing automation:', error);
    res.status(500).json({ error: 'Automation execution failed' });
  }
});

// Update automation

app.put('/api/testcases/:id/automation', async (req, res) => {
  try {
    await connectDB();
    const testCaseId = req.params.id;
    const { automationScript, automationStatus } = req.body;
    await testcases.updateOne(
      { _id: new ObjectId(testCaseId) },
      { $set: { automationScript, automationStatus } }
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Error updating automation:', error);
    res.status(500).json({ error: 'Failed to update automation' });
  }
});

// Update execution status

app.put('/api/testcases/:id/execution', async (req, res) => {
  try {
    await connectDB();
    const testCaseId = req.params.id;
    const { executionStatus } = req.body;
    await testcases.updateOne(
      { _id: new ObjectId(testCaseId) },
      { $set: { executionStatus } }
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Error updating execution status:', error);
    res.status(500).json({ error: 'Failed to update execution status' });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
