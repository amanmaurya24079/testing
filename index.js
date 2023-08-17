require('dotenv').config();



const fs =require("fs");
const express =require("express");
const axios = require('axios');
const bodyParser = require('body-parser');
const crypto = require("crypto");
const { decryptData, encryptData } =require('./cryptoFunctions.js');

// Destructure env variables...

const {privatekey_psw,PRIVATE_KEY_PATH, PUBLIC_KEY_PATH } = process.env;

// Check if any of the required env variables have NOT been set...
if (!privatekey_psw || !PRIVATE_KEY_PATH || !PUBLIC_KEY_PATH) {
  console.error("\n------ ERROR: Not all 3 required environment variables are set ------");
  // Exit application
  process.exit(1);
}

const privateKeyPassword  =process.env.privatekey_psw;
const privateKeyPath      = process.env.PRIVATE_KEY_PATH;
const elixirPublicKeyPath = process.env.PUBLIC_KEY_PATH;

// Create variables to hold the public/private Key data...
let privateKey;
let elixirPublicKey;

try {
  // Try and read the file contents into the variables...
  privateKey      = fs.readFileSync(privateKeyPath, { encoding: 'utf8' });
  elixirPublicKey = fs.readFileSync(elixirPublicKeyPath, { encoding: 'utf8' });
} 

catch (error) {
  // Required files likely not found, so log error and exit the app.
  console.error('\n------ Error: ', error.message);
  // If we can't open files then we need to exit...
  process.exit(1);
}

// Express variables

// Check if port variable exists from .env file, else default to port 8080
const port = process.env.PORT || 8000;
const app = express();

// Parse text into body of request...
app.use(express.text());
app.use(bodyParser.json());

// Endpoints
app.post('/hook', async (req, res) => {

  try {
    // This Currently ONLY handles data received from Elixir API for activation of the webhook URL

    // Call decryptData function and pass in encryptedData, privateKeyPassword & privateKey.
    const decryptedData = decryptData(req.body, privateKeyPassword, privateKey);

    // If no decryptedData, return 400.
    if (!decryptedData?.data) {
      console.log("!decryptedData.data, returning 400");
      return res.sendStatus(400);
    }

    // Destructure returnThis from decryptedData...
    const { returnThis } = decryptedData.data;

    // If returnThis doesn't exist return 400
    if (!returnThis) {
      console.log("!returnThis, returning 400");
      return res.sendStatus(400);
    }

    // Create a variable containing the encrypted base64 string of returnThis data.
    const returnThisEncrypted = encryptData(returnThis, elixirPublicKey);

    // Set content type and return the 'returnThis' value back to Elixir API...
    res.set('Content-Type', 'text/plain');
    res.status(200).send(returnThisEncrypted);
  }
  catch (error) {
    console.error("Error Main: ", error);
    return res.sendStatus(500);
  }
});


// Test endpoint...
app.get("/", (req, res) => {
  res.send("----------Hello I'm working!----------");
});

/////////////////////////////////////////////////////
//add patient
app.post('/add_patient', (req, res) => {
  const apikey=fs.readFileSync("./Apikey.pem",{encoding:'utf8'});
const teamPrivateKey = fs.readFileSync("./privatekey_add.pem", { encoding: 'utf8' });
const teamPrivateKeyPass = "test";
const elixirPublicKey = fs.readFileSync("./Elixir_PPAPI_PublicKey_add.pem", { encoding: 'utf8' });
  const patientFields=req.body;
  console.log("Data_formate_:",patientFields)
   const cryptoLayer = {
   encrypt(jsonObject) {
    if (!jsonObject) return '';
    const data = JSON.stringify(jsonObject);
    const CHUNK_SIZE = 210;
    const toEncrypt = Buffer.from(data, "utf8");
    const bufs = [];
    for (let i = 0; i < toEncrypt.byteLength; i += CHUNK_SIZE) {
      bufs.push(
        crypto.publicEncrypt(elixirPublicKey, toEncrypt.slice(i, Math.min(i + CHUNK_SIZE, toEncrypt.byteLength)))
      );
    }
    return Buffer.concat(bufs).toString("base64");
  },
  decrypt(encryptedData) {
    const decBuf = Buffer.from(encryptedData, "base64");
    const MOD_BYTES = 256;
    const chunks = [];
    for (let i = 0; i < decBuf.byteLength; i += MOD_BYTES) {
      chunks.push(
        crypto.privateDecrypt({
          key: teamPrivateKey,
          passphrase: teamPrivateKeyPass,
        }, decBuf.slice(i, Math.min(i + MOD_BYTES, decBuf.byteLength)))
      );
    }
    let result = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (typeof (result) === 'string') result = JSON.parse(result);
    return result;
  }
};

const main = async () => {
  const client = axios.create({
    headers: {
      "Content-Type": "application/json",
      "X-Elixir-API-Key": apikey,
    },
    timeout: 15000,
    validateStatus: () => true
  });

  const payload = {
    entropy: crypto.randomBytes(32).toString('hex'),
    data: patientFields
  };

  const res_ = await client.request({
    method: 'POST',
    url: "https://ppapi.elixirapp.nz/patient",
    data: { data: cryptoLayer.encrypt(payload) },
  });

  res.json(cryptoLayer.decrypt(res_.data))
  // Process the response here if needed
};

main().catch(error => {
  console.error(error);
});

  })

app.listen(port, () => {
  console.log(`Webhook Server is listening on port ${ port }`);
});