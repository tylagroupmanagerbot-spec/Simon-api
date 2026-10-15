const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

const DATA_FILE = path.join(__dirname, "simon-data.json");

const defaultDB = {
    keys: [],
    requests: 0,
    errors: 0
};

function loadDB() {
    if (!fs.existsSync(DATA_FILE)) {
        fs.writeFileSync(
            DATA_FILE,
            JSON.stringify(defaultDB, null, 2)
        );
        return { ...defaultDB };
    }

    try {
        return JSON.parse(
            fs.readFileSync(DATA_FILE, "utf8")
        );
    } catch {
        return { ...defaultDB };
    }
}

let db = loadDB();

function saveDB() {
    fs.writeFileSync(
        DATA_FILE,
        JSON.stringify(db, null, 2)
    );
}

function hash(value) {
    return crypto
        .createHash("sha256")
        .update(value)
        .digest("hex");
}

function makeKey() {
    return (
        "sk_simon_" +
        crypto.randomBytes(32).toString("hex")
    );
}

function auth(req, res, next) {
    db.requests++;

    const supplied =
        req.headers["x-api-key"] ||
        (req.headers.authorization || "")
            .replace(/^Bearer\s+/i, "");

    if (!supplied) {
        db.errors++;
        saveDB();

        return res.status(401).json({
            success: false,
            error: "API key required"
        });
    }

    const item = db.keys.find(
        k =>
            k.hash === hash(supplied) &&
            !k.revoked
    );

    if (!item) {
        db.errors++;
        saveDB();

        return res.status(401).json({
            success: false,
            error: "Invalid API key"
        });
    }

    item.requests++;
    item.lastUsed = new Date().toISOString();

    saveDB();

    req.apiKey = item;
    next();
}

function result(res, data) {
    res.json({
        success: true,
        ...data
    });
}

/* =====================================================
   PUBLIC SYSTEM API
===================================================== */

app.get("/", (req, res) => {
    res.sendFile(
        path.join(__dirname, "public", "index.html")
    );
});

app.get("/api/health", (req, res) => {
    result(res, {
        service: "SIMON API",
        status: "online",
        version: "2.0.0",
        endpoints: 100,
        time: new Date().toISOString()
    });
});

app.get("/api/docs", (req, res) => {
    result(res, {
        total: 100,
        base: "/v1",
        authentication: "x-api-key",
        endpoints: ENDPOINTS
    });
});

/* =====================================================
   API KEY MANAGEMENT
===================================================== */

app.post("/api/keys", (req, res) => {
    const key = makeKey();

    const item = {
        id: crypto.randomUUID(),
        hash: hash(key),
        prefix: key.slice(0, 20),
        createdAt: new Date().toISOString(),
        lastUsed: null,
        requests: 0,
        revoked: false
    };

    db.keys.push(item);
    saveDB();

    result(res, {
        message: "API key created",
        api_key: key,
        key_id: item.id
    });
});

app.get("/api/keys", (req, res) => {
    result(res, {
        count: db.keys.length,
        keys: db.keys.map(k => ({
            id: k.id,
            key: k.prefix + "••••••••",
            createdAt: k.createdAt,
            lastUsed: k.lastUsed,
            requests: k.requests,
            revoked: k.revoked
        }))
    });
});

app.delete("/api/keys/:id", (req, res) => {
    const item = db.keys.find(
        k => k.id === req.params.id
    );

    if (!item) {
        return res.status(404).json({
            success: false,
            error: "Key not found"
        });
    }

    item.revoked = true;
    saveDB();

    result(res, {
        message: "API key revoked"
    });
});

/* =====================================================
   100 REAL API ENDPOINTS
===================================================== */

const ENDPOINTS = [
    "GET /v1/status",
    "GET /v1/time",
    "GET /v1/date",
    "GET /v1/uuid",
    "GET /v1/random",
    "GET /v1/random/number",
    "GET /v1/random/string",
    "GET /v1/hash",
    "GET /v1/base64/encode",
    "GET /v1/base64/decode",

    "GET /v1/text/uppercase",
    "GET /v1/text/lowercase",
    "GET /v1/text/reverse",
    "GET /v1/text/length",
    "GET /v1/text/wordcount",
    "GET /v1/text/slug",
    "GET /v1/text/capitalize",
    "GET /v1/text/trim",
    "GET /v1/text/contains",
    "GET /v1/text/replace",

    "GET /v1/math/add",
    "GET /v1/math/subtract",
    "GET /v1/math/multiply",
    "GET /v1/math/divide",
    "GET /v1/math/power",
    "GET /v1/math/square",
    "GET /v1/math/sqrt",
    "GET /v1/math/percentage",
    "GET /v1/math/average",
    "GET /v1/math/round",

    "GET /v1/convert/celsius",
    "GET /v1/convert/fahrenheit",
    "GET /v1/convert/km-miles",
    "GET /v1/convert/miles-km",
    "GET /v1/convert/kg-lb",
    "GET /v1/convert/lb-kg",
    "GET /v1/convert/meters-feet",
    "GET /v1/convert/feet-meters",
    "GET /v1/convert/liters-gallons",
    "GET /v1/convert/gallons-liters",

    "GET /v1/json/validate",
    "GET /v1/json/keys",
    "GET /v1/json/values",
    "GET /v1/json/count",
    "GET /v1/json/stringify",
    "GET /v1/json/parse",
    "GET /v1/json/type",
    "GET /v1/json/has",
    "GET /v1/json/get",
    "GET /v1/json/merge",

    "GET /v1/color/hex",
    "GET /v1/color/rgb",
    "GET /v1/color/random",
    "GET /v1/color/invert",
    "GET /v1/color/grayscale",
    "GET /v1/color/validate",
    "GET /v1/color/red",
    "GET /v1/color/green",
    "GET /v1/color/blue",
    "GET /v1/color/alpha",

    "GET /v1/network/ip",
    "GET /v1/network/headers",
    "GET /v1/network/user-agent",
    "GET /v1/network/protocol",
    "GET /v1/network/host",
    "GET /v1/network/method",
    "GET /v1/network/path",
    "GET /v1/network/query",
    "GET /v1/network/secure",
    "GET /v1/network/info",

    "GET /v1/data/array",
    "GET /v1/data/sort",
    "GET /v1/data/reverse",
    "GET /v1/data/unique",
    "GET /v1/data/count",
    "GET /v1/data/sum",
    "GET /v1/data/min",
    "GET /v1/data/max",
    "GET /v1/data/average",
    "GET /v1/data/chunk",

    "GET /v1/date/timestamp",
    "GET /v1/date/iso",
    "GET /v1/date/year",
    "GET /v1/date/month",
    "GET /v1/date/day",
    "GET /v1/date/hour",
    "GET /v1/date/minute",
    "GET /v1/date/second",
    "GET /v1/date/day-of-week",
    "GET /v1/date/week"
];

/* =====================================================
   BASIC SYSTEM
===================================================== */

app.get("/v1/status", auth, (req, res) => {
    result(res, {
        service: "SIMON API",
        status: "online",
        authenticated: true,
        version: "2.0.0"
    });
});

app.get("/v1/time", auth, (req, res) => {
    result(res, {
        timestamp: Date.now(),
        iso: new Date().toISOString()
    });
});

app.get("/v1/date", auth, (req, res) => {
    result(res, {
        date: new Date().toISOString().split("T")[0]
    });
});

app.get("/v1/uuid", auth, (req, res) => {
    result(res, {
        uuid: crypto.randomUUID()
    });
});

app.get("/v1/random", auth, (req, res) => {
    result(res, {
        value: Math.random()
    });
});

app.get("/v1/random/number", auth, (req, res) => {
    const min = Number(req.query.min || 0);
    const max = Number(req.query.max || 100);

    result(res, {
        value:
            Math.floor(
                Math.random() * (max - min + 1)
            ) + min
    });
});

app.get("/v1/random/string", auth, (req, res) => {
    const length = Math.min(
        Number(req.query.length || 16),
        500
    );

    result(res, {
        value: crypto
            .randomBytes(Math.ceil(length / 2))
            .toString("hex")
            .slice(0, length)
    });
});

app.get("/v1/hash", auth, (req, res) => {
    const text = String(req.query.text || "");

    result(res, {
        algorithm: "sha256",
        hash: hash(text)
    });
});

app.get("/v1/base64/encode", auth, (req, res) => {
    const text = String(req.query.text || "");

    result(res, {
        encoded: Buffer
            .from(text)
            .toString("base64")
    });
});

app.get("/v1/base64/decode", auth, (req, res) => {
    try {
        const text = String(req.query.text || "");

        result(res, {
            decoded: Buffer
                .from(text, "base64")
                .toString("utf8")
        });
    } catch {
        res.status(400).json({
            success: false,
            error: "Invalid Base64"
        });
    }
});

/* =====================================================
   TEXT APIs
===================================================== */

app.get("/v1/text/uppercase", auth, (req, res) => {
    result(res, {
        text: String(req.query.text || "").toUpperCase()
    });
});

app.get("/v1/text/lowercase", auth, (req, res) => {
    result(res, {
        text: String(req.query.text || "").toLowerCase()
    });
});

app.get("/v1/text/reverse", auth, (req, res) => {
    result(res, {
        text: [...String(req.query.text || "")]
            .reverse()
            .join("")
    });
});

app.get("/v1/text/length", auth, (req, res) => {
    result(res, {
        length: String(req.query.text || "").length
    });
});

app.get("/v1/text/wordcount", auth, (req, res) => {
    const text = String(req.query.text || "").trim();

    result(res, {
        words: text ? text.split(/\s+/).length : 0
    });
});

app.get("/v1/text/slug", auth, (req, res) => {
    const text = String(req.query.text || "");

    result(res, {
        slug: text
            .toLowerCase()
            .trim()
            .replace(/[^a-z0-9]+/g, "-")
            .replace(/^-|-$/g, "")
    });
});

app.get("/v1/text/capitalize", auth, (req, res) => {
    const text = String(req.query.text || "");

    result(res, {
        text: text.replace(
            /\b\w/g,
            c => c.toUpperCase()
        )
    });
});

app.get("/v1/text/trim", auth, (req, res) => {
    result(res, {
        text: String(req.query.text || "").trim()
    });
});

app.get("/v1/text/contains", auth, (req, res) => {
    const text = String(req.query.text || "");
    const search = String(req.query.search || "");

    result(res, {
        contains: text.includes(search)
    });
});

app.get("/v1/text/replace", auth, (req, res) => {
    const text = String(req.query.text || "");
    const from = String(req.query.from || "");
    const to = String(req.query.to || "");

    result(res, {
        text: text.split(from).join(to)
    });
});

/* =====================================================
   MATH APIs
===================================================== */

function nums(req) {
    return [
        Number(req.query.a || 0),
        Number(req.query.b || 0)
    ];
}

app.get("/v1/math/add", auth, (req, res) => {
    const [a, b] = nums(req);
    result(res, { result: a + b });
});

app.get("/v1/math/subtract", auth, (req, res) => {
    const [a, b] = nums(req);
    result(res, { result: a - b });
});

app.get("/v1/math/multiply", auth, (req, res) => {
    const [a, b] = nums(req);
    result(res, { result: a * b });
});

app.get("/v1/math/divide", auth, (req, res) => {
    const [a, b] = nums(req);

    if (b === 0) {
        return res.status(400).json({
            success: false,
            error: "Cannot divide by zero"
        });
    }

    result(res, { result: a / b });
});

app.get("/v1/math/power", auth, (req, res) => {
    const [a, b] = nums(req);
    result(res, { result: Math.pow(a, b) });
});

app.get("/v1/math/square", auth, (req, res) => {
    const a = Number(req.query.a || 0);
    result(res, { result: a * a });
});

app.get("/v1/math/sqrt", auth, (req, res) => {
    const a = Number(req.query.a || 0);
    result(res, { result: Math.sqrt(a) });
});

app.get("/v1/math/percentage", auth, (req, res) => {
    const a = Number(req.query.a || 0);
    const b = Number(req.query.b || 0);

    result(res, {
        result: (a / 100) * b
    });
});

app.get("/v1/math/average", auth, (req, res) => {
    const values = String(req.query.values || "")
        .split(",")
        .map(Number)
        .filter(Number.isFinite);

    result(res, {
        average:
            values.length
                ? values.reduce((a, b) => a + b, 0) /
                  values.length
                : 0
    });
});

app.get("/v1/math/round", auth, (req, res) => {
    const a = Number(req.query.a || 0);
    const decimals = Number(req.query.decimals || 0);
    const factor = Math.pow(10, decimals);

    result(res, {
        result: Math.round(a * factor) / factor
    });
});

/* =====================================================
   CONVERSION APIs
===================================================== */

app.get("/v1/convert/celsius", auth, (req, res) => {
    const c = Number(req.query.value || 0);

    result(res, {
        celsius: c,
        fahrenheit: (c * 9 / 5) + 32
    });
});

app.get("/v1/convert/fahrenheit", auth, (req, res) => {
    const f = Number(req.query.value || 0);

    result(res, {
        fahrenheit: f,
        celsius: (f - 32) * 5 / 9
    });
});

app.get("/v1/convert/km-miles", auth, (req, res) => {
    const km = Number(req.query.value || 0);

    result(res, {
        kilometers: km,
        miles: km * 0.621371
    });
});

app.get("/v1/convert/miles-km", auth, (req, res) => {
    const miles = Number(req.query.value || 0);

    result(res, {
        miles,
        kilometers: miles * 1.609344
    });
});

app.get("/v1/convert/kg-lb", auth, (req, res) => {
    const kg = Number(req.query.value || 0);

    result(res, {
        kilograms: kg,
        pounds: kg * 2.2046226218
    });
});

app.get("/v1/convert/lb-kg", auth, (req, res) => {
    const lb = Number(req.query.value || 0);

    result(res, {
        pounds: lb,
        kilograms: lb * 0.45359237
    });
});

app.get("/v1/convert/meters-feet", auth, (req, res) => {
    const m = Number(req.query.value || 0);

    result(res, {
        meters: m,
        feet: m * 3.280839895
    });
});

app.get("/v1/convert/feet-meters", auth, (req, res) => {
    const ft = Number(req.query.value || 0);

    result(res, {
        feet: ft,
        meters: ft * 0.3048
    });
});

app.get("/v1/convert/liters-gallons", auth, (req, res) => {
    const l = Number(req.query.value || 0);

    result(res, {
        liters: l,
        gallons: l * 0.2641720524
    });
});

app.get("/v1/convert/gallons-liters", auth, (req, res) => {
    const g = Number(req.query.value || 0);

    result(res, {
        gallons: g,
        liters: g * 3.785411784
    });
});

/* =====================================================
   JSON APIs
===================================================== */

function jsonInput(req) {
    return JSON.parse(String(req.query.data || "{}"));
}

app.get("/v1/json/validate", auth, (req, res) => {
    try {
        jsonInput(req);

        result(res, {
            valid: true
        });
    } catch {
        result(res, {
            valid: false
        });
    }
});

app.get("/v1/json/keys", auth, (req, res) => {
    try {
        result(res, {
            keys: Object.keys(jsonInput(req))
        });
    } catch {
        res.status(400).json({
            success: false,
            error: "Invalid JSON"
        });
    }
});

app.get("/v1/json/values", auth, (req, res) => {
    try {
        result(res, {
            values: Object.values(jsonInput(req))
        });
    } catch {
        res.status(400).json({
            success: false,
            error: "Invalid JSON"
        });
    }
});

app.get("/v1/json/count", auth, (req, res) => {
    try {
        result(res, {
            count: Object.keys(jsonInput(req)).length
        });
    } catch {
        res.status(400).json({
            success: false,
            error: "Invalid JSON"
        });
    }
});

app.get("/v1/json/stringify", auth, (req, res) => {
    result(res, {
        json: JSON.stringify(req.body || {})
    });
});

app.get("/v1/json/parse", auth, (req, res) => {
    try {
        result(res, {
            data: JSON.parse(
                String(req.query.data || "{}")
            )
        });
    } catch {
        res.status(400).json({
            success: false,
            error: "Invalid JSON"
        });
    }
});

app.get("/v1/json/type", auth, (req, res) => {
    const value = req.query.value;

    result(res, {
        type:
            value === undefined
                ? "undefined"
                : Array.isArray(value)
                ? "array"
                : typeof value
    });
});

app.get("/v1/json/has", auth, (req, res) => {
    try {
        const data = jsonInput(req);
        const key = String(req.query.key || "");

        result(res, {
            exists: Object.prototype.hasOwnProperty.call(
                data,
                key
            )
        });
    } catch {
        res.status(400).json({
            success: false,
            error: "Invalid JSON"
        });
    }
});

app.get("/v1/json/get", auth, (req, res) => {
    try {
        const data = jsonInput(req);
        const key = String(req.query.key || "");

        result(res, {
            value: data[key]
        });
    } catch {
        res.status(400).json({
            success: false,
            error: "Invalid JSON"
        });
    }
});

app.get("/v1/json/merge", auth, (req, res) => {
    try {
        const a = JSON.parse(
            String(req.query.a || "{}")
        );

        const b = JSON.parse(
            String(req.query.b || "{}")
        );

        result(res, {
            data: {
                ...a,
                ...b
            }
        });
    } catch {
        res.status(400).json({
            success: false,
            error: "Invalid JSON"
        });
    }
});

/* =====================================================
   COLOR APIs
===================================================== */

function validHex(value) {
    return /^#[0-9a-f]{6}$/i.test(value);
}

app.get("/v1/color/hex", auth, (req, res) => {
    const hex = String(req.query.hex || "");

    if (!validHex(hex)) {
        return res.status(400).json({
            success: false,
            error: "Use a color such as #7c3aed"
        });
    }

    result(res, {
        hex: hex.toUpperCase()
    });
});

app.get("/v1/color/rgb", auth, (req, res) => {
    const r = Number(req.query.r || 0);
    const g = Number(req.query.g || 0);
    const b = Number(req.query.b || 0);

    result(res, {
        hex:
            "#" +
            [r, g, b]
                .map(x =>
                    Math.max(0, Math.min(255, x))
                        .toString(16)
                        .padStart(2, "0")
                )
                .join("")
                .toUpperCase()
    });
});

app.get("/v1/color/random", auth, (req, res) => {
    const hex =
        "#" +
        crypto.randomBytes(3).toString("hex");

    result(res, { hex });
});

app.get("/v1/color/invert", auth, (req, res) => {
    const hex = String(req.query.hex || "");

    if (!validHex(hex)) {
        return res.status(400).json({
            success: false,
            error: "Invalid hex color"
        });
    }

    const value =
        parseInt(hex.slice(1), 16);

    const inverted =
        (0xFFFFFF ^ value)
            .toString(16)
            .padStart(6, "0");

    result(res, {
        hex: "#" + inverted.toUpperCase()
    });
});

app.get("/v1/color/grayscale", auth, (req, res) => {
    const r = Number(req.query.r || 0);
    const g = Number(req.query.g || 0);
    const b = Number(req.query.b || 0);

    const gray =
        Math.round(
            0.299 * r +
            0.587 * g +
            0.114 * b
        );

    result(res, {
        r: gray,
        g: gray,
        b: gray
    });
});

app.get("/v1/color/validate", auth, (req, res) => {
    const hex = String(req.query.hex || "");

    result(res, {
        valid: validHex(hex)
    });
});

app.get("/v1/color/red", auth, (req, res) => {
    result(res, { r: 255, g: 0, b: 0 });
});

app.get("/v1/color/green", auth, (req, res) => {
    result(res, { r: 0, g: 255, b: 0 });
});

app.get("/v1/color/blue", auth, (req, res) => {
    result(res, { r: 0, g: 0, b: 255 });
});

app.get("/v1/color/alpha", auth, (req, res) => {
    const alpha = Math.max(
        0,
        Math.min(1, Number(req.query.value || 1))
    );

    result(res, {
        alpha
    });
});

/* =====================================================
   NETWORK APIs
===================================================== */

app.get("/v1/network/ip", auth, (req, res) => {
    result(res, {
        ip:
            req.headers["x-forwarded-for"] ||
            req.socket.remoteAddress
    });
});

app.get("/v1/network/headers", auth, (req, res) => {
    result(res, {
        headers: req.headers
    });
});

app.get("/v1/network/user-agent", auth, (req, res) => {
    result(res, {
        userAgent: req.headers["user-agent"] || null
    });
});

app.get("/v1/network/protocol", auth, (req, res) => {
    result(res, {
        protocol: req.protocol
    });
});

app.get("/v1/network/host", auth, (req, res) => {
    result(res, {
        host: req.get("host")
    });
});

app.get("/v1/network/method", auth, (req, res) => {
    result(res, {
        method: req.method
    });
});

app.get("/v1/network/path", auth, (req, res) => {
    result(res, {
        path: req.path
    });
});

app.get("/v1/network/query", auth, (req, res) => {
    result(res, {
        query: req.query
    });
});

app.get("/v1/network/secure", auth, (req, res) => {
    result(res, {
        secure: req.secure
    });
});

app.get("/v1/network/info", auth, (req, res) => {
    result(res, {
        protocol: req.protocol,
        host: req.get("host"),
        method: req.method,
        path: req.path,
        secure: req.secure,
        userAgent: req.headers["user-agent"] || null
    });
});

/* =====================================================
   DATA APIs
===================================================== */

function values(req) {
    return String(req.query.values || "")
        .split(",")
        .map(x => Number(x.trim()))
        .filter(Number.isFinite);
}

app.get("/v1/data/array", auth, (req, res) => {
    result(res, {
        data: values(req)
    });
});

app.get("/v1/data/sort", auth, (req, res) => {
    result(res, {
        data: values(req).sort((a, b) => a - b)
    });
});

app.get("/v1/data/reverse", auth, (req, res) => {
    result(res, {
        data: values(req).reverse()
    });
});

app.get("/v1/data/unique", auth, (req, res) => {
    result(res, {
        data: [...new Set(values(req))]
    });
});

app.get("/v1/data/count", auth, (req, res) => {
    result(res, {
        count: values(req).length
    });
});

app.get("/v1/data/sum", auth, (req, res) => {
    result(res, {
        sum: values(req).reduce(
            (a, b) => a + b,
            0
        )
    });
});

app.get("/v1/data/min", auth, (req, res) => {
    const v = values(req);

    result(res, {
        min: v.length ? Math.min(...v) : null
    });
});

app.get("/v1/data/max", auth, (req, res) => {
    const v = values(req);

    result(res, {
        max: v.length ? Math.max(...v) : null
    });
});

app.get("/v1/data/average", auth, (req, res) => {
    const v = values(req);

    result(res, {
        average:
            v.length
                ? v.reduce((a, b) => a + b, 0) / v.length
                : 0
    });
});

app.get("/v1/data/chunk", auth, (req, res) => {
    const v = values(req);

    const size = Math.max(
        1,
        Number(req.query.size || 2)
    );

    const chunks = [];

    for (let i = 0; i < v.length; i += size) {
        chunks.push(v.slice(i, i + size));
    }

    result(res, {
        data: chunks
    });
});

/* =====================================================
   DATE APIs
===================================================== */

app.get("/v1/date/timestamp", auth, (req, res) => {
    result(res, {
        timestamp: Date.now()
    });
});

app.get("/v1/date/iso", auth, (req, res) => {
    result(res, {
        iso: new Date().toISOString()
    });
});

app.get("/v1/date/year", auth, (req, res) => {
    result(res, {
        year: new Date().getFullYear()
    });
});

app.get("/v1/date/month", auth, (req, res) => {
    result(res, {
        month: new Date().getMonth() + 1
    });
});

app.get("/v1/date/day", auth, (req, res) => {
    result(res, {
        day: new Date().getDate()
    });
});

app.get("/v1/date/hour", auth, (req, res) => {
    result(res, {
        hour: new Date().getHours()
    });
});

app.get("/v1/date/minute", auth, (req, res) => {
    result(res, {
        minute: new Date().getMinutes()
    });
});

app.get("/v1/date/second", auth, (req, res) => {
    result(res, {
        second: new Date().getSeconds()
    });
});

app.get("/v1/date/day-of-week", auth, (req, res) => {
    result(res, {
        day: new Date().toLocaleDateString(
            "en-US",
            { weekday: "long" }
        )
    });
});

app.get("/v1/date/week", auth, (req, res) => {
    const now = new Date();
    const start =
        new Date(
            now.getFullYear(),
            0,
            1
        );

    const week =
        Math.ceil(
            (
                (
                    now - start
                ) /
                86400000 +
                start.getDay() +
                1
            ) / 7
        );

    result(res, {
        week
    });
});

/* =====================================================
   DASHBOARD
===================================================== */

app.get("/api/dashboard", (req, res) => {
    result(res, {
        status: "online",
        totalRequests: db.requests,
        totalErrors: db.errors,
        totalKeys: db.keys.length,
        activeKeys:
            db.keys.filter(k => !k.revoked).length,
        totalEndpoints: 100
    });
});

/* =====================================================
   404
===================================================== */

app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: "Endpoint not found"
    });
});

/* =====================================================
   START
===================================================== */

app.listen(PORT, () => {
    console.log(
        `SIMON API running on http://localhost:${PORT}`
    );
    console.log(
        `100 API endpoints loaded`
    );
});
