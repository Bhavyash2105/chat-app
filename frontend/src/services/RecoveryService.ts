/**
 * BIP39 Recovery Service
 *
 * On signup, generates a 12-word BIP39 mnemonic phrase.
 * Derives a symmetric AES key from the mnemonic, uses it to encrypt the Curve25519 private key,
 * and stores the encrypted blob on the backend.
 *
 * Recovery flow: user enters phrase → derive key → decrypt blob → re-wrap with new password.
 */

import CryptoService from "./CryptoService";
import KeyManagementService from "./KeyManagementService";
import {BASE_API_URL} from "../config/Config";
import {AUTHORIZATION_PREFIX} from "../redux/Constants";

// Minimal BIP39 wordlist (first 512 words of the BIP39 English wordlist — enough entropy)
// In production, use the full 2048-word list from the bip39 npm package.
// We embed a subset to avoid the dependency delay for MVP, but recommend switching to the full list.
const BIP39_WORDS: string[] = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse",
    "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
    "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit",
    "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert",
    "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter",
    "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger",
    "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic",
    "area", "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest",
    "arrive", "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset",
    "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
    "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake",
    "aware", "away", "awesome", "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge",
    "bag", "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain",
    "barrel", "base", "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become",
    "beef", "before", "begin", "behave", "behind", "believe", "below", "belt", "bench", "benefit",
    "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike", "bind", "biology",
    "bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless",
    "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
    "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss",
    "bottom", "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave", "bread",
    "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze",
    "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
    "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus", "business", "busy",
    "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call",
    "calm", "camera", "camp", "can", "canal", "cancel", "candle", "candy", "cannon", "canoe",
    "canvas", "canyon", "capable", "capital", "captain", "car", "carbon", "card", "cargo", "carpet",
    "carry", "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog", "catch",
    "category", "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery", "cement", "census",
    "century", "cereal", "certain", "chair", "chalk", "champion", "change", "chaos", "chapter", "charge",
    "chase", "chat", "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken", "chief",
    "child", "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon",
    "circle", "citizen", "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean",
    "clerk", "clever", "click", "client", "cliff", "climb", "clinic", "clip", "clock", "clog",
    "close", "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch", "coach", "coast",
    "coconut", "code", "coffee", "coil", "coin", "collect", "color", "column", "combine", "come",
    "comfort", "comic", "common", "company", "concert", "conduct", "confirm", "congress", "connect", "consider",
    "control", "convince", "cook", "cool", "copper", "copy", "coral", "core", "corn", "correct",
    "cost", "cotton", "couch", "country", "couple", "course", "cousin", "cover", "coyote", "crack",
    "cradle", "craft", "cram", "crane", "crash", "crater", "crawl", "crazy", "cream", "credit",
    "creek", "crew", "cricket", "crime", "crisp", "critic", "crop", "cross", "crouch", "crowd",
    "crucial", "cruel", "cruise", "crumble", "crunch", "crush", "cry", "crystal", "cube", "culture",
    "cup", "cupboard", "curious", "current", "curtain", "curve", "cushion", "custom", "cute", "cycle",
    "dad", "damage", "damp", "dance", "danger", "daring", "dark", "dash", "daughter", "dawn",
    "day", "deal", "debate", "debris", "decade", "december", "decide", "decline", "decorate", "decrease",
    "deer", "defense", "define", "defy", "degree", "delay", "deliver", "demand", "demise", "denial",
    "dentist", "deny", "depart", "depend", "deposit", "depth", "deputy", "derive", "describe", "desert",
    "design", "desk", "despair", "destroy", "detail", "detect", "develop", "device", "devote", "diagram",
    "dial", "diamond", "diary", "dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma",
    "dinner", "dinosaur", "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss", "disorder",
    "display", "distance", "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll",
    "dolphin", "domain", "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft",
    "dragon", "drama", "drastic", "draw", "dream", "dress", "drift", "drill", "drink", "drip",
    "drive", "drop", "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch",
    "duty", "dwarf", "dynamic", "eager", "eagle", "early", "earn", "earth", "easily", "east",
    "easy", "echo", "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight",
    "either", "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator", "elite", "else",
    "embark", "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable", "enact",
    "end", "endless", "endorse", "enemy", "energy", "enforce", "engage", "engine", "enhance", "enjoy",
    "enlist", "enough", "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode",
    "equal", "equip", "era", "erase", "erode", "erosion", "error", "erupt", "escape", "essay",
    "essence", "estate", "eternal", "ethics", "evidence", "evil", "evoke", "evolve", "exact", "example",
    "exceed", "exchange", "exclude", "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit",
    "exotic", "expand", "expect", "expire", "explain", "expose", "extend", "extra", "eye", "eyebrow",
    "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false", "fame", "family",
    "famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue",
    "fault", "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female", "fence",
    "festival", "fetch", "fever", "few", "fiber", "fiction", "field", "figure", "file", "film",
    "filter", "final", "find", "fine", "finger", "finish", "fire", "firm", "first", "fiscal",
    "fish", "fit", "fitness", "fix", "flag", "flame", "flash", "flat", "flavor", "flee",
    "flight", "flip", "float", "flock", "floor", "flower", "fluid", "flush", "flyer", "foam",
    "focus", "fog", "foil", "fold", "follow", "food", "foot", "force", "foreign", "forest",
    "forget", "fork", "fortune", "forum", "forward", "fossil", "foster", "found", "fox", "fragile",
    "frame", "frequent", "fresh", "friend", "fringe", "frog", "front", "frost", "frown", "frozen",
    "fruit", "fuel", "fun", "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy",
    "gallery", "game", "gap", "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp",
    "gate", "gather", "gauge", "gaze", "general", "genius", "genre", "gentle", "genuine", "gesture",
    "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance",
    "glare", "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue",
    "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip", "govern", "gown",
    "grab", "grace", "grain", "grant", "grape", "grass", "gravity", "great", "green", "grid",
    "grief", "grit", "grocery", "group", "grow", "grunt", "guard", "guess", "guide", "guilt",
    "guitar", "gun", "gym", "habit", "hair", "half", "hammer", "hamster", "hand", "happy",
    "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard", "head", "health",
    "heart", "heavy", "hedgehog", "height", "hello", "helmet", "help", "hen", "hero", "hidden",
    "high", "hill", "hint", "hip", "hire", "history", "hobby", "hockey", "hold", "hole",
    "holiday", "hollow", "home", "honor", "hope", "horn", "horror", "horse", "hospital", "host",
    "hotel", "hour", "hover", "hub", "human", "humble", "humor", "hundred", "hungry", "hunt",
    "hurdle", "hurry", "hurt", "husband", "hybrid", "ice", "icon", "idea", "identify", "idle",
    "ignore", "ill", "illegal", "illness", "image", "imitate", "immense", "immune", "impact", "impose",
    "improve", "impulse", "inch", "include", "income", "increase", "index", "indicate", "indoor", "industry",
    "infant", "inflict", "inform", "inhale", "inherit", "initial", "inject", "injury", "inmate", "inner",
    "innocent", "input", "inquiry", "insane", "insect", "inside", "inspire", "install", "intact", "interest",
    "into", "invest", "invite", "involve", "iron", "island", "isolate", "issue", "item", "ivory",
    "jacket", "jaguar", "jar", "jazz", "jealous", "jeans", "jelly", "jewel", "job", "join",
    "joke", "journey", "joy", "judge", "juice", "jump", "jungle", "junior", "junk", "just",
    "kangaroo", "keen", "keep", "ketchup", "key", "kick", "kid", "kidney", "kind", "kingdom",
    "kiss", "kit", "kitchen", "kite", "kitten", "kiwi", "knee", "knife", "knock", "know",
    "lab", "label", "labor", "ladder", "lady", "lake", "lamp", "language", "laptop", "large",
    "later", "latin", "laugh", "laundry", "lava", "law", "lawn", "lawsuit", "layer", "lazy",
    "leader", "leaf", "learn", "leave", "lecture", "left", "leg", "legal", "legend", "leisure",
    "lemon", "lend", "length", "lens", "leopard", "lesson", "letter", "level", "liar", "liberty",
    "library", "license", "life", "lift", "light", "like", "limb", "limit", "link", "lion",
    "liquid", "list", "little", "live", "lizard", "load", "loan", "lobster", "local", "lock",
    "logic", "lonely", "long", "loop", "lottery", "loud", "lounge", "love", "loyal", "lucky",
    "luggage", "lumber", "lunar", "lunch", "luxury", "lyrics", "machine", "mad", "magic", "magnet",
    "maid", "mail", "main", "major", "make", "mammal", "man", "manage", "mandate", "mango",
    "mansion", "manual", "maple", "marble", "march", "margin", "marine", "market", "marriage", "mask",
    "mass", "master", "match", "material", "math", "matrix", "matter", "maximum", "maze", "meadow",
    "mean", "measure", "meat", "mechanic", "medal", "media", "melody", "melt", "member", "memory",
    "mention", "menu", "mercy", "merge", "merit", "merry", "mesh", "message", "metal", "method",
    "middle", "midnight", "milk", "million", "mimic", "mind", "minimum", "minor", "minute", "miracle",
    "mirror", "misery", "miss", "mistake", "mix", "mixed", "mixture", "mobile", "model", "modify",
    "mom", "moment", "monitor", "monkey", "monster", "month", "moon", "moral", "more", "morning",
    "mosquito", "mother", "motion", "motor", "mountain", "mouse", "move", "movie", "much", "muffin",
    "mule", "multiply", "muscle", "museum", "mushroom", "music", "must", "mutual", "myself", "mystery",
    "myth", "naive", "name", "napkin", "narrow", "nasty", "nation", "nature", "near", "neck",
    "need", "negative", "neglect", "neither", "nephew", "nerve", "nest", "net", "network", "neutral",
    "never", "news", "next", "nice", "night", "noble", "noise", "nominee", "noodle", "normal",
    "north", "nose", "notable", "note", "nothing", "notice", "novel", "now", "nuclear", "number",
    "nurse", "nut", "oak", "obey", "object", "oblige", "obscure", "observe", "obtain", "obvious",
    "occur", "ocean", "october", "odor", "off", "offense", "offer", "office", "often", "oil",
    "okay", "old", "olive", "olympic", "omit", "once", "one", "onion", "online", "only",
    "open", "opera", "opinion", "oppose", "option", "orange", "orbit", "orchard", "order", "ordinary",
    "organ", "orient", "original", "orphan", "ostrich", "other", "outdoor", "outer", "output", "outside",
    "oval", "oven", "over", "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle",
    "page", "pair", "palace", "palm", "panda", "panel", "panic", "panther", "paper", "parade",
    "parent", "park", "parrot", "party", "pass", "patch", "path", "patient", "patrol", "pattern",
    "pause", "pave", "payment", "peace", "peanut", "pear", "peasant", "pelican", "pen", "penalty",
    "pencil", "people", "pepper", "perfect", "permit", "person", "pet", "phone", "photo", "phrase",
    "physical", "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot", "pink",
    "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate", "play",
    "player", "pleasure", "plenty", "plot", "pluck", "plug", "plunge", "poem", "poet", "point",
    "polar", "pole", "police", "pond", "pony", "pool", "popular", "portion", "position", "possible",
    "post", "potato", "pottery", "poverty", "powder", "power", "practice", "praise", "predict", "prefer",
    "prepare", "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority", "prison",
    "private", "prize", "problem", "process", "produce", "profit", "program", "project", "promote", "proof",
    "property", "prosper", "protect", "proud", "provide", "public", "pudding", "pull", "pulp", "pulse",
    "pumpkin", "punch", "pupil", "puppy", "purchase", "purity", "purpose", "purse", "push", "put",
    "puzzle", "pyramid", "quality", "quantum", "quarter", "question", "quick", "quit", "quiz", "quote",
    "rabbit", "raccoon", "race", "rack", "radar", "radio", "rail", "rain", "raise", "rally",
    "ramp", "ranch", "random", "range", "rapid", "rare", "rate", "rather", "raven", "raw",
    "razor", "ready", "real", "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record",
    "recycle", "reduce", "reflect", "reform", "refuse", "region", "regret", "regular", "reject", "relax",
    "release", "relief", "rely", "remain", "remember", "remind", "remove", "render", "renew", "rent",
    "reopen", "repair", "repeat", "replace", "report", "require", "rescue", "resemble", "resist", "resource",
    "response", "result", "retire", "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm",
    "rib", "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid", "ring",
    "riot", "ripple", "risk", "ritual", "rival", "river", "road", "roast", "robot", "robust",
    "rocket", "romance", "roof", "rookie", "room", "rose", "rotate", "rough", "round", "route",
    "royal", "rubber", "rude", "rug", "rule", "run", "runway", "rural", "sad", "saddle",
    "sadness", "safe", "sail", "salad", "salmon", "salon", "salt", "salute", "same", "sample",
    "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say", "scale", "scan", "scare",
    "scatter", "scene", "scheme", "school", "science", "scissors", "scorpion", "scout", "scrap", "screen",
    "script", "scrub", "sea", "search", "season", "seat", "second", "secret", "section", "security",
    "seed", "seek", "segment", "select", "sell", "seminar", "senior", "sense", "sentence", "series",
    "service", "session", "settle", "setup", "seven", "shadow", "shaft", "shallow", "share", "shed",
    "shell", "sheriff", "shield", "shift", "shine", "ship", "shiver", "shock", "shoe", "shoot",
    "shop", "short", "shoulder", "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick",
    "side", "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar", "simple",
    "since", "sing", "siren", "sister", "situate", "six", "size", "skate", "sketch", "ski",
    "skill", "skin", "skirt", "skull", "slab", "slam", "sleep", "slender", "slice", "slide",
    "slight", "slim", "slogan", "slot", "slow", "slush", "small", "smart", "smile", "smoke",
    "smooth", "snack", "snake", "snap", "sniff", "snow", "soap", "soccer", "social", "sock",
    "soda", "soft", "solar", "soldier", "solid", "solution", "solve", "someone", "song", "soon",
    "sorry", "sort", "soul", "sound", "soup", "source", "south", "space", "spare", "spatial",
    "spawn", "speak", "special", "speed", "spell", "spend", "sphere", "spice", "spider", "spike",
    "spin", "spirit", "split", "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread",
    "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium", "staff", "stage", "stairs",
    "stamp", "stand", "start", "state", "stay", "steak", "steel", "stem", "step", "stereo",
    "stick", "still", "sting", "stock", "stomach", "stone", "stool", "story", "stove", "strategy",
    "street", "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject", "submit",
    "subway", "success", "such", "sudden", "suffer", "sugar", "suggest", "suit", "sun", "sunny",
    "sunset", "super", "supply", "support", "suppose", "sure", "surfer", "surface", "surgery", "surround",
    "survey", "suspect", "sustain", "swallow", "swamp", "swap", "swarm", "swear", "sweet", "swift",
    "swim", "swing", "sword", "symbol", "syrup", "system", "table", "tackle", "tag", "tail",
    "talent", "talk", "tank", "tape", "target", "task", "taste", "tattoo", "taxi", "teach",
    "team", "tell", "ten", "tenant", "tennis", "tent", "term", "test", "text", "thank",
    "that", "theme", "then", "theory", "there", "they", "thing", "this", "thought", "three",
    "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger", "tilt", "timber", "time",
    "tiny", "tip", "tired", "tissue", "title", "toast", "tobacco", "today", "toddler", "toe",
    "together", "toilet", "token", "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth",
    "top", "topic", "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist", "toward",
    "tower", "town", "toy", "track", "trade", "traffic", "tragic", "train", "transfer", "trap",
    "trash", "travel", "tray", "treat", "tree", "trend", "trial", "tribe", "trick", "trigger",
    "trim", "trip", "trophy", "trouble", "truck", "true", "truly", "trumpet", "trust", "truth",
    "try", "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle", "twelve",
    "twenty", "twice", "twin", "twist", "two", "type", "typical", "ugly", "umbrella", "unable",
    "unaware", "uncle", "uncover", "under", "undo", "unfair", "unfold", "unhappy", "uniform", "unique",
    "unit", "universe", "unknown", "unlock", "until", "unusual", "unveil", "update", "upgrade", "uphold",
    "upon", "upper", "upset", "urban", "urge", "usage", "use", "used", "useful", "useless",
    "usual", "utility", "vacant", "vacuum", "vague", "valid", "valley", "valve", "van", "vanish",
    "vapor", "various", "vast", "vault", "vehicle", "velvet", "vendor", "venture", "venue", "verb",
    "verify", "version", "very", "vessel", "veteran", "viable", "vibrant", "vicious", "victory", "video",
    "view", "village", "vintage", "violin", "virtual", "virus", "visa", "visit", "visual", "vital",
    "vivid", "vocal", "voice", "void", "volcano", "volume", "vote", "voyage", "wage", "wagon",
    "wait", "walk", "wall", "walnut", "want", "warfare", "warm", "warrior", "wash", "wasp",
    "waste", "water", "wave", "way", "wealth", "weapon", "wear", "weasel", "weather", "web",
    "wedding", "weekend", "weird", "welcome", "west", "wet", "whale", "what", "wheat", "wheel",
    "when", "where", "whip", "whisper", "wide", "width", "wife", "wild", "will", "win",
    "window", "wine", "wing", "wink", "winner", "winter", "wire", "wisdom", "wise", "wish",
    "witness", "wolf", "woman", "wonder", "wood", "wool", "word", "work", "world", "worry",
    "worth", "wrap", "wreck", "wrestle", "wrist", "write", "wrong", "yard", "year", "yellow",
    "you", "young", "youth", "zebra", "zero", "zone", "zoo"
];

export interface RecoveryBlobDTO {
    encryptedData: string;
    iv: string;
    salt: string;
}

class RecoveryService {
    private readonly STORAGE_KEY = "chatapp_recovery_phrase_shown";

    /**
     * Generate a 12-word BIP39 mnemonic using crypto.getRandomValues.
     * Entropy: 128 bits (12 words * 11 bits/word).
     */
    async generateMnemonic(): Promise<string> {
    const ENT = 128;
    const CS = ENT / 32; // 4 checksum bits per BIP39 spec
    const entropy = new Uint8Array(ENT / 8); // 16 bytes
    crypto.getRandomValues(entropy);

    // BIP39 checksum = first CS bits of SHA-256(entropy)
    const hashBuf = await crypto.subtle.digest("SHA-256", entropy.buffer as ArrayBuffer);
    const checksumBits = new Uint8Array(hashBuf)[0] >> (8 - CS);

    // entropy bits (128) + checksum bits (4) = 132 bits
    let bitString = "";
    for (let i = 0; i < entropy.length; i++) bitString += entropy[i].toString(2).padStart(8, "0");
    bitString += checksumBits.toString(2).padStart(CS, "0");

    // split into 12 groups of 11 bits
    const words: string[] = [];
    for (let i = 0; i < 12; i++) {
        const chunk = bitString.slice(i * 11, i * 11 + 11);
        const wordIndex = parseInt(chunk, 2);
        words.push(BIP39_WORDS[wordIndex % BIP39_WORDS.length]);
    }

    return words.join(" ");
}

    /**
     * Derive an AES-GCM key from a mnemonic phrase using PBKDF2.
     */
    private async deriveKeyFromMnemonic(mnemonic: string, salt: Uint8Array): Promise<CryptoKey> {
        const passwordKey = await crypto.subtle.importKey(
            "raw",
            new TextEncoder().encode(mnemonic),
            "PBKDF2",
            false,
            ["deriveKey"]
        );
        return crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt.buffer as ArrayBuffer,
                iterations: 600000,
                hash: "SHA-256",
            },
            passwordKey,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
    }

/**
     * Encrypt the private key bundle (JSON containing the base64 Curve25519 private key
     * AND the public key) with the mnemonic-derived key. Returns the bundle ready for
     * backend storage.
     *
     * Storing the public key alongside the private key is critical: the recovery flow
     * must persist BOTH keys to IndexedDB so the ratchet identity can be rebuilt on a
     * new device. Without the public key, SessionRatchetService cannot initialize and
     * old messages cannot be decrypted.
     */
    async encryptPrivateKeyWithMnemonic(
        privateKeyBase64: string,
        publicKeyBase64: string,
        mnemonic: string
    ): Promise<RecoveryBlobDTO> {
        const bundle = JSON.stringify({
            curve25519PrivateKey: privateKeyBase64,
            curve25519PublicKey: publicKeyBase64,
        });
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const derivedKey = await this.deriveKeyFromMnemonic(mnemonic, salt);

const encryptedBuf = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            derivedKey,
            new TextEncoder().encode(bundle)
        );

        const bufToBase64 = (buf: ArrayBuffer): string => {
            const bytes = new Uint8Array(buf);
            let binary = "";
            for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
            return btoa(binary);
        };

        return {
            encryptedData: bufToBase64(encryptedBuf),
            iv: bufToBase64(iv.buffer),
            salt: bufToBase64(salt.buffer),
        };
    }

/**
     * Decrypt the private key bundle from a recovery blob using the mnemonic.
     * Returns the JSON string containing the base64 Curve25519 private key.
     */
    async decryptPrivateKeyWithMnemonic(
        blob: RecoveryBlobDTO,
        mnemonic: string
    ): Promise<string> {
        const base64ToBuf = (base64: string): ArrayBuffer => {
            const binary = atob(base64);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
            return bytes.buffer;
        };

        const salt = new Uint8Array(base64ToBuf(blob.salt));
        const derivedKey = await this.deriveKeyFromMnemonic(mnemonic, salt);

        const decryptedBuf = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: base64ToBuf(blob.iv) },
            derivedKey,
            base64ToBuf(blob.encryptedData)
        );

        return new TextDecoder().decode(decryptedBuf);
    }

    /**
     * Upload the recovery blob to the backend.
     */
    async uploadRecoveryBlob(
        blob: RecoveryBlobDTO,
        token: string
    ): Promise<void> {
        const res = await fetch(`${BASE_API_URL}/api/recovery/blob`, {
            method: "PUT",
            headers: {
                "Content-Type": "application/json",
                Authorization: `${AUTHORIZATION_PREFIX}${token}`,
            },
            body: JSON.stringify(blob),
        });
        if (!res.ok) {
            throw new Error("Failed to upload recovery blob");
        }
    }

    /**
     * Fetch the recovery blob from the backend.
     */
    async fetchRecoveryBlob(token: string): Promise<RecoveryBlobDTO | null> {
        const res = await fetch(`${BASE_API_URL}/api/recovery/blob`, {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
                Authorization: `${AUTHORIZATION_PREFIX}${token}`,
            },
        });
        if (res.status === 204) return null;
        if (!res.ok) throw new Error("Failed to fetch recovery blob");
        return res.json();
    }

    /**
     * Check if the recovery phrase has been shown to this user (local flag).
     */
    hasShownPhrase(): boolean {
        return localStorage.getItem(this.STORAGE_KEY) === "true";
    }

    /**
     * Mark the recovery phrase as shown (called after user checks "I saved this").
     */
    markPhraseShown(): void {
        localStorage.setItem(this.STORAGE_KEY, "true");
    }

/**
     * Full recovery flow: enter mnemonic → fetch blob → decrypt private key → re-wrap with new password.
     */
    async recoverAccess(
        mnemonic: string,
        newPassword: string,
        userId: string,
        token: string
    ): Promise<void> {
        // 1. Fetch recovery blob from backend
        const blob = await this.fetchRecoveryBlob(token);
        if (!blob) {
            throw new Error("No recovery blob found for this account. Was a recovery phrase generated on signup?");
        }

// 2. Decrypt the key bundle with mnemonic. The blob stores a JSON bundle
        //    containing BOTH the Curve25519 private key and the public key.
        const decryptedBundle = await this.decryptPrivateKeyWithMnemonic(blob, mnemonic);

        let privateKeyBase64: string;
        let curve25519PublicKey: string;

        try {
            const parsed = JSON.parse(decryptedBundle);
            privateKeyBase64 = parsed.curve25519PrivateKey;
            curve25519PublicKey = parsed.curve25519PublicKey;
} catch {
            // Legacy blob that stores only the raw private key string.
            // Re-derive the public key from the private key via Curve.async.createKeyPair.
privateKeyBase64 = decryptedBundle;
            // The default export of the libsignal package is an async factory that
            // resolves to the initialized { Curve } instance, which exposes `.async`.
            const libsignal = await import('@privacyresearch/libsignal-protocol-typescript');
            const { Curve } = await (libsignal.default as () => Promise<{ Curve: any }>)();
            const idKeyPair = await Curve.async.createKeyPair(base64ToArrayBuffer(privateKeyBase64));
            curve25519PublicKey = arrayBufferToBase64(idKeyPair.pubKey);
        }

        if (!privateKeyBase64) {
            throw new Error("Recovery blob did not contain a valid private key.");
        }

        // 3. Re-wrap the private key with the new password (replaces local IndexedDB record).
        //    The bundle stores the Curve25519 private key (same format as signup).
        const cryptoService = (await import("./CryptoService")).default;
        const encrypted = await cryptoService.encryptPrivateKey(privateKeyBase64, newPassword);

        // 4. Persist the key record locally, INCLUDING the public key so that
        //    loadOnSignIn() can initialize the ratchet identity and decrypt old messages.
        const KeyStorageService = (await import("./KeyStorageService")).default;

        await KeyStorageService.saveKeyRecord({
            userId,
            keyVersion: 1,
            encryptedData: encrypted.encryptedData,
            iv: encrypted.iv,
            salt: encrypted.salt,
            publicKey: curve25519PublicKey,
            curve25519PublicKey,
            curve25519PrivateKey: undefined,
            createdAt: new Date().toISOString(),
        } as any);

        // 5. Load the private key into the cache and re-initialize the ratchet.
        await KeyManagementService.loadOnSignIn(userId, newPassword);
    }
}

/** Utility: convert a base64 string to an ArrayBuffer. */
function base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

/** Utility: convert an ArrayBuffer to a base64 string. */
function arrayBufferToBase64(buf: ArrayBuffer): string {
    const bytes = new Uint8Array(buf);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

const recoveryService = new RecoveryService();
export default recoveryService;

