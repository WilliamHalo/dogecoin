// Copyright (c) 2023 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/bip39.h"

#include "crypto/sha256.h"
#include "crypto/hmac_sha512.h"
#include "hash.h"
#include "random.h"
#include "support/cleanse.h"
#include "utilstrencodings.h"

#include <algorithm>
#include <cstring>
#include <sstream>

// BIP39 English word list (2048 words)
// This is the standard BIP39 word list for English
static const char* g_englishWordList[] = {
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
    "calm", "camera", "camp", "can", "canal", "cancel", "candy", "cannon", "canoe", "canvas",
    "canyon", "capable", "capital", "captain", "car", "carbon", "card", "cargo", "carpet", "carry",
    "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog", "catch", "category",
    "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery", "cement", "census", "century",
    "cereal", "certain", "chair", "chalk", "champion", "change", "chaos", "chapter", "charge", "chase",
    "chat", "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child",
    "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon", "circle",
    "citizen", "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean", "clerk",
    "clever", "click", "client", "cliff", "climb", "clinic", "clip", "clock", "clog", "close",
    "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch", "coach", "coast", "coconut",
    "code", "coffee", "coil", "coin", "collect", "color", "column", "combine", "come", "comfort",
    "comic", "common", "company", "concert", "conduct", "confirm", "connect", "consent", "consider", "control",
    "convince", "cook", "cool", "copper", "copy", "coral", "core", "corn", "correct", "cost",
    "cotton", "couch", "country", "couple", "course", "cousin", "cover", "coyote", "crack", "cradle",
    "craft", "cram", "crane", "crash", "crater", "crawl", "crazy", "cream", "credit", "creek",
    "crew", "cricket", "crime", "crisp", "critic", "crop", "cross", "crouch", "crowd", "crucial",
    "cruel", "cruise", "crumble", "crunch", "crush", "cry", "crystal", "cube", "culture", "cup",
    "cupboard", "curious", "current", "curtain", "curve", "cushion", "custom", "cute", "cycle", "dad",
    "damage", "damp", "dance", "danger", "daring", "dash", "daughter", "dawn", "day", "deal",
    "debate", "debris", "decade", "december", "decide", "decline", "decorate", "decrease", "deer", "defense",
    "define", "defy", "degree", "delay", "deliver", "demand", "demise", "denial", "dentist", "deny",
    "depart", "depend", "deposit", "depth", "deputy", "derive", "describe", "desert", "design", "desk",
    "despair", "destroy", "detail", "detect", "develop", "device", "devote", "diagram", "dial", "diamond",
    "diary", "dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur",
    "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss", "disorder", "display", "distance",
    "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll", "dolphin", "domain",
    "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft", "dragon", "drama",
    "drastic", "draw", "dream", "dress", "drift", "drill", "drink", "drip", "drive", "drop",
    "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch", "duty", "dwarf",
    "dynamic", "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy", "echo",
    "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight", "either", "elbow",
    "elder", "electric", "elegant", "element", "elephant", "elevator", "elite", "else", "embark", "embody",
    "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable", "enact", "end", "endless",
    "endorse", "enemy", "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist", "enough",
    "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode", "equal", "equip",
    "era", "erase", "erode", "erosion", "error", "erupt", "escape", "essay", "essence", "estate",
    "eternal", "ethics", "evidence", "evil", "evoke", "evolve", "exact", "example", "excess", "exchange",
    "excite", "exclude", "excuse", "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit",
    "exotic", "expand", "expect", "expire", "explain", "expose", "express", "extend", "extra", "eye",
    "eyebrow", "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false", "fame",
    "family", "famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father",
    "fatigue", "fault", "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female",
    "fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field", "figure", "file",
    "filter", "final", "find", "fine", "finger", "finish", "fire", "firm", "first", "fiscal",
    "fish", "fit", "fitness", "fix", "flag", "flame", "flash", "flat", "flavor", "flee",
    "flight", "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly", "foam",
    "focus", "fog", "foil", "fold", "follow", "food", "foot", "force", "forest", "forget",
    "fork", "fortune", "forum", "forward", "fossil", "foster", "found", "fox", "fragile", "frame",
    "frequent", "fresh", "friend", "fringe", "frog", "front", "frost", "frown", "frozen", "fruit",
    "fuel", "fun", "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy", "gallery",
    "game", "gap", "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp", "gate",
    "gather", "gauge", "gaze", "general", "genius", "genre", "gentle", "genuine", "gesture", "ghost",
    "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance", "glare",
    "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue", "goat",
    "gold", "good", "goose", "gossip", "govern", "gown", "grab", "grace", "grade", "gradual",
    "grain", "grand", "grape", "grass", "gravity", "great", "green", "grid", "grief", "grit",
    "grocery", "group", "grow", "grunt", "guard", "guess", "guide", "guilt", "guitar", "gun",
    "gym", "habit", "hair", "half", "hammer", "hamster", "hand", "happy", "harbor", "hard",
    "harsh", "harvest", "hat", "have", "hawk", "hazard", "head", "health", "heart", "heavy",
    "hedgehog", "height", "hello", "helmet", "help", "hen", "hero", "hidden", "high", "hill",
    "hint", "hip", "hire", "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow",
    "holy", "home", "honey", "hood", "hope", "horn", "horror", "horse", "hospital", "host",
    "hotel", "hour", "hover", "hub", "huge", "human", "humble", "humor", "hundred", "hungry",
    "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "ice", "icon", "idea", "identify",
    "idle", "ignore", "ill", "illegal", "illness", "image", "imitate", "immense", "immune", "impact",
    "impose", "improve", "impulse", "inch", "include", "income", "increase", "index", "indicate", "indoor",
    "industry", "infant", "inflict", "inform", "inhale", "inherit", "initial", "inject", "injury", "inmate",
    "inner", "innocent", "input", "inquiry", "insane", "insect", "inside", "insight", "insist", "inspire",
    "install", "intact", "interest", "into", "invest", "invite", "involve", "iron", "island", "isolate",
    "issue", "item", "ivory", "jacket", "jaguar", "jar", "jazz", "jealous", "jeans", "jelly",
    "jewel", "job", "join", "joke", "journey", "joy", "judge", "juice", "jump", "jungle",
    "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup", "key", "kick", "kid",
    "kidney", "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten", "kiwi", "knee",
    "knife", "knock", "know", "lab", "label", "labor", "ladder", "lady", "lake", "lamp",
    "language", "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law", "lawn",
    "lawsuit", "layer", "lazy", "leader", "leaf", "league", "learn", "leave", "lecture", "left",
    "leg", "legal", "legend", "leisure", "lemon", "lend", "length", "lens", "leopard", "lesson",
    "letter", "level", "liar", "liberty", "library", "license", "life", "lift", "light", "like",
    "limb", "limit", "link", "lion", "liquid", "list", "little", "live", "lizard", "load",
    "loan", "lobster", "local", "lock", "logic", "lonely", "long", "loop", "lottery", "loud",
    "lounge", "love", "loyal", "lucky", "lunch", "luxury", "lyrics", "machine", "mad", "magic",
    "magnet", "maid", "mail", "main", "major", "make", "mammal", "man", "manage", "mandate",
    "mango", "mansion", "manual", "maple", "marble", "march", "margin", "marine", "market", "marriage",
    "mask", "mass", "master", "match", "material", "math", "matrix", "matter", "maximum", "maze",
    "meadow", "mean", "measure", "meat", "mechanic", "medal", "media", "melody", "melt", "member",
    "memory", "mention", "menu", "mercy", "merge", "merit", "merry", "mesh", "message", "metal",
    "method", "middle", "midnight", "milk", "million", "mimic", "mind", "minimum", "minor", "minute",
    "miracle", "mirror", "misery", "miss", "mistake", "mix", "mixed", "mixture", "mobile", "model",
    "modify", "mom", "moment", "monitor", "monkey", "month", "moon", "moral", "more", "morning",
    "mosquito", "mother", "motion", "motor", "mountain", "mouse", "move", "movie", "much", "muffin",
    "mule", "multiply", "muscle", "museum", "mushroom", "music", "must", "mutual", "myself", "mystery",
    "myth", "naive", "name", "napkin", "narrow", "nasty", "nation", "nature", "near", "neck",
    "need", "negative", "neglect", "neither", "nephew", "nerve", "nest", "net", "network", "neutral",
    "never", "news", "next", "nice", "night", "noble", "noise", "nominee", "noodle", "normal",
    "north", "nose", "notable", "note", "nothing", "notice", "novel", "now", "nuclear", "number",
    "nurse", "nut", "oak", "obey", "object", "oblige", "obscure", "observe", "obtain", "obvious",
    "occur", "ocean", "october", "odor", "off", "offer", "office", "often", "oil", "okay",
    "old", "olive", "olympic", "omit", "once", "one", "onion", "online", "only", "open",
    "opera", "opinion", "oppose", "option", "orange", "orbit", "orchard", "order", "ordinary", "organ",
    "organize", "orient", "original", "orphan", "ostrich", "other", "outdoor", "outer", "output", "outside",
    "oval", "oven", "over", "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle",
    "page", "pair", "palace", "palm", "panda", "panel", "panic", "panther", "paper", "parade",
    "parent", "park", "parrot", "party", "pass", "patch", "path", "patient", "patrol", "pattern",
    "pause", "pave", "payment", "peace", "peanut", "pear", "peasant", "pelican", "pen", "penalty",
    "pencil", "people", "pepper", "perfect", "permit", "person", "pet", "phone", "photo", "phrase",
    "physical", "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot", "pink",
    "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate", "play",
    "please", "pledge", "pluck", "plug", "plunge", "poem", "poet", "point", "polar", "pole",
    "police", "pond", "pony", "pool", "popular", "portion", "position", "possible", "post", "potato",
    "pottery", "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare", "present",
    "pretty", "prevent", "price", "pride", "primary", "print", "priority", "prison", "private", "prize",
    "problem", "process", "produce", "profit", "program", "project", "promote", "proof", "property", "prosper",
    "protect", "proud", "provide", "public", "pudding", "pull", "pulp", "pulse", "pumpkin", "punch",
    "pupil", "puppy", "purchase", "purity", "purpose", "purse", "push", "put", "puzzle", "pyramid",
    "quality", "quantum", "quarter", "question", "quick", "quit", "quiz", "quote", "rabbit", "raccoon",
    "race", "rack", "radar", "radio", "rail", "rain", "raise", "rally", "ramp", "ranch",
    "random", "range", "rapid", "rare", "rate", "rather", "raven", "raw", "razor", "ready",
    "real", "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record", "recycle", "reduce",
    "reflect", "reform", "refuse", "region", "regret", "regular", "reject", "relax", "release", "relief",
    "rely", "remain", "remember", "remind", "remove", "render", "renew", "rent", "reopen", "repair",
    "repeat", "replace", "report", "require", "rescue", "resemble", "resist", "resource", "response", "result",
    "retire", "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm", "rib", "ribbon",
    "rice", "rich", "ride", "ridge", "rifle", "right", "rigid", "ring", "riot", "ripple",
    "risk", "ritual", "rival", "river", "road", "roast", "robot", "robust", "rocket", "romance",
    "roof", "rookie", "room", "rose", "rotate", "rough", "round", "route", "royal", "rubber",
    "rude", "rug", "rule", "rumor", "run", "rural", "rush", "rust", "sad", "saddle",
    "sadness", "safe", "sail", "salad", "salmon", "salon", "salt", "salute", "same", "sample",
    "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say", "scale", "scan", "scare",
    "scatter", "scene", "scheme", "school", "science", "scissors", "scorpion", "scout", "scrap", "screen",
    "script", "scrub", "sea", "search", "season", "seat", "second", "secret", "section", "security",
    "seed", "seek", "segment", "select", "sell", "seminar", "senior", "sense", "sentence", "series",
    "service", "session", "settle", "setup", "seven", "shadow", "shaft", "shallow", "share", "shark",
    "sharp", "sheep", "sheet", "shelf", "shell", "shelter", "shift", "shine", "ship", "shiver",
    "shock", "shoe", "shoot", "shop", "short", "shoulder", "shove", "shrimp", "shrug", "shuffle",
    "shy", "sibling", "sick", "side", "siege", "sight", "sign", "silent", "silk", "silly",
    "silver", "similar", "simple", "since", "sing", "siren", "sister", "situate", "six", "size",
    "skate", "sketch", "ski", "skill", "skin", "skirt", "skull", "slab", "slam", "sleep",
    "slender", "slice", "slide", "slight", "slim", "slogan", "slot", "slow", "slush", "small",
    "smart", "smile", "smoke", "smooth", "snack", "snake", "snap", "sniff", "snow", "soap",
    "soccer", "social", "sock", "soda", "soft", "solar", "soldier", "solid", "solution", "solve",
    "someone", "song", "soon", "sorry", "sort", "soul", "sound", "soup", "source", "south",
    "space", "spare", "spatial", "spawn", "speak", "special", "speed", "spell", "spend", "sphere",
    "spice", "spider", "spike", "spin", "spirit", "split", "spoil", "sponsor", "spoon", "sport",
    "spot", "spray", "spread", "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium",
    "staff", "stage", "stairs", "stamp", "stand", "start", "state", "stay", "steak", "steel",
    "stem", "step", "stereo", "stick", "still", "sting", "stock", "stomach", "stone", "stool",
    "story", "stove", "strategy", "street", "strike", "strong", "struggle", "student", "stuff", "stumble",
    "style", "subject", "submit", "subway", "success", "such", "sudden", "suffer", "sugar", "suggest",
    "suit", "summer", "sun", "sunny", "sunset", "super", "supply", "supreme", "sure", "surface",
    "surge", "surprise", "surround", "survey", "suspect", "sustain", "swallow", "swamp", "swap", "swarm",
    "swear", "sweet", "swift", "swim", "swing", "switch", "sword", "symbol", "symptom", "syrup",
    "system", "table", "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target",
    "task", "taste", "tattoo", "taxi", "teach", "team", "tell", "ten", "tenant", "tennis",
    "tent", "term", "test", "text", "thank", "that", "theme", "then", "theory", "there",
    "they", "thing", "this", "thought", "three", "thrive", "throw", "thunder", "ticket", "tide",
    "tiger", "tilt", "timber", "time", "tiny", "tip", "tired", "tissue", "title", "toast",
    "tobacco", "today", "toddler", "toe", "together", "toilet", "token", "tomato", "tomorrow", "tone",
    "tongue", "tonight", "tool", "tooth", "top", "topic", "topple", "torch", "tornado", "tortoise",
    "toss", "total", "tourist", "toward", "tower", "town", "toy", "track", "trade", "traffic",
    "tragic", "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree", "trend",
    "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy", "trouble", "truck", "true",
    "truly", "trumpet", "trust", "truth", "try", "tube", "tuition", "tumble", "tuna", "tunnel",
    "turkey", "turn", "turtle", "twelve", "twenty", "twice", "twin", "twist", "two", "type",
    "typical", "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo", "unfair",
    "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown", "unlock", "until", "unusual",
    "unveil", "update", "upgrade", "uphold", "upon", "upper", "upset", "urban", "urge", "usage",
    "use", "used", "useful", "useless", "usual", "utility", "vacant", "vacuum", "vague", "valid",
    "valley", "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle", "velvet",
    "vendor", "venture", "venue", "verb", "verify", "version", "very", "vessel", "veteran", "viable",
    "vibrant", "vicious", "victory", "video", "view", "village", "vintage", "violin", "virtual", "virus",
    "visa", "visit", "visual", "vital", "vivid", "vocal", "voice", "void", "volcano", "volume",
    "vote", "voyage", "wage", "wagon", "wait", "walk", "wall", "walnut", "want", "warfare",
    "warm", "warrior", "wash", "wasp", "waste", "water", "wave", "way", "wealth", "weapon",
    "wear", "weasel", "weather", "web", "wedding", "weekend", "weird", "welcome", "west", "wet",
    "whale", "what", "wheat", "wheel", "when", "where", "whip", "whisper", "wide", "width",
    "wife", "wild", "will", "win", "window", "wine", "wing", "wink", "winner", "winter",
    "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman", "wonder", "wood", "wool",
    "word", "work", "world", "worry", "worth", "wrap", "wreck", "wrestle", "wrist", "write",
    "wrong", "yard", "year", "yellow", "you", "young", "youth", "zebra", "zero", "zone", "zoo"
};

const char* const* BIP39::GetWordList(Language language)
{
    switch (language) {
    case Language::ENGLISH:
        return g_englishWordList;
    default:
        return g_englishWordList;
    }
}

size_t BIP39::GetWordListSize(Language language)
{
    (void)language;  // Language parameter unused - all lists have same size
    return 2048;  // BIP39 standard word list size
}

SecureVector BIP39::GenerateEntropy(size_t size)
{
    // Valid sizes per BIP39: 16, 20, 24, 28, 32 bytes
    if (size != 16 && size != 20 && size != 24 && size != 28 && size != 32) {
        size = 32;  // Default to 256-bit entropy
    }

    SecureVector entropy(size);
    GetRandBytes(entropy.data(), size);
    return entropy;
}

size_t BIP39::GetChecksumBits(size_t entropyLen)
{
    // CS = ENT / 32
    return entropyLen * 8 / 32;
}

uint8_t BIP39::ComputeChecksum(const SecureVector& entropy)
{
    // Compute SHA256 hash of entropy
    std::vector<unsigned char> vchEntropy(entropy.begin(), entropy.end());
    uint256 hash = Hash(vchEntropy.begin(), vchEntropy.end());

    // CS = ENT / 32 (number of checksum bits)
    size_t checksumBits = GetChecksumBits(entropy.size());

    // Take the first checksumBits from the hash
    // For example, if checksumBits is 8, we want the first byte
    uint8_t mask = 0xFF << (8 - checksumBits);
    return hash.begin()[0] & mask;
}

std::string BIP39::EntropyToMnemonic(const SecureVector& entropy, Language language)
{
    // Validate entropy length
    if (entropy.size() != 16 && entropy.size() != 20 && entropy.size() != 24 &&
        entropy.size() != 28 && entropy.size() != 32) {
        return "";
    }

    const char* const* wordList = GetWordList(language);

    // Compute checksum
    uint8_t checksum = ComputeChecksum(entropy);

    // Combine entropy + checksum
    // Total bits = ENT + CS = ENT + ENT/32 = ENT * 33/32
    size_t totalBits = entropy.size() * 8 + GetChecksumBits(entropy.size());
    size_t numWords = totalBits / 11;  // Each word represents 11 bits

    std::vector<std::string> words;
    words.reserve(numWords);

    // Convert to bits and extract 11-bit chunks
    std::vector<bool> bits;
    bits.reserve(totalBits);

    // Add entropy bits
    for (size_t i = 0; i < entropy.size(); i++) {
        for (int j = 7; j >= 0; j--) {
            bits.push_back((entropy[i] >> j) & 1);
        }
    }

    // Add checksum bits
    size_t checksumBits = GetChecksumBits(entropy.size());
    for (size_t i = 0; i < checksumBits; i++) {
        bits.push_back((checksum >> (7 - i)) & 1);
    }

    // Extract 11-bit indices
    for (size_t i = 0; i < numWords; i++) {
        size_t index = 0;
        for (size_t j = 0; j < 11; j++) {
            index = (index << 1) | (bits[i * 11 + j] ? 1 : 0);
        }
        words.push_back(wordList[index]);
    }

    // Join words with spaces
    std::string mnemonic;
    for (size_t i = 0; i < words.size(); i++) {
        if (i > 0) mnemonic += " ";
        mnemonic += words[i];
    }

    return mnemonic;
}

SecureVector BIP39::MnemonicToEntropy(const std::string& mnemonic, Language language)
{
    // Split mnemonic into words
    std::vector<std::string> words;
    std::istringstream iss(mnemonic);
    std::string word;
    while (iss >> word) {
        words.push_back(word);
    }

    // Validate word count
    if (words.size() != 12 && words.size() != 15 && words.size() != 18 &&
        words.size() != 21 && words.size() != 24) {
        return SecureVector();
    }

    const char* const* wordList = GetWordList(language);
    size_t wordListSize = GetWordListSize(language);

    // Build index list
    std::vector<size_t> indices;
    indices.reserve(words.size());

    for (const std::string& w : words) {
        // Find word in list
        size_t index = wordListSize;
        for (size_t i = 0; i < wordListSize; i++) {
            if (std::strcmp(w.c_str(), wordList[i]) == 0) {
                index = i;
                break;
            }
        }
        if (index >= wordListSize) {
            return SecureVector();  // Word not found
        }
        indices.push_back(index);
    }

    // Convert 11-bit indices back to entropy
    size_t numWords = words.size();
    size_t totalBits = numWords * 11;
    size_t checksumBits = totalBits % 32;  // CS = totalBits - ENT
    size_t entropyBits = totalBits - checksumBits;
    size_t entropyBytes = entropyBits / 8;

    SecureVector entropy(entropyBytes);
    size_t bitPos = 0;

    for (size_t idx : indices) {
        for (int i = 10; i >= 0; i--) {
            size_t bytePos = bitPos / 8;
            size_t bitOffset = 7 - (bitPos % 8);
            if ((idx >> i) & 1) {
                entropy[bytePos] |= (1 << bitOffset);
            }
            bitPos++;
        }
    }

    // Verify checksum
    uint8_t expectedChecksum = ComputeChecksum(entropy);
    uint8_t actualChecksum = 0;
    for (size_t i = 0; i < checksumBits; i++) {
        size_t bitPos = entropyBits + i;
        size_t bytePos = bitPos / 8;
        size_t bitOffset = 7 - (bitPos % 8);
        if (entropy[bytePos] & (1 << bitOffset)) {
            actualChecksum |= (1 << (7 - i));
        }
    }

    // Remove checksum bits from entropy
    // (Actually we need to mask them out since we included them)
    // They should already be in the correct positions

    if (expectedChecksum != (actualChecksum & (0xFF << (8 - checksumBits)))) {
        return SecureVector();  // Checksum mismatch
    }

    return entropy;
}

bool BIP39::CheckMnemonic(const std::string& mnemonic, Language* language)
{
    // Try each language
    for (uint8_t lang = 0; lang < static_cast<uint8_t>(Language::COUNT); lang++) {
        Language l = static_cast<Language>(lang);
        SecureVector entropy = MnemonicToEntropy(mnemonic, l);
        if (!entropy.empty()) {
            if (language) {
                *language = l;
            }
            return true;
        }
    }
    return false;
}

SecureVector BIP39::MnemonicToSeed(const std::string& mnemonic, const std::string& passphrase)
{
    // BIP39 seed generation: PBKDF2-HMAC-SHA512
    // Password = mnemonic (the PBKDF2 password parameter)
    // Salt = "mnemonic" + passphrase
    std::string salt = std::string("mnemonic") + passphrase;

    // 2048 iterations
    const int iterations = 2048;

    SecureVector seed(64);  // 512 bits

    // PBKDF2-HMAC-SHA512 implementation
    // T = F(Password, Salt, c, i) where F is the PRF (HMAC-SHA512 here)
    // For each block i (1-indexed):
    //   U_1 = PRF(Password, Salt || INT_32_BE(i))
    //   U_2 = PRF(Password, U_1)
    //   ...
    //   U_c = PRF(Password, U_{c-1})
    //   T_i = U_1 XOR U_2 XOR ... XOR U_c

    std::vector<unsigned char> t(64, 0);
    std::vector<unsigned char> u(64);

    // Block index 1 (big endian)
    unsigned char blockIndex[4] = {0x00, 0x00, 0x00, 0x01};

    // U_1 = HMAC-SHA512(Key=mnemonic, Data=salt || blockIndex)
    // Note: In PBKDF2, Password is the HMAC key, Salt is the message prefix
    CHMAC_SHA512 hmac1((const unsigned char*)mnemonic.data(), mnemonic.size());
    hmac1.Write((const unsigned char*)salt.data(), salt.size());
    hmac1.Write(blockIndex, 4);
    hmac1.Finalize(u.data());

    // T = U_1
    t = u;

    // Remaining iterations: U_i = HMAC-SHA512(Key=mnemonic, Data=U_{i-1})
    for (int i = 1; i < iterations; i++) {
        CHMAC_SHA512 hmac((const unsigned char*)mnemonic.data(), mnemonic.size());
        hmac.Write(u.data(), u.size());
        hmac.Finalize(u.data());

        // XOR with t
        for (size_t j = 0; j < t.size(); j++) {
            t[j] ^= u[j];
        }
    }

    memcpy(seed.data(), t.data(), 64);
    memory_cleanse(u.data(), u.size());
    memory_cleanse(t.data(), t.size());

    return seed;
}

std::string BIP39::GenerateMnemonic(size_t strength, Language language)
{
    // Validate strength
    if (strength != 128 && strength != 160 && strength != 192 && strength != 224 && strength != 256) {
        strength = 256;
    }

    size_t entropySize = strength / 8;
    SecureVector entropy = GenerateEntropy(entropySize);
    std::string mnemonic = EntropyToMnemonic(entropy, language);

    // Clear entropy
    memory_cleanse(entropy.data(), entropy.size());

    return mnemonic;
}

// CMnemonicSeed implementation

bool CMnemonicSeed::Init(const std::string& mnemonic, const std::string& passphrase, Language lang)
{
    // Validate mnemonic
    if (!BIP39::CheckMnemonic(mnemonic, nullptr)) {
        return false;
    }

    language = lang;
    strMnemonic = mnemonic;
    strPassphrase = passphrase;
    vchSeed = BIP39::MnemonicToSeed(mnemonic, passphrase);

    return IsValid();
}

bool CMnemonicSeed::InitFromEntropy(const SecureVector& entropy, const std::string& passphrase, Language lang)
{
    strMnemonic = BIP39::EntropyToMnemonic(entropy, lang);
    if (strMnemonic.empty()) {
        return false;
    }

    language = lang;
    strPassphrase = passphrase;
    vchSeed = BIP39::MnemonicToSeed(strMnemonic, passphrase);

    return IsValid();
}

void CMnemonicSeed::Clear()
{
    // Securely clear all data
    memory_cleanse(&strMnemonic[0], strMnemonic.size());
    strMnemonic.clear();

    memory_cleanse(vchSeed.data(), vchSeed.size());
    vchSeed.clear();

    memory_cleanse(&strPassphrase[0], strPassphrase.size());
    strPassphrase.clear();
}
